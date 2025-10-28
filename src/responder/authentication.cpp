#include "opaque/responder.h"
#include <sodium.h>
#include <algorithm>
namespace ecliptix::security::opaque::responder {
namespace {
    namespace oblivious_prf = ecliptix::security::opaque::oblivious_prf;
    namespace crypto = ecliptix::security::opaque::crypto;
}
KE2::KE2() : responder_nonce(NONCE_LENGTH), responder_public_key(PUBLIC_KEY_LENGTH),
             credential_response(CREDENTIAL_RESPONSE_LENGTH), responder_mac(MAC_LENGTH) {}
ResponderState::ResponderState() : responder_private_key(PRIVATE_KEY_LENGTH),
                            responder_public_key(PUBLIC_KEY_LENGTH),
                            responder_ephemeral_private_key(PRIVATE_KEY_LENGTH),
                            responder_ephemeral_public_key(PUBLIC_KEY_LENGTH),
                            initiator_public_key(PUBLIC_KEY_LENGTH),
                            session_key(0),
                            expected_initiator_mac(MAC_LENGTH) {}
ResponderState::~ResponderState() {
    sodium_memzero(responder_private_key.data(), responder_private_key.size());
    sodium_memzero(responder_public_key.data(), responder_public_key.size());
    sodium_memzero(responder_ephemeral_private_key.data(), responder_ephemeral_private_key.size());
    sodium_memzero(responder_ephemeral_public_key.data(), responder_ephemeral_public_key.size());
    sodium_memzero(initiator_public_key.data(), initiator_public_key.size());
    if (!session_key.empty()) {
        sodium_memzero(session_key.data(), session_key.size());
    }
    sodium_memzero(expected_initiator_mac.data(), expected_initiator_mac.size());
}
Result generate_ke2_impl(const uint8_t* ke1_data, size_t ke1_length,
                        const ResponderCredentials& credentials,
                        const secure_bytes& responder_private_key,
                        const secure_bytes& responder_public_key,
                        KE2& ke2, ResponderState& state) {
    (void)responder_public_key;
    if (!ke1_data || ke1_length != KE1_LENGTH) {
        return Result::InvalidInput;
    }
    const uint8_t* credential_request = ke1_data;
    const uint8_t* initiator_public_key = ke1_data + crypto_core_ristretto255_BYTES;
    const uint8_t* initiator_nonce = ke1_data + crypto_core_ristretto255_BYTES + PUBLIC_KEY_LENGTH;
    std::copy(initiator_public_key, initiator_public_key + PUBLIC_KEY_LENGTH,
             state.initiator_public_key.begin());
    std::copy(responder_private_key.begin(), responder_private_key.end(),
              state.responder_private_key.begin());
    std::copy(responder_public_key.begin(), responder_public_key.end(),
              state.responder_public_key.begin());

    // Generate responder ephemeral keypair for this session
    Result result = crypto::random_bytes(state.responder_ephemeral_private_key.data(), PRIVATE_KEY_LENGTH);
    if (result != Result::Success) [[unlikely]] {
        return result;
    }
    if (crypto_scalarmult_ristretto255_base(state.responder_ephemeral_public_key.data(),
                                           state.responder_ephemeral_private_key.data()) != 0) [[unlikely]] {
        return Result::CryptoError;
    }

    result = crypto::random_bytes(ke2.responder_nonce.data(), NONCE_LENGTH);
    if (result != Result::Success) [[unlikely]] {
        return result;
    }

    // Send responder EPHEMERAL public key, not static
    std::copy(state.responder_ephemeral_public_key.begin(), state.responder_ephemeral_public_key.end(),
             ke2.responder_public_key.begin());
    uint8_t evaluated_element[crypto_core_ristretto255_BYTES];
    result = oblivious_prf::evaluate(credential_request, credentials.masking_key.data(), evaluated_element);
    if (result != Result::Success) [[unlikely]] {
        return result;
    }
    size_t offset = 0;
    std::copy(evaluated_element, evaluated_element + crypto_core_ristretto255_BYTES,
             ke2.credential_response.begin() + static_cast<std::ptrdiff_t>(offset));
    offset += crypto_core_ristretto255_BYTES;
    std::copy(credentials.envelope.begin(), credentials.envelope.end(),
             ke2.credential_response.begin() + static_cast<std::ptrdiff_t>(offset));
    const uint8_t* initiator_ephemeral_public = initiator_public_key;
    const uint8_t* initiator_static_public = credentials.initiator_public_key.data();
    uint8_t dh1[PUBLIC_KEY_LENGTH];
    if (crypto_scalarmult_ristretto255(dh1, responder_private_key.data(),
                                      initiator_static_public) != 0) {
        return Result::CryptoError;
    }
    uint8_t dh2[PUBLIC_KEY_LENGTH];
    if (crypto_scalarmult_ristretto255(dh2, responder_private_key.data(),
                                      initiator_ephemeral_public) != 0) {
        return Result::CryptoError;
    }
    uint8_t dh3[PUBLIC_KEY_LENGTH];
    if (crypto_scalarmult_ristretto255(dh3, state.responder_ephemeral_private_key.data(),
                                      initiator_static_public) != 0) {
        return Result::CryptoError;
    }
    secure_bytes ikm(3 * PUBLIC_KEY_LENGTH);
    std::copy(dh1, dh1 + PUBLIC_KEY_LENGTH,
             ikm.begin());
    std::copy(dh2, dh2 + PUBLIC_KEY_LENGTH,
             ikm.begin() + PUBLIC_KEY_LENGTH);
    std::copy(dh3, dh3 + PUBLIC_KEY_LENGTH,
             ikm.begin() + 2 * PUBLIC_KEY_LENGTH);
    uint8_t prk[crypto_auth_hmacsha512_BYTES];
    const uint8_t salt[] = "OPAQUE";
    result = crypto::key_derivation_extract(salt, sizeof(salt) - 1, ikm.data(), ikm.size(), prk);
    if (result != Result::Success) {
        return result;
    }
    state.session_key.resize(HASH_LENGTH);
    const uint8_t session_info[] = "SessionKey";
    result = crypto::key_derivation_expand(prk, sizeof(prk), session_info, sizeof(session_info) - 1,
                               state.session_key.data(), state.session_key.size());
    if (result != Result::Success) {
        return result;
    }
    secure_bytes mac_input(2 * NONCE_LENGTH + 2 * PUBLIC_KEY_LENGTH);
    offset = 0;
    std::copy(initiator_ephemeral_public, initiator_ephemeral_public + PUBLIC_KEY_LENGTH,
             mac_input.begin() + static_cast<std::ptrdiff_t>(offset));
    offset += PUBLIC_KEY_LENGTH;
    std::copy(state.responder_ephemeral_public_key.begin(), state.responder_ephemeral_public_key.end(),
             mac_input.begin() + static_cast<std::ptrdiff_t>(offset));
    offset += PUBLIC_KEY_LENGTH;
    std::copy(initiator_nonce, initiator_nonce + NONCE_LENGTH,
             mac_input.begin() + static_cast<std::ptrdiff_t>(offset));
    offset += NONCE_LENGTH;
    std::copy(ke2.responder_nonce.begin(), ke2.responder_nonce.end(),
             mac_input.begin() + static_cast<std::ptrdiff_t>(offset));
    uint8_t responder_mac_key[crypto_auth_hmacsha512_BYTES];
    const uint8_t responder_mac_info[] = "ResponderMAC";
    result = crypto::key_derivation_expand(prk, sizeof(prk), responder_mac_info, sizeof(responder_mac_info) - 1,
                               responder_mac_key, sizeof(responder_mac_key));
    if (result != Result::Success) {
        return result;
    }
    result = crypto::hmac(responder_mac_key, sizeof(responder_mac_key),
                         mac_input.data(), mac_input.size(),
                         ke2.responder_mac.data());
    if (result != Result::Success) {
        return result;
    }
    uint8_t initiator_mac_key[crypto_auth_hmacsha512_BYTES];
    const uint8_t initiator_mac_info[] = "InitiatorMAC";
    result = crypto::key_derivation_expand(prk, sizeof(prk), initiator_mac_info, sizeof(initiator_mac_info) - 1,
                               initiator_mac_key, sizeof(initiator_mac_key));
    if (result != Result::Success) {
        return result;
    }
    result = crypto::hmac(initiator_mac_key, sizeof(initiator_mac_key),
                         mac_input.data(), mac_input.size(),
                         state.expected_initiator_mac.data());
    sodium_memzero(prk, sizeof(prk));
    sodium_memzero(responder_mac_key, sizeof(responder_mac_key));
    sodium_memzero(initiator_mac_key, sizeof(initiator_mac_key));
    return result;
}
Result responder_finish_impl(const uint8_t* ke3_data, size_t ke3_length,
                         const ResponderState& state, secure_bytes& session_key) {
    if (!ke3_data || ke3_length != KE3_LENGTH) {
        return Result::InvalidInput;
    }
    const uint8_t* initiator_mac = ke3_data;
    if (crypto_verify_64(initiator_mac, state.expected_initiator_mac.data()) != 0) {
        return Result::AuthenticationError;
    }
    session_key = state.session_key;
    return Result::Success;
}
}