#include "opaque/server.h"
#include <sodium.h>
#include <algorithm>
namespace ecliptix::security::opaque::server {
namespace {
    namespace oprf = ecliptix::security::opaque::oprf;
    namespace crypto = ecliptix::security::opaque::crypto;
}
KE2::KE2() : server_nonce(NONCE_LENGTH), server_public_key(PUBLIC_KEY_LENGTH),
             credential_response(CREDENTIAL_RESPONSE_LENGTH), server_mac(MAC_LENGTH) {}
ServerState::ServerState() : server_private_key(PRIVATE_KEY_LENGTH),
                            server_public_key(PUBLIC_KEY_LENGTH),
                            client_public_key(PUBLIC_KEY_LENGTH),
                            session_key(0),
                            expected_client_mac(MAC_LENGTH) {}
ServerState::~ServerState() {
    sodium_memzero(server_private_key.data(), server_private_key.size());
    sodium_memzero(server_public_key.data(), server_public_key.size());
    sodium_memzero(client_public_key.data(), client_public_key.size());
    if (!session_key.empty()) {
        sodium_memzero(session_key.data(), session_key.size());
    }
    sodium_memzero(expected_client_mac.data(), expected_client_mac.size());
}
Result generate_ke2_impl(const uint8_t* ke1_data, size_t ke1_length,
                        const ServerCredentials& credentials,
                        const secure_bytes& server_private_key,
                        const secure_bytes& server_public_key,
                        KE2& ke2, ServerState& state) {
    (void)server_public_key; 
    if (!ke1_data || ke1_length != KE1_LENGTH) {
        return Result::InvalidInput;
    }
    const uint8_t* credential_request = ke1_data;
    const uint8_t* client_public_key = ke1_data + PUBLIC_KEY_LENGTH;
    const uint8_t* client_nonce = ke1_data + PUBLIC_KEY_LENGTH + PUBLIC_KEY_LENGTH;
    std::copy(client_public_key, client_public_key + PUBLIC_KEY_LENGTH,
             state.client_public_key.begin());
    crypto::random_bytes(state.server_private_key.data(), PRIVATE_KEY_LENGTH);
    if (crypto_scalarmult_ristretto255_base(state.server_public_key.data(),
                                           state.server_private_key.data()) != 0) {
        return Result::CryptoError;
    }
    crypto::random_bytes(ke2.server_nonce.data(), NONCE_LENGTH);
    std::copy(state.server_public_key.begin(), state.server_public_key.end(),
             ke2.server_public_key.begin());
    uint8_t evaluated_element[crypto_core_ristretto255_BYTES];
    Result result = oprf::evaluate(credential_request, server_private_key.data(), evaluated_element);
    if (result != Result::Success) {
        return result;
    }
    size_t offset = 0;
    std::copy(evaluated_element, evaluated_element + crypto_core_ristretto255_BYTES,
             ke2.credential_response.begin() + offset);
    offset += crypto_core_ristretto255_BYTES;
    std::copy(credentials.envelope.begin(), credentials.envelope.end(),
             ke2.credential_response.begin() + offset);
    const uint8_t* client_ephemeral_public = ke1_data + PUBLIC_KEY_LENGTH;
    const uint8_t* client_static_public = state.client_public_key.data();
    uint8_t dh1[PUBLIC_KEY_LENGTH];
    if (crypto_scalarmult_ristretto255(dh1, server_private_key.data(),
                                      client_static_public) != 0) {
        return Result::CryptoError;
    }
    uint8_t dh2[PUBLIC_KEY_LENGTH];
    if (crypto_scalarmult_ristretto255(dh2, state.server_private_key.data(),
                                      client_static_public) != 0) {
        return Result::CryptoError;
    }
    uint8_t dh3[PUBLIC_KEY_LENGTH];
    if (crypto_scalarmult_ristretto255(dh3, server_private_key.data(),
                                      client_ephemeral_public) != 0) {
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
    result = crypto::kdf_extract(salt, sizeof(salt) - 1, ikm.data(), ikm.size(), prk);
    if (result != Result::Success) {
        return result;
    }
    state.session_key.resize(HASH_LENGTH);
    const uint8_t session_info[] = "SessionKey";
    result = crypto::kdf_expand(prk, sizeof(prk), session_info, sizeof(session_info) - 1,
                               state.session_key.data(), state.session_key.size());
    if (result != Result::Success) {
        return result;
    }
    secure_bytes mac_input(2 * NONCE_LENGTH + 2 * PUBLIC_KEY_LENGTH);
    offset = 0;
    std::copy(client_ephemeral_public, client_ephemeral_public + PUBLIC_KEY_LENGTH,
             mac_input.begin() + offset);
    offset += PUBLIC_KEY_LENGTH;
    std::copy(state.server_public_key.begin(), state.server_public_key.end(),
             mac_input.begin() + offset);
    offset += PUBLIC_KEY_LENGTH;
    std::copy(client_nonce, client_nonce + NONCE_LENGTH,
             mac_input.begin() + offset);
    offset += NONCE_LENGTH;
    std::copy(ke2.server_nonce.begin(), ke2.server_nonce.end(),
             mac_input.begin() + offset);
    uint8_t server_mac_key[crypto_auth_hmacsha512_BYTES];
    const uint8_t server_mac_info[] = "ServerMAC";
    result = crypto::kdf_expand(prk, sizeof(prk), server_mac_info, sizeof(server_mac_info) - 1,
                               server_mac_key, sizeof(server_mac_key));
    if (result != Result::Success) {
        return result;
    }
    result = crypto::hmac(server_mac_key, sizeof(server_mac_key),
                         mac_input.data(), mac_input.size(),
                         ke2.server_mac.data());
    if (result != Result::Success) {
        return result;
    }
    uint8_t client_mac_key[crypto_auth_hmacsha512_BYTES];
    const uint8_t client_mac_info[] = "ClientMAC";
    result = crypto::kdf_expand(prk, sizeof(prk), client_mac_info, sizeof(client_mac_info) - 1,
                               client_mac_key, sizeof(client_mac_key));
    if (result != Result::Success) {
        return result;
    }
    result = crypto::hmac(client_mac_key, sizeof(client_mac_key),
                         mac_input.data(), mac_input.size(),
                         state.expected_client_mac.data());
    sodium_memzero(prk, sizeof(prk));
    sodium_memzero(server_mac_key, sizeof(server_mac_key));
    sodium_memzero(client_mac_key, sizeof(client_mac_key));
    return result;
}
Result server_finish_impl(const uint8_t* ke3_data, size_t ke3_length,
                         const ServerState& state, secure_bytes& session_key) {
    if (!ke3_data || ke3_length != KE3_LENGTH) {
        return Result::InvalidInput;
    }
    const uint8_t* client_mac = ke3_data;
    if (crypto_verify_64(client_mac, state.expected_client_mac.data()) != 0) {
        return Result::AuthenticationError;
    }
    session_key = state.session_key;
    return Result::Success;
}
}