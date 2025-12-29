#include "opaque/responder.h"
#include <sodium.h>
#include <algorithm>

namespace ecliptix::security::opaque::responder {
    namespace {
        namespace oblivious_prf = oblivious_prf;
        namespace crypto = crypto;
    }

    KE2::KE2() : responder_nonce(NONCE_LENGTH), responder_public_key(PUBLIC_KEY_LENGTH),
                 credential_response(CREDENTIAL_RESPONSE_LENGTH), responder_mac(MAC_LENGTH) {
    }

    ResponderState::ResponderState() : responder_private_key(PRIVATE_KEY_LENGTH),
                                       responder_public_key(PUBLIC_KEY_LENGTH),
                                       responder_ephemeral_private_key(PRIVATE_KEY_LENGTH),
                                       responder_ephemeral_public_key(PUBLIC_KEY_LENGTH),
                                       initiator_public_key(PUBLIC_KEY_LENGTH),
                                       session_key(0),
                                       expected_initiator_mac(MAC_LENGTH),
                                       master_key(0),
                                       handshake_complete(false) {
    }

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
        if (!master_key.empty()) {
            sodium_memzero(master_key.data(), master_key.size());
        }
    }

    Result generate_ke2_impl(const uint8_t *ke1_data, size_t ke1_length,
                             const ResponderCredentials &credentials,
                             const secure_bytes &responder_private_key,
                             const secure_bytes &responder_public_key,
                             const uint8_t *account_id,
                             size_t account_id_length,
                             KE2 &ke2, ResponderState &state) {
        if (!ke1_data || ke1_length != KE1_LENGTH) {
            return Result::InvalidInput;
        }
        if (!account_id || account_id_length == 0) {
            return Result::InvalidInput;
        }
        if (!crypto::init()) {
            return Result::CryptoError;
        }
        auto is_all_zero = [](const uint8_t *data, size_t length) {
            for (size_t i = 0; i < length; ++i) {
                if (data[i] != 0) {
                    return false;
                }
            }
            return true;
        };
        const uint8_t *credential_request = ke1_data;
        const uint8_t *initiator_public_key = ke1_data + crypto_core_ristretto255_BYTES;
        const uint8_t *initiator_nonce = ke1_data + crypto_core_ristretto255_BYTES + PUBLIC_KEY_LENGTH;
        const uint8_t *initiator_ephemeral_public = initiator_public_key;
        const uint8_t *initiator_static_public = credentials.initiator_public_key.data();
        if (crypto_core_ristretto255_is_valid_point(credential_request) != 1 ||
            is_all_zero(credential_request, crypto_core_ristretto255_BYTES)) {
            return Result::InvalidInput;
        }
        if (crypto_core_ristretto255_is_valid_point(initiator_public_key) != 1 ||
            is_all_zero(initiator_public_key, PUBLIC_KEY_LENGTH)) {
            return Result::InvalidPublicKey;
        }
        if (credentials.initiator_public_key.size() != PUBLIC_KEY_LENGTH ||
            crypto_core_ristretto255_is_valid_point(credentials.initiator_public_key.data()) != 1 ||
            is_all_zero(credentials.initiator_public_key.data(), PUBLIC_KEY_LENGTH)) {
            return Result::InvalidPublicKey;
        }
        if (credentials.envelope.size() != ENVELOPE_LENGTH) {
            return Result::InvalidInput;
        }
        std::copy(initiator_public_key, initiator_public_key + PUBLIC_KEY_LENGTH,
                  state.initiator_public_key.begin());
        std::copy(responder_private_key.begin(), responder_private_key.end(),
                  state.responder_private_key.begin());
        std::copy(responder_public_key.begin(), responder_public_key.end(),
                  state.responder_public_key.begin());
        state.handshake_complete = false;

        Result result = Result::Success;
        uint8_t evaluated_element[crypto_core_ristretto255_BYTES] = {};
        uint8_t oprf_key[PRIVATE_KEY_LENGTH] = {};
        uint8_t dh1[PUBLIC_KEY_LENGTH] = {};
        uint8_t dh2[PUBLIC_KEY_LENGTH] = {};
        uint8_t dh3[PUBLIC_KEY_LENGTH] = {};
        uint8_t prk[crypto_auth_hmacsha512_BYTES] = {};
        uint8_t responder_mac_key[crypto_auth_hmacsha512_BYTES] = {};
        uint8_t initiator_mac_key[crypto_auth_hmacsha512_BYTES] = {};
        uint8_t transcript_hash[crypto_hash_sha512_BYTES] = {};
        secure_bytes ikm;
        secure_bytes mac_input;
        const auto* session_info = reinterpret_cast<const uint8_t *>(labels::kSessionKeyInfo);
        constexpr size_t session_info_length = labels::kSessionKeyInfoLength;
        const auto* master_key_info = reinterpret_cast<const uint8_t *>(labels::kMasterKeyInfo);
        constexpr size_t master_key_info_length = labels::kMasterKeyInfoLength;
        const auto* responder_mac_info = reinterpret_cast<const uint8_t *>(labels::kResponderMacInfo);
        constexpr size_t responder_mac_info_length = labels::kResponderMacInfoLength;
        const auto* initiator_mac_info = reinterpret_cast<const uint8_t *>(labels::kInitiatorMacInfo);
        constexpr size_t initiator_mac_info_length = labels::kInitiatorMacInfoLength;
        const uint8_t *responder_static_public = responder_public_key.data();
        const uint8_t *credential_response = ke2.credential_response.data();
        constexpr size_t mac_input_size = 2 * NONCE_LENGTH + 4 * PUBLIC_KEY_LENGTH + CREDENTIAL_RESPONSE_LENGTH;
        size_t offset = 0;

        do {
            crypto_core_ristretto255_scalar_random(state.responder_ephemeral_private_key.data());
        } while (sodium_is_zero(state.responder_ephemeral_private_key.data(),
                                state.responder_ephemeral_private_key.size()) == 1);
        if (crypto_scalarmult_ristretto255_base(state.responder_ephemeral_public_key.data(),
                                                state.responder_ephemeral_private_key.data()) != 0) [[unlikely]] {
            result = Result::CryptoError;
            goto cleanup;
        }

        result = crypto::random_bytes(ke2.responder_nonce.data(), NONCE_LENGTH);
        if (result != Result::Success) [[unlikely]] {
            goto cleanup;
        }


        std::ranges::copy(state.responder_ephemeral_public_key,
                          ke2.responder_public_key.begin());
        result = crypto::derive_oprf_key(responder_private_key.data(), responder_private_key.size(),
                                         account_id, account_id_length, oprf_key);
        if (result != Result::Success) [[unlikely]] {
            sodium_memzero(oprf_key, sizeof(oprf_key));
            goto cleanup;
        }
        result = oblivious_prf::evaluate(credential_request, oprf_key, evaluated_element);
        sodium_memzero(oprf_key, sizeof(oprf_key));
        if (result != Result::Success) [[unlikely]] {
            goto cleanup;
        }
        offset = 0;
        std::copy_n(evaluated_element, crypto_core_ristretto255_BYTES,
                  ke2.credential_response.begin() + static_cast<std::ptrdiff_t>(offset));
        offset += crypto_core_ristretto255_BYTES;
        std::ranges::copy(credentials.envelope,
                          ke2.credential_response.begin() + static_cast<std::ptrdiff_t>(offset));
        if (crypto_scalarmult_ristretto255(dh1, responder_private_key.data(),
                                           initiator_static_public) != 0) {
            result = Result::CryptoError;
            goto cleanup;
        }
        if (crypto_scalarmult_ristretto255(dh2, responder_private_key.data(),
                                           initiator_ephemeral_public) != 0) {
            result = Result::CryptoError;
            goto cleanup;
        }
        if (crypto_scalarmult_ristretto255(dh3, state.responder_ephemeral_private_key.data(),
                                           initiator_static_public) != 0) {
            result = Result::CryptoError;
            goto cleanup;
        }
        ikm.resize(3 * PUBLIC_KEY_LENGTH);
        std::copy_n(dh1, PUBLIC_KEY_LENGTH,
                  ikm.begin());
        std::copy_n(dh2, PUBLIC_KEY_LENGTH,
                  ikm.begin() + PUBLIC_KEY_LENGTH);
        std::copy_n(dh3, PUBLIC_KEY_LENGTH,
                  ikm.begin() + 2 * PUBLIC_KEY_LENGTH);
        mac_input.resize(mac_input_size);
        offset = 0;
        std::copy_n(initiator_ephemeral_public, PUBLIC_KEY_LENGTH,
                  mac_input.begin() + static_cast<std::ptrdiff_t>(offset));
        offset += PUBLIC_KEY_LENGTH;
        std::ranges::copy(state.responder_ephemeral_public_key,
                          mac_input.begin() + static_cast<std::ptrdiff_t>(offset));
        offset += PUBLIC_KEY_LENGTH;
        std::copy_n(initiator_nonce, NONCE_LENGTH,
                  mac_input.begin() + static_cast<std::ptrdiff_t>(offset));
        offset += NONCE_LENGTH;
        std::ranges::copy(ke2.responder_nonce,
                          mac_input.begin() + static_cast<std::ptrdiff_t>(offset));
        offset += NONCE_LENGTH;
        std::copy_n(initiator_static_public, PUBLIC_KEY_LENGTH,
                  mac_input.begin() + static_cast<std::ptrdiff_t>(offset));
        offset += PUBLIC_KEY_LENGTH;
        std::copy_n(responder_static_public, PUBLIC_KEY_LENGTH,
                  mac_input.begin() + static_cast<std::ptrdiff_t>(offset));
        offset += PUBLIC_KEY_LENGTH;
        std::copy_n(credential_response, CREDENTIAL_RESPONSE_LENGTH,
                  mac_input.begin() + static_cast<std::ptrdiff_t>(offset));
        crypto_hash_sha512_state transcript_state;
        crypto_hash_sha512_init(&transcript_state);
        crypto_hash_sha512_update(&transcript_state,
                                  reinterpret_cast<const uint8_t *>(labels::kTranscriptContext),
                                  labels::kTranscriptContextLength);
        crypto_hash_sha512_update(&transcript_state, mac_input.data(), mac_input.size());
        crypto_hash_sha512_final(&transcript_state, transcript_hash);
        result = crypto::key_derivation_extract(transcript_hash, sizeof(transcript_hash), ikm.data(), ikm.size(), prk);
        sodium_memzero(transcript_hash, sizeof(transcript_hash));
        if (result != Result::Success) {
            goto cleanup;
        }
        state.session_key.resize(HASH_LENGTH);
        result = crypto::key_derivation_expand(prk, sizeof(prk), session_info, session_info_length,
                                               state.session_key.data(), state.session_key.size());
        if (result != Result::Success) {
            goto cleanup;
        }

        state.master_key.resize(MASTER_KEY_LENGTH);
        result = crypto::key_derivation_expand(prk, sizeof(prk), master_key_info, master_key_info_length,
                                               state.master_key.data(), state.master_key.size());
        if (result != Result::Success) {
            goto cleanup;
        }
        result = crypto::key_derivation_expand(prk, sizeof(prk), responder_mac_info, responder_mac_info_length,
                                               responder_mac_key, sizeof(responder_mac_key));
        if (result != Result::Success) {
            goto cleanup;
        }
        result = crypto::hmac(responder_mac_key, sizeof(responder_mac_key),
                              mac_input.data(), mac_input.size(),
                              ke2.responder_mac.data());
        if (result != Result::Success) {
            goto cleanup;
        }
        result = crypto::key_derivation_expand(prk, sizeof(prk), initiator_mac_info, initiator_mac_info_length,
                                               initiator_mac_key, sizeof(initiator_mac_key));
        if (result != Result::Success) {
            goto cleanup;
        }
        result = crypto::hmac(initiator_mac_key, sizeof(initiator_mac_key),
                              mac_input.data(), mac_input.size(),
                              state.expected_initiator_mac.data());
        if (result != Result::Success) {
        }

    cleanup:
        sodium_memzero(evaluated_element, sizeof(evaluated_element));
        sodium_memzero(dh1, sizeof(dh1));
        sodium_memzero(dh2, sizeof(dh2));
        sodium_memzero(dh3, sizeof(dh3));
        sodium_memzero(prk, sizeof(prk));
        sodium_memzero(responder_mac_key, sizeof(responder_mac_key));
        sodium_memzero(initiator_mac_key, sizeof(initiator_mac_key));
        if (result != Result::Success) {
            if (!state.session_key.empty()) {
                sodium_memzero(state.session_key.data(), state.session_key.size());
                state.session_key.clear();
            }
            sodium_memzero(state.expected_initiator_mac.data(), state.expected_initiator_mac.size());
            if (!state.master_key.empty()) {
                sodium_memzero(state.master_key.data(), state.master_key.size());
                state.master_key.clear();
            }
            state.handshake_complete = false;
        }
        return result;
    }

    Result responder_finish_impl(const uint8_t *ke3_data, size_t ke3_length,
                                 ResponderState &state, secure_bytes &session_key,
                                 secure_bytes &master_key) {
        if (!ke3_data || ke3_length != KE3_LENGTH) {
            return Result::InvalidInput;
        }
        if (!crypto::init()) {
            return Result::CryptoError;
        }
        if (state.session_key.empty() || state.master_key.size() != MASTER_KEY_LENGTH) {
            return Result::ValidationError;
        }
        const uint8_t *initiator_mac = ke3_data;
        if (crypto_verify_64(initiator_mac, state.expected_initiator_mac.data()) != 0) {
            if (!state.session_key.empty()) {
                sodium_memzero(state.session_key.data(), state.session_key.size());
                state.session_key.clear();
            }
            if (!state.master_key.empty()) {
                sodium_memzero(state.master_key.data(), state.master_key.size());
                state.master_key.clear();
            }
            sodium_memzero(state.expected_initiator_mac.data(), state.expected_initiator_mac.size());
            state.handshake_complete = false;
            return Result::AuthenticationError;
        }
        session_key = state.session_key;
        master_key = state.master_key;
        if (!state.session_key.empty()) {
            sodium_memzero(state.session_key.data(), state.session_key.size());
            state.session_key.clear();
        }
        if (!state.master_key.empty()) {
            sodium_memzero(state.master_key.data(), state.master_key.size());
            state.master_key.clear();
        }
        sodium_memzero(state.expected_initiator_mac.data(), state.expected_initiator_mac.size());
        state.handshake_complete = true;
        return Result::Success;
    }
}
