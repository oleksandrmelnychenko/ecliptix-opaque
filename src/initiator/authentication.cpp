#include "opaque/initiator.h"
#include <sodium.h>
#include <algorithm>

namespace ecliptix::security::opaque::initiator {
    namespace {
        namespace oblivious_prf = oblivious_prf;
        namespace crypto = crypto;
        namespace envelope = envelope;
    }

    KE1::KE1() : initiator_nonce(NONCE_LENGTH), initiator_public_key(PUBLIC_KEY_LENGTH),
                 credential_request(crypto_core_ristretto255_BYTES) {
    }

    KE3::KE3() : initiator_mac(MAC_LENGTH) {
    }

    Result generate_ke1_impl(const uint8_t *secure_key, size_t secure_key_length,
                             KE1 &ke1, InitiatorState &state) {
        if (!secure_key || secure_key_length == 0 ||
            secure_key_length > MAX_SECURE_KEY_LENGTH) {
            return Result::InvalidInput;
        }
        if (!crypto::init()) {
            return Result::CryptoError;
        }
        state.secure_key.assign(secure_key, secure_key + secure_key_length);
        do {
            crypto_core_ristretto255_scalar_random(state.initiator_ephemeral_private_key.data());
        } while (sodium_is_zero(state.initiator_ephemeral_private_key.data(),
                                state.initiator_ephemeral_private_key.size()) == 1);
        if (crypto_scalarmult_ristretto255_base(state.initiator_ephemeral_public_key.data(),
                                                state.initiator_ephemeral_private_key.data()) != 0) {
            return Result::CryptoError;
        }
        Result result = crypto::random_bytes(ke1.initiator_nonce.data(), NONCE_LENGTH);
        if (result != Result::Success) [[unlikely]] {
            return result;
        }
        std::ranges::copy(ke1.initiator_nonce, state.initiator_nonce.begin());
        std::ranges::copy(state.initiator_ephemeral_public_key,
                          ke1.initiator_public_key.begin());
        return oblivious_prf::blind(secure_key, secure_key_length, ke1.credential_request.data(),
                                    state.oblivious_prf_blind_scalar.data());
    }

    Result generate_ke3_impl(const uint8_t *ke2_data, size_t ke2_length,
                             const uint8_t *responder_public_key, InitiatorState &state, KE3 &ke3) {
        if (!ke2_data || ke2_length != KE2_LENGTH) {
            return Result::InvalidInput;
        }
        if (!responder_public_key) {
            return Result::InvalidInput;
        }
        if (!crypto::init()) {
            return Result::CryptoError;
        }
        if (crypto_core_ristretto255_is_valid_point(responder_public_key) != 1 ||
            util::is_all_zero(responder_public_key, PUBLIC_KEY_LENGTH)) {
            return Result::InvalidPublicKey;
        }
        if (!state.responder_public_key.empty()) {
            sodium_memzero(state.responder_public_key.data(), state.responder_public_key.size());
        }
        if (!state.initiator_private_key.empty()) {
            sodium_memzero(state.initiator_private_key.data(), state.initiator_private_key.size());
        }
        if (!state.initiator_public_key.empty()) {
            sodium_memzero(state.initiator_public_key.data(), state.initiator_public_key.size());
        }
        if (!state.master_key.empty()) {
            sodium_memzero(state.master_key.data(), state.master_key.size());
        }
        if (!state.session_key.empty()) {
            sodium_memzero(state.session_key.data(), state.session_key.size());
        }
        const uint8_t *responder_nonce = ke2_data;
        const uint8_t *responder_ephemeral_public_key = ke2_data + NONCE_LENGTH;
        const uint8_t *credential_response = ke2_data + NONCE_LENGTH + PUBLIC_KEY_LENGTH;
        const uint8_t *evaluated_element = credential_response;
        const uint8_t *envelope_data = credential_response + crypto_core_ristretto255_BYTES;
        const uint8_t *responder_mac = ke2_data + NONCE_LENGTH + PUBLIC_KEY_LENGTH + CREDENTIAL_RESPONSE_LENGTH;
        if (crypto_core_ristretto255_is_valid_point(responder_ephemeral_public_key) != 1 ||
            util::is_all_zero(responder_ephemeral_public_key, PUBLIC_KEY_LENGTH)) {
            return Result::InvalidPublicKey;
        }

        Result result = Result::Success;
        uint8_t oblivious_prf_output[crypto_hash_sha512_BYTES] = {};
        uint8_t randomized_pwd[crypto_hash_sha512_BYTES] = {};
        uint8_t recovered_responder_public_key[PUBLIC_KEY_LENGTH] = {};
        uint8_t recovered_initiator_private_key[PRIVATE_KEY_LENGTH] = {};
        uint8_t recovered_initiator_public_key[PUBLIC_KEY_LENGTH] = {};
        uint8_t dh1[PUBLIC_KEY_LENGTH] = {};
        uint8_t dh2[PUBLIC_KEY_LENGTH] = {};
        uint8_t dh3[PUBLIC_KEY_LENGTH] = {};
        uint8_t prk[crypto_auth_hmacsha512_BYTES] = {};
        uint8_t responder_mac_key[crypto_auth_hmacsha512_BYTES] = {};
        uint8_t expected_responder_mac[crypto_auth_hmacsha512_BYTES] = {};
        uint8_t initiator_mac_key[crypto_auth_hmacsha512_BYTES] = {};
        uint8_t derived_master_key[MASTER_KEY_LENGTH] = {};
        uint8_t transcript_hash[crypto_hash_sha512_BYTES] = {};
        Envelope env;
        secure_bytes ikm;
        secure_bytes mac_input;
        secure_bytes session_key(HASH_LENGTH);
        const auto* session_info = reinterpret_cast<const uint8_t *>(labels::kSessionKeyInfo);
        constexpr size_t session_info_length = labels::kSessionKeyInfoLength;
        const auto* master_key_info = reinterpret_cast<const uint8_t *>(labels::kMasterKeyInfo);
        constexpr size_t master_key_info_length = labels::kMasterKeyInfoLength;
        const auto* responder_mac_info = reinterpret_cast<const uint8_t *>(labels::kResponderMacInfo);
        constexpr size_t responder_mac_info_length = labels::kResponderMacInfoLength;
        const auto* initiator_mac_info = reinterpret_cast<const uint8_t *>(labels::kInitiatorMacInfo);
        constexpr size_t initiator_mac_info_length = labels::kInitiatorMacInfoLength;


        constexpr size_t ciphertext_size = ENVELOPE_LENGTH - NONCE_LENGTH - crypto_secretbox_MACBYTES;
        constexpr size_t mac_input_size = 2 * NONCE_LENGTH + 4 * PUBLIC_KEY_LENGTH + CREDENTIAL_RESPONSE_LENGTH;
        size_t offset = 0;

        result = oblivious_prf::finalize(state.secure_key.data(), state.secure_key.size(),
                                         state.oblivious_prf_blind_scalar.data(),
                                         evaluated_element, oblivious_prf_output);
        if (result != Result::Success) {
            goto cleanup;
        }
        result = crypto::derive_randomized_password(oblivious_prf_output, sizeof(oblivious_prf_output),
                                                    state.secure_key.data(), state.secure_key.size(),
                                                    randomized_pwd, sizeof(randomized_pwd));
        if (result != Result::Success) {
            goto cleanup;
        }
        env.nonce.assign(envelope_data, envelope_data + NONCE_LENGTH);
        env.ciphertext.assign(envelope_data + NONCE_LENGTH,
                              envelope_data + NONCE_LENGTH + ciphertext_size);
        env.auth_tag.assign(envelope_data + NONCE_LENGTH + ciphertext_size,
                            envelope_data + NONCE_LENGTH + ciphertext_size + crypto_secretbox_MACBYTES);

        result = envelope::open(env, randomized_pwd, sizeof(randomized_pwd),
                                responder_public_key, recovered_responder_public_key, recovered_initiator_private_key,
                                recovered_initiator_public_key);
        if (result != Result::Success) {
            goto cleanup;
        }
        if (crypto_verify_32(recovered_responder_public_key, responder_public_key) != 0) {
            result = Result::AuthenticationError;
            goto cleanup;
        }
        if (crypto_scalarmult_ristretto255(dh1, recovered_initiator_private_key,
                                           recovered_responder_public_key) != 0) {
            result = Result::CryptoError;
            goto cleanup;
        }
        if (crypto_scalarmult_ristretto255(dh2, state.initiator_ephemeral_private_key.data(),
                                           recovered_responder_public_key) != 0) {
            result = Result::CryptoError;
            goto cleanup;
        }
        if (crypto_scalarmult_ristretto255(dh3, recovered_initiator_private_key,
                                           responder_ephemeral_public_key) != 0) {
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
        std::ranges::copy(state.initiator_ephemeral_public_key,
                          mac_input.begin() + static_cast<std::ptrdiff_t>(offset));
        offset += PUBLIC_KEY_LENGTH;
        std::copy_n(responder_ephemeral_public_key, PUBLIC_KEY_LENGTH,
                    mac_input.begin() + static_cast<std::ptrdiff_t>(offset));
        offset += PUBLIC_KEY_LENGTH;
        std::ranges::copy(state.initiator_nonce,
                          mac_input.begin() + static_cast<std::ptrdiff_t>(offset));
        offset += NONCE_LENGTH;
        std::copy_n(responder_nonce, NONCE_LENGTH,
                    mac_input.begin() + static_cast<std::ptrdiff_t>(offset));
        offset += NONCE_LENGTH;
        std::copy_n(recovered_initiator_public_key, PUBLIC_KEY_LENGTH,
                    mac_input.begin() + static_cast<std::ptrdiff_t>(offset));
        offset += PUBLIC_KEY_LENGTH;
        std::copy_n(recovered_responder_public_key, PUBLIC_KEY_LENGTH,
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
        result = crypto::key_derivation_expand(prk, sizeof(prk), session_info, session_info_length,
                                               session_key.data(), session_key.size());
        if (result != Result::Success) {
            goto cleanup;
        }

        result = crypto::key_derivation_expand(prk, sizeof(prk), master_key_info, master_key_info_length,
                                               derived_master_key, sizeof(derived_master_key));
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
                              expected_responder_mac);
        if (result != Result::Success) {
            goto cleanup;
        }
        if (crypto_verify_64(responder_mac, expected_responder_mac) != 0) {
            result = Result::AuthenticationError;
            goto cleanup;
        }
        result = crypto::key_derivation_expand(prk, sizeof(prk), initiator_mac_info, initiator_mac_info_length,
                                               initiator_mac_key, sizeof(initiator_mac_key));
        if (result != Result::Success) {
            goto cleanup;
        }
        result = crypto::hmac(initiator_mac_key, sizeof(initiator_mac_key),
                              mac_input.data(), mac_input.size(),
                              ke3.initiator_mac.data());
        if (result == Result::Success) {
            std::copy_n(recovered_responder_public_key, PUBLIC_KEY_LENGTH,
                        state.responder_public_key.begin());
            std::copy_n(recovered_initiator_private_key, PRIVATE_KEY_LENGTH,
                        state.initiator_private_key.begin());
            std::copy_n(recovered_initiator_public_key, PUBLIC_KEY_LENGTH,
                        state.initiator_public_key.begin());

            state.master_key.resize(MASTER_KEY_LENGTH);
            std::copy_n(derived_master_key, MASTER_KEY_LENGTH,
                        state.master_key.begin());
            state.session_key = std::move(session_key);
        }

    cleanup:
        sodium_memzero(randomized_pwd, sizeof(randomized_pwd));
        sodium_memzero(oblivious_prf_output, sizeof(oblivious_prf_output));
        sodium_memzero(prk, sizeof(prk));
        sodium_memzero(responder_mac_key, sizeof(responder_mac_key));
        sodium_memzero(expected_responder_mac, sizeof(expected_responder_mac));
        sodium_memzero(initiator_mac_key, sizeof(initiator_mac_key));
        sodium_memzero(recovered_responder_public_key, sizeof(recovered_responder_public_key));
        sodium_memzero(recovered_initiator_private_key, sizeof(recovered_initiator_private_key));
        sodium_memzero(recovered_initiator_public_key, sizeof(recovered_initiator_public_key));
        sodium_memzero(derived_master_key, sizeof(derived_master_key));
        sodium_memzero(dh1, sizeof(dh1));
        sodium_memzero(dh2, sizeof(dh2));
        sodium_memzero(dh3, sizeof(dh3));
        return result;
    }

    Result initiator_finish_impl(InitiatorState &state, secure_bytes &session_key, secure_bytes &master_key) {
        if (state.session_key.empty() || state.master_key.size() != MASTER_KEY_LENGTH) {
            return Result::InvalidInput;
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
        return Result::Success;
    }
}
