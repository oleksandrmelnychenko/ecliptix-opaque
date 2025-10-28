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
        if (!secure_key || secure_key_length == 0) {
            return Result::InvalidInput;
        }
        state.secure_key.assign(secure_key, secure_key + secure_key_length);
        Result result = crypto::random_bytes(state.initiator_ephemeral_private_key.data(), PRIVATE_KEY_LENGTH);
        if (result != Result::Success) [[unlikely]] {
            return result;
        }
        if (crypto_scalarmult_ristretto255_base(state.initiator_ephemeral_public_key.data(),
                                                state.initiator_ephemeral_private_key.data()) != 0) {
            return Result::CryptoError;
        }
        result = crypto::random_bytes(ke1.initiator_nonce.data(), NONCE_LENGTH);
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
        const uint8_t *responder_nonce = ke2_data;
        const uint8_t *responder_ephemeral_public_key = ke2_data + NONCE_LENGTH;
        const uint8_t *credential_response = ke2_data + NONCE_LENGTH + PUBLIC_KEY_LENGTH;
        const uint8_t *evaluated_element = credential_response;
        const uint8_t *envelope_data = credential_response + crypto_core_ristretto255_BYTES;
        uint8_t oblivious_prf_output[crypto_hash_sha512_BYTES];
        Result result = oblivious_prf::finalize(state.secure_key.data(), state.secure_key.size(),
                                                state.oblivious_prf_blind_scalar.data(),
                                                evaluated_element, oblivious_prf_output);
        if (result != Result::Success) {
            return result;
        }
        uint8_t randomized_pwd[crypto_hash_sha512_BYTES];
        crypto_hash_sha512_state hash_state;
        crypto_hash_sha512_init(&hash_state);
        crypto_hash_sha512_update(&hash_state, oblivious_prf_output, sizeof(oblivious_prf_output));
        crypto_hash_sha512_update(&hash_state, state.secure_key.data(), state.secure_key.size());
        crypto_hash_sha512_final(&hash_state, randomized_pwd);
        Envelope env;
        env.nonce.assign(envelope_data, envelope_data + NONCE_LENGTH);
        constexpr size_t ciphertext_size = ENVELOPE_LENGTH - NONCE_LENGTH - crypto_secretbox_MACBYTES;
        env.ciphertext.assign(envelope_data + NONCE_LENGTH,
                              envelope_data + NONCE_LENGTH + ciphertext_size);
        env.auth_tag.assign(envelope_data + NONCE_LENGTH + ciphertext_size,
                            envelope_data + NONCE_LENGTH + ciphertext_size + crypto_secretbox_MACBYTES);
        uint8_t recovered_responder_public_key[PUBLIC_KEY_LENGTH];
        uint8_t recovered_initiator_private_key[PRIVATE_KEY_LENGTH];
        uint8_t recovered_initiator_public_key[PUBLIC_KEY_LENGTH];
        uint8_t recovered_master_key[MASTER_KEY_LENGTH];
        result = envelope::open(env, randomized_pwd, sizeof(randomized_pwd),
                                responder_public_key, recovered_responder_public_key, recovered_initiator_private_key,
                                recovered_initiator_public_key, recovered_master_key);
        if (result != Result::Success) {
            return result;
        }
        std::copy_n(recovered_responder_public_key, PUBLIC_KEY_LENGTH,
                    state.responder_public_key.begin());
        std::copy_n(recovered_initiator_private_key, PRIVATE_KEY_LENGTH,
                    state.initiator_private_key.begin());
        std::copy_n(recovered_initiator_public_key, PUBLIC_KEY_LENGTH,
                    state.initiator_public_key.begin());
        std::copy_n(recovered_master_key, MASTER_KEY_LENGTH,
                    state.master_key.begin());
        uint8_t dh1[PUBLIC_KEY_LENGTH];
        if (crypto_scalarmult_ristretto255(dh1, recovered_initiator_private_key,
                                           recovered_responder_public_key) != 0) {
            return Result::CryptoError;
        }
        uint8_t dh2[PUBLIC_KEY_LENGTH];
        if (crypto_scalarmult_ristretto255(dh2, state.initiator_ephemeral_private_key.data(),
                                           recovered_responder_public_key) != 0) {
            return Result::CryptoError;
        }
        uint8_t dh3[PUBLIC_KEY_LENGTH];
        if (crypto_scalarmult_ristretto255(dh3, recovered_initiator_private_key,
                                           responder_ephemeral_public_key) != 0) {
            return Result::CryptoError;
        }
        secure_bytes ikm(3 * PUBLIC_KEY_LENGTH);
        std::copy_n(dh1, PUBLIC_KEY_LENGTH,
                    ikm.begin());
        std::copy_n(dh2, PUBLIC_KEY_LENGTH,
                    ikm.begin() + PUBLIC_KEY_LENGTH);
        std::copy_n(dh3, PUBLIC_KEY_LENGTH,
                    ikm.begin() + 2 * PUBLIC_KEY_LENGTH);
        uint8_t prk[crypto_auth_hmacsha512_BYTES];
        constexpr uint8_t salt[] = "OPAQUE";
        result = crypto::key_derivation_extract(salt, sizeof(salt) - 1, ikm.data(), ikm.size(), prk);
        if (result != Result::Success) {
            return result;
        }
        state.session_key.resize(HASH_LENGTH);
        constexpr uint8_t session_info[] = "SessionKey";
        result = crypto::key_derivation_expand(prk, sizeof(prk), session_info, sizeof(session_info) - 1,
                                               state.session_key.data(), state.session_key.size());
        if (result != Result::Success) {
            return result;
        }
        secure_bytes mac_input(2 * NONCE_LENGTH + 2 * PUBLIC_KEY_LENGTH);
        size_t offset = 0;
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
        uint8_t initiator_mac_key[crypto_auth_hmacsha512_BYTES];
        constexpr uint8_t mac_info[] = "InitiatorMAC";
        result = crypto::key_derivation_expand(prk, sizeof(prk), mac_info, sizeof(mac_info) - 1,
                                               initiator_mac_key, sizeof(initiator_mac_key));
        if (result != Result::Success) {
            return result;
        }
        result = crypto::hmac(initiator_mac_key, sizeof(initiator_mac_key),
                              mac_input.data(), mac_input.size(),
                              ke3.initiator_mac.data());
        sodium_memzero(randomized_pwd, sizeof(randomized_pwd));
        sodium_memzero(oblivious_prf_output, sizeof(oblivious_prf_output));
        sodium_memzero(prk, sizeof(prk));
        sodium_memzero(initiator_mac_key, sizeof(initiator_mac_key));
        return result;
    }

    Result initiator_finish_impl(const InitiatorState &state, secure_bytes &session_key) {
        if (state.session_key.empty()) {
            return Result::InvalidInput;
        }
        session_key = state.session_key;
        return Result::Success;
    }
}
