#include "opaque/initiator.h"
#include "opaque/protocol.h"
#include "opaque/pq.h"
#include "opaque/debug_log.h"
#include <sodium.h>
#include <algorithm>

namespace ecliptix::security::opaque::initiator {
    namespace {
        namespace oblivious_prf = oblivious_prf;
        namespace crypto = crypto;
        namespace envelope = envelope;

        void secure_wipe(secure_bytes &buffer) {
            if (!buffer.empty()) {
                sodium_memzero(buffer.data(), buffer.size());
            }
        }

        void secure_clear(secure_bytes &buffer) {
            if (!buffer.empty()) {
                sodium_memzero(buffer.data(), buffer.size());
                buffer.clear();
            }
        }
    }

    KE1::KE1() : initiator_nonce(NONCE_LENGTH),
                 initiator_public_key(PUBLIC_KEY_LENGTH),
                 credential_request(REGISTRATION_REQUEST_LENGTH),
                 pq_ephemeral_public_key(pq_constants::KEM_PUBLIC_KEY_LENGTH) {
    }

    KE3::KE3() : initiator_mac(MAC_LENGTH) {
    }

    Result initiator_finish_impl(InitiatorState &state, secure_bytes &session_key, secure_bytes &master_key) {
        log::section("AGENT: Finish (Export Keys)");
        if (state.session_key.empty() || state.master_key.size() != MASTER_KEY_LENGTH) {
            return Result::InvalidInput;
        }
        session_key = state.session_key;
        master_key = state.master_key;
        log::hex("FINAL session_key", session_key);
        log::hex("FINAL master_key", master_key);
        secure_clear(state.session_key);
        secure_clear(state.master_key);
        secure_clear(state.pq_shared_secret);
        secure_clear(state.pq_ephemeral_secret_key);
        secure_clear(state.secure_key);
        secure_clear(state.oblivious_prf_blind_scalar);
        return Result::Success;
    }

    Result generate_ke1_impl(const uint8_t *secure_key, size_t secure_key_length,
                             KE1 &ke1, InitiatorState &state) {
        log::section("AGENT: Generate KE1 (PQ Authentication Start)");
        if (!secure_key || secure_key_length == 0 ||
            secure_key_length > MAX_SECURE_KEY_LENGTH) {
            return Result::InvalidInput;
        }
        if (!crypto::init()) {
            return Result::CryptoError;
        }
        log::hex("secure_key (password)", secure_key, secure_key_length);
        state.secure_key.assign(secure_key, secure_key + secure_key_length);

        do {
            crypto_core_ristretto255_scalar_random(state.initiator_ephemeral_private_key.data());
        } while (sodium_is_zero(state.initiator_ephemeral_private_key.data(),
                                state.initiator_ephemeral_private_key.size()) == 1);
        log::hex("initiator_ephemeral_private_key (EC)", state.initiator_ephemeral_private_key);

        if (crypto_scalarmult_ristretto255_base(state.initiator_ephemeral_public_key.data(),
                                                state.initiator_ephemeral_private_key.data()) != 0) {
            return Result::CryptoError;
        }
        log::hex("initiator_ephemeral_public_key (EC)", state.initiator_ephemeral_public_key);

        state.pq_ephemeral_public_key.resize(pq_constants::KEM_PUBLIC_KEY_LENGTH);
        state.pq_ephemeral_secret_key.resize(pq_constants::KEM_SECRET_KEY_LENGTH);

        if (pq::kem::keypair_generate(state.pq_ephemeral_public_key.data(),
                                      state.pq_ephemeral_secret_key.data()) != Result::Success) {
            return Result::CryptoError;
        }
        log::hex("pq_ephemeral_public_key (ML-KEM-768)", state.pq_ephemeral_public_key);

        Result result = crypto::random_bytes(ke1.initiator_nonce.data(), NONCE_LENGTH);
        if (result != Result::Success) [[unlikely]] {
            return result;
        }
        log::hex("initiator_nonce", ke1.initiator_nonce);

        std::ranges::copy(ke1.initiator_nonce, state.initiator_nonce.begin());
        std::ranges::copy(state.initiator_ephemeral_public_key,
                          ke1.initiator_public_key.begin());

        result = oblivious_prf::blind(secure_key, secure_key_length, ke1.credential_request.data(),
                                    state.oblivious_prf_blind_scalar.data());
        if (result != Result::Success) {
            return result;
        }
        log::hex("oblivious_prf_blind_scalar", state.oblivious_prf_blind_scalar);
        log::hex("ke1.credential_request (blinded)", ke1.credential_request);

        ke1.pq_ephemeral_public_key.resize(pq_constants::KEM_PUBLIC_KEY_LENGTH);
        std::ranges::copy(state.pq_ephemeral_public_key,
                          ke1.pq_ephemeral_public_key.begin());
        log::hex("ke1.pq_ephemeral_public_key (ML-KEM-768)", ke1.pq_ephemeral_public_key);

        return Result::Success;
    }

    Result generate_ke3_impl(const uint8_t *ke2_data, size_t ke2_length,
                             const uint8_t *responder_public_key, InitiatorState &state, KE3 &ke3) {
        log::section("AGENT: Generate KE3 (Process KE2)");

        if (!ke2_data || ke2_length != KE2_LENGTH) {
            return Result::InvalidInput;
        }
        if (!responder_public_key) {
            return Result::InvalidInput;
        }
        if (!crypto::init()) {
            return Result::CryptoError;
        }
        log::hex("ke2_data (full)", ke2_data, ke2_length);
        log::hex("responder_public_key (expected)", responder_public_key, PUBLIC_KEY_LENGTH);

        if (Result key_result = crypto::validate_public_key(responder_public_key, PUBLIC_KEY_LENGTH);
            key_result != Result::Success) {
            return key_result;
        }

        protocol::Ke2View ke2_view{};
        if (Result parse_result = protocol::parse_ke2(ke2_data, ke2_length, ke2_view);
            parse_result != Result::Success) {
            return parse_result;
        }

        secure_wipe(state.responder_public_key);
        secure_wipe(state.initiator_private_key);
        secure_wipe(state.initiator_public_key);
        secure_wipe(state.master_key);
        secure_wipe(state.session_key);

        const uint8_t *responder_nonce = ke2_view.responder_nonce;
        const uint8_t *responder_ephemeral_public_key = ke2_view.responder_public_key;
        const uint8_t *credential_response = ke2_view.credential_response;
        const uint8_t *evaluated_element = credential_response;
        const uint8_t *envelope_data = credential_response + crypto_core_ristretto255_BYTES;
        const uint8_t *responder_mac = ke2_view.responder_mac;
        const uint8_t *kem_ciphertext = ke2_view.kem_ciphertext;

        log::hex("responder_nonce (from KE2)", responder_nonce, NONCE_LENGTH);
        log::hex("responder_ephemeral_public_key (from KE2)", responder_ephemeral_public_key, PUBLIC_KEY_LENGTH);
        log::hex("evaluated_element (from KE2)", evaluated_element, crypto_core_ristretto255_BYTES);
        log::hex("envelope_data (from KE2)", envelope_data, ENVELOPE_LENGTH);
        log::hex("responder_mac (from KE2)", responder_mac, MAC_LENGTH);
        log::hex("kem_ciphertext (from KE2)", kem_ciphertext, pq_constants::KEM_CIPHERTEXT_LENGTH);

        if (Result key_result = crypto::validate_public_key(responder_ephemeral_public_key, PUBLIC_KEY_LENGTH);
            key_result != Result::Success) {
            return key_result;
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
        uint8_t kem_shared_secret[pq_constants::KEM_SHARED_SECRET_LENGTH] = {};
        uint8_t prk[crypto_auth_hmacsha512_BYTES] = {};
        uint8_t responder_mac_key[crypto_auth_hmacsha512_BYTES] = {};
        uint8_t expected_responder_mac[crypto_auth_hmacsha512_BYTES] = {};
        uint8_t initiator_mac_key[crypto_auth_hmacsha512_BYTES] = {};
        uint8_t derived_master_key[MASTER_KEY_LENGTH] = {};
        uint8_t transcript_hash[crypto_hash_sha512_BYTES] = {};
        Envelope env;
        secure_bytes classical_ikm;
        secure_bytes mac_input;
        secure_bytes session_key(HASH_LENGTH);
        const auto* session_info = reinterpret_cast<const uint8_t *>(pq::labels::kPqSessionKeyInfo);
        constexpr size_t session_info_length = pq::labels::kPqSessionKeyInfoLength;
        const auto* master_key_info = reinterpret_cast<const uint8_t *>(pq::labels::kPqMasterKeyInfo);
        constexpr size_t master_key_info_length = pq::labels::kPqMasterKeyInfoLength;
        const auto* responder_mac_info = reinterpret_cast<const uint8_t *>(pq::labels::kPqResponderMacInfo);
        constexpr size_t responder_mac_info_length = pq::labels::kPqResponderMacInfoLength;
        const auto* initiator_mac_info = reinterpret_cast<const uint8_t *>(pq::labels::kPqInitiatorMacInfo);
        constexpr size_t initiator_mac_info_length = pq::labels::kPqInitiatorMacInfoLength;

        constexpr size_t ciphertext_size = ENVELOPE_LENGTH - NONCE_LENGTH - crypto_secretbox_MACBYTES;

        constexpr size_t mac_input_size = 2 * NONCE_LENGTH + 4 * PUBLIC_KEY_LENGTH + CREDENTIAL_RESPONSE_LENGTH +
                                          pq_constants::KEM_CIPHERTEXT_LENGTH + pq_constants::KEM_PUBLIC_KEY_LENGTH;
        size_t offset = 0;

        result = oblivious_prf::finalize(state.secure_key.data(), state.secure_key.size(),
                                         state.oblivious_prf_blind_scalar.data(),
                                         evaluated_element, oblivious_prf_output);
        if (result != Result::Success) {
            goto cleanup;
        }
        log::hex("oblivious_prf_output", oblivious_prf_output, sizeof(oblivious_prf_output));

        result = crypto::derive_randomized_password(oblivious_prf_output, sizeof(oblivious_prf_output),
                                                    state.secure_key.data(), state.secure_key.size(),
                                                    randomized_pwd, sizeof(randomized_pwd));
        if (result != Result::Success) {
            goto cleanup;
        }
        log::hex("randomized_pwd", randomized_pwd, sizeof(randomized_pwd));

        env.nonce.assign(envelope_data, envelope_data + NONCE_LENGTH);
        env.ciphertext.assign(envelope_data + NONCE_LENGTH,
                              envelope_data + NONCE_LENGTH + ciphertext_size);
        env.auth_tag.assign(envelope_data + NONCE_LENGTH + ciphertext_size,
                            envelope_data + NONCE_LENGTH + ciphertext_size + crypto_secretbox_MACBYTES);
        log::hex("envelope.nonce", env.nonce);
        log::hex("envelope.ciphertext", env.ciphertext);
        log::hex("envelope.auth_tag", env.auth_tag);

        result = envelope::open(env, randomized_pwd, sizeof(randomized_pwd),
                                responder_public_key, recovered_responder_public_key, recovered_initiator_private_key,
                                recovered_initiator_public_key);
        if (result != Result::Success) {
            goto cleanup;
        }
        log::hex("recovered_responder_public_key", recovered_responder_public_key, PUBLIC_KEY_LENGTH);
        log::hex("recovered_initiator_private_key", recovered_initiator_private_key, PRIVATE_KEY_LENGTH);
        log::hex("recovered_initiator_public_key", recovered_initiator_public_key, PUBLIC_KEY_LENGTH);

        if (crypto_verify_32(recovered_responder_public_key, responder_public_key) != 0) {
            result = Result::AuthenticationError;
            goto cleanup;
        }

        if (crypto_scalarmult_ristretto255(dh1, recovered_initiator_private_key,
                                           recovered_responder_public_key) != 0) {
            result = Result::CryptoError;
            goto cleanup;
        }
        log::hex("dh1 (initiator_private * responder_public)", dh1, PUBLIC_KEY_LENGTH);

        if (crypto_scalarmult_ristretto255(dh2, state.initiator_ephemeral_private_key.data(),
                                           recovered_responder_public_key) != 0) {
            result = Result::CryptoError;
            goto cleanup;
        }
        log::hex("dh2 (ephemeral_private * responder_public)", dh2, PUBLIC_KEY_LENGTH);

        if (crypto_scalarmult_ristretto255(dh3, recovered_initiator_private_key,
                                           responder_ephemeral_public_key) != 0) {
            result = Result::CryptoError;
            goto cleanup;
        }
        log::hex("dh3 (initiator_private * responder_ephemeral)", dh3, PUBLIC_KEY_LENGTH);

        result = pq::kem::decapsulate(state.pq_ephemeral_secret_key.data(),
                                      kem_ciphertext,
                                      kem_shared_secret);
        if (result != Result::Success) {
            goto cleanup;
        }
        log::hex("kem_shared_secret (decapsulated)", kem_shared_secret, sizeof(kem_shared_secret));

        sodium_memzero(state.pq_ephemeral_secret_key.data(), state.pq_ephemeral_secret_key.size());
        state.pq_ephemeral_secret_key.clear();

        state.pq_shared_secret.resize(pq_constants::KEM_SHARED_SECRET_LENGTH);
        std::copy_n(kem_shared_secret, pq_constants::KEM_SHARED_SECRET_LENGTH,
                    state.pq_shared_secret.begin());

        classical_ikm.resize(3 * PUBLIC_KEY_LENGTH);
        std::copy_n(dh1, PUBLIC_KEY_LENGTH, classical_ikm.begin());
        std::copy_n(dh2, PUBLIC_KEY_LENGTH, classical_ikm.begin() + PUBLIC_KEY_LENGTH);
        std::copy_n(dh3, PUBLIC_KEY_LENGTH, classical_ikm.begin() + 2 * PUBLIC_KEY_LENGTH);

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
        offset += CREDENTIAL_RESPONSE_LENGTH;

        std::ranges::copy(state.pq_ephemeral_public_key,
                          mac_input.begin() + static_cast<std::ptrdiff_t>(offset));
        offset += pq_constants::KEM_PUBLIC_KEY_LENGTH;
        std::copy_n(kem_ciphertext, pq_constants::KEM_CIPHERTEXT_LENGTH,
                    mac_input.begin() + static_cast<std::ptrdiff_t>(offset));

        {
            crypto_hash_sha512_state transcript_state;
            crypto_hash_sha512_init(&transcript_state);
            crypto_hash_sha512_update(&transcript_state,
                                      reinterpret_cast<const uint8_t *>(labels::kTranscriptContext),
                                      labels::kTranscriptContextLength);
            crypto_hash_sha512_update(&transcript_state, mac_input.data(), mac_input.size());
            crypto_hash_sha512_final(&transcript_state, transcript_hash);
        }

        result = pq::combine_key_material(classical_ikm.data(), classical_ikm.size(),
                                          kem_shared_secret, sizeof(kem_shared_secret),
                                          transcript_hash, sizeof(transcript_hash),
                                          prk);
        sodium_memzero(transcript_hash, sizeof(transcript_hash));
        if (result != Result::Success) {
            goto cleanup;
        }
        log::hex("prk (pseudo-random key from PQ combiner)", prk, sizeof(prk));

        result = crypto::key_derivation_expand(prk, sizeof(prk), session_info, session_info_length,
                                               session_key.data(), session_key.size());
        if (result != Result::Success) {
            goto cleanup;
        }
        log::hex("session_key (derived)", session_key);

        result = crypto::key_derivation_expand(prk, sizeof(prk), master_key_info, master_key_info_length,
                                               derived_master_key, sizeof(derived_master_key));
        if (result != Result::Success) {
            goto cleanup;
        }
        log::hex("master_key (derived)", derived_master_key, sizeof(derived_master_key));

        result = crypto::key_derivation_expand(prk, sizeof(prk), responder_mac_info, responder_mac_info_length,
                                               responder_mac_key, sizeof(responder_mac_key));
        if (result != Result::Success) {
            goto cleanup;
        }
        log::hex("responder_mac_key", responder_mac_key, sizeof(responder_mac_key));

        result = crypto::hmac(responder_mac_key, sizeof(responder_mac_key),
                              mac_input.data(), mac_input.size(),
                              expected_responder_mac);
        if (result != Result::Success) {
            goto cleanup;
        }
        log::hex("expected_responder_mac (calculated)", expected_responder_mac, sizeof(expected_responder_mac));
        log::hex("responder_mac (received)", responder_mac, MAC_LENGTH);

        if (crypto_verify_64(responder_mac, expected_responder_mac) != 0) {
            log::msg("ERROR: Responder MAC verification failed!");
            result = Result::AuthenticationError;
            goto cleanup;
        }
        log::msg("Responder MAC verified successfully");

        result = crypto::key_derivation_expand(prk, sizeof(prk), initiator_mac_info, initiator_mac_info_length,
                                               initiator_mac_key, sizeof(initiator_mac_key));
        if (result != Result::Success) {
            goto cleanup;
        }
        log::hex("initiator_mac_key", initiator_mac_key, sizeof(initiator_mac_key));

        result = crypto::hmac(initiator_mac_key, sizeof(initiator_mac_key),
                              mac_input.data(), mac_input.size(),
                              ke3.initiator_mac.data());
        log::hex("ke3.initiator_mac", ke3.initiator_mac);

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
        sodium_memzero(kem_shared_secret, sizeof(kem_shared_secret));
        if (!classical_ikm.empty()) {
            sodium_memzero(classical_ikm.data(), classical_ikm.size());
        }
        return result;
    }

}
