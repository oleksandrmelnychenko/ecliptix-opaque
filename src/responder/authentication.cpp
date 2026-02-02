#include "opaque/responder.h"
#include "opaque/protocol.h"
#include "opaque/pq.h"
#include "opaque/debug_log.h"
#include <sodium.h>
#include <algorithm>

namespace ecliptix::security::opaque::responder {
    namespace {
        namespace oblivious_prf = oblivious_prf;
        namespace crypto = crypto;

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

    KE2::KE2() : responder_nonce(NONCE_LENGTH),
                 responder_public_key(PUBLIC_KEY_LENGTH),
                 credential_response(CREDENTIAL_RESPONSE_LENGTH),
                 responder_mac(MAC_LENGTH),
                 kem_ciphertext(pq_constants::KEM_CIPHERTEXT_LENGTH) {
    }

    ResponderState::ResponderState() : responder_private_key(PRIVATE_KEY_LENGTH),
                                       responder_public_key(PUBLIC_KEY_LENGTH),
                                       responder_ephemeral_private_key(PRIVATE_KEY_LENGTH),
                                       responder_ephemeral_public_key(PUBLIC_KEY_LENGTH),
                                       initiator_public_key(PUBLIC_KEY_LENGTH),
                                       session_key(0),
                                       expected_initiator_mac(MAC_LENGTH),
                                       master_key(0),
                                       handshake_complete(false),
                                       pq_shared_secret(0) {
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

        if (!pq_shared_secret.empty()) {
            sodium_memzero(pq_shared_secret.data(), pq_shared_secret.size());
        }
    }

    Result responder_finish_impl(const uint8_t *ke3_data, size_t ke3_length,
                                 ResponderState &state, secure_bytes &session_key,
                                 secure_bytes &master_key) {
        log::section("RELAY: Finish (Verify KE3)");
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
        log::hex("ke3 initiator_mac (received)", initiator_mac, MAC_LENGTH);
        log::hex("expected_initiator_mac", state.expected_initiator_mac);
        if (crypto_verify_64(initiator_mac, state.expected_initiator_mac.data()) != 0) {
            log::msg("ERROR: Initiator MAC verification failed!");
            secure_clear(state.session_key);
            secure_clear(state.master_key);
            secure_clear(state.pq_shared_secret);
            secure_wipe(state.expected_initiator_mac);
            state.handshake_complete = false;
            return Result::AuthenticationError;
        }
        log::msg("Initiator MAC verified successfully");
        session_key = state.session_key;
        master_key = state.master_key;
        log::hex("FINAL session_key", session_key);
        log::hex("FINAL master_key", master_key);
        secure_clear(state.session_key);
        secure_clear(state.master_key);
        secure_clear(state.pq_shared_secret);
        secure_wipe(state.expected_initiator_mac);
        state.handshake_complete = true;
        return Result::Success;
    }

    Result generate_ke2_impl(const uint8_t *ke1_data, size_t ke1_length,
                             const ResponderCredentials &credentials,
                             const secure_bytes &responder_private_key,
                             const secure_bytes &responder_public_key,
                             const uint8_t *account_id,
                             size_t account_id_length,
                             KE2 &ke2, ResponderState &state) {
        log::section("RELAY: Generate KE2 (PQ)");

        if (!ke1_data || ke1_length != KE1_LENGTH) {
            return Result::InvalidInput;
        }
        if (!account_id || account_id_length == 0) {
            return Result::InvalidInput;
        }
        if (!crypto::init()) {
            return Result::CryptoError;
        }
        log::hex("ke1_data (full)", ke1_data, ke1_length);
        log::hex("responder_private_key", responder_private_key);
        log::hex("responder_public_key", responder_public_key);
        log::hex("account_id", account_id, account_id_length);
        log::hex("credentials.envelope", credentials.envelope);
        log::hex("credentials.initiator_public_key (EC)", credentials.initiator_public_key);

        protocol::Ke1View ke1_view{};
        Result parse_result = protocol::parse_ke1(ke1_data, ke1_length, ke1_view);
        if (parse_result != Result::Success) {
            return parse_result;
        }

        const uint8_t *credential_request = ke1_view.credential_request;
        const uint8_t *initiator_ephemeral_public = ke1_view.initiator_public_key;
        const uint8_t *initiator_nonce = ke1_view.initiator_nonce;
        const uint8_t *initiator_pq_ephemeral_public = ke1_view.pq_ephemeral_public_key;
        const uint8_t *initiator_static_public = credentials.initiator_public_key.data();

        log::hex("credential_request (from KE1)", credential_request, crypto_core_ristretto255_BYTES);
        log::hex("initiator_ephemeral_public_key (from KE1)", initiator_ephemeral_public, PUBLIC_KEY_LENGTH);
        log::hex("initiator_nonce (from KE1)", initiator_nonce, NONCE_LENGTH);
        log::hex("initiator_pq_ephemeral_public_key (from KE1)", initiator_pq_ephemeral_public, pq_constants::KEM_PUBLIC_KEY_LENGTH);
        log::hex("initiator_static_public (from credentials)", initiator_static_public, PUBLIC_KEY_LENGTH);

        if (Result point_result = crypto::validate_ristretto_point(credential_request, REGISTRATION_REQUEST_LENGTH);
            point_result != Result::Success) {
            return Result::InvalidInput;
        }
        if (Result key_result = crypto::validate_public_key(initiator_ephemeral_public, PUBLIC_KEY_LENGTH);
            key_result != Result::Success) {
            return key_result;
        }
        if (credentials.initiator_public_key.size() != PUBLIC_KEY_LENGTH) {
            return Result::InvalidPublicKey;
        }
        if (Result key_result = crypto::validate_public_key(credentials.initiator_public_key.data(), PUBLIC_KEY_LENGTH);
            key_result != Result::Success) {
            return key_result;
        }
        if (credentials.envelope.size() != ENVELOPE_LENGTH) {
            return Result::InvalidInput;
        }

        std::copy(initiator_ephemeral_public, initiator_ephemeral_public + PUBLIC_KEY_LENGTH,
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
        uint8_t kem_shared_secret[pq_constants::KEM_SHARED_SECRET_LENGTH] = {};
        uint8_t prk[crypto_auth_hmacsha512_BYTES] = {};
        uint8_t responder_mac_key[crypto_auth_hmacsha512_BYTES] = {};
        uint8_t initiator_mac_key[crypto_auth_hmacsha512_BYTES] = {};
        uint8_t transcript_hash[crypto_hash_sha512_BYTES] = {};
        secure_bytes classical_ikm;
        secure_bytes mac_input;
        const auto* session_info = reinterpret_cast<const uint8_t *>(pq::labels::kPqSessionKeyInfo);
        constexpr size_t session_info_length = pq::labels::kPqSessionKeyInfoLength;
        const auto* master_key_info = reinterpret_cast<const uint8_t *>(pq::labels::kPqMasterKeyInfo);
        constexpr size_t master_key_info_length = pq::labels::kPqMasterKeyInfoLength;
        const auto* responder_mac_info = reinterpret_cast<const uint8_t *>(pq::labels::kPqResponderMacInfo);
        constexpr size_t responder_mac_info_length = pq::labels::kPqResponderMacInfoLength;
        const auto* initiator_mac_info = reinterpret_cast<const uint8_t *>(pq::labels::kPqInitiatorMacInfo);
        constexpr size_t initiator_mac_info_length = pq::labels::kPqInitiatorMacInfoLength;
        const uint8_t *responder_static_public = responder_public_key.data();
        const uint8_t *credential_response = ke2.credential_response.data();

        constexpr size_t mac_input_size = 2 * NONCE_LENGTH + 4 * PUBLIC_KEY_LENGTH + CREDENTIAL_RESPONSE_LENGTH +
                                          pq_constants::KEM_CIPHERTEXT_LENGTH + pq_constants::KEM_PUBLIC_KEY_LENGTH;
        size_t offset = 0;

        do {
            crypto_core_ristretto255_scalar_random(state.responder_ephemeral_private_key.data());
        } while (sodium_is_zero(state.responder_ephemeral_private_key.data(),
                                state.responder_ephemeral_private_key.size()) == 1);
        log::hex("responder_ephemeral_private_key", state.responder_ephemeral_private_key);

        if (crypto_scalarmult_ristretto255_base(state.responder_ephemeral_public_key.data(),
                                                state.responder_ephemeral_private_key.data()) != 0) [[unlikely]] {
            result = Result::CryptoError;
            goto cleanup;
        }
        log::hex("responder_ephemeral_public_key", state.responder_ephemeral_public_key);

        result = crypto::random_bytes(ke2.responder_nonce.data(), NONCE_LENGTH);
        if (result != Result::Success) [[unlikely]] {
            goto cleanup;
        }
        log::hex("responder_nonce", ke2.responder_nonce);

        std::ranges::copy(state.responder_ephemeral_public_key,
                          ke2.responder_public_key.begin());

        result = crypto::derive_oprf_key(responder_private_key.data(), responder_private_key.size(),
                                         account_id, account_id_length, oprf_key);
        if (result != Result::Success) [[unlikely]] {
            sodium_memzero(oprf_key, sizeof(oprf_key));
            goto cleanup;
        }
        log::hex("oprf_key (derived)", oprf_key, sizeof(oprf_key));

        result = oblivious_prf::evaluate(credential_request, oprf_key, evaluated_element);
        sodium_memzero(oprf_key, sizeof(oprf_key));
        if (result != Result::Success) [[unlikely]] {
            goto cleanup;
        }
        log::hex("evaluated_element (OPRF output)", evaluated_element, sizeof(evaluated_element));

        offset = 0;
        std::copy_n(evaluated_element, crypto_core_ristretto255_BYTES,
                  ke2.credential_response.begin() + static_cast<std::ptrdiff_t>(offset));
        offset += crypto_core_ristretto255_BYTES;
        std::ranges::copy(credentials.envelope,
                          ke2.credential_response.begin() + static_cast<std::ptrdiff_t>(offset));
        log::hex("ke2.credential_response", ke2.credential_response);

        if (crypto_scalarmult_ristretto255(dh1, responder_private_key.data(),
                                           initiator_static_public) != 0) {
            result = Result::CryptoError;
            goto cleanup;
        }
        log::hex("dh1 (responder_private * initiator_static)", dh1, PUBLIC_KEY_LENGTH);

        if (crypto_scalarmult_ristretto255(dh2, responder_private_key.data(),
                                           initiator_ephemeral_public) != 0) {
            result = Result::CryptoError;
            goto cleanup;
        }
        log::hex("dh2 (responder_private * initiator_ephemeral)", dh2, PUBLIC_KEY_LENGTH);

        if (crypto_scalarmult_ristretto255(dh3, state.responder_ephemeral_private_key.data(),
                                           initiator_static_public) != 0) {
            result = Result::CryptoError;
            goto cleanup;
        }
        log::hex("dh3 (responder_ephemeral * initiator_static)", dh3, PUBLIC_KEY_LENGTH);

        result = pq::kem::encapsulate(initiator_pq_ephemeral_public,
                                      ke2.kem_ciphertext.data(),
                                      kem_shared_secret);
        if (result != Result::Success) {
            goto cleanup;
        }
        log::hex("kem_shared_secret (encapsulated)", kem_shared_secret, sizeof(kem_shared_secret));
        log::hex("ke2.kem_ciphertext", ke2.kem_ciphertext);

        state.pq_shared_secret.resize(pq_constants::KEM_SHARED_SECRET_LENGTH);
        std::copy_n(kem_shared_secret, pq_constants::KEM_SHARED_SECRET_LENGTH,
                    state.pq_shared_secret.begin());

        classical_ikm.resize(3 * PUBLIC_KEY_LENGTH);
        std::copy_n(dh1, PUBLIC_KEY_LENGTH, classical_ikm.begin());
        std::copy_n(dh2, PUBLIC_KEY_LENGTH, classical_ikm.begin() + PUBLIC_KEY_LENGTH);
        std::copy_n(dh3, PUBLIC_KEY_LENGTH, classical_ikm.begin() + 2 * PUBLIC_KEY_LENGTH);

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
        offset += CREDENTIAL_RESPONSE_LENGTH;

        std::copy_n(initiator_pq_ephemeral_public, pq_constants::KEM_PUBLIC_KEY_LENGTH,
                  mac_input.begin() + static_cast<std::ptrdiff_t>(offset));
        offset += pq_constants::KEM_PUBLIC_KEY_LENGTH;
        std::ranges::copy(ke2.kem_ciphertext,
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

        state.session_key.resize(HASH_LENGTH);
        result = crypto::key_derivation_expand(prk, sizeof(prk), session_info, session_info_length,
                                               state.session_key.data(), state.session_key.size());
        if (result != Result::Success) {
            goto cleanup;
        }
        log::hex("session_key (derived)", state.session_key);

        state.master_key.resize(MASTER_KEY_LENGTH);
        result = crypto::key_derivation_expand(prk, sizeof(prk), master_key_info, master_key_info_length,
                                               state.master_key.data(), state.master_key.size());
        if (result != Result::Success) {
            goto cleanup;
        }
        log::hex("master_key (derived)", state.master_key);

        result = crypto::key_derivation_expand(prk, sizeof(prk), responder_mac_info, responder_mac_info_length,
                                               responder_mac_key, sizeof(responder_mac_key));
        if (result != Result::Success) {
            goto cleanup;
        }
        log::hex("responder_mac_key", responder_mac_key, sizeof(responder_mac_key));

        result = crypto::hmac(responder_mac_key, sizeof(responder_mac_key),
                              mac_input.data(), mac_input.size(),
                              ke2.responder_mac.data());
        if (result != Result::Success) {
            goto cleanup;
        }
        log::hex("ke2.responder_mac", ke2.responder_mac);

        result = crypto::key_derivation_expand(prk, sizeof(prk), initiator_mac_info, initiator_mac_info_length,
                                               initiator_mac_key, sizeof(initiator_mac_key));
        if (result != Result::Success) {
            goto cleanup;
        }
        log::hex("initiator_mac_key", initiator_mac_key, sizeof(initiator_mac_key));

        result = crypto::hmac(initiator_mac_key, sizeof(initiator_mac_key),
                              mac_input.data(), mac_input.size(),
                              state.expected_initiator_mac.data());
        log::hex("expected_initiator_mac", state.expected_initiator_mac);

    cleanup:
        sodium_memzero(evaluated_element, sizeof(evaluated_element));
        sodium_memzero(dh1, sizeof(dh1));
        sodium_memzero(dh2, sizeof(dh2));
        sodium_memzero(dh3, sizeof(dh3));
        sodium_memzero(kem_shared_secret, sizeof(kem_shared_secret));
        if (!classical_ikm.empty()) {
            sodium_memzero(classical_ikm.data(), classical_ikm.size());
        }
        sodium_memzero(prk, sizeof(prk));
        sodium_memzero(responder_mac_key, sizeof(responder_mac_key));
        sodium_memzero(initiator_mac_key, sizeof(initiator_mac_key));
        if (result != Result::Success) {
            secure_clear(state.session_key);
            secure_wipe(state.expected_initiator_mac);
            secure_clear(state.master_key);
            secure_clear(state.pq_shared_secret);
            state.handshake_complete = false;
        }
        return result;
    }

}
