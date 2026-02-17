#include "opaque/initiator.h"
#include "opaque/protocol.h"
#include "opaque/pq.h"
#include "opaque/secure_cleanup.h"
#include "opaque/debug_log.h"
#include <sodium.h>
#include <algorithm>

namespace ecliptix::security::opaque::initiator {

KE1::KE1() : initiator_nonce(NONCE_LENGTH),
             initiator_public_key(PUBLIC_KEY_LENGTH),
             credential_request(REGISTRATION_REQUEST_LENGTH),
             pq_ephemeral_public_key(pq_constants::KEM_PUBLIC_KEY_LENGTH) {}

KE3::KE3() : initiator_mac(MAC_LENGTH) {}


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

    if (!secure_key || secure_key_length == 0 || secure_key_length > MAX_SECURE_KEY_LENGTH) {
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

    if (crypto_scalarmult_ristretto255_base(state.initiator_ephemeral_public_key.data(),
                                            state.initiator_ephemeral_private_key.data()) != 0) {
        return Result::CryptoError;
    }

    state.pq_ephemeral_public_key.resize(pq_constants::KEM_PUBLIC_KEY_LENGTH);
    state.pq_ephemeral_secret_key.resize(pq_constants::KEM_SECRET_KEY_LENGTH);

    OPAQUE_TRY(pq::kem::keypair_generate(state.pq_ephemeral_public_key.data(),
                                          state.pq_ephemeral_secret_key.data()));

    OPAQUE_TRY(crypto::random_bytes(ke1.initiator_nonce.data(), NONCE_LENGTH));

    std::ranges::copy(ke1.initiator_nonce, state.initiator_nonce.begin());
    std::ranges::copy(state.initiator_ephemeral_public_key, ke1.initiator_public_key.begin());

    OPAQUE_TRY(oblivious_prf::blind(secure_key, secure_key_length,
                                     ke1.credential_request.data(),
                                     state.oblivious_prf_blind_scalar.data()));

    ke1.pq_ephemeral_public_key.resize(pq_constants::KEM_PUBLIC_KEY_LENGTH);
    std::ranges::copy(state.pq_ephemeral_public_key, ke1.pq_ephemeral_public_key.begin());

    log::hex("ke1.credential_request (blinded)", ke1.credential_request);
    log::hex("ke1.pq_ephemeral_public_key (ML-KEM-768)", ke1.pq_ephemeral_public_key);

    return Result::Success;
}


Result generate_ke3_impl(const uint8_t *ke2_data, size_t ke2_length,
                         const uint8_t *responder_public_key, InitiatorState &state, KE3 &ke3) {
    log::section("AGENT: Generate KE3 (Process KE2)");

    if (!ke2_data || ke2_length != KE2_LENGTH || !responder_public_key) {
        return Result::InvalidInput;
    }
    if (!crypto::init()) {
        return Result::CryptoError;
    }

    OPAQUE_TRY(crypto::validate_public_key(responder_public_key, PUBLIC_KEY_LENGTH));

    protocol::Ke2View ke2_view{};
    OPAQUE_TRY(protocol::parse_ke2(ke2_data, ke2_length, ke2_view));

    SecureLocal<crypto_hash_sha512_BYTES> oprf_output;
    SecureLocal<crypto_hash_sha512_BYTES> randomized_pwd;
    SecureLocal<PUBLIC_KEY_LENGTH>        recovered_rpk;    /* responder public key */
    SecureLocal<PRIVATE_KEY_LENGTH>       recovered_isk;    /* initiator secret key */
    SecureLocal<PUBLIC_KEY_LENGTH>        recovered_ipk;    /* initiator public key */
    SecureLocal<PUBLIC_KEY_LENGTH>        dh1, dh2, dh3;
    SecureLocal<pq_constants::KEM_SHARED_SECRET_LENGTH> kem_ss;
    SecureLocal<crypto_auth_hmacsha512_BYTES> resp_mac_key;
    SecureLocal<crypto_auth_hmacsha512_BYTES> expected_resp_mac;
    SecureLocal<crypto_auth_hmacsha512_BYTES> init_mac_key;
    SecureLocal<MASTER_KEY_LENGTH>        derived_mk;
    SecureLocal<crypto_hash_sha512_BYTES> transcript_hash;

    auto failure_guard = make_cleanup([&] {
        secure_clear(state.session_key);
        secure_clear(state.master_key);
        secure_clear(state.pq_shared_secret);
    });

    const uint8_t *responder_nonce = ke2_view.responder_nonce;
    const uint8_t *resp_eph_pk = ke2_view.responder_public_key;
    const uint8_t *cred_resp = ke2_view.credential_response;
    const uint8_t *evaluated_elem = cred_resp;
    const uint8_t *envelope_data = cred_resp + crypto_core_ristretto255_BYTES;
    const uint8_t *resp_mac = ke2_view.responder_mac;
    const uint8_t *kem_ct = ke2_view.kem_ciphertext;

    OPAQUE_TRY(crypto::validate_public_key(resp_eph_pk, PUBLIC_KEY_LENGTH));

    OPAQUE_TRY(oblivious_prf::finalize(state.secure_key.data(), state.secure_key.size(),
                                        state.oblivious_prf_blind_scalar.data(),
                                        evaluated_elem, oprf_output));

    OPAQUE_TRY(crypto::derive_randomized_password(oprf_output, oprf_output.size(),
                                                   state.secure_key.data(), state.secure_key.size(),
                                                   randomized_pwd, randomized_pwd.size()));

    constexpr size_t ct_size = ENVELOPE_LENGTH - NONCE_LENGTH - crypto_secretbox_MACBYTES;
    Envelope env;
    env.nonce.assign(envelope_data, envelope_data + NONCE_LENGTH);
    env.ciphertext.assign(envelope_data + NONCE_LENGTH, envelope_data + NONCE_LENGTH + ct_size);
    env.auth_tag.assign(envelope_data + NONCE_LENGTH + ct_size,
                        envelope_data + NONCE_LENGTH + ct_size + crypto_secretbox_MACBYTES);

    OPAQUE_TRY(envelope::open(env, randomized_pwd, randomized_pwd.size(),
                               responder_public_key, recovered_rpk, recovered_isk, recovered_ipk));

    if (crypto_verify_32(recovered_rpk, responder_public_key) != 0) {
        return Result::AuthenticationError;
    }

    if (crypto_scalarmult_ristretto255(dh1, recovered_isk, recovered_rpk) != 0)
        return Result::CryptoError;

    if (crypto_scalarmult_ristretto255(dh2, state.initiator_ephemeral_private_key.data(), recovered_rpk) != 0)
        return Result::CryptoError;

    if (crypto_scalarmult_ristretto255(dh3, recovered_isk, resp_eph_pk) != 0)
        return Result::CryptoError;

    log::hex("dh1", dh1.data(), PUBLIC_KEY_LENGTH);
    log::hex("dh2", dh2.data(), PUBLIC_KEY_LENGTH);
    log::hex("dh3", dh3.data(), PUBLIC_KEY_LENGTH);

    OPAQUE_TRY(pq::kem::decapsulate(state.pq_ephemeral_secret_key.data(), kem_ct, kem_ss));

    sodium_memzero(state.pq_ephemeral_secret_key.data(), state.pq_ephemeral_secret_key.size());
    state.pq_ephemeral_secret_key.clear();

    state.pq_shared_secret.resize(pq_constants::KEM_SHARED_SECRET_LENGTH);
    std::copy_n(kem_ss.data(), pq_constants::KEM_SHARED_SECRET_LENGTH, state.pq_shared_secret.begin());

    {
        SecureLocal<crypto_auth_hmacsha512_BYTES> prk;
        constexpr size_t CLASSICAL_IKM_LENGTH = 3 * PUBLIC_KEY_LENGTH;
        SecureLocal<CLASSICAL_IKM_LENGTH> classical_ikm;
        std::copy_n(dh1.data(), PUBLIC_KEY_LENGTH, classical_ikm.data());
        std::copy_n(dh2.data(), PUBLIC_KEY_LENGTH, classical_ikm.data() + PUBLIC_KEY_LENGTH);
        std::copy_n(dh3.data(), PUBLIC_KEY_LENGTH, classical_ikm.data() + 2 * PUBLIC_KEY_LENGTH);

        constexpr size_t mac_input_size =
            2 * NONCE_LENGTH + 4 * PUBLIC_KEY_LENGTH + CREDENTIAL_RESPONSE_LENGTH
            + pq_constants::KEM_CIPHERTEXT_LENGTH + pq_constants::KEM_PUBLIC_KEY_LENGTH;

        secure_bytes mac_input(mac_input_size);
        size_t off = 0;

        auto append = [&](const uint8_t* src, size_t len) {
            std::copy_n(src, len, mac_input.begin() + static_cast<std::ptrdiff_t>(off));
            off += len;
        };

        append(state.initiator_ephemeral_public_key.data(), PUBLIC_KEY_LENGTH);
        append(resp_eph_pk, PUBLIC_KEY_LENGTH);
        append(state.initiator_nonce.data(), NONCE_LENGTH);
        append(responder_nonce, NONCE_LENGTH);
        append(recovered_ipk, PUBLIC_KEY_LENGTH);
        append(recovered_rpk, PUBLIC_KEY_LENGTH);
        append(cred_resp, CREDENTIAL_RESPONSE_LENGTH);
        append(state.pq_ephemeral_public_key.data(), pq_constants::KEM_PUBLIC_KEY_LENGTH);
        append(kem_ct, pq_constants::KEM_CIPHERTEXT_LENGTH);

        {
            crypto_hash_sha512_state ts;
            crypto_hash_sha512_init(&ts);
            crypto_hash_sha512_update(&ts,
                reinterpret_cast<const uint8_t*>(labels::kTranscriptContext),
                labels::kTranscriptContextLength);
            crypto_hash_sha512_update(&ts, mac_input.data(), mac_input.size());
            crypto_hash_sha512_final(&ts, transcript_hash);
        }

        OPAQUE_TRY(pq::combine_key_material(
            classical_ikm.data(), classical_ikm.size(),
            kem_ss, kem_ss.size(),
            transcript_hash, transcript_hash.size(),
            prk));

        secure_bytes session_key(HASH_LENGTH);
        OPAQUE_TRY(crypto::key_derivation_expand(prk, prk.size(),
            reinterpret_cast<const uint8_t*>(pq::labels::kPqSessionKeyInfo),
            pq::labels::kPqSessionKeyInfoLength,
            session_key.data(), session_key.size()));

        OPAQUE_TRY(crypto::key_derivation_expand(prk, prk.size(),
            reinterpret_cast<const uint8_t*>(pq::labels::kPqMasterKeyInfo),
            pq::labels::kPqMasterKeyInfoLength,
            derived_mk, derived_mk.size()));

        OPAQUE_TRY(crypto::key_derivation_expand(prk, prk.size(),
            reinterpret_cast<const uint8_t*>(pq::labels::kPqResponderMacInfo),
            pq::labels::kPqResponderMacInfoLength,
            resp_mac_key, resp_mac_key.size()));

        OPAQUE_TRY(crypto::hmac(resp_mac_key, resp_mac_key.size(),
                                 mac_input.data(), mac_input.size(),
                                 expected_resp_mac));

        if (crypto_verify_64(resp_mac, expected_resp_mac) != 0) {
            log::msg("ERROR: Responder MAC verification failed!");
            return Result::AuthenticationError;
        }
        log::msg("Responder MAC verified successfully");

        OPAQUE_TRY(crypto::key_derivation_expand(prk, prk.size(),
            reinterpret_cast<const uint8_t*>(pq::labels::kPqInitiatorMacInfo),
            pq::labels::kPqInitiatorMacInfoLength,
            init_mac_key, init_mac_key.size()));

        OPAQUE_TRY(crypto::hmac(init_mac_key, init_mac_key.size(),
                                 mac_input.data(), mac_input.size(),
                                 ke3.initiator_mac.data()));

        std::copy_n(recovered_rpk.data(), PUBLIC_KEY_LENGTH, state.responder_public_key.begin());
        std::copy_n(recovered_isk.data(), PRIVATE_KEY_LENGTH, state.initiator_private_key.begin());
        std::copy_n(recovered_ipk.data(), PUBLIC_KEY_LENGTH, state.initiator_public_key.begin());
        state.master_key.resize(MASTER_KEY_LENGTH);
        std::copy_n(derived_mk.data(), MASTER_KEY_LENGTH, state.master_key.begin());
        state.session_key = std::move(session_key);

        sodium_memzero(classical_ikm.data(), classical_ikm.size());
        sodium_memzero(mac_input.data(), mac_input.size());
    }

    failure_guard.dismiss();

    log::hex("ke3.initiator_mac", ke3.initiator_mac);
    return Result::Success;
}

} // namespace ecliptix::security::opaque::initiator
