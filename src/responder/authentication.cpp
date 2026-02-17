#include "opaque/responder.h"
#include "opaque/protocol.h"
#include "opaque/pq.h"
#include "opaque/secure_cleanup.h"
#include "opaque/debug_log.h"
#include <sodium.h>
#include <algorithm>

namespace ecliptix::security::opaque::responder {

KE2::KE2() : responder_nonce(NONCE_LENGTH),
             responder_public_key(PUBLIC_KEY_LENGTH),
             credential_response(CREDENTIAL_RESPONSE_LENGTH),
             responder_mac(MAC_LENGTH),
             kem_ciphertext(pq_constants::KEM_CIPHERTEXT_LENGTH) {}


ResponderState::ResponderState()
    : responder_private_key(PRIVATE_KEY_LENGTH)
    , responder_public_key(PUBLIC_KEY_LENGTH)
    , responder_ephemeral_private_key(PRIVATE_KEY_LENGTH)
    , responder_ephemeral_public_key(PUBLIC_KEY_LENGTH)
    , initiator_public_key(PUBLIC_KEY_LENGTH)
    , session_key(0)
    , expected_initiator_mac(MAC_LENGTH)
    , master_key(0)
    , handshake_complete(false)
    , pq_shared_secret(0) {}


ResponderState::~ResponderState() {
    secure_wipe(responder_private_key);
    secure_wipe(responder_public_key);
    secure_wipe(responder_ephemeral_private_key);
    secure_wipe(responder_ephemeral_public_key);
    secure_wipe(initiator_public_key);
    secure_clear(session_key);
    secure_wipe(expected_initiator_mac);
    secure_clear(master_key);
    secure_clear(pq_shared_secret);
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

    if (!ke1_data || ke1_length != KE1_LENGTH)
        return Result::InvalidInput;
    if (!account_id || account_id_length == 0)
        return Result::InvalidInput;
    if (!crypto::init())
        return Result::CryptoError;
    if (credentials.initiator_public_key.size() != PUBLIC_KEY_LENGTH)
        return Result::InvalidPublicKey;
    if (credentials.envelope.size() != ENVELOPE_LENGTH)
        return Result::InvalidInput;

    log::hex("ke1_data (full)", ke1_data, ke1_length);
    log::hex("responder_private_key", responder_private_key);
    log::hex("responder_public_key", responder_public_key);

    protocol::Ke1View ke1_view{};
    OPAQUE_TRY(protocol::parse_ke1(ke1_data, ke1_length, ke1_view));

    const uint8_t *cred_req = ke1_view.credential_request;
    const uint8_t *init_eph_pk = ke1_view.initiator_public_key;
    const uint8_t *init_nonce = ke1_view.initiator_nonce;
    const uint8_t *init_pq_pk = ke1_view.pq_ephemeral_public_key;
    const uint8_t *init_static_pk = credentials.initiator_public_key.data();

    OPAQUE_TRY(crypto::validate_ristretto_point(cred_req, REGISTRATION_REQUEST_LENGTH));
    OPAQUE_TRY(crypto::validate_public_key(init_eph_pk, PUBLIC_KEY_LENGTH));
    OPAQUE_TRY(crypto::validate_public_key(init_static_pk, PUBLIC_KEY_LENGTH));

    std::copy_n(init_eph_pk, PUBLIC_KEY_LENGTH, state.initiator_public_key.begin());
    std::copy_n(responder_private_key.begin(), responder_private_key.size(),
                state.responder_private_key.begin());
    std::copy_n(responder_public_key.begin(), responder_public_key.size(),
                state.responder_public_key.begin());
    state.handshake_complete = false;

    SecureLocal<crypto_core_ristretto255_BYTES> evaluated_elem;
    SecureLocal<PRIVATE_KEY_LENGTH>             oprf_key;
    SecureLocal<PUBLIC_KEY_LENGTH>              dh1, dh2, dh3;
    SecureLocal<pq_constants::KEM_SHARED_SECRET_LENGTH> kem_ss;
    SecureLocal<crypto_auth_hmacsha512_BYTES>   prk;
    SecureLocal<crypto_auth_hmacsha512_BYTES>   init_mac_key;
    SecureLocal<crypto_hash_sha512_BYTES>       transcript_hash;

    auto failure_guard = make_cleanup([&] {
        secure_clear(state.session_key);
        secure_wipe(state.expected_initiator_mac);
        secure_clear(state.master_key);
        secure_clear(state.pq_shared_secret);
        state.handshake_complete = false;
    });

    do {
        crypto_core_ristretto255_scalar_random(state.responder_ephemeral_private_key.data());
    } while (sodium_is_zero(state.responder_ephemeral_private_key.data(),
                            state.responder_ephemeral_private_key.size()) == 1);

    if (crypto_scalarmult_ristretto255_base(state.responder_ephemeral_public_key.data(),
                                            state.responder_ephemeral_private_key.data()) != 0) {
        return Result::CryptoError;
    }

    OPAQUE_TRY(crypto::random_bytes(ke2.responder_nonce.data(), NONCE_LENGTH));

    std::ranges::copy(state.responder_ephemeral_public_key, ke2.responder_public_key.begin());

    OPAQUE_TRY(crypto::derive_oprf_key(responder_private_key.data(), responder_private_key.size(),
                                        account_id, account_id_length, oprf_key));

    OPAQUE_TRY(oblivious_prf::evaluate(cred_req, oprf_key, evaluated_elem));

    log::hex("evaluated_element (OPRF)", evaluated_elem.data(), evaluated_elem.size());

    {
        size_t off = 0;
        std::copy_n(evaluated_elem.data(), crypto_core_ristretto255_BYTES,
                    ke2.credential_response.begin() + static_cast<std::ptrdiff_t>(off));
        off += crypto_core_ristretto255_BYTES;
        std::ranges::copy(credentials.envelope,
                          ke2.credential_response.begin() + static_cast<std::ptrdiff_t>(off));
    }

    if (crypto_scalarmult_ristretto255(dh1, responder_private_key.data(), init_static_pk) != 0)
        return Result::CryptoError;

    if (crypto_scalarmult_ristretto255(dh2, responder_private_key.data(), init_eph_pk) != 0)
        return Result::CryptoError;

    if (crypto_scalarmult_ristretto255(dh3, state.responder_ephemeral_private_key.data(), init_static_pk) != 0)
        return Result::CryptoError;

    log::hex("dh1 (resp_priv * init_static)", dh1.data(), PUBLIC_KEY_LENGTH);
    log::hex("dh2 (resp_priv * init_eph)", dh2.data(), PUBLIC_KEY_LENGTH);
    log::hex("dh3 (resp_eph * init_static)", dh3.data(), PUBLIC_KEY_LENGTH);

    OPAQUE_TRY(pq::kem::encapsulate(init_pq_pk, ke2.kem_ciphertext.data(), kem_ss));

    state.pq_shared_secret.resize(pq_constants::KEM_SHARED_SECRET_LENGTH);
    std::copy_n(kem_ss.data(), pq_constants::KEM_SHARED_SECRET_LENGTH, state.pq_shared_secret.begin());

    log::hex("kem_shared_secret (encapsulated)", kem_ss.data(), kem_ss.size());

    {
        SecureLocal<crypto_auth_hmacsha512_BYTES> resp_mac_key;
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

        append(init_eph_pk, PUBLIC_KEY_LENGTH);
        append(state.responder_ephemeral_public_key.data(), PUBLIC_KEY_LENGTH);
        append(init_nonce, NONCE_LENGTH);
        append(ke2.responder_nonce.data(), NONCE_LENGTH);
        append(init_static_pk, PUBLIC_KEY_LENGTH);
        append(responder_public_key.data(), PUBLIC_KEY_LENGTH);
        append(ke2.credential_response.data(), CREDENTIAL_RESPONSE_LENGTH);
        append(init_pq_pk, pq_constants::KEM_PUBLIC_KEY_LENGTH);
        append(ke2.kem_ciphertext.data(), pq_constants::KEM_CIPHERTEXT_LENGTH);

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

        log::hex("prk (PQ combiner)", prk.data(), prk.size());

        state.session_key.resize(HASH_LENGTH);
        OPAQUE_TRY(crypto::key_derivation_expand(prk, prk.size(),
            reinterpret_cast<const uint8_t*>(pq::labels::kPqSessionKeyInfo),
            pq::labels::kPqSessionKeyInfoLength,
            state.session_key.data(), state.session_key.size()));

        state.master_key.resize(MASTER_KEY_LENGTH);
        OPAQUE_TRY(crypto::key_derivation_expand(prk, prk.size(),
            reinterpret_cast<const uint8_t*>(pq::labels::kPqMasterKeyInfo),
            pq::labels::kPqMasterKeyInfoLength,
            state.master_key.data(), state.master_key.size()));

        OPAQUE_TRY(crypto::key_derivation_expand(prk, prk.size(),
            reinterpret_cast<const uint8_t*>(pq::labels::kPqResponderMacInfo),
            pq::labels::kPqResponderMacInfoLength,
            resp_mac_key, resp_mac_key.size()));

        OPAQUE_TRY(crypto::hmac(resp_mac_key, resp_mac_key.size(),
                                 mac_input.data(), mac_input.size(),
                                 ke2.responder_mac.data()));

        log::hex("ke2.responder_mac", ke2.responder_mac);

        OPAQUE_TRY(crypto::key_derivation_expand(prk, prk.size(),
            reinterpret_cast<const uint8_t*>(pq::labels::kPqInitiatorMacInfo),
            pq::labels::kPqInitiatorMacInfoLength,
            init_mac_key, init_mac_key.size()));

        OPAQUE_TRY(crypto::hmac(init_mac_key, init_mac_key.size(),
                                 mac_input.data(), mac_input.size(),
                                 state.expected_initiator_mac.data()));

        log::hex("expected_initiator_mac", state.expected_initiator_mac);

        sodium_memzero(classical_ikm.data(), classical_ikm.size());
        sodium_memzero(mac_input.data(), mac_input.size());
    }

    failure_guard.dismiss();

    return Result::Success;
}

} // namespace ecliptix::security::opaque::responder
