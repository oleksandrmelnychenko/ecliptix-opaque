/**
 * @file test_security_properties.cpp
 * @brief Implementation-level verification of formal security properties.
 *
 * Maps to Tamarin lemmas and paper Theorems 1-4:
 *   - Password independence (different passwords → different keys)
 *   - Account isolation (different account_id → different OPRF output)
 *   - Transcript binding (any field change → MAC failure)
 *   - KEM contribution (KEM shared secret affects session key)
 *   - Key confirmation (client and server derive same keys)
 *   - Secure memory cleanup (sensitive data zeroed after use)
 */

#include <catch2/catch_test_macros.hpp>
#include "opaque/opaque.h"
#include "opaque/initiator.h"
#include "opaque/responder.h"
#include "opaque/protocol.h"
#include "opaque/pq.h"
#include <sodium.h>
#include <cstring>
#include <vector>
#include <set>

using namespace ecliptix::security::opaque;

namespace {

constexpr uint8_t kAccountId1[16] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
};
constexpr uint8_t kAccountId2[16] = {
    0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8,
    0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0
};

Result BuildKe1(const initiator::KE1& ke1, secure_bytes& out) {
    out.resize(KE1_LENGTH);
    return protocol::write_ke1(
        ke1.credential_request.data(), ke1.credential_request.size(),
        ke1.initiator_public_key.data(), ke1.initiator_public_key.size(),
        ke1.initiator_nonce.data(), ke1.initiator_nonce.size(),
        ke1.pq_ephemeral_public_key.data(), ke1.pq_ephemeral_public_key.size(),
        out.data(), out.size());
}

Result BuildKe2(const responder::KE2& ke2, secure_bytes& out) {
    out.resize(KE2_LENGTH);
    return protocol::write_ke2(
        ke2.responder_nonce.data(), ke2.responder_nonce.size(),
        ke2.responder_public_key.data(), ke2.responder_public_key.size(),
        ke2.credential_response.data(), ke2.credential_response.size(),
        ke2.responder_mac.data(), ke2.responder_mac.size(),
        ke2.kem_ciphertext.data(), ke2.kem_ciphertext.size(),
        out.data(), out.size());
}

Result BuildRecord(const initiator::RegistrationRecord& rec, secure_bytes& out) {
    out.resize(REGISTRATION_RECORD_LENGTH);
    return protocol::write_registration_record(
        rec.envelope.data(), rec.envelope.size(),
        rec.initiator_public_key.data(), rec.initiator_public_key.size(),
        out.data(), out.size());
}

struct RegisteredUser {
    ResponderCredentials credentials;
    secure_bytes record_buf;
};

RegisteredUser register_user(responder::OpaqueResponder& server,
                             initiator::OpaqueInitiator& client,
                             const char* password,
                             const uint8_t* account_id, size_t account_id_len) {
    RegisteredUser u;
    initiator::InitiatorState st;
    initiator::RegistrationRequest req;
    initiator::OpaqueInitiator::create_registration_request(
        reinterpret_cast<const uint8_t*>(password), strlen(password), req, st);

    responder::RegistrationResponse resp;
    server.create_registration_response(
        req.data.data(), req.data.size(), account_id, account_id_len, resp);

    initiator::RegistrationRecord rec;
    client.finalize_registration(resp.data.data(), resp.data.size(), st, rec);

    BuildRecord(rec, u.record_buf);
    responder::build_credentials(u.record_buf.data(), u.record_buf.size(), u.credentials);
    return u;
}

} // anonymous namespace


/* ============================================================
 * PASSWORD INDEPENDENCE
 * Different passwords must produce different registration records,
 * different envelopes, and different session keys.
 * Maps to: Theorem 1 (Password Secrecy)
 * ============================================================ */
TEST_CASE("Password Independence — Different passwords yield different records",
          "[security][password]") {
    REQUIRE(sodium_init() >= 0);

    responder::ResponderKeyPair kp;
    responder::ResponderKeyPair::generate(kp);
    responder::OpaqueResponder server(kp);
    ResponderPublicKey pk(kp.public_key.data(), kp.public_key.size());
    initiator::OpaqueInitiator client(pk);

    const char* passwords[] = {
        "password_alpha", "password_beta", "password_gamma",
        "password_delta", "password_epsilon", "p", "a_very_long_password_that_exceeds_normal_lengths_significantly"
    };
    constexpr size_t N = sizeof(passwords) / sizeof(passwords[0]);

    std::set<secure_bytes> unique_records;
    for (size_t i = 0; i < N; ++i) {
        auto u = register_user(server, client, passwords[i], kAccountId1, sizeof(kAccountId1));
        unique_records.insert(u.record_buf);
    }

    /* All records must differ */
    REQUIRE(unique_records.size() == N);
}

TEST_CASE("Password Independence — Same password, same credentials, different session keys",
          "[security][password]") {
    REQUIRE(sodium_init() >= 0);

    responder::ResponderKeyPair kp;
    responder::ResponderKeyPair::generate(kp);
    responder::OpaqueResponder server(kp);
    ResponderPublicKey pk(kp.public_key.data(), kp.public_key.size());
    initiator::OpaqueInitiator client(pk);

    const char* password = "same_password_test";
    auto u = register_user(server, client, password, kAccountId1, sizeof(kAccountId1));

    std::set<secure_bytes> session_keys;
    for (int i = 0; i < 20; ++i) {
        initiator::InitiatorState cst;
        initiator::KE1 ke1;
        initiator::OpaqueInitiator::generate_ke1(
            reinterpret_cast<const uint8_t*>(password), strlen(password), ke1, cst);
        secure_bytes ke1d;
        BuildKe1(ke1, ke1d);

        responder::ResponderState sst;
        responder::KE2 ke2;
        server.generate_ke2(ke1d.data(), ke1d.size(),
                            kAccountId1, sizeof(kAccountId1),
                            u.credentials, ke2, sst);
        secure_bytes ke2d;
        BuildKe2(ke2, ke2d);

        initiator::KE3 ke3;
        REQUIRE(client.generate_ke3(ke2d.data(), ke2d.size(), cst, ke3) == Result::Success);

        secure_bytes sk, mk;
        REQUIRE(server.responder_finish(ke3.initiator_mac.data(), ke3.initiator_mac.size(),
                                         sst, sk, mk) == Result::Success);
        session_keys.insert(sk);
    }

    REQUIRE(session_keys.size() == 20);
}


/* ============================================================
 * ACCOUNT ISOLATION
 * Different account_id with same password must produce different
 * OPRF keys, thus different envelopes and session keys.
 * Maps to: OPRF key derivation uses account_id as input
 * ============================================================ */
TEST_CASE("Account Isolation — Different account_id yields different credentials",
          "[security][isolation]") {
    REQUIRE(sodium_init() >= 0);

    responder::ResponderKeyPair kp;
    responder::ResponderKeyPair::generate(kp);
    responder::OpaqueResponder server(kp);
    ResponderPublicKey pk(kp.public_key.data(), kp.public_key.size());
    initiator::OpaqueInitiator client(pk);

    const char* password = "same_password_for_both";

    auto u1 = register_user(server, client, password, kAccountId1, sizeof(kAccountId1));
    auto u2 = register_user(server, client, password, kAccountId2, sizeof(kAccountId2));

    /* Records must differ (different OPRF keys → different envelopes) */
    REQUIRE(u1.record_buf != u2.record_buf);
}


/* ============================================================
 * TRANSCRIPT BINDING
 * Modifying ANY single field in KE2 must cause MAC verification
 * failure on the client side. Tests each field systematically.
 * Maps to: Theorem 3 (Mutual Authentication)
 * ============================================================ */
TEST_CASE("Transcript Binding — Each KE2 field tampered individually",
          "[security][transcript]") {
    REQUIRE(sodium_init() >= 0);

    responder::ResponderKeyPair kp;
    responder::ResponderKeyPair::generate(kp);
    responder::OpaqueResponder server(kp);
    ResponderPublicKey pk(kp.public_key.data(), kp.public_key.size());
    initiator::OpaqueInitiator client(pk);

    const char* password = "transcript_binding_test";
    auto u = register_user(server, client, password, kAccountId1, sizeof(kAccountId1));

    /* KE2 field offsets */
    struct FieldInfo {
        const char* name;
        size_t offset;
        size_t length;
    };

    FieldInfo fields[] = {
        {"responder_nonce",      0, NONCE_LENGTH},
        {"responder_public_key", NONCE_LENGTH, PUBLIC_KEY_LENGTH},
        {"credential_response",  NONCE_LENGTH + PUBLIC_KEY_LENGTH, CREDENTIAL_RESPONSE_LENGTH},
        {"responder_mac",        NONCE_LENGTH + PUBLIC_KEY_LENGTH + CREDENTIAL_RESPONSE_LENGTH, MAC_LENGTH},
        {"kem_ciphertext",       NONCE_LENGTH + PUBLIC_KEY_LENGTH + CREDENTIAL_RESPONSE_LENGTH + MAC_LENGTH,
                                 pq_constants::KEM_CIPHERTEXT_LENGTH},
    };

    for (const auto& field : fields) {
        INFO("Tampering field: " << field.name);

        /* Do honest KE1 → KE2 */
        initiator::InitiatorState cst;
        initiator::KE1 ke1;
        REQUIRE(initiator::OpaqueInitiator::generate_ke1(
            reinterpret_cast<const uint8_t*>(password), strlen(password),
            ke1, cst) == Result::Success);
        secure_bytes ke1d;
        REQUIRE(BuildKe1(ke1, ke1d) == Result::Success);

        responder::ResponderState sst;
        responder::KE2 ke2;
        REQUIRE(server.generate_ke2(ke1d.data(), ke1d.size(),
                                     kAccountId1, sizeof(kAccountId1),
                                     u.credentials, ke2, sst) == Result::Success);
        secure_bytes ke2d;
        REQUIRE(BuildKe2(ke2, ke2d) == Result::Success);

        /* Tamper one byte in the middle of this field */
        size_t tamper_pos = field.offset + field.length / 2;
        REQUIRE(tamper_pos < ke2d.size());
        ke2d[tamper_pos] ^= 0x01;

        /* Client must reject */
        initiator::KE3 ke3;
        Result r = client.generate_ke3(ke2d.data(), ke2d.size(), cst, ke3);
        REQUIRE((r == Result::AuthenticationError || r == Result::InvalidPublicKey));
    }
}

TEST_CASE("Transcript Binding — Each KE1 field tampered individually",
          "[security][transcript]") {
    REQUIRE(sodium_init() >= 0);

    responder::ResponderKeyPair kp;
    responder::ResponderKeyPair::generate(kp);
    responder::OpaqueResponder server(kp);
    ResponderPublicKey pk(kp.public_key.data(), kp.public_key.size());
    initiator::OpaqueInitiator client(pk);

    const char* password = "transcript_ke1_test";
    auto u = register_user(server, client, password, kAccountId1, sizeof(kAccountId1));

    /* Fields that, when tampered, should cause server to either reject
     * or produce wrong keys that client will reject */
    struct FieldInfo {
        const char* name;
        size_t offset;
        size_t length;
    };

    FieldInfo fields[] = {
        {"credential_request",        0, REGISTRATION_REQUEST_LENGTH},
        {"initiator_public_key",      REGISTRATION_REQUEST_LENGTH, PUBLIC_KEY_LENGTH},
        {"initiator_nonce",           REGISTRATION_REQUEST_LENGTH + PUBLIC_KEY_LENGTH, NONCE_LENGTH},
        {"pq_ephemeral_public_key",   REGISTRATION_REQUEST_LENGTH + PUBLIC_KEY_LENGTH + NONCE_LENGTH,
                                      pq_constants::KEM_PUBLIC_KEY_LENGTH},
    };

    for (const auto& field : fields) {
        INFO("Tampering KE1 field: " << field.name);

        initiator::InitiatorState cst;
        initiator::KE1 ke1;
        REQUIRE(initiator::OpaqueInitiator::generate_ke1(
            reinterpret_cast<const uint8_t*>(password), strlen(password),
            ke1, cst) == Result::Success);
        secure_bytes ke1d;
        REQUIRE(BuildKe1(ke1, ke1d) == Result::Success);

        /* Tamper */
        size_t tamper_pos = field.offset + field.length / 2;
        REQUIRE(tamper_pos < ke1d.size());
        ke1d[tamper_pos] ^= 0xFF;

        /* Server generates KE2 with tampered KE1 */
        responder::ResponderState sst;
        responder::KE2 ke2;
        Result r = server.generate_ke2(ke1d.data(), ke1d.size(),
                                        kAccountId1, sizeof(kAccountId1),
                                        u.credentials, ke2, sst);

        if (r == Result::Success) {
            /* Server accepted — but client should reject due to mismatched transcript */
            secure_bytes ke2d;
            REQUIRE(BuildKe2(ke2, ke2d) == Result::Success);
            initiator::KE3 ke3;
            Result ke3_r = client.generate_ke3(ke2d.data(), ke2d.size(), cst, ke3);

            if (ke3_r == Result::Success) {
                /* Client accepted — server finish should fail (mismatched MAC) */
                secure_bytes sk, mk;
                Result fin_r = server.responder_finish(
                    ke3.initiator_mac.data(), ke3.initiator_mac.size(), sst, sk, mk);
                REQUIRE(fin_r == Result::AuthenticationError);
            }
            /* else: client correctly rejected */
        }
        /* else: server correctly rejected malformed KE1 */
    }
}


/* ============================================================
 * KEM CONTRIBUTION (AND-MODEL)
 * Verify that the KEM shared secret actually contributes to
 * the derived session key. If KEM is removed/zeroed, keys differ.
 * Maps to: Theorem 4 (AND-model), Tamarin lemma and_model_security
 * ============================================================ */
TEST_CASE("KEM Contribution — PQ combiner is sensitive to KEM shared secret",
          "[security][and-model]") {
    REQUIRE(sodium_init() >= 0);

    /* Test combiner directly: same classical IKM, different KEM ss → different PRK */
    uint8_t classical_ikm[96];
    uint8_t transcript_hash[crypto_hash_sha512_BYTES];
    randombytes_buf(classical_ikm, sizeof(classical_ikm));
    randombytes_buf(transcript_hash, sizeof(transcript_hash));

    uint8_t kem_ss_a[pq_constants::KEM_SHARED_SECRET_LENGTH];
    uint8_t kem_ss_b[pq_constants::KEM_SHARED_SECRET_LENGTH];
    randombytes_buf(kem_ss_a, sizeof(kem_ss_a));
    randombytes_buf(kem_ss_b, sizeof(kem_ss_b));

    uint8_t prk_a[crypto_auth_hmacsha512_BYTES];
    uint8_t prk_b[crypto_auth_hmacsha512_BYTES];

    REQUIRE(pq::combine_key_material(classical_ikm, sizeof(classical_ikm),
                                      kem_ss_a, sizeof(kem_ss_a),
                                      transcript_hash, sizeof(transcript_hash),
                                      prk_a) == Result::Success);
    REQUIRE(pq::combine_key_material(classical_ikm, sizeof(classical_ikm),
                                      kem_ss_b, sizeof(kem_ss_b),
                                      transcript_hash, sizeof(transcript_hash),
                                      prk_b) == Result::Success);

    /* Different KEM ss MUST produce different PRK */
    REQUIRE(std::memcmp(prk_a, prk_b, sizeof(prk_a)) != 0);
}

TEST_CASE("KEM Contribution — Classical IKM also contributes",
          "[security][and-model]") {
    REQUIRE(sodium_init() >= 0);

    uint8_t classical_ikm_a[96], classical_ikm_b[96];
    uint8_t kem_ss[pq_constants::KEM_SHARED_SECRET_LENGTH];
    uint8_t transcript_hash[crypto_hash_sha512_BYTES];
    randombytes_buf(classical_ikm_a, sizeof(classical_ikm_a));
    randombytes_buf(classical_ikm_b, sizeof(classical_ikm_b));
    randombytes_buf(kem_ss, sizeof(kem_ss));
    randombytes_buf(transcript_hash, sizeof(transcript_hash));

    uint8_t prk_a[crypto_auth_hmacsha512_BYTES];
    uint8_t prk_b[crypto_auth_hmacsha512_BYTES];

    REQUIRE(pq::combine_key_material(classical_ikm_a, sizeof(classical_ikm_a),
                                      kem_ss, sizeof(kem_ss),
                                      transcript_hash, sizeof(transcript_hash),
                                      prk_a) == Result::Success);
    REQUIRE(pq::combine_key_material(classical_ikm_b, sizeof(classical_ikm_b),
                                      kem_ss, sizeof(kem_ss),
                                      transcript_hash, sizeof(transcript_hash),
                                      prk_b) == Result::Success);

    REQUIRE(std::memcmp(prk_a, prk_b, sizeof(prk_a)) != 0);
}


/* ============================================================
 * KEY CONFIRMATION
 * Client and server MUST derive identical session and master keys
 * after a successful authentication. Test with many iterations.
 * Maps to: Protocol correctness (sanity check)
 * ============================================================ */
TEST_CASE("Key Confirmation — Client and server agree on keys (N=50)",
          "[security][key-confirmation]") {
    REQUIRE(sodium_init() >= 0);

    responder::ResponderKeyPair kp;
    responder::ResponderKeyPair::generate(kp);
    responder::OpaqueResponder server(kp);
    ResponderPublicKey pk(kp.public_key.data(), kp.public_key.size());
    initiator::OpaqueInitiator client(pk);

    const char* password = "key_confirmation_pwd";
    auto u = register_user(server, client, password, kAccountId1, sizeof(kAccountId1));

    for (int i = 0; i < 50; ++i) {
        INFO("Iteration " << i);

        initiator::InitiatorState cst;
        initiator::KE1 ke1;
        REQUIRE(initiator::OpaqueInitiator::generate_ke1(
            reinterpret_cast<const uint8_t*>(password), strlen(password),
            ke1, cst) == Result::Success);
        secure_bytes ke1d;
        BuildKe1(ke1, ke1d);

        responder::ResponderState sst;
        responder::KE2 ke2;
        REQUIRE(server.generate_ke2(ke1d.data(), ke1d.size(),
                                     kAccountId1, sizeof(kAccountId1),
                                     u.credentials, ke2, sst) == Result::Success);
        secure_bytes ke2d;
        BuildKe2(ke2, ke2d);

        initiator::KE3 ke3;
        REQUIRE(client.generate_ke3(ke2d.data(), ke2d.size(), cst, ke3) == Result::Success);

        secure_bytes srv_sk, srv_mk;
        REQUIRE(server.responder_finish(ke3.initiator_mac.data(), ke3.initiator_mac.size(),
                                         sst, srv_sk, srv_mk) == Result::Success);

        secure_bytes cli_sk, cli_mk;
        REQUIRE(initiator::OpaqueInitiator::initiator_finish(cst, cli_sk, cli_mk) == Result::Success);

        REQUIRE(cli_sk == srv_sk);
        REQUIRE(cli_mk == srv_mk);
        REQUIRE(cli_sk.size() == HASH_LENGTH);
        REQUIRE(cli_mk.size() == MASTER_KEY_LENGTH);
    }
}


/* ============================================================
 * SECURE MEMORY CLEANUP
 * After protocol completion, sensitive state must be zeroed.
 * Maps to: Implementation security requirement
 * ============================================================ */
TEST_CASE("Secure Memory Cleanup — State zeroed after finish",
          "[security][memory]") {
    REQUIRE(sodium_init() >= 0);

    responder::ResponderKeyPair kp;
    responder::ResponderKeyPair::generate(kp);
    responder::OpaqueResponder server(kp);
    ResponderPublicKey pk(kp.public_key.data(), kp.public_key.size());
    initiator::OpaqueInitiator client(pk);

    const char* password = "cleanup_test_pwd";
    auto u = register_user(server, client, password, kAccountId1, sizeof(kAccountId1));

    initiator::InitiatorState cst;
    initiator::KE1 ke1;
    initiator::OpaqueInitiator::generate_ke1(
        reinterpret_cast<const uint8_t*>(password), strlen(password), ke1, cst);
    secure_bytes ke1d;
    BuildKe1(ke1, ke1d);

    responder::ResponderState sst;
    responder::KE2 ke2;
    server.generate_ke2(ke1d.data(), ke1d.size(),
                         kAccountId1, sizeof(kAccountId1),
                         u.credentials, ke2, sst);
    secure_bytes ke2d;
    BuildKe2(ke2, ke2d);

    initiator::KE3 ke3;
    client.generate_ke3(ke2d.data(), ke2d.size(), cst, ke3);

    secure_bytes srv_sk, srv_mk;
    server.responder_finish(ke3.initiator_mac.data(), ke3.initiator_mac.size(),
                             sst, srv_sk, srv_mk);

    secure_bytes cli_sk, cli_mk;
    initiator::OpaqueInitiator::initiator_finish(cst, cli_sk, cli_mk);

    /* After finish, internal state must be cleared */
    REQUIRE(cst.session_key.empty());
    REQUIRE(cst.master_key.empty());
    REQUIRE(cst.pq_shared_secret.empty());
    REQUIRE(cst.pq_ephemeral_secret_key.empty());
    REQUIRE(cst.secure_key.empty());

    REQUIRE(sst.session_key.empty());
    REQUIRE(sst.master_key.empty());
    REQUIRE(sst.pq_shared_secret.empty());
    REQUIRE(sst.handshake_complete == true);
}


/* ============================================================
 * DOMAIN SEPARATION
 * Keys derived with different labels must be different.
 * Tests that HKDF-Expand with different info produces different output.
 * ============================================================ */
TEST_CASE("Domain Separation — Different HKDF labels yield different keys",
          "[security][domain-separation]") {
    REQUIRE(sodium_init() >= 0);

    uint8_t prk[crypto_auth_hmacsha512_BYTES];
    randombytes_buf(prk, sizeof(prk));

    const char* labels[] = {
        "ECLIPTIX-OPAQUE-PQ-v1/SessionKey",
        "ECLIPTIX-OPAQUE-PQ-v1/MasterKey",
        "ECLIPTIX-OPAQUE-PQ-v1/ResponderMAC",
        "ECLIPTIX-OPAQUE-PQ-v1/InitiatorMAC",
    };
    constexpr size_t N = sizeof(labels) / sizeof(labels[0]);

    std::set<std::vector<uint8_t>> unique_keys;

    for (size_t i = 0; i < N; ++i) {
        uint8_t okm[64];
        REQUIRE(crypto::key_derivation_expand(
            prk, sizeof(prk),
            reinterpret_cast<const uint8_t*>(labels[i]), strlen(labels[i]),
            okm, sizeof(okm)) == Result::Success);
        unique_keys.insert(std::vector<uint8_t>(okm, okm + sizeof(okm)));
    }

    REQUIRE(unique_keys.size() == N);
}
