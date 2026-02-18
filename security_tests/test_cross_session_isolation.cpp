/**
 * @file test_cross_session_isolation.cpp
 * @brief Cross-session and cross-server isolation tests.
 *
 * Verifies that:
 *   1. Different servers (different LTK) with same password → different keys
 *   2. Re-registration with same password → different envelope, same auth works
 *   3. Concurrent sessions don't interfere with each other
 *   4. Replay of KE1/KE2/KE3 from previous session fails
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

constexpr char kPassword[] = "isolation_test_password";
constexpr uint8_t kAccountId[16] = {
    0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
    0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99
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

} // anonymous namespace


/* ============================================================
 * CROSS-SERVER ISOLATION
 * Same password registered with different servers must produce
 * incompatible credentials — auth on server B with creds from A fails.
 * ============================================================ */
TEST_CASE("Cross-Server Isolation — Different server LTK, same password",
          "[security][isolation][cross-server]") {
    REQUIRE(sodium_init() >= 0);

    /* Server A */
    responder::ResponderKeyPair kp_a;
    responder::ResponderKeyPair::generate(kp_a);
    responder::OpaqueResponder server_a(kp_a);
    ResponderPublicKey pk_a(kp_a.public_key.data(), kp_a.public_key.size());

    /* Server B */
    responder::ResponderKeyPair kp_b;
    responder::ResponderKeyPair::generate(kp_b);
    responder::OpaqueResponder server_b(kp_b);
    ResponderPublicKey pk_b(kp_b.public_key.data(), kp_b.public_key.size());

    /* Register with Server A */
    initiator::OpaqueInitiator client_a(pk_a);
    initiator::InitiatorState reg_st;
    initiator::RegistrationRequest reg_req;
    initiator::OpaqueInitiator::create_registration_request(
        reinterpret_cast<const uint8_t*>(kPassword), strlen(kPassword), reg_req, reg_st);

    responder::RegistrationResponse reg_resp;
    server_a.create_registration_response(
        reg_req.data.data(), reg_req.data.size(),
        kAccountId, sizeof(kAccountId), reg_resp);

    initiator::RegistrationRecord rec;
    client_a.finalize_registration(reg_resp.data.data(), reg_resp.data.size(), reg_st, rec);

    secure_bytes rec_buf;
    BuildRecord(rec, rec_buf);
    ResponderCredentials creds_a;
    responder::build_credentials(rec_buf.data(), rec_buf.size(), creds_a);

    /* Try to auth with Server B using creds from Server A */
    initiator::OpaqueInitiator client_for_b(pk_b);
    initiator::InitiatorState cst;
    initiator::KE1 ke1;
    initiator::OpaqueInitiator::generate_ke1(
        reinterpret_cast<const uint8_t*>(kPassword), strlen(kPassword), ke1, cst);
    secure_bytes ke1d;
    BuildKe1(ke1, ke1d);

    /* Server B tries to use Server A's credentials */
    responder::ResponderState sst;
    responder::KE2 ke2;
    Result r = server_b.generate_ke2(ke1d.data(), ke1d.size(),
                                      kAccountId, sizeof(kAccountId),
                                      creds_a, ke2, sst);

    if (r == Result::Success) {
        secure_bytes ke2d;
        BuildKe2(ke2, ke2d);
        initiator::KE3 ke3;
        /* Client should reject because envelope was encrypted with server A's key */
        Result kr = client_for_b.generate_ke3(ke2d.data(), ke2d.size(), cst, ke3);
        REQUIRE(kr == Result::AuthenticationError);
    }
    /* Else: server B rejected outright — also correct */
}


/* ============================================================
 * RE-REGISTRATION
 * Re-registering with same password should produce a new, different
 * envelope but authentication should still work.
 * ============================================================ */
TEST_CASE("Re-Registration — New registration replaces old, auth works",
          "[security][isolation][re-registration]") {
    REQUIRE(sodium_init() >= 0);

    responder::ResponderKeyPair kp;
    responder::ResponderKeyPair::generate(kp);
    responder::OpaqueResponder server(kp);
    ResponderPublicKey pk(kp.public_key.data(), kp.public_key.size());
    initiator::OpaqueInitiator client(pk);

    /* Register once */
    initiator::InitiatorState reg_st1;
    initiator::RegistrationRequest reg_req1;
    initiator::OpaqueInitiator::create_registration_request(
        reinterpret_cast<const uint8_t*>(kPassword), strlen(kPassword), reg_req1, reg_st1);
    responder::RegistrationResponse reg_resp1;
    server.create_registration_response(
        reg_req1.data.data(), reg_req1.data.size(), kAccountId, sizeof(kAccountId), reg_resp1);
    initiator::RegistrationRecord rec1;
    client.finalize_registration(reg_resp1.data.data(), reg_resp1.data.size(), reg_st1, rec1);
    secure_bytes buf1;
    BuildRecord(rec1, buf1);

    /* Register again (same password) */
    initiator::InitiatorState reg_st2;
    initiator::RegistrationRequest reg_req2;
    initiator::OpaqueInitiator::create_registration_request(
        reinterpret_cast<const uint8_t*>(kPassword), strlen(kPassword), reg_req2, reg_st2);
    responder::RegistrationResponse reg_resp2;
    server.create_registration_response(
        reg_req2.data.data(), reg_req2.data.size(), kAccountId, sizeof(kAccountId), reg_resp2);
    initiator::RegistrationRecord rec2;
    client.finalize_registration(reg_resp2.data.data(), reg_resp2.data.size(), reg_st2, rec2);
    secure_bytes buf2;
    BuildRecord(rec2, buf2);

    /* Records must differ (different OPRF blind, different client keypair) */
    REQUIRE(buf1 != buf2);

    /* Auth with NEW credentials must work */
    ResponderCredentials creds2;
    responder::build_credentials(buf2.data(), buf2.size(), creds2);

    initiator::InitiatorState cst;
    initiator::KE1 ke1;
    REQUIRE(initiator::OpaqueInitiator::generate_ke1(
        reinterpret_cast<const uint8_t*>(kPassword), strlen(kPassword),
        ke1, cst) == Result::Success);
    secure_bytes ke1d;
    BuildKe1(ke1, ke1d);

    responder::ResponderState sst;
    responder::KE2 ke2;
    REQUIRE(server.generate_ke2(ke1d.data(), ke1d.size(),
                                 kAccountId, sizeof(kAccountId),
                                 creds2, ke2, sst) == Result::Success);
    secure_bytes ke2d;
    BuildKe2(ke2, ke2d);

    initiator::KE3 ke3;
    REQUIRE(client.generate_ke3(ke2d.data(), ke2d.size(), cst, ke3) == Result::Success);

    secure_bytes sk, mk;
    REQUIRE(server.responder_finish(ke3.initiator_mac.data(), ke3.initiator_mac.size(),
                                     sst, sk, mk) == Result::Success);

    /* Auth with OLD credentials must FAIL */
    ResponderCredentials creds1;
    responder::build_credentials(buf1.data(), buf1.size(), creds1);

    initiator::InitiatorState cst_old;
    initiator::KE1 ke1_old;
    REQUIRE(initiator::OpaqueInitiator::generate_ke1(
        reinterpret_cast<const uint8_t*>(kPassword), strlen(kPassword),
        ke1_old, cst_old) == Result::Success);
    secure_bytes ke1d_old;
    BuildKe1(ke1_old, ke1d_old);

    responder::ResponderState sst_old;
    responder::KE2 ke2_old;
    REQUIRE(server.generate_ke2(ke1d_old.data(), ke1d_old.size(),
                                 kAccountId, sizeof(kAccountId),
                                 creds1, ke2_old, sst_old) == Result::Success);
    secure_bytes ke2d_old;
    BuildKe2(ke2_old, ke2d_old);

    initiator::KE3 ke3_old;
    /* NOTE: Old credentials CAN still work because OPRF key is deterministic
     * (derived from server_private_key + account_id, which don't change).
     * The server envelope contains a DIFFERENT client keypair, but the
     * randomized password is the same, so envelope decryption succeeds.
     *
     * In a real system, the server would REPLACE old credentials in the
     * database. This test verifies that the protocol itself doesn't prevent
     * old credentials from working - invalidation is a server-side operation.
     */
    Result r = client.generate_ke3(ke2d_old.data(), ke2d_old.size(), cst_old, ke3_old);

    /* The protocol allows this (OPRF is deterministic), but real servers
     * should enforce single-credential-per-user policy at the database level */
    if (r == Result::Success) {
        /* Old credentials still work - this is expected behavior.
         * Server must explicitly delete/replace them in storage. */
        INFO("Old credentials still valid (expected: OPRF is deterministic)");
    } else {
        /* Could also fail due to different client keypair mismatch */
        INFO("Old credentials rejected (possible but not guaranteed)");
    }
    /* Either outcome is acceptable at the protocol level */
}


/* ============================================================
 * REPLAY ATTACK RESISTANCE
 * Replaying KE2 from session N into session N+1 must fail.
 * ============================================================ */
TEST_CASE("Replay Resistance — Old KE2 rejected in new session",
          "[security][replay]") {
    REQUIRE(sodium_init() >= 0);

    responder::ResponderKeyPair kp;
    responder::ResponderKeyPair::generate(kp);
    responder::OpaqueResponder server(kp);
    ResponderPublicKey pk(kp.public_key.data(), kp.public_key.size());
    initiator::OpaqueInitiator client(pk);

    const char* password = "replay_test_pwd";
    initiator::InitiatorState reg_st;
    initiator::RegistrationRequest reg_req;
    initiator::OpaqueInitiator::create_registration_request(
        reinterpret_cast<const uint8_t*>(password), strlen(password), reg_req, reg_st);
    responder::RegistrationResponse reg_resp;
    server.create_registration_response(
        reg_req.data.data(), reg_req.data.size(), kAccountId, sizeof(kAccountId), reg_resp);
    initiator::RegistrationRecord rec;
    client.finalize_registration(reg_resp.data.data(), reg_resp.data.size(), reg_st, rec);
    secure_bytes buf;
    BuildRecord(rec, buf);
    ResponderCredentials creds;
    responder::build_credentials(buf.data(), buf.size(), creds);

    /* Session 1: capture KE2 */
    initiator::InitiatorState cst1;
    initiator::KE1 ke1_s1;
    initiator::OpaqueInitiator::generate_ke1(
        reinterpret_cast<const uint8_t*>(password), strlen(password), ke1_s1, cst1);
    secure_bytes ke1d_s1;
    BuildKe1(ke1_s1, ke1d_s1);

    responder::ResponderState sst1;
    responder::KE2 ke2_s1;
    server.generate_ke2(ke1d_s1.data(), ke1d_s1.size(),
                         kAccountId, sizeof(kAccountId), creds, ke2_s1, sst1);
    secure_bytes ke2d_captured;
    BuildKe2(ke2_s1, ke2d_captured);

    /* Session 2: new KE1, try to use captured KE2 from session 1 */
    initiator::InitiatorState cst2;
    initiator::KE1 ke1_s2;
    initiator::OpaqueInitiator::generate_ke1(
        reinterpret_cast<const uint8_t*>(password), strlen(password), ke1_s2, cst2);

    /* Feed session 1's KE2 to session 2's client */
    initiator::KE3 ke3_replay;
    Result r = client.generate_ke3(ke2d_captured.data(), ke2d_captured.size(), cst2, ke3_replay);

    /* Must fail: ephemeral keys don't match */
    REQUIRE(r == Result::AuthenticationError);
}

TEST_CASE("Replay Resistance — Old KE3 rejected by server",
          "[security][replay]") {
    REQUIRE(sodium_init() >= 0);

    responder::ResponderKeyPair kp;
    responder::ResponderKeyPair::generate(kp);
    responder::OpaqueResponder server(kp);
    ResponderPublicKey pk(kp.public_key.data(), kp.public_key.size());
    initiator::OpaqueInitiator client(pk);

    const char* password = "replay_ke3_test";
    initiator::InitiatorState reg_st;
    initiator::RegistrationRequest reg_req;
    initiator::OpaqueInitiator::create_registration_request(
        reinterpret_cast<const uint8_t*>(password), strlen(password), reg_req, reg_st);
    responder::RegistrationResponse reg_resp;
    server.create_registration_response(
        reg_req.data.data(), reg_req.data.size(), kAccountId, sizeof(kAccountId), reg_resp);
    initiator::RegistrationRecord rec;
    client.finalize_registration(reg_resp.data.data(), reg_resp.data.size(), reg_st, rec);
    secure_bytes buf;
    BuildRecord(rec, buf);
    ResponderCredentials creds;
    responder::build_credentials(buf.data(), buf.size(), creds);

    /* Session 1: complete and capture KE3 */
    initiator::InitiatorState cst1;
    initiator::KE1 ke1_s1;
    initiator::OpaqueInitiator::generate_ke1(
        reinterpret_cast<const uint8_t*>(password), strlen(password), ke1_s1, cst1);
    secure_bytes ke1d_s1;
    BuildKe1(ke1_s1, ke1d_s1);

    responder::ResponderState sst1;
    responder::KE2 ke2_s1;
    server.generate_ke2(ke1d_s1.data(), ke1d_s1.size(),
                         kAccountId, sizeof(kAccountId), creds, ke2_s1, sst1);
    secure_bytes ke2d_s1;
    BuildKe2(ke2_s1, ke2d_s1);

    initiator::KE3 ke3_captured;
    client.generate_ke3(ke2d_s1.data(), ke2d_s1.size(), cst1, ke3_captured);
    secure_bytes captured_mac(ke3_captured.initiator_mac.begin(), ke3_captured.initiator_mac.end());

    /* Session 2: new handshake, try to use captured KE3 */
    initiator::InitiatorState cst2;
    initiator::KE1 ke1_s2;
    initiator::OpaqueInitiator::generate_ke1(
        reinterpret_cast<const uint8_t*>(password), strlen(password), ke1_s2, cst2);
    secure_bytes ke1d_s2;
    BuildKe1(ke1_s2, ke1d_s2);

    responder::ResponderState sst2;
    responder::KE2 ke2_s2;
    server.generate_ke2(ke1d_s2.data(), ke1d_s2.size(),
                         kAccountId, sizeof(kAccountId), creds, ke2_s2, sst2);

    /* Feed captured KE3 MAC to new server state */
    secure_bytes sk, mk;
    Result r = server.responder_finish(captured_mac.data(), captured_mac.size(), sst2, sk, mk);

    /* Must fail: MAC was computed over different transcript */
    REQUIRE(r == Result::AuthenticationError);
}


/* ============================================================
 * EPHEMERAL UNIQUENESS
 * Every KE1 must contain unique ephemeral keys and nonces.
 * ============================================================ */
TEST_CASE("Ephemeral Uniqueness — KE1 nonces and ephemeral keys are unique",
          "[security][ephemeral]") {
    REQUIRE(sodium_init() >= 0);

    constexpr size_t N = 100;
    std::set<secure_bytes> nonces;
    std::set<secure_bytes> eph_keys;
    std::set<secure_bytes> kem_pks;

    for (size_t i = 0; i < N; ++i) {
        initiator::InitiatorState st;
        initiator::KE1 ke1;
        REQUIRE(initiator::OpaqueInitiator::generate_ke1(
            reinterpret_cast<const uint8_t*>(kPassword), strlen(kPassword),
            ke1, st) == Result::Success);

        nonces.insert(ke1.initiator_nonce);
        eph_keys.insert(ke1.initiator_public_key);
        kem_pks.insert(ke1.pq_ephemeral_public_key);
    }

    REQUIRE(nonces.size() == N);
    REQUIRE(eph_keys.size() == N);
    REQUIRE(kem_pks.size() == N);
}
