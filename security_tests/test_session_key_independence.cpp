/**
 * @file test_session_key_independence.cpp
 * @brief Verifies forward secrecy property at implementation level.
 *
 * Property: Each authentication session MUST produce a unique session key,
 * even with the same password and credentials. This is guaranteed by
 * ephemeral DH keys and ephemeral KEM keypairs.
 *
 * Tests:
 *   1. N sessions → N unique session keys (no collisions)
 *   2. Hamming distance between consecutive keys ≈ 50% (randomness)
 *   3. No correlation between session keys (byte distribution)
 *   4. Master keys also independent across sessions
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
#include <cmath>
#include <numeric>
#include <algorithm>

using namespace ecliptix::security::opaque;

namespace {

constexpr char kPassword[] = "session_independence_password";
constexpr uint8_t kAccountId[16] = {
    0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18,
    0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F, 0x90
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

struct TestFixture {
    responder::ResponderKeyPair server_keypair;
    ResponderPublicKey server_pk;
    ResponderCredentials credentials;
    responder::OpaqueResponder* server;
    initiator::OpaqueInitiator* client;

    TestFixture() : server(nullptr), client(nullptr) {
        responder::ResponderKeyPair::generate(server_keypair);
        server_pk = ResponderPublicKey(
            server_keypair.public_key.data(), server_keypair.public_key.size());
        server = new responder::OpaqueResponder(server_keypair);
        client = new initiator::OpaqueInitiator(server_pk);

        /* Register once */
        initiator::InitiatorState reg_st;
        initiator::RegistrationRequest reg_req;
        initiator::OpaqueInitiator::create_registration_request(
            reinterpret_cast<const uint8_t*>(kPassword), strlen(kPassword),
            reg_req, reg_st);

        responder::RegistrationResponse reg_resp;
        server->create_registration_response(
            reg_req.data.data(), reg_req.data.size(),
            kAccountId, sizeof(kAccountId), reg_resp);

        initiator::RegistrationRecord reg_rec;
        client->finalize_registration(
            reg_resp.data.data(), reg_resp.data.size(), reg_st, reg_rec);

        secure_bytes buf;
        BuildRecord(reg_rec, buf);
        responder::build_credentials(buf.data(), buf.size(), credentials);
    }

    ~TestFixture() {
        delete server;
        delete client;
    }

    bool do_auth(secure_bytes& session_key_out, secure_bytes& master_key_out) {
        initiator::InitiatorState cst;
        initiator::KE1 ke1;
        if (initiator::OpaqueInitiator::generate_ke1(
                reinterpret_cast<const uint8_t*>(kPassword), strlen(kPassword),
                ke1, cst) != Result::Success) return false;

        secure_bytes ke1_data;
        if (BuildKe1(ke1, ke1_data) != Result::Success) return false;

        responder::ResponderState sst;
        responder::KE2 ke2;
        if (server->generate_ke2(ke1_data.data(), ke1_data.size(),
                                  kAccountId, sizeof(kAccountId),
                                  credentials, ke2, sst) != Result::Success) return false;

        secure_bytes ke2_data;
        if (BuildKe2(ke2, ke2_data) != Result::Success) return false;

        initiator::KE3 ke3;
        if (client->generate_ke3(ke2_data.data(), ke2_data.size(), cst, ke3) != Result::Success)
            return false;

        secure_bytes srv_sk, srv_mk;
        if (server->responder_finish(ke3.initiator_mac.data(), ke3.initiator_mac.size(),
                                      sst, srv_sk, srv_mk) != Result::Success) return false;

        secure_bytes cli_sk, cli_mk;
        if (initiator::OpaqueInitiator::initiator_finish(cst, cli_sk, cli_mk) != Result::Success)
            return false;

        if (cli_sk != srv_sk || cli_mk != srv_mk) return false;

        session_key_out = cli_sk;
        master_key_out = cli_mk;
        return true;
    }
};

size_t hamming_distance_bits(const secure_bytes& a, const secure_bytes& b) {
    size_t dist = 0;
    size_t len = std::min(a.size(), b.size());
    for (size_t i = 0; i < len; ++i) {
        uint8_t diff = a[i] ^ b[i];
        while (diff) {
            dist += diff & 1;
            diff >>= 1;
        }
    }
    return dist;
}

} // anonymous namespace

TEST_CASE("Session Key Independence — No Collisions", "[security][forward-secrecy]") {
    REQUIRE(sodium_init() >= 0);

    TestFixture fix;
    constexpr size_t N = 100;

    std::set<secure_bytes> unique_session_keys;
    std::set<secure_bytes> unique_master_keys;

    for (size_t i = 0; i < N; ++i) {
        INFO("Session " << i);
        secure_bytes sk, mk;
        REQUIRE(fix.do_auth(sk, mk));
        REQUIRE(sk.size() == HASH_LENGTH);
        REQUIRE(mk.size() == MASTER_KEY_LENGTH);
        unique_session_keys.insert(sk);
        unique_master_keys.insert(mk);
    }

    /* Every session key must be unique */
    REQUIRE(unique_session_keys.size() == N);
    REQUIRE(unique_master_keys.size() == N);
}

TEST_CASE("Session Key Independence — Hamming Distance", "[security][forward-secrecy]") {
    REQUIRE(sodium_init() >= 0);

    TestFixture fix;
    constexpr size_t N = 50;

    std::vector<secure_bytes> keys;
    keys.reserve(N);

    for (size_t i = 0; i < N; ++i) {
        secure_bytes sk, mk;
        REQUIRE(fix.do_auth(sk, mk));
        keys.push_back(sk);
    }

    /* Hamming distance between consecutive keys should be ~50% of bits */
    std::vector<double> distances;
    for (size_t i = 1; i < N; ++i) {
        size_t hd = hamming_distance_bits(keys[i - 1], keys[i]);
        double ratio = static_cast<double>(hd) / static_cast<double>(HASH_LENGTH * 8);
        distances.push_back(ratio);
    }

    double mean = std::accumulate(distances.begin(), distances.end(), 0.0)
                  / static_cast<double>(distances.size());

    /* Expected: ~0.50 for random keys. Allow [0.40, 0.60] */
    INFO("Mean hamming distance ratio: " << mean);
    REQUIRE(mean > 0.40);
    REQUIRE(mean < 0.60);
}

TEST_CASE("Session Key Independence — Byte Distribution", "[security][forward-secrecy]") {
    REQUIRE(sodium_init() >= 0);

    TestFixture fix;
    constexpr size_t N = 50;

    /* Count byte value distribution across all session keys */
    size_t byte_counts[256] = {};
    size_t total_bytes = 0;

    for (size_t i = 0; i < N; ++i) {
        secure_bytes sk, mk;
        REQUIRE(fix.do_auth(sk, mk));
        for (uint8_t b : sk) {
            byte_counts[b]++;
            total_bytes++;
        }
    }

    /* Chi-squared test for uniform distribution */
    double expected = static_cast<double>(total_bytes) / 256.0;
    double chi2 = 0.0;
    for (size_t i = 0; i < 256; ++i) {
        double diff = static_cast<double>(byte_counts[i]) - expected;
        chi2 += (diff * diff) / expected;
    }

    /* For 255 df, chi2 critical value at p=0.001 is ~310.
     * We use a generous threshold — we're not a crypto lab,
     * just verifying keys don't have obvious bias. */
    INFO("Chi-squared statistic: " << chi2 << " (critical ~310 at p=0.001)");
    REQUIRE(chi2 < 400.0);
}
