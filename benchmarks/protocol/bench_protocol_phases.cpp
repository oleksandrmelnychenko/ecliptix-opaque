/**
 * @file bench_protocol_phases.cpp
 * @brief Macrobenchmarks for full protocol phases (registration + authentication).
 *
 * Measures each protocol step separately and end-to-end.
 * Output: Table 6.3 in the paper — "Protocol Phase Latency"
 */

#include "opaque/opaque.h"
#include "opaque/initiator.h"
#include "opaque/responder.h"
#include "opaque/protocol.h"
#include "opaque/pq.h"
#include "../bench_utils.h"
#include <sodium.h>
#include <cstring>

using namespace ecliptix::security::opaque;

static constexpr size_t N_ITER = 500;
static constexpr size_t N_WARMUP = 20;
/* Registration includes Argon2id so is much slower */
static constexpr size_t N_ITER_REG = 30;
static constexpr size_t N_WARMUP_REG = 3;

static constexpr char kPassword[] = "benchmark_password_v1";
static constexpr uint8_t kAccountId[16] = {
    0x4f, 0x8c, 0x2d, 0xa1, 0x91, 0x73, 0x4f, 0x2a,
    0xb6, 0x11, 0x22, 0x9d, 0x3c, 0xf0, 0x7a, 0x5e
};

namespace {

Result BuildKe1Data(const initiator::KE1& ke1, secure_bytes& out) {
    out.resize(KE1_LENGTH);
    return protocol::write_ke1(
        ke1.credential_request.data(), ke1.credential_request.size(),
        ke1.initiator_public_key.data(), ke1.initiator_public_key.size(),
        ke1.initiator_nonce.data(), ke1.initiator_nonce.size(),
        ke1.pq_ephemeral_public_key.data(), ke1.pq_ephemeral_public_key.size(),
        out.data(), out.size());
}

Result BuildKe2Data(const responder::KE2& ke2, secure_bytes& out) {
    out.resize(KE2_LENGTH);
    return protocol::write_ke2(
        ke2.responder_nonce.data(), ke2.responder_nonce.size(),
        ke2.responder_public_key.data(), ke2.responder_public_key.size(),
        ke2.credential_response.data(), ke2.credential_response.size(),
        ke2.responder_mac.data(), ke2.responder_mac.size(),
        ke2.kem_ciphertext.data(), ke2.kem_ciphertext.size(),
        out.data(), out.size());
}

Result BuildRecordBuffer(const initiator::RegistrationRecord& rec, secure_bytes& out) {
    out.resize(REGISTRATION_RECORD_LENGTH);
    return protocol::write_registration_record(
        rec.envelope.data(), rec.envelope.size(),
        rec.initiator_public_key.data(), rec.initiator_public_key.size(),
        out.data(), out.size());
}

/**
 * Setup: do one full registration, return credentials for auth benchmarks.
 */
struct SetupResult {
    responder::ResponderKeyPair server_keypair;
    ResponderPublicKey server_pk;
    ResponderCredentials credentials;
};

SetupResult do_registration() {
    SetupResult r;
    responder::ResponderKeyPair::generate(r.server_keypair);
    r.server_pk = ResponderPublicKey(
        r.server_keypair.public_key.data(), r.server_keypair.public_key.size());

    responder::OpaqueResponder server(r.server_keypair);
    initiator::OpaqueInitiator client(r.server_pk);

    initiator::InitiatorState reg_state;
    initiator::RegistrationRequest reg_req;
    initiator::OpaqueInitiator::create_registration_request(
        reinterpret_cast<const uint8_t*>(kPassword), strlen(kPassword),
        reg_req, reg_state);

    responder::RegistrationResponse reg_resp;
    server.create_registration_response(
        reg_req.data.data(), reg_req.data.size(),
        kAccountId, sizeof(kAccountId), reg_resp);

    initiator::RegistrationRecord reg_record;
    client.finalize_registration(
        reg_resp.data.data(), reg_resp.data.size(),
        reg_state, reg_record);

    secure_bytes rec_buf;
    BuildRecordBuffer(reg_record, rec_buf);

    responder::build_credentials(rec_buf.data(), rec_buf.size(), r.credentials);
    return r;
}

} // anonymous namespace


int main() {
    if (sodium_init() < 0) return 1;
    if (!pq::kem::init()) return 1;

    bench::print_platform_info();

    /* Pre-register for auth benchmarks */
    auto setup = do_registration();
    responder::OpaqueResponder server(setup.server_keypair);
    initiator::OpaqueInitiator client(setup.server_pk);

    /* ============================================================
     * REGISTRATION PHASE BENCHMARKS
     * ============================================================ */
    bench::print_separator("Protocol Phase: Registration (includes Argon2id)");

    bench::print_stats("Agent: create_registration_request",
        bench::run_benchmark([&] {
            initiator::InitiatorState st;
            initiator::RegistrationRequest req;
            initiator::OpaqueInitiator::create_registration_request(
                reinterpret_cast<const uint8_t*>(kPassword), strlen(kPassword),
                req, st);
        }, N_ITER, N_WARMUP));

    /* For relay side benchmark we need a valid request each time */
    bench::print_stats("Relay: create_registration_response",
        bench::run_benchmark([&] {
            initiator::InitiatorState st;
            initiator::RegistrationRequest req;
            initiator::OpaqueInitiator::create_registration_request(
                reinterpret_cast<const uint8_t*>(kPassword), strlen(kPassword),
                req, st);
            responder::RegistrationResponse resp;
            server.create_registration_response(
                req.data.data(), req.data.size(),
                kAccountId, sizeof(kAccountId), resp);
        }, N_ITER, N_WARMUP));

    bench::print_stats("Agent: finalize_registration (Argon2id!)",
        bench::run_benchmark([&] {
            initiator::InitiatorState st;
            initiator::RegistrationRequest req;
            initiator::OpaqueInitiator::create_registration_request(
                reinterpret_cast<const uint8_t*>(kPassword), strlen(kPassword),
                req, st);
            responder::RegistrationResponse resp;
            server.create_registration_response(
                req.data.data(), req.data.size(),
                kAccountId, sizeof(kAccountId), resp);
            initiator::RegistrationRecord rec;
            client.finalize_registration(
                resp.data.data(), resp.data.size(), st, rec);
        }, N_ITER_REG, N_WARMUP_REG));

    bench::print_stats("Full Registration (Agent+Relay, end-to-end)",
        bench::run_benchmark([&] {
            initiator::InitiatorState st;
            initiator::RegistrationRequest req;
            initiator::OpaqueInitiator::create_registration_request(
                reinterpret_cast<const uint8_t*>(kPassword), strlen(kPassword),
                req, st);
            responder::RegistrationResponse resp;
            server.create_registration_response(
                req.data.data(), req.data.size(),
                kAccountId, sizeof(kAccountId), resp);
            initiator::RegistrationRecord rec;
            client.finalize_registration(
                resp.data.data(), resp.data.size(), st, rec);
            secure_bytes buf;
            BuildRecordBuffer(rec, buf);
            ResponderCredentials creds;
            responder::build_credentials(buf.data(), buf.size(), creds);
        }, N_ITER_REG, N_WARMUP_REG));

    /* ============================================================
     * AUTHENTICATION PHASE BENCHMARKS
     * ============================================================ */
    bench::print_separator("Protocol Phase: Authentication (3DH + ML-KEM-768)");

    bench::print_stats("Agent: generate_ke1",
        bench::run_benchmark([&] {
            initiator::InitiatorState st;
            initiator::KE1 ke1;
            initiator::OpaqueInitiator::generate_ke1(
                reinterpret_cast<const uint8_t*>(kPassword), strlen(kPassword),
                ke1, st);
        }, N_ITER, N_WARMUP));

    /* For KE2 benchmark we need a valid KE1 each time */
    bench::print_stats("Relay: generate_ke2",
        bench::run_benchmark([&] {
            initiator::InitiatorState cst;
            initiator::KE1 ke1;
            initiator::OpaqueInitiator::generate_ke1(
                reinterpret_cast<const uint8_t*>(kPassword), strlen(kPassword),
                ke1, cst);
            secure_bytes ke1_data;
            BuildKe1Data(ke1, ke1_data);

            responder::ResponderState sst;
            responder::KE2 ke2;
            server.generate_ke2(ke1_data.data(), ke1_data.size(),
                                kAccountId, sizeof(kAccountId),
                                setup.credentials, ke2, sst);
        }, N_ITER, N_WARMUP));

    bench::print_stats("Agent: generate_ke3 (includes Argon2id!)",
        bench::run_benchmark([&] {
            initiator::InitiatorState cst;
            initiator::KE1 ke1;
            initiator::OpaqueInitiator::generate_ke1(
                reinterpret_cast<const uint8_t*>(kPassword), strlen(kPassword),
                ke1, cst);
            secure_bytes ke1_data;
            BuildKe1Data(ke1, ke1_data);

            responder::ResponderState sst;
            responder::KE2 ke2;
            server.generate_ke2(ke1_data.data(), ke1_data.size(),
                                kAccountId, sizeof(kAccountId),
                                setup.credentials, ke2, sst);
            secure_bytes ke2_data;
            BuildKe2Data(ke2, ke2_data);

            initiator::KE3 ke3;
            client.generate_ke3(ke2_data.data(), ke2_data.size(), cst, ke3);
        }, N_ITER_REG, N_WARMUP_REG));

    bench::print_stats("Relay: finish (verify KE3)",
        bench::run_benchmark([&] {
            initiator::InitiatorState cst;
            initiator::KE1 ke1;
            initiator::OpaqueInitiator::generate_ke1(
                reinterpret_cast<const uint8_t*>(kPassword), strlen(kPassword),
                ke1, cst);
            secure_bytes ke1_data;
            BuildKe1Data(ke1, ke1_data);

            responder::ResponderState sst;
            responder::KE2 ke2;
            server.generate_ke2(ke1_data.data(), ke1_data.size(),
                                kAccountId, sizeof(kAccountId),
                                setup.credentials, ke2, sst);
            secure_bytes ke2_data;
            BuildKe2Data(ke2, ke2_data);

            initiator::KE3 ke3;
            client.generate_ke3(ke2_data.data(), ke2_data.size(), cst, ke3);

            secure_bytes sk, mk;
            server.responder_finish(ke3.initiator_mac.data(), ke3.initiator_mac.size(),
                                    sst, sk, mk);
        }, N_ITER_REG, N_WARMUP_REG));

    bench::print_stats("Full Authentication (KE1+KE2+KE3+Finish, end-to-end)",
        bench::run_benchmark([&] {
            initiator::InitiatorState cst;
            initiator::KE1 ke1;
            initiator::OpaqueInitiator::generate_ke1(
                reinterpret_cast<const uint8_t*>(kPassword), strlen(kPassword),
                ke1, cst);
            secure_bytes ke1_data;
            BuildKe1Data(ke1, ke1_data);

            responder::ResponderState sst;
            responder::KE2 ke2;
            server.generate_ke2(ke1_data.data(), ke1_data.size(),
                                kAccountId, sizeof(kAccountId),
                                setup.credentials, ke2, sst);
            secure_bytes ke2_data;
            BuildKe2Data(ke2, ke2_data);

            initiator::KE3 ke3;
            client.generate_ke3(ke2_data.data(), ke2_data.size(), cst, ke3);

            secure_bytes srv_sk, srv_mk;
            server.responder_finish(ke3.initiator_mac.data(), ke3.initiator_mac.size(),
                                    sst, srv_sk, srv_mk);

            secure_bytes cli_sk, cli_mk;
            initiator::OpaqueInitiator::initiator_finish(cst, cli_sk, cli_mk);
        }, N_ITER_REG, N_WARMUP_REG));

    std::printf("\n");
    return 0;
}
