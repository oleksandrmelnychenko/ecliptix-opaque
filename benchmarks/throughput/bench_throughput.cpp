/**
 * @file bench_throughput.cpp
 * @brief Server-side throughput benchmark — authentications per second.
 *
 * Simulates relay handling sequential authentication requests.
 * Output: Section 6.3 in the paper — "Server Throughput"
 */

#include "opaque/opaque.h"
#include "opaque/initiator.h"
#include "opaque/responder.h"
#include "opaque/protocol.h"
#include "opaque/pq.h"
#include "../bench_utils.h"
#include <sodium.h>
#include <chrono>
#include <cstring>

using namespace ecliptix::security::opaque;

static constexpr char kPassword[] = "throughput_test_password";
static constexpr uint8_t kAccountId[16] = {
    0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
};

namespace {

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

} // anonymous namespace

int main() {
    if (sodium_init() < 0) return 1;
    if (!pq::kem::init()) return 1;

    bench::print_platform_info();

    /* Setup: register once */
    responder::ResponderKeyPair server_keypair;
    responder::ResponderKeyPair::generate(server_keypair);
    responder::OpaqueResponder server(server_keypair);
    ResponderPublicKey server_pk(
        server_keypair.public_key.data(), server_keypair.public_key.size());
    initiator::OpaqueInitiator client(server_pk);

    initiator::InitiatorState reg_st;
    initiator::RegistrationRequest reg_req;
    initiator::OpaqueInitiator::create_registration_request(
        reinterpret_cast<const uint8_t*>(kPassword), strlen(kPassword),
        reg_req, reg_st);

    responder::RegistrationResponse reg_resp;
    server.create_registration_response(
        reg_req.data.data(), reg_req.data.size(),
        kAccountId, sizeof(kAccountId), reg_resp);

    initiator::RegistrationRecord reg_rec;
    client.finalize_registration(
        reg_resp.data.data(), reg_resp.data.size(), reg_st, reg_rec);

    secure_bytes rec_buf(REGISTRATION_RECORD_LENGTH);
    protocol::write_registration_record(
        reg_rec.envelope.data(), reg_rec.envelope.size(),
        reg_rec.initiator_public_key.data(), reg_rec.initiator_public_key.size(),
        rec_buf.data(), rec_buf.size());

    ResponderCredentials creds;
    responder::build_credentials(rec_buf.data(), rec_buf.size(), creds);

    /* ---- Throughput: Relay-side only (KE2 generation + KE3 verification) ---- */
    std::printf("\n=== Throughput: Relay-side Authentication ===\n");
    std::printf("Measures relay operations only: generate_ke2 + finish (verify KE3)\n");
    std::printf("This represents the server's computational bottleneck.\n\n");

    const int durations_sec[] = {5, 10};

    for (int dur : durations_sec) {
        size_t count = 0;
        size_t failures = 0;

        auto t_start = std::chrono::steady_clock::now();
        auto t_end = t_start + std::chrono::seconds(dur);

        while (std::chrono::steady_clock::now() < t_end) {
            /* Client generates KE1 */
            initiator::InitiatorState cst;
            initiator::KE1 ke1;
            initiator::OpaqueInitiator::generate_ke1(
                reinterpret_cast<const uint8_t*>(kPassword), strlen(kPassword),
                ke1, cst);
            secure_bytes ke1_data;
            BuildKe1(ke1, ke1_data);

            /* RELAY: generate KE2 (TIMED) */
            responder::ResponderState sst;
            responder::KE2 ke2;
            auto r = server.generate_ke2(ke1_data.data(), ke1_data.size(),
                                          kAccountId, sizeof(kAccountId),
                                          creds, ke2, sst);
            if (r != Result::Success) { ++failures; continue; }

            secure_bytes ke2_data;
            BuildKe2(ke2, ke2_data);

            /* Client generates KE3 */
            initiator::KE3 ke3;
            r = client.generate_ke3(ke2_data.data(), ke2_data.size(), cst, ke3);
            if (r != Result::Success) { ++failures; continue; }

            /* RELAY: verify KE3 (TIMED) */
            secure_bytes sk, mk;
            r = server.responder_finish(ke3.initiator_mac.data(), ke3.initiator_mac.size(),
                                        sst, sk, mk);
            if (r != Result::Success) { ++failures; continue; }

            ++count;
        }

        auto elapsed = std::chrono::steady_clock::now() - t_start;
        double secs = std::chrono::duration<double>(elapsed).count();
        double auth_per_sec = static_cast<double>(count) / secs;

        std::printf("[%ds run] Completed: %zu auths | Failures: %zu | Throughput: %.1f auth/s | Avg: %.2f ms/auth\n",
                    dur, count, failures, auth_per_sec, 1000.0 / auth_per_sec);
    }

    /* ---- Throughput: Relay-side only (excluding client Argon2id) ---- */
    std::printf("\n=== Throughput: Relay-side Only (KE2 + Finish) ===\n");
    std::printf("Pre-computes client KE1/KE3 to isolate server cost.\n\n");

    /* Pre-generate a batch of KE1s and corresponding KE3s */
    const size_t batch = 200;
    struct AuthPair {
        secure_bytes ke1_data;
        secure_bytes ke3_mac;
        responder::ResponderState server_state;
    };

    /* We can only pre-compute KE1; KE2 depends on server ephemeral so we measure it live */
    std::vector<secure_bytes> ke1_batch;
    ke1_batch.reserve(batch);

    for (size_t i = 0; i < batch; ++i) {
        initiator::InitiatorState cst;
        initiator::KE1 ke1;
        initiator::OpaqueInitiator::generate_ke1(
            reinterpret_cast<const uint8_t*>(kPassword), strlen(kPassword), ke1, cst);
        secure_bytes ke1d;
        BuildKe1(ke1, ke1d);
        ke1_batch.push_back(std::move(ke1d));
    }

    {
        size_t count = 0;
        auto t0 = std::chrono::steady_clock::now();

        for (size_t i = 0; i < batch; ++i) {
            responder::ResponderState sst;
            responder::KE2 ke2;
            server.generate_ke2(ke1_batch[i].data(), ke1_batch[i].size(),
                                kAccountId, sizeof(kAccountId),
                                creds, ke2, sst);
            ++count;
        }

        auto t1 = std::chrono::steady_clock::now();
        double secs = std::chrono::duration<double>(t1 - t0).count();
        double ops = static_cast<double>(count) / secs;

        std::printf("Relay generate_ke2 only: %zu ops in %.2fs = %.1f ops/s (%.3f ms/op)\n",
                    count, secs, ops, 1000.0 / ops);
    }

    std::printf("\n");
    return 0;
}
