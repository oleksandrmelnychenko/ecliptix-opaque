/**
 * @file bench_wire_overhead.cpp
 * @brief Communication overhead measurement — exact wire sizes of all protocol messages.
 *
 * Measures and reports the byte size of every message exchanged during
 * registration and authentication, calculates PQ overhead vs hypothetical
 * classic OPAQUE (without ML-KEM), and provides total bandwidth per flow.
 *
 * Output: Table 5.1 in the paper — "Communication Overhead Analysis"
 */

#include "opaque/opaque.h"
#include "opaque/initiator.h"
#include "opaque/responder.h"
#include "opaque/protocol.h"
#include "opaque/pq.h"
#include "../bench_utils.h"
#include <sodium.h>
#include <cstdio>
#include <cstring>

using namespace ecliptix::security::opaque;

static constexpr char kPassword[] = "overhead_test_password";
static constexpr uint8_t kAccountId[16] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
};

namespace {

void print_size_row(const char* name, size_t bytes, const char* direction) {
    std::printf("  %-45s  %6zu bytes   %s\n", name, bytes, direction);
}

void print_field_row(const char* name, size_t bytes) {
    std::printf("    |- %-41s  %6zu bytes\n", name, bytes);
}

void print_comparison_row(const char* name, size_t classic, size_t hybrid, const char* direction) {
    long diff = static_cast<long>(hybrid) - static_cast<long>(classic);
    double pct = classic > 0 ? (static_cast<double>(diff) / static_cast<double>(classic)) * 100.0 : 0.0;
    std::printf("  %-30s  %6zu  ->  %6zu   (%+ld, %+.1f%%)   %s\n",
                name, classic, hybrid, diff, pct, direction);
}

} // anonymous namespace

int main() {
    if (sodium_init() < 0) return 1;

    bench::print_platform_info();

    /* ================================================================
     * SECTION 1: Message Structure Breakdown
     * ================================================================ */
    std::printf("=== Wire Format: Message Structure Breakdown ===\n\n");

    /* --- Registration --- */
    std::printf("--- Registration Phase ---\n");

    print_size_row("RegistrationRequest", REGISTRATION_REQUEST_LENGTH, "Agent -> Relay");
    print_field_row("blinded_element (Ristretto255)", crypto_core_ristretto255_BYTES);

    print_size_row("RegistrationResponse", REGISTRATION_RESPONSE_LENGTH, "Relay -> Agent");
    print_field_row("evaluated_element (Ristretto255)", crypto_core_ristretto255_BYTES);
    print_field_row("server_public_key (Ristretto255)", PUBLIC_KEY_LENGTH);

    print_size_row("RegistrationRecord (stored)", REGISTRATION_RECORD_LENGTH, "Agent -> Relay");
    print_field_row("envelope (nonce+ct+tag)", ENVELOPE_LENGTH);
    print_field_row("  |- nonce", NONCE_LENGTH);
    size_t env_ct = ENVELOPE_LENGTH - NONCE_LENGTH - crypto_secretbox_MACBYTES;
    print_field_row("  |- ciphertext", env_ct);
    print_field_row("  |- auth_tag", crypto_secretbox_MACBYTES);
    print_field_row("initiator_public_key", PUBLIC_KEY_LENGTH);

    size_t reg_agent_to_relay = REGISTRATION_REQUEST_LENGTH + REGISTRATION_RECORD_LENGTH;
    size_t reg_relay_to_agent = REGISTRATION_RESPONSE_LENGTH;
    size_t reg_total = reg_agent_to_relay + reg_relay_to_agent;

    std::printf("\n  Registration totals:\n");
    std::printf("    Agent -> Relay:   %zu bytes\n", reg_agent_to_relay);
    std::printf("    Relay -> Agent:   %zu bytes\n", reg_relay_to_agent);
    std::printf("    Total:            %zu bytes\n", reg_total);

    /* --- Authentication --- */
    std::printf("\n--- Authentication Phase (Hybrid PQ-OPAQUE) ---\n");

    print_size_row("KE1", KE1_LENGTH, "Agent -> Relay");
    print_field_row("credential_request (blinded)", REGISTRATION_REQUEST_LENGTH);
    print_field_row("initiator_ephemeral_public_key", PUBLIC_KEY_LENGTH);
    print_field_row("initiator_nonce", NONCE_LENGTH);
    print_field_row("pq_ephemeral_public_key (ML-KEM-768)", pq_constants::KEM_PUBLIC_KEY_LENGTH);

    print_size_row("KE2", KE2_LENGTH, "Relay -> Agent");
    print_field_row("responder_nonce", NONCE_LENGTH);
    print_field_row("responder_ephemeral_public_key", PUBLIC_KEY_LENGTH);
    print_field_row("credential_response", CREDENTIAL_RESPONSE_LENGTH);
    print_field_row("  |- evaluated_element", crypto_core_ristretto255_BYTES);
    print_field_row("  |- envelope", ENVELOPE_LENGTH);
    print_field_row("responder_mac (HMAC-SHA-512)", MAC_LENGTH);
    print_field_row("kem_ciphertext (ML-KEM-768)", pq_constants::KEM_CIPHERTEXT_LENGTH);

    print_size_row("KE3", KE3_LENGTH, "Agent -> Relay");
    print_field_row("initiator_mac (HMAC-SHA-512)", MAC_LENGTH);

    size_t auth_agent_to_relay = KE1_LENGTH + KE3_LENGTH;
    size_t auth_relay_to_agent = KE2_LENGTH;
    size_t auth_total = auth_agent_to_relay + auth_relay_to_agent;

    std::printf("\n  Authentication totals:\n");
    std::printf("    Agent -> Relay:   %zu bytes (KE1 + KE3)\n", auth_agent_to_relay);
    std::printf("    Relay -> Agent:   %zu bytes (KE2)\n", auth_relay_to_agent);
    std::printf("    Total:            %zu bytes (3 messages)\n", auth_total);

    /* ================================================================
     * SECTION 2: Classic vs Hybrid Comparison
     * ================================================================ */
    std::printf("\n\n=== Classic OPAQUE vs Hybrid PQ-OPAQUE Comparison ===\n\n");

    /* Classic OPAQUE (no KEM): KE1 has no pq_ephemeral_public_key, KE2 has no kem_ciphertext */
    size_t classic_ke1 = REGISTRATION_REQUEST_LENGTH + PUBLIC_KEY_LENGTH + NONCE_LENGTH;
    /* KE1_LENGTH = classic_ke1 + KEM_PUBLIC_KEY_LENGTH */
    size_t hybrid_ke1 = KE1_LENGTH;

    size_t classic_ke2 = NONCE_LENGTH + PUBLIC_KEY_LENGTH + CREDENTIAL_RESPONSE_LENGTH + MAC_LENGTH;
    size_t hybrid_ke2 = KE2_LENGTH;

    size_t classic_ke3 = KE3_LENGTH; /* same — just MAC */
    size_t hybrid_ke3 = KE3_LENGTH;

    size_t classic_auth_total = classic_ke1 + classic_ke2 + classic_ke3;
    size_t hybrid_auth_total = hybrid_ke1 + hybrid_ke2 + hybrid_ke3;

    std::printf("  %-30s  %6s  %8s   %12s   %s\n",
                "Message", "Classic", "Hybrid", "Overhead", "Direction");
    std::printf("  %s\n", std::string(90, '-').c_str());

    print_comparison_row("KE1", classic_ke1, hybrid_ke1, "Agent -> Relay");
    print_comparison_row("KE2", classic_ke2, hybrid_ke2, "Relay -> Agent");
    print_comparison_row("KE3", classic_ke3, hybrid_ke3, "Agent -> Relay");
    std::printf("  %s\n", std::string(90, '-').c_str());
    print_comparison_row("Total Authentication", classic_auth_total, hybrid_auth_total, "round-trip");

    size_t pq_overhead = hybrid_auth_total - classic_auth_total;
    double pq_overhead_pct = static_cast<double>(pq_overhead) / static_cast<double>(classic_auth_total) * 100.0;

    std::printf("\n  PQ Overhead Breakdown:\n");
    std::printf("    KE1: +%zu bytes (ML-KEM-768 public key: %zu bytes)\n",
                hybrid_ke1 - classic_ke1, pq_constants::KEM_PUBLIC_KEY_LENGTH);
    std::printf("    KE2: +%zu bytes (ML-KEM-768 ciphertext: %zu bytes)\n",
                hybrid_ke2 - classic_ke2, pq_constants::KEM_CIPHERTEXT_LENGTH);
    std::printf("    KE3: +%zu bytes (no change)\n", hybrid_ke3 - classic_ke3);
    std::printf("    Total PQ overhead: %zu bytes (+%.1f%%)\n", pq_overhead, pq_overhead_pct);

    /* ================================================================
     * SECTION 3: Constant Sizes Verification
     * ================================================================ */
    std::printf("\n\n=== Size Constants Verification ===\n\n");

    struct SizeCheck {
        const char* name;
        size_t expected;
        size_t actual;
    };

    SizeCheck checks[] = {
        {"PRIVATE_KEY_LENGTH",             32, PRIVATE_KEY_LENGTH},
        {"PUBLIC_KEY_LENGTH",              32, PUBLIC_KEY_LENGTH},
        {"NONCE_LENGTH",                   24, NONCE_LENGTH},
        {"MAC_LENGTH",                     64, MAC_LENGTH},
        {"HASH_LENGTH",                    64, HASH_LENGTH},
        {"KEM_PUBLIC_KEY_LENGTH",        1184, pq_constants::KEM_PUBLIC_KEY_LENGTH},
        {"KEM_SECRET_KEY_LENGTH",        2400, pq_constants::KEM_SECRET_KEY_LENGTH},
        {"KEM_CIPHERTEXT_LENGTH",        1088, pq_constants::KEM_CIPHERTEXT_LENGTH},
        {"KEM_SHARED_SECRET_LENGTH",       32, pq_constants::KEM_SHARED_SECRET_LENGTH},
        {"KE1_LENGTH",            KE1_LENGTH, REGISTRATION_REQUEST_LENGTH + PUBLIC_KEY_LENGTH + NONCE_LENGTH + pq_constants::KEM_PUBLIC_KEY_LENGTH},
        {"KE2_LENGTH",            KE2_LENGTH, NONCE_LENGTH + PUBLIC_KEY_LENGTH + CREDENTIAL_RESPONSE_LENGTH + MAC_LENGTH + pq_constants::KEM_CIPHERTEXT_LENGTH},
        {"KE3_LENGTH",            KE3_LENGTH, MAC_LENGTH},
    };

    bool all_ok = true;
    for (const auto& c : checks) {
        bool ok = (c.expected == c.actual);
        std::printf("  %-30s  expected=%5zu  actual=%5zu  %s\n",
                    c.name, c.expected, c.actual, ok ? "OK" : "MISMATCH!");
        if (!ok) all_ok = false;
    }

    std::printf("\n  All constants: %s\n", all_ok ? "PASS" : "FAIL");

    /* ================================================================
     * SECTION 4: Credential Storage Overhead
     * ================================================================ */
    std::printf("\n\n=== Server-Side Storage (per user) ===\n\n");

    size_t cred_storage = RESPONDER_CREDENTIALS_LENGTH;
    std::printf("  ResponderCredentials:  %zu bytes\n", cred_storage);
    print_field_row("envelope", ENVELOPE_LENGTH);
    print_field_row("initiator_public_key", PUBLIC_KEY_LENGTH);
    std::printf("  (OPRF key derived from server_private_key + account_id, not stored)\n");

    std::printf("\n  Storage for 1M users: %.2f MB\n",
                static_cast<double>(cred_storage) * 1000000.0 / (1024.0 * 1024.0));
    std::printf("  Storage for 10M users: %.2f MB\n",
                static_cast<double>(cred_storage) * 10000000.0 / (1024.0 * 1024.0));

    /* ================================================================
     * SECTION 5: Summary Table (paper-ready)
     * ================================================================ */
    std::printf("\n\n=== Summary Table (Paper-Ready) ===\n\n");
    std::printf("  +---------------------+----------+----------+----------+\n");
    std::printf("  | Message             | Classic  | Hybrid   | Overhead |\n");
    std::printf("  +---------------------+----------+----------+----------+\n");
    std::printf("  | KE1 (Agent->Relay)  | %5zu B  | %5zu B  | +%4zu B  |\n",
                classic_ke1, hybrid_ke1, hybrid_ke1 - classic_ke1);
    std::printf("  | KE2 (Relay->Agent)  | %5zu B  | %5zu B  | +%4zu B  |\n",
                classic_ke2, hybrid_ke2, hybrid_ke2 - classic_ke2);
    std::printf("  | KE3 (Agent->Relay)  | %5zu B  | %5zu B  | +%4zu B  |\n",
                classic_ke3, hybrid_ke3, hybrid_ke3 - classic_ke3);
    std::printf("  +---------------------+----------+----------+----------+\n");
    std::printf("  | Total               | %5zu B  | %5zu B  | +%4zu B  |\n",
                classic_auth_total, hybrid_auth_total, pq_overhead);
    std::printf("  +---------------------+----------+----------+----------+\n");
    std::printf("  | Overhead %%          |          |          | +%.1f%%  |\n", pq_overhead_pct);
    std::printf("  +---------------------+----------+----------+----------+\n");

    std::printf("\n");
    return 0;
}
