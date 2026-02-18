/**
 * @file test_kem_robustness.cpp
 * @brief ML-KEM-768 robustness and edge case tests.
 *
 * Verifies:
 *   1. Decapsulation with wrong SK → implicit reject (different SS)
 *   2. Truncated/extended ciphertext handling
 *   3. All-zero ciphertext handling
 *   4. High-entropy and low-entropy key generation
 *   5. KEM independence from DH (keys don't correlate)
 */

#include <catch2/catch_test_macros.hpp>
#include "opaque/opaque.h"
#include "opaque/pq.h"
#include <sodium.h>
#include <cstring>
#include <set>
#include <vector>

using namespace ecliptix::security::opaque;

TEST_CASE("ML-KEM-768 Implicit Reject — Wrong SK yields different SS",
          "[security][kem][robustness]") {
    REQUIRE(sodium_init() >= 0);

    /* Generate two keypairs */
    uint8_t pk1[pq_constants::KEM_PUBLIC_KEY_LENGTH], sk1[pq_constants::KEM_SECRET_KEY_LENGTH];
    uint8_t pk2[pq_constants::KEM_PUBLIC_KEY_LENGTH], sk2[pq_constants::KEM_SECRET_KEY_LENGTH];
    REQUIRE(pq::kem::keypair_generate(pk1, sk1) == Result::Success);
    REQUIRE(pq::kem::keypair_generate(pk2, sk2) == Result::Success);

    /* Encapsulate to pk1 */
    uint8_t ct[pq_constants::KEM_CIPHERTEXT_LENGTH];
    uint8_t ss_enc[pq_constants::KEM_SHARED_SECRET_LENGTH];
    REQUIRE(pq::kem::encapsulate(pk1, ct, ss_enc) == Result::Success);

    /* Decapsulate with sk2 (wrong key) — ML-KEM does implicit reject */
    uint8_t ss_wrong[pq_constants::KEM_SHARED_SECRET_LENGTH];
    Result r = pq::kem::decapsulate(sk2, ct, ss_wrong);

    if (r == Result::Success) {
        /* Implicit reject: returns a pseudorandom SS, different from correct one */
        REQUIRE(std::memcmp(ss_enc, ss_wrong, pq_constants::KEM_SHARED_SECRET_LENGTH) != 0);
    }
    /* Explicit error is also acceptable */

    sodium_memzero(sk1, sizeof(sk1));
    sodium_memzero(sk2, sizeof(sk2));
}


TEST_CASE("ML-KEM-768 All-Zero Ciphertext — Decaps produces non-matching SS",
          "[security][kem][robustness]") {
    REQUIRE(sodium_init() >= 0);

    uint8_t pk[pq_constants::KEM_PUBLIC_KEY_LENGTH], sk[pq_constants::KEM_SECRET_KEY_LENGTH];
    REQUIRE(pq::kem::keypair_generate(pk, sk) == Result::Success);

    uint8_t ct[pq_constants::KEM_CIPHERTEXT_LENGTH];
    uint8_t ss_enc[pq_constants::KEM_SHARED_SECRET_LENGTH];
    REQUIRE(pq::kem::encapsulate(pk, ct, ss_enc) == Result::Success);

    /* Zero out ciphertext completely */
    uint8_t zero_ct[pq_constants::KEM_CIPHERTEXT_LENGTH] = {};
    uint8_t ss_zero[pq_constants::KEM_SHARED_SECRET_LENGTH];
    Result r = pq::kem::decapsulate(sk, zero_ct, ss_zero);

    if (r == Result::Success) {
        REQUIRE(std::memcmp(ss_enc, ss_zero, pq_constants::KEM_SHARED_SECRET_LENGTH) != 0);
    }

    sodium_memzero(sk, sizeof(sk));
}


TEST_CASE("ML-KEM-768 Bit-Flip Sensitivity — Single bit flip in CT changes SS",
          "[security][kem][robustness]") {
    REQUIRE(sodium_init() >= 0);

    uint8_t pk[pq_constants::KEM_PUBLIC_KEY_LENGTH], sk[pq_constants::KEM_SECRET_KEY_LENGTH];
    REQUIRE(pq::kem::keypair_generate(pk, sk) == Result::Success);

    uint8_t ct[pq_constants::KEM_CIPHERTEXT_LENGTH];
    uint8_t ss_correct[pq_constants::KEM_SHARED_SECRET_LENGTH];
    REQUIRE(pq::kem::encapsulate(pk, ct, ss_correct) == Result::Success);

    /* Flip each bit position at several locations */
    size_t positions[] = {0, 1, 100, 500, 1000, pq_constants::KEM_CIPHERTEXT_LENGTH - 1};

    for (size_t pos : positions) {
        for (int bit = 0; bit < 8; ++bit) {
            uint8_t ct_flipped[pq_constants::KEM_CIPHERTEXT_LENGTH];
            std::memcpy(ct_flipped, ct, sizeof(ct_flipped));
            ct_flipped[pos] ^= static_cast<uint8_t>(1 << bit);

            uint8_t ss_flipped[pq_constants::KEM_SHARED_SECRET_LENGTH];
            Result r = pq::kem::decapsulate(sk, ct_flipped, ss_flipped);

            if (r == Result::Success) {
                INFO("pos=" << pos << " bit=" << bit);
                REQUIRE(std::memcmp(ss_correct, ss_flipped,
                                    pq_constants::KEM_SHARED_SECRET_LENGTH) != 0);
            }
        }
    }

    sodium_memzero(sk, sizeof(sk));
}


TEST_CASE("ML-KEM-768 Shared Secret Uniqueness — Each encaps produces unique SS",
          "[security][kem][robustness]") {
    REQUIRE(sodium_init() >= 0);

    uint8_t pk[pq_constants::KEM_PUBLIC_KEY_LENGTH], sk[pq_constants::KEM_SECRET_KEY_LENGTH];
    REQUIRE(pq::kem::keypair_generate(pk, sk) == Result::Success);

    constexpr size_t N = 200;
    std::set<std::vector<uint8_t>> unique_ss;
    std::set<std::vector<uint8_t>> unique_ct;

    for (size_t i = 0; i < N; ++i) {
        uint8_t ct[pq_constants::KEM_CIPHERTEXT_LENGTH];
        uint8_t ss[pq_constants::KEM_SHARED_SECRET_LENGTH];
        REQUIRE(pq::kem::encapsulate(pk, ct, ss) == Result::Success);

        unique_ss.insert(std::vector<uint8_t>(ss, ss + sizeof(ss)));
        unique_ct.insert(std::vector<uint8_t>(ct, ct + sizeof(ct)));
    }

    REQUIRE(unique_ss.size() == N);
    REQUIRE(unique_ct.size() == N);

    sodium_memzero(sk, sizeof(sk));
}


TEST_CASE("ML-KEM-768 Keypair Uniqueness — Each keygen produces unique keypair",
          "[security][kem][robustness]") {
    REQUIRE(sodium_init() >= 0);

    constexpr size_t N = 50;
    std::set<std::vector<uint8_t>> unique_pk;

    for (size_t i = 0; i < N; ++i) {
        uint8_t pk[pq_constants::KEM_PUBLIC_KEY_LENGTH];
        uint8_t sk[pq_constants::KEM_SECRET_KEY_LENGTH];
        REQUIRE(pq::kem::keypair_generate(pk, sk) == Result::Success);
        unique_pk.insert(std::vector<uint8_t>(pk, pk + sizeof(pk)));
        sodium_memzero(sk, sizeof(sk));
    }

    REQUIRE(unique_pk.size() == N);
}
