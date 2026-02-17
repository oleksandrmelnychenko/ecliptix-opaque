/**
 * @file bench_micro_primitives.cpp
 * @brief Microbenchmarks for individual cryptographic primitives.
 *
 * Measures each primitive in isolation with statistical reporting.
 * Output: Table 6.2 in the paper — "Computational Cost of Individual Operations"
 */

#include "opaque/opaque.h"
#include "opaque/pq.h"
#include "../bench_utils.h"
#include <sodium.h>
#include <cstring>

using namespace ecliptix::security::opaque;

static constexpr size_t N_ITER = 2000;
static constexpr size_t N_WARMUP = 100;
/* Argon2id is slow — use fewer iterations */
static constexpr size_t N_ITER_SLOW = 50;
static constexpr size_t N_WARMUP_SLOW = 5;

int main() {
    if (sodium_init() < 0) {
        std::fprintf(stderr, "sodium_init failed\n");
        return 1;
    }
    if (!pq::kem::init()) {
        std::fprintf(stderr, "pq::kem::init failed\n");
        return 1;
    }

    bench::print_platform_info();
    bench::print_separator("Microbenchmarks: Individual Cryptographic Primitives");

    /* Pre-generate keys and data for benchmarks */
    uint8_t scalar_a[PRIVATE_KEY_LENGTH], scalar_b[PRIVATE_KEY_LENGTH];
    uint8_t point_a[PUBLIC_KEY_LENGTH], point_b[PUBLIC_KEY_LENGTH];
    uint8_t dh_result[PUBLIC_KEY_LENGTH];
    crypto_core_ristretto255_scalar_random(scalar_a);
    crypto_core_ristretto255_scalar_random(scalar_b);
    crypto_scalarmult_ristretto255_base(point_a, scalar_a);
    crypto_scalarmult_ristretto255_base(point_b, scalar_b);

    uint8_t kem_pk[pq_constants::KEM_PUBLIC_KEY_LENGTH];
    uint8_t kem_sk[pq_constants::KEM_SECRET_KEY_LENGTH];
    uint8_t kem_ct[pq_constants::KEM_CIPHERTEXT_LENGTH];
    uint8_t kem_ss[pq_constants::KEM_SHARED_SECRET_LENGTH];
    pq::kem::keypair_generate(kem_pk, kem_sk);
    pq::kem::encapsulate(kem_pk, kem_ct, kem_ss);

    uint8_t password[] = "benchmark_password_v1";
    uint8_t blinded[PUBLIC_KEY_LENGTH], blind_scalar[PRIVATE_KEY_LENGTH];
    uint8_t evaluated[PUBLIC_KEY_LENGTH], oprf_out[crypto_hash_sha512_BYTES];
    uint8_t oprf_key[PRIVATE_KEY_LENGTH];
    crypto_core_ristretto255_scalar_random(oprf_key);
    oblivious_prf::blind(password, sizeof(password) - 1, blinded, blind_scalar);
    oblivious_prf::evaluate(blinded, oprf_key, evaluated);

    uint8_t hkdf_salt[64], hkdf_ikm[128], hkdf_prk[crypto_auth_hmacsha512_BYTES];
    uint8_t hkdf_okm[64];
    randombytes_buf(hkdf_salt, sizeof(hkdf_salt));
    randombytes_buf(hkdf_ikm, sizeof(hkdf_ikm));
    crypto::key_derivation_extract(hkdf_salt, sizeof(hkdf_salt),
                                   hkdf_ikm, sizeof(hkdf_ikm), hkdf_prk);

    uint8_t hmac_key[64], hmac_data[256], hmac_out[crypto_auth_hmacsha512_BYTES];
    randombytes_buf(hmac_key, sizeof(hmac_key));
    randombytes_buf(hmac_data, sizeof(hmac_data));

    uint8_t env_key[crypto_secretbox_KEYBYTES];
    uint8_t env_nonce[NONCE_LENGTH];
    uint8_t env_plain[64], env_cipher[64], env_tag[crypto_secretbox_MACBYTES];
    uint8_t env_decrypted[64];
    randombytes_buf(env_key, sizeof(env_key));
    randombytes_buf(env_nonce, sizeof(env_nonce));
    randombytes_buf(env_plain, sizeof(env_plain));

    /* ----- Ristretto255 ----- */
    bench::print_stats("Ristretto255: keypair (scalar_mult_base)",
        bench::run_benchmark([&] {
            uint8_t sk[PRIVATE_KEY_LENGTH], pk[PUBLIC_KEY_LENGTH];
            crypto_core_ristretto255_scalar_random(sk);
            crypto_scalarmult_ristretto255_base(pk, sk);
        }, N_ITER, N_WARMUP));

    bench::print_stats("Ristretto255: scalar_mult (single DH)",
        bench::run_benchmark([&] {
            crypto_scalarmult_ristretto255(dh_result, scalar_a, point_b);
        }, N_ITER, N_WARMUP));

    bench::print_stats("Ristretto255: 3DH (3x scalar_mult)",
        bench::run_benchmark([&] {
            uint8_t r1[32], r2[32], r3[32];
            crypto_scalarmult_ristretto255(r1, scalar_a, point_b);
            crypto_scalarmult_ristretto255(r2, scalar_a, point_a);
            crypto_scalarmult_ristretto255(r3, scalar_b, point_a);
        }, N_ITER, N_WARMUP));

    /* ----- ML-KEM-768 ----- */
    bench::print_stats("ML-KEM-768: keypair_generate",
        bench::run_benchmark([&] {
            uint8_t pk[pq_constants::KEM_PUBLIC_KEY_LENGTH];
            uint8_t sk[pq_constants::KEM_SECRET_KEY_LENGTH];
            pq::kem::keypair_generate(pk, sk);
            sodium_memzero(sk, sizeof(sk));
        }, N_ITER, N_WARMUP));

    bench::print_stats("ML-KEM-768: encapsulate",
        bench::run_benchmark([&] {
            uint8_t ct[pq_constants::KEM_CIPHERTEXT_LENGTH];
            uint8_t ss[pq_constants::KEM_SHARED_SECRET_LENGTH];
            pq::kem::encapsulate(kem_pk, ct, ss);
        }, N_ITER, N_WARMUP));

    bench::print_stats("ML-KEM-768: decapsulate",
        bench::run_benchmark([&] {
            uint8_t ss[pq_constants::KEM_SHARED_SECRET_LENGTH];
            pq::kem::decapsulate(kem_sk, kem_ct, ss);
        }, N_ITER, N_WARMUP));

    bench::print_stats("ML-KEM-768: full round (keygen+encaps+decaps)",
        bench::run_benchmark([&] {
            uint8_t pk[pq_constants::KEM_PUBLIC_KEY_LENGTH];
            uint8_t sk[pq_constants::KEM_SECRET_KEY_LENGTH];
            uint8_t ct[pq_constants::KEM_CIPHERTEXT_LENGTH];
            uint8_t ss1[pq_constants::KEM_SHARED_SECRET_LENGTH];
            uint8_t ss2[pq_constants::KEM_SHARED_SECRET_LENGTH];
            pq::kem::keypair_generate(pk, sk);
            pq::kem::encapsulate(pk, ct, ss1);
            pq::kem::decapsulate(sk, ct, ss2);
            sodium_memzero(sk, sizeof(sk));
        }, N_ITER, N_WARMUP));

    /* ----- OPRF ----- */
    bench::print_stats("OPRF: blind",
        bench::run_benchmark([&] {
            uint8_t bl[PUBLIC_KEY_LENGTH], sc[PRIVATE_KEY_LENGTH];
            oblivious_prf::blind(password, sizeof(password) - 1, bl, sc);
        }, N_ITER, N_WARMUP));

    bench::print_stats("OPRF: evaluate",
        bench::run_benchmark([&] {
            uint8_t ev[PUBLIC_KEY_LENGTH];
            oblivious_prf::evaluate(blinded, oprf_key, ev);
        }, N_ITER, N_WARMUP));

    bench::print_stats("OPRF: finalize",
        bench::run_benchmark([&] {
            uint8_t out[crypto_hash_sha512_BYTES];
            oblivious_prf::finalize(password, sizeof(password) - 1,
                                    blind_scalar, evaluated, out);
        }, N_ITER, N_WARMUP));

    /* ----- HKDF ----- */
    bench::print_stats("HKDF-Extract (HMAC-SHA-512)",
        bench::run_benchmark([&] {
            uint8_t prk[crypto_auth_hmacsha512_BYTES];
            crypto::key_derivation_extract(hkdf_salt, sizeof(hkdf_salt),
                                           hkdf_ikm, sizeof(hkdf_ikm), prk);
        }, N_ITER, N_WARMUP));

    bench::print_stats("HKDF-Expand (64 bytes output)",
        bench::run_benchmark([&] {
            uint8_t okm[64];
            crypto::key_derivation_expand(hkdf_prk, sizeof(hkdf_prk),
                                          hkdf_salt, 32, okm, sizeof(okm));
        }, N_ITER, N_WARMUP));

    /* ----- HMAC ----- */
    bench::print_stats("HMAC-SHA-512 (256-byte message)",
        bench::run_benchmark([&] {
            uint8_t mac[crypto_auth_hmacsha512_BYTES];
            crypto::hmac(hmac_key, sizeof(hmac_key),
                         hmac_data, sizeof(hmac_data), mac);
        }, N_ITER, N_WARMUP));

    /* ----- Authenticated Encryption ----- */
    bench::print_stats("XChaCha20-Poly1305: encrypt (64 bytes)",
        bench::run_benchmark([&] {
            crypto::encrypt_envelope(env_key, sizeof(env_key),
                                     env_plain, sizeof(env_plain),
                                     env_nonce, env_cipher, env_tag);
        }, N_ITER, N_WARMUP));

    bench::print_stats("XChaCha20-Poly1305: decrypt (64 bytes)",
        bench::run_benchmark([&] {
            crypto::decrypt_envelope(env_key, sizeof(env_key),
                                     env_cipher, sizeof(env_cipher),
                                     env_nonce, env_tag, env_decrypted);
        }, N_ITER, N_WARMUP));

    /* ----- Argon2id (SLOW — dominates registration) ----- */
    bench::print_stats("Argon2id (MODERATE params)",
        bench::run_benchmark([&] {
            uint8_t oprf_dummy[crypto_hash_sha512_BYTES];
            randombytes_buf(oprf_dummy, sizeof(oprf_dummy));
            uint8_t rwd[crypto_hash_sha512_BYTES];
            crypto::derive_randomized_password(oprf_dummy, sizeof(oprf_dummy),
                                               password, sizeof(password) - 1,
                                               rwd, sizeof(rwd));
        }, N_ITER_SLOW, N_WARMUP_SLOW));

    /* ----- Hybrid Key Combiner ----- */
    {
        uint8_t cikm[96], pqss[pq_constants::KEM_SHARED_SECRET_LENGTH];
        uint8_t th[crypto_hash_sha512_BYTES];
        randombytes_buf(cikm, sizeof(cikm));
        randombytes_buf(pqss, sizeof(pqss));
        randombytes_buf(th, sizeof(th));

        bench::print_stats("PQ Hybrid Combiner (HKDF-Extract with labeled salt)",
            bench::run_benchmark([&] {
                uint8_t prk[crypto_auth_hmacsha512_BYTES];
                pq::combine_key_material(cikm, sizeof(cikm),
                                         pqss, sizeof(pqss),
                                         th, sizeof(th), prk);
            }, N_ITER, N_WARMUP));
    }

    std::printf("\n");
    return 0;
}
