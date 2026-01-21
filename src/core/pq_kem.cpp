#include "opaque/pq.h"
#include "opaque/debug_log.h"
#include <sodium.h>
#include <oqs/oqs.h>
#include <algorithm>
#include <mutex>
#include <memory>

namespace ecliptix::security::opaque::pq {

namespace kem {

namespace {
    std::once_flag init_flag;
    bool init_success = false;

    struct KemCtxDeleter {
        void operator()(OQS_KEM* ctx) const noexcept {
            OQS_KEM_free(ctx);
        }
    };

    OQS_KEM* get_kem_ctx() {
        thread_local std::unique_ptr<OQS_KEM, KemCtxDeleter> kem_ctx{OQS_KEM_new(OQS_KEM_alg_ml_kem_768)};
        if (!kem_ctx) {
            log::msg("get_kem_ctx: OQS_KEM_new returned nullptr");
            log::msg("Checking if ML-KEM-768 is enabled...");
            if (OQS_KEM_alg_is_enabled(OQS_KEM_alg_ml_kem_768)) {
                log::msg("ML-KEM-768 IS enabled in liboqs");
            } else {
                log::msg("ML-KEM-768 is NOT enabled in liboqs build");
            }
        }
        return kem_ctx.get();
    }
}

bool init() {
    std::call_once(init_flag, [] {
        OQS_init();

        if (sodium_init() == -1) {
            init_success = false;
            return;
        }

        init_success = true;
    });
    return init_success;
}

Result keypair_generate(uint8_t* public_key, uint8_t* secret_key) {
    log::section("PQ-KEM: Generate ML-KEM-768 Keypair");

    if (!public_key || !secret_key) [[unlikely]] {
        return Result::InvalidInput;
    }

    if (!init()) {
        return Result::CryptoError;
    }

    OQS_KEM* kem_ctx = get_kem_ctx();
    if (!kem_ctx) [[unlikely]] {
        log::msg("ERROR: Failed to create ML-KEM-768 context");
        return Result::CryptoError;
    }

    OQS_STATUS status = OQS_KEM_keypair(kem_ctx, public_key, secret_key);

    if (status != OQS_SUCCESS) [[unlikely]] {

        sodium_memzero(public_key, KEM_PUBLIC_KEY_LENGTH);
        sodium_memzero(secret_key, KEM_SECRET_KEY_LENGTH);
        log::msg("ERROR: ML-KEM keypair generation failed");
        return Result::CryptoError;
    }

    log::hex("kem_public_key", public_key, KEM_PUBLIC_KEY_LENGTH);
    log::msg("ML-KEM-768 keypair generated successfully");

    return Result::Success;
}

Result encapsulate(
    const uint8_t* public_key,
    uint8_t* ciphertext,
    uint8_t* shared_secret
) {
    log::section("PQ-KEM: Encapsulate (Server side)");

    if (!public_key || !ciphertext || !shared_secret) [[unlikely]] {
        return Result::InvalidInput;
    }

    if (!init()) {
        return Result::CryptoError;
    }

    OQS_KEM* kem_ctx = get_kem_ctx();
    if (!kem_ctx) [[unlikely]] {
        log::msg("ERROR: Failed to create ML-KEM-768 context");
        return Result::CryptoError;
    }

    OQS_STATUS status = OQS_KEM_encaps(kem_ctx, ciphertext, shared_secret, public_key);

    if (status != OQS_SUCCESS) [[unlikely]] {
        sodium_memzero(ciphertext, KEM_CIPHERTEXT_LENGTH);
        sodium_memzero(shared_secret, KEM_SHARED_SECRET_LENGTH);
        log::msg("ERROR: ML-KEM encapsulation failed");
        return Result::CryptoError;
    }

    log::hex("kem_ciphertext", ciphertext, KEM_CIPHERTEXT_LENGTH);
    log::hex("kem_shared_secret (server)", shared_secret, KEM_SHARED_SECRET_LENGTH);

    return Result::Success;
}

Result decapsulate(
    const uint8_t* secret_key,
    const uint8_t* ciphertext,
    uint8_t* shared_secret
) {
    log::section("PQ-KEM: Decapsulate (Client side)");

    if (!secret_key || !ciphertext || !shared_secret) [[unlikely]] {
        return Result::InvalidInput;
    }

    if (!init()) {
        return Result::CryptoError;
    }

    OQS_KEM* kem_ctx = get_kem_ctx();
    if (!kem_ctx) [[unlikely]] {
        log::msg("ERROR: Failed to create ML-KEM-768 context");
        return Result::CryptoError;
    }

    OQS_STATUS status = OQS_KEM_decaps(kem_ctx, shared_secret, ciphertext, secret_key);

    if (status != OQS_SUCCESS) [[unlikely]] {
        sodium_memzero(shared_secret, KEM_SHARED_SECRET_LENGTH);
        log::msg("ERROR: ML-KEM decapsulation failed");
        return Result::CryptoError;
    }

    log::hex("kem_shared_secret (client)", shared_secret, KEM_SHARED_SECRET_LENGTH);

    return Result::Success;
}

}

Result combine_key_material(
    const uint8_t* classical_ikm,
    size_t classical_ikm_length,
    const uint8_t* pq_shared_secret,
    size_t pq_ss_length,
    const uint8_t* transcript_hash,
    size_t transcript_length,
    uint8_t* prk
) {
    log::section("PQ: Combine Classical + Post-Quantum Key Material");

    if (!classical_ikm || classical_ikm_length != 96 ||
        !pq_shared_secret || pq_ss_length != KEM_SHARED_SECRET_LENGTH ||
        !transcript_hash || transcript_length != crypto_hash_sha512_BYTES ||
        !prk) [[unlikely]] {
        return Result::InvalidInput;
    }

    secure_bytes combined_ikm(COMBINED_IKM_LENGTH);

    std::copy_n(classical_ikm, classical_ikm_length, combined_ikm.begin());
    std::copy_n(pq_shared_secret, pq_ss_length,
                combined_ikm.begin() + static_cast<std::ptrdiff_t>(classical_ikm_length));

    log::hex("classical_ikm (3DH)", classical_ikm, classical_ikm_length);
    log::hex("pq_shared_secret (KEM)", pq_shared_secret, pq_ss_length);
    log::hex("combined_ikm (pq)", combined_ikm);

    secure_bytes labeled_transcript(labels::kPqCombinerContextLength + transcript_length);

    std::copy_n(
        reinterpret_cast<const uint8_t*>(labels::kPqCombinerContext),
        labels::kPqCombinerContextLength,
        labeled_transcript.begin()
    );
    std::copy_n(
        transcript_hash, transcript_length,
        labeled_transcript.begin() + static_cast<std::ptrdiff_t>(labels::kPqCombinerContextLength)
    );

    Result result = crypto::key_derivation_extract(
        labeled_transcript.data(), labeled_transcript.size(),
        combined_ikm.data(), combined_ikm.size(),
        prk
    );

    sodium_memzero(combined_ikm.data(), combined_ikm.size());
    sodium_memzero(labeled_transcript.data(), labeled_transcript.size());

    if (result == Result::Success) {
        log::hex("pq_prk", prk, crypto_auth_hmacsha512_BYTES);
        log::msg("PQ key combination successful");
    }

    return result;
}

}
