#pragma once

#include "opaque.h"
#include <cstdint>

namespace ecliptix::security::opaque::pq {

constexpr inline size_t KEM_PUBLIC_KEY_LENGTH = pq_constants::KEM_PUBLIC_KEY_LENGTH;

constexpr inline size_t KEM_SECRET_KEY_LENGTH = pq_constants::KEM_SECRET_KEY_LENGTH;

constexpr inline size_t KEM_CIPHERTEXT_LENGTH = pq_constants::KEM_CIPHERTEXT_LENGTH;

constexpr inline size_t KEM_SHARED_SECRET_LENGTH = pq_constants::KEM_SHARED_SECRET_LENGTH;

constexpr inline size_t COMBINED_IKM_LENGTH = pq_constants::COMBINED_IKM_LENGTH;

namespace labels {

    constexpr inline char kPqCombinerContext[] = "ECLIPTIX-OPAQUE-PQ-v1/Combiner";
    constexpr inline size_t kPqCombinerContextLength = sizeof(kPqCombinerContext) - 1;

    constexpr inline char kPqKemContext[] = "ECLIPTIX-OPAQUE-PQ-v1/KEM";
    constexpr inline size_t kPqKemContextLength = sizeof(kPqKemContext) - 1;

    constexpr inline char kPqSessionKeyInfo[] = "ECLIPTIX-OPAQUE-PQ-v1/SessionKey";
    constexpr inline size_t kPqSessionKeyInfoLength = sizeof(kPqSessionKeyInfo) - 1;

    constexpr inline char kPqMasterKeyInfo[] = "ECLIPTIX-OPAQUE-PQ-v1/MasterKey";
    constexpr inline size_t kPqMasterKeyInfoLength = sizeof(kPqMasterKeyInfo) - 1;

    constexpr inline char kPqResponderMacInfo[] = "ECLIPTIX-OPAQUE-PQ-v1/ResponderMAC";
    constexpr inline size_t kPqResponderMacInfoLength = sizeof(kPqResponderMacInfo) - 1;

    constexpr inline char kPqInitiatorMacInfo[] = "ECLIPTIX-OPAQUE-PQ-v1/InitiatorMAC";
    constexpr inline size_t kPqInitiatorMacInfoLength = sizeof(kPqInitiatorMacInfo) - 1;

}

namespace kem {

    [[nodiscard]] bool init();

    [[nodiscard]] Result keypair_generate(
        uint8_t* public_key,
        uint8_t* secret_key
    );

    [[nodiscard]] Result encapsulate(
        const uint8_t* public_key,
        uint8_t* ciphertext,
        uint8_t* shared_secret
    );

    [[nodiscard]] Result decapsulate(
        const uint8_t* secret_key,
        const uint8_t* ciphertext,
        uint8_t* shared_secret
    );

}

[[nodiscard]] Result combine_key_material(
    const uint8_t* classical_ikm,
    size_t classical_ikm_length,
    const uint8_t* pq_shared_secret,
    size_t pq_ss_length,
    const uint8_t* transcript_hash,
    size_t transcript_length,
    uint8_t* prk
);

}
