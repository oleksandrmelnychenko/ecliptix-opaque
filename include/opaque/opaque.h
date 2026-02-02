#pragma once
#include <cstdint>
#include <memory>
#include <vector>
#include <algorithm>
#include <concepts>

namespace ecliptix::security::opaque {

    constexpr inline size_t OPRF_SEED_LENGTH = 32;
    constexpr inline size_t PRIVATE_KEY_LENGTH = 32;
    constexpr inline size_t PUBLIC_KEY_LENGTH = 32;
    constexpr inline size_t MASTER_KEY_LENGTH = 32;
    constexpr inline size_t NONCE_LENGTH = 24;
    constexpr inline size_t MAC_LENGTH = 64;
    constexpr inline size_t HASH_LENGTH = 64;

    constexpr inline size_t ENVELOPE_LENGTH = 136;
    constexpr inline size_t REGISTRATION_REQUEST_LENGTH = 32;
    constexpr inline size_t REGISTRATION_RESPONSE_LENGTH = 64;
    constexpr inline size_t CREDENTIAL_REQUEST_LENGTH = REGISTRATION_REQUEST_LENGTH;
    constexpr inline size_t CREDENTIAL_RESPONSE_LENGTH = 168;
    constexpr inline size_t MAX_SECURE_KEY_LENGTH = 4096;

    constexpr inline size_t KE1_BASE_LENGTH = REGISTRATION_REQUEST_LENGTH + PUBLIC_KEY_LENGTH + NONCE_LENGTH;
    constexpr inline size_t KE2_BASE_LENGTH = NONCE_LENGTH + PUBLIC_KEY_LENGTH + CREDENTIAL_RESPONSE_LENGTH + MAC_LENGTH;
    constexpr inline size_t KE3_LENGTH = MAC_LENGTH;
    constexpr inline size_t REGISTRATION_RECORD_LENGTH = ENVELOPE_LENGTH + PUBLIC_KEY_LENGTH;
    constexpr inline size_t RESPONDER_CREDENTIALS_LENGTH = REGISTRATION_RECORD_LENGTH;

    namespace pq_constants {

        constexpr inline size_t KEM_PUBLIC_KEY_LENGTH = 1184;

        constexpr inline size_t KEM_SECRET_KEY_LENGTH = 2400;

        constexpr inline size_t KEM_CIPHERTEXT_LENGTH = 1088;

        constexpr inline size_t KEM_SHARED_SECRET_LENGTH = 32;

        constexpr inline size_t COMBINED_IKM_LENGTH = 96 + KEM_SHARED_SECRET_LENGTH;

    }

    constexpr inline size_t KE1_LENGTH = KE1_BASE_LENGTH + pq_constants::KEM_PUBLIC_KEY_LENGTH;
    constexpr inline size_t KE2_LENGTH = KE2_BASE_LENGTH + pq_constants::KEM_CIPHERTEXT_LENGTH;

    namespace labels {
        constexpr inline char kOprfContext[] = "ECLIPTIX-OPAQUE-v1/OPRF";
        constexpr inline size_t kOprfContextLength = sizeof(kOprfContext) - 1;
        constexpr inline char kOprfKeyInfo[] = "ECLIPTIX-OPAQUE-v1/OPRF-Key";
        constexpr inline size_t kOprfKeyInfoLength = sizeof(kOprfKeyInfo) - 1;
        constexpr inline char kOprfSeedInfo[] = "ECLIPTIX-OPAQUE-v1/OPRF-Seed";
        constexpr inline size_t kOprfSeedInfoLength = sizeof(kOprfSeedInfo) - 1;
        constexpr inline char kEnvelopeContext[] = "ECLIPTIX-OPAQUE-v1/EnvelopeKey";
        constexpr inline size_t kEnvelopeContextLength = sizeof(kEnvelopeContext) - 1;
        constexpr inline char kHkdfSalt[] = "ECLIPTIX-OPAQUE-v1/HKDF-Salt";
        constexpr inline size_t kHkdfSaltLength = sizeof(kHkdfSalt) - 1;
        constexpr inline char kTranscriptContext[] = "ECLIPTIX-OPAQUE-v1/Transcript";
        constexpr inline size_t kTranscriptContextLength = sizeof(kTranscriptContext) - 1;
        constexpr inline char kKsfContext[] = "ECLIPTIX-OPAQUE-v1/KSF";
        constexpr inline size_t kKsfContextLength = sizeof(kKsfContext) - 1;
        constexpr inline char kKsfSaltLabel[] = "ECLIPTIX-OPAQUE-v1/KSF-Salt";
        constexpr inline size_t kKsfSaltLabelLength = sizeof(kKsfSaltLabel) - 1;
        constexpr inline char kSessionKeyInfo[] = "ECLIPTIX-OPAQUE-v1/SessionKey";
        constexpr inline size_t kSessionKeyInfoLength = sizeof(kSessionKeyInfo) - 1;
        constexpr inline char kMasterKeyInfo[] = "ECLIPTIX-OPAQUE-v1/MasterKey";
        constexpr inline size_t kMasterKeyInfoLength = sizeof(kMasterKeyInfo) - 1;
        constexpr inline char kResponderMacInfo[] = "ECLIPTIX-OPAQUE-v1/ResponderMAC";
        constexpr inline size_t kResponderMacInfoLength = sizeof(kResponderMacInfo) - 1;
        constexpr inline char kInitiatorMacInfo[] = "ECLIPTIX-OPAQUE-v1/InitiatorMAC";
        constexpr inline size_t kInitiatorMacInfoLength = sizeof(kInitiatorMacInfo) - 1;
    }

    static_assert(PRIVATE_KEY_LENGTH == PUBLIC_KEY_LENGTH, "Key lengths must match for ristretto255");
    static_assert(PRIVATE_KEY_LENGTH == 32, "ristretto255 requires 32-byte keys");
    static_assert(NONCE_LENGTH == 24, "Nonce length must match crypto_secretbox nonce size");
    static_assert(MAC_LENGTH == 64, "HMAC-SHA512 produces 64-byte MACs");
    static_assert(CREDENTIAL_REQUEST_LENGTH == REGISTRATION_REQUEST_LENGTH,
                  "Credential request length must match registration request length");
    static_assert(CREDENTIAL_RESPONSE_LENGTH == PUBLIC_KEY_LENGTH + ENVELOPE_LENGTH,
                  "Credential response size mismatch: 32 + 136 = 168");
    static_assert(KE1_BASE_LENGTH == 88, "Base KE1 length: 32 + 32 + 24 = 88");
    static_assert(KE2_BASE_LENGTH == 288, "Base KE2 length: 24 + 32 + 168 + 64 = 288");
    static_assert(REGISTRATION_RECORD_LENGTH == 168, "Registration record length: 136 + 32 = 168");
    static_assert(KE1_LENGTH == 1272, "KE1 length: 88 + 1184 = 1272");
    static_assert(KE2_LENGTH == 1376, "KE2 length: 288 + 1088 = 1376");

    enum class [[nodiscard]] Result {
        Success = 0,
        InvalidInput = -1,
        CryptoError = -2,
        MemoryError = -3,
        ValidationError = -4,
        AuthenticationError = -5,
        InvalidPublicKey = -6
    };

    template<typename T>
    concept SecurelyAllocatable = std::is_trivially_copyable_v<T> && !std::is_const_v<T>;

    template<SecurelyAllocatable T>
    class SecureAllocator {
    public:
        using value_type = T;

        T *allocate(size_t n);

        void deallocate(T *p, size_t n);

        template<SecurelyAllocatable U>
        bool operator==(const SecureAllocator<U> &) const noexcept { return true; }

        template<SecurelyAllocatable U>
        bool operator!=(const SecureAllocator<U> &) const noexcept { return false; }
    };

    template<typename T>
    using secure_vector = std::vector<T, SecureAllocator<T> >;
    using secure_bytes = secure_vector<uint8_t>;

    class SecureBuffer {
    public:
        explicit SecureBuffer(size_t size);

        ~SecureBuffer();

        SecureBuffer(const SecureBuffer &) = delete;

        SecureBuffer &operator=(const SecureBuffer &) = delete;

        SecureBuffer(SecureBuffer &&other) noexcept;

        SecureBuffer &operator=(SecureBuffer &&other) noexcept;

        uint8_t *data() noexcept;

        [[nodiscard]] const uint8_t *data() const noexcept;

        [[nodiscard]] size_t size() const noexcept;

        void make_readonly();

        void make_readwrite();

        void make_noaccess();

    private:
        uint8_t *data_;
        size_t size_;
    };

    struct Envelope {
        secure_bytes nonce;
        secure_bytes ciphertext;
        secure_bytes auth_tag;

        Envelope();

        explicit Envelope(size_t auth_tag_size);
    };

    struct ResponderPublicKey {
        secure_bytes key_data;

        ResponderPublicKey();

        explicit ResponderPublicKey(const uint8_t *data, size_t size);

        [[nodiscard]] bool verify() const;
    };

    struct InitiatorCredentials {
        secure_bytes envelope;
        secure_bytes responder_public_key;

        InitiatorCredentials();
    };

    struct ResponderCredentials {
        secure_bytes envelope;
        secure_bytes initiator_public_key;

        ResponderCredentials();
    };

    namespace util {
        template<size_t N>
        [[nodiscard]] inline bool is_all_zero(const uint8_t (&data)[N]) noexcept {
            uint8_t accumulator = 0;
            for (size_t i = 0; i < N; ++i) {
                accumulator |= data[i];
            }
            return accumulator == 0;
        }

        [[nodiscard]] inline bool is_all_zero(const uint8_t *data, size_t length) noexcept {
            uint8_t accumulator = 0;
            for (size_t i = 0; i < length; ++i) {
                accumulator |= data[i];
            }
            return accumulator == 0;
        }
    }

    namespace oblivious_prf {
        [[nodiscard]] Result hash_to_group(const uint8_t *input, size_t input_length, uint8_t *point);

        [[nodiscard]] Result evaluate(const uint8_t *blinded_element, const uint8_t *responder_private_key,
                                      uint8_t *evaluated_element);

        [[nodiscard]] Result finalize(const uint8_t *input, size_t input_length, const uint8_t *blind_scalar,
                                      const uint8_t *evaluated_element, uint8_t *output);

        [[nodiscard]] Result blind(const uint8_t *input, size_t input_length, uint8_t *blinded_element,
                                   uint8_t *blind_scalar);
    }

    namespace crypto {
        [[nodiscard]] bool init();

        [[nodiscard]] Result random_bytes(uint8_t *buffer, size_t length);

        [[nodiscard]] Result derive_key_pair(const uint8_t *seed, size_t seed_length,
                                             uint8_t *private_key, uint8_t *public_key);

        [[nodiscard]] Result scalar_mult(const uint8_t *scalar, const uint8_t *point, uint8_t *result);

        [[nodiscard]] Result validate_ristretto_point(const uint8_t *point, size_t length);

        [[nodiscard]] Result validate_public_key(const uint8_t *key, size_t length);

        [[nodiscard]] Result key_derivation_extract(const uint8_t *salt, size_t salt_length, const uint8_t *ikm,
                                                    size_t ikm_length, uint8_t *prk);

        [[nodiscard]] Result key_derivation_expand(const uint8_t *prk, size_t prk_length, const uint8_t *info,
                                                   size_t info_length, uint8_t *okm, size_t okm_length);

        [[nodiscard]] Result hmac(const uint8_t *key, size_t key_length, const uint8_t *data, size_t data_length,
                                  uint8_t *mac);

        [[nodiscard]] Result derive_oprf_key(const uint8_t *server_secret, size_t server_secret_length,
                                             const uint8_t *account_id, size_t account_id_length,
                                             uint8_t *oprf_key);

        [[nodiscard]] Result derive_randomized_password(const uint8_t *oprf_output, size_t oprf_output_length,
                                                        const uint8_t *secure_key, size_t secure_key_length,
                                                        uint8_t *randomized_pwd, size_t randomized_pwd_length);

        [[nodiscard]] Result encrypt_envelope(const uint8_t *key, size_t key_length, const uint8_t *plaintext,
                                              size_t plaintext_length, const uint8_t *nonce, uint8_t *ciphertext,
                                              uint8_t *auth_tag);

        [[nodiscard]] Result decrypt_envelope(const uint8_t *key, size_t key_length, const uint8_t *ciphertext,
                                              size_t ciphertext_length, const uint8_t *nonce, const uint8_t *auth_tag,
                                              uint8_t *plaintext);
    }

    namespace envelope {
        [[nodiscard]] Result seal(const uint8_t *randomized_pwd, size_t pwd_length, const uint8_t *responder_public_key,
                                  const uint8_t *initiator_private_key, const uint8_t *initiator_public_key,
                                  Envelope &envelope);

        [[nodiscard]] Result open(const Envelope &envelope, const uint8_t *randomized_pwd, size_t pwd_length,
                                  const uint8_t *known_responder_public_key, uint8_t *responder_public_key,
                                  uint8_t *initiator_private_key, uint8_t *initiator_public_key);
    }
}
