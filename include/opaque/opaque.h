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
    constexpr inline size_t NONCE_LENGTH = 32;
    constexpr inline size_t MAC_LENGTH = 64;
    constexpr inline size_t HASH_LENGTH = 64;
    constexpr inline size_t ENVELOPE_LENGTH = 176;
    constexpr inline size_t REGISTRATION_REQUEST_LENGTH = 32;
    constexpr inline size_t REGISTRATION_RESPONSE_LENGTH = 96;
    constexpr inline size_t CREDENTIAL_REQUEST_LENGTH = 96;
    constexpr inline size_t CREDENTIAL_RESPONSE_LENGTH = 208;
    constexpr inline size_t KE1_LENGTH = 96;
    constexpr inline size_t KE2_LENGTH = 336;
    constexpr inline size_t KE3_LENGTH = 64;

    static_assert(PRIVATE_KEY_LENGTH == PUBLIC_KEY_LENGTH, "Key lengths must match for ristretto255");
    static_assert(PRIVATE_KEY_LENGTH == 32, "ristretto255 requires 32-byte keys");
    static_assert(NONCE_LENGTH >= 24, "Nonce must be at least 24 bytes for crypto_secretbox");
    static_assert(MAC_LENGTH == 64, "HMAC-SHA512 produces 64-byte MACs");
    static_assert(CREDENTIAL_RESPONSE_LENGTH == PUBLIC_KEY_LENGTH + ENVELOPE_LENGTH,
                  "Credential response size mismatch");
    static_assert(KE2_LENGTH == NONCE_LENGTH + PUBLIC_KEY_LENGTH + CREDENTIAL_RESPONSE_LENGTH + MAC_LENGTH,
                  "KE2 length calculation error");

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

        const uint8_t *data() const noexcept;

        size_t size() const noexcept;

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

        bool verify() const;
    };

    struct InitiatorCredentials {
        secure_bytes envelope;
        secure_bytes responder_public_key;

        InitiatorCredentials();
    };

    struct ResponderCredentials {
        secure_bytes envelope;
        secure_bytes masking_key;
        secure_bytes initiator_public_key;

        ResponderCredentials();
    };

    namespace oblivious_prf {
        [[nodiscard]] Result hash_to_group(const uint8_t *input, size_t input_length, uint8_t *point);

        [[nodiscard]] Result evaluate(const uint8_t *blinded_element, const uint8_t *responder_private_key,
                                      uint8_t *evaluated_element);

        [[nodiscard]] Result finalize(const uint8_t *input, size_t input_length, const uint8_t *blind_scalar,
                                      const uint8_t *evaluated_element, uint8_t *output);

        [[nodiscard]] Result blind(const uint8_t *input, size_t input_length, uint8_t *blinded_element,
                                   uint8_t *blind_scalar);
    } // namespace oblivious_prf

    namespace crypto {
        [[nodiscard]] bool init();

        [[nodiscard]] Result random_bytes(uint8_t *buffer, size_t length);

        [[nodiscard]] Result derive_key_pair(const uint8_t *seed, uint8_t *private_key, uint8_t *public_key);

        [[nodiscard]] Result scalar_mult(const uint8_t *scalar, const uint8_t *point, uint8_t *result);

        [[nodiscard]] Result key_derivation_extract(const uint8_t *salt, size_t salt_length, const uint8_t *ikm,
                                                    size_t ikm_length, uint8_t *prk);

        [[nodiscard]] Result key_derivation_expand(const uint8_t *prk, size_t prk_length, const uint8_t *info,
                                                   size_t info_length, uint8_t *okm, size_t okm_length);

        [[nodiscard]] Result hmac(const uint8_t *key, size_t key_length, const uint8_t *data, size_t data_length,
                                  uint8_t *mac);

        [[nodiscard]] Result encrypt_envelope(const uint8_t *key, size_t key_length, const uint8_t *plaintext,
                                              size_t plaintext_length, const uint8_t *nonce, uint8_t *ciphertext,
                                              uint8_t *auth_tag);

        [[nodiscard]] Result decrypt_envelope(const uint8_t *key, size_t key_length, const uint8_t *ciphertext,
                                              size_t ciphertext_length, const uint8_t *nonce, const uint8_t *auth_tag,
                                              uint8_t *plaintext);
    } // namespace crypto
    namespace envelope {
        [[nodiscard]] Result seal(const uint8_t *randomized_pwd, size_t pwd_length, const uint8_t *responder_public_key,
                                  const uint8_t *initiator_private_key, const uint8_t *initiator_public_key,
                                  const uint8_t *master_key, Envelope &envelope);

        [[nodiscard]] Result open(const Envelope &envelope, const uint8_t *randomized_pwd, size_t pwd_length,
                                  const uint8_t *known_responder_public_key, uint8_t *responder_public_key,
                                  uint8_t *initiator_private_key, uint8_t *initiator_public_key, uint8_t *master_key);
    } // namespace envelope
}
