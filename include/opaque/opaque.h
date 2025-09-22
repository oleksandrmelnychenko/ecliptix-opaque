#pragma once

#include <cstdint>
#include <memory>
#include <vector>
#include <algorithm>

namespace ecliptix::security::opaque {

constexpr size_t OPRF_SEED_LENGTH = 32;
constexpr size_t PRIVATE_KEY_LENGTH = 32;
constexpr size_t PUBLIC_KEY_LENGTH = 32;
constexpr size_t NONCE_LENGTH = 32;
constexpr size_t MAC_LENGTH = 64;
constexpr size_t HASH_LENGTH = 64;
constexpr size_t ENVELOPE_LENGTH = 96;
constexpr size_t REGISTRATION_REQUEST_LENGTH = 32;
constexpr size_t REGISTRATION_RESPONSE_LENGTH = 96;
constexpr size_t CREDENTIAL_REQUEST_LENGTH = 96;
constexpr size_t CREDENTIAL_RESPONSE_LENGTH = 192;
constexpr size_t KE1_LENGTH = 96;
constexpr size_t KE2_LENGTH = 320;
constexpr size_t KE3_LENGTH = 64;

enum class Result {
    Success = 0,
    InvalidInput = -1,
    CryptoError = -2,
    MemoryError = -3,
    ValidationError = -4,
    AuthenticationError = -5
};

template<typename T>
class SecureAllocator {
public:
    using value_type = T;

    T* allocate(size_t n);
    void deallocate(T* p, size_t n);

    template<typename U>
    bool operator==(const SecureAllocator<U>&) const noexcept { return true; }

    template<typename U>
    bool operator!=(const SecureAllocator<U>&) const noexcept { return false; }
};

template<typename T>
using secure_vector = std::vector<T, SecureAllocator<T>>;

using secure_bytes = secure_vector<uint8_t>;

class SecureBuffer {
public:
    explicit SecureBuffer(size_t size);
    ~SecureBuffer();

    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    SecureBuffer(SecureBuffer&& other) noexcept;
    SecureBuffer& operator=(SecureBuffer&& other) noexcept;

    uint8_t* data() noexcept;
    const uint8_t* data() const noexcept;
    size_t size() const noexcept;

    void make_readonly();
    void make_readwrite();
    void make_noaccess();

private:
    uint8_t* data_;
    size_t size_;
};

struct Envelope {
    secure_bytes nonce;
    secure_bytes auth_tag;

    Envelope();
    explicit Envelope(size_t auth_tag_size);
};

struct ServerPublicKey {
    secure_bytes key_data;

    ServerPublicKey();
    explicit ServerPublicKey(const uint8_t* data, size_t size);

    bool verify() const;
};

struct ClientCredentials {
    secure_bytes envelope;
    secure_bytes server_public_key;

    ClientCredentials();
};

struct ServerCredentials {
    secure_bytes envelope;
    secure_bytes masking_key;

    ServerCredentials();
};

namespace oprf {
    Result hash_to_group(const uint8_t* input, size_t input_length, uint8_t* point);
    Result evaluate(const uint8_t* blinded_element, const uint8_t* server_private_key, uint8_t* evaluated_element);
    Result finalize(const uint8_t* input, size_t input_length, const uint8_t* blind_scalar, const uint8_t* evaluated_element, uint8_t* output);
    Result blind(const uint8_t* input, size_t input_length, uint8_t* blinded_element, uint8_t* blind_scalar);
}

namespace crypto {
    bool init();
    Result random_bytes(uint8_t* buffer, size_t length);
    Result kdf_extract(const uint8_t* salt, size_t salt_length, const uint8_t* ikm, size_t ikm_length, uint8_t* prk);
    Result kdf_expand(const uint8_t* prk, size_t prk_length, const uint8_t* info, size_t info_length, uint8_t* okm, size_t okm_length);
    Result hmac(const uint8_t* key, size_t key_length, const uint8_t* data, size_t data_length, uint8_t* mac);
}

namespace envelope {
    Result seal(const uint8_t* randomized_pwd, size_t pwd_length, const uint8_t* server_public_key, const uint8_t* client_private_key, const uint8_t* client_public_key, Envelope& envelope);
    Result open(const Envelope& envelope, const uint8_t* randomized_pwd, size_t pwd_length, const uint8_t* server_public_key, uint8_t* client_private_key, uint8_t* client_public_key);
}

}