#pragma once

#include <cstdint>
#include <memory>

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

}