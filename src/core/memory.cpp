#include "opaque/opaque.h"
#include <sodium.h>
#include <stdexcept>
#include <algorithm>

namespace ecliptix::security::opaque {

template<typename T>
T* SecureAllocator<T>::allocate(size_t n) {
    if (n > SIZE_MAX / sizeof(T)) {
        throw std::bad_alloc();
    }

    void* ptr = sodium_malloc(n * sizeof(T));
    if (!ptr) {
        throw std::bad_alloc();
    }

    return static_cast<T*>(ptr);
}

template<typename T>
void SecureAllocator<T>::deallocate(T* p, size_t) {
    if (p) {
        sodium_free(p);
    }
}

template class SecureAllocator<uint8_t>;

SecureBuffer::SecureBuffer(size_t size) : data_(nullptr), size_(size) {
    if (size == 0) {
        return;
    }

    data_ = static_cast<uint8_t*>(sodium_malloc(size));
    if (!data_) {
        throw std::bad_alloc();
    }
}

SecureBuffer::~SecureBuffer() {
    if (data_) {
        sodium_free(data_);
        data_ = nullptr;
    }
    size_ = 0;
}

SecureBuffer::SecureBuffer(SecureBuffer&& other) noexcept
    : data_(other.data_), size_(other.size_) {
    other.data_ = nullptr;
    other.size_ = 0;
}

SecureBuffer& SecureBuffer::operator=(SecureBuffer&& other) noexcept {
    if (this != &other) {
        if (data_) {
            sodium_free(data_);
        }

        data_ = other.data_;
        size_ = other.size_;
        other.data_ = nullptr;
        other.size_ = 0;
    }
    return *this;
}

uint8_t* SecureBuffer::data() noexcept {
    return data_;
}

const uint8_t* SecureBuffer::data() const noexcept {
    return data_;
}

size_t SecureBuffer::size() const noexcept {
    return size_;
}

void SecureBuffer::make_readonly() {
    if (data_ && size_ > 0) {
        sodium_mprotect_readonly(data_);
    }
}

void SecureBuffer::make_readwrite() {
    if (data_ && size_ > 0) {
        sodium_mprotect_readwrite(data_);
    }
}

void SecureBuffer::make_noaccess() {
    if (data_ && size_ > 0) {
        sodium_mprotect_noaccess(data_);
    }
}

Envelope::Envelope() : nonce(NONCE_LENGTH), auth_tag(MAC_LENGTH) {}

Envelope::Envelope(size_t auth_tag_size) : nonce(NONCE_LENGTH), auth_tag(auth_tag_size) {}

ServerPublicKey::ServerPublicKey() : key_data(PUBLIC_KEY_LENGTH) {}

ServerPublicKey::ServerPublicKey(const uint8_t* data, size_t size) : key_data(size) {
    if (data && size > 0) {
        std::copy(data, data + size, key_data.begin());
    }
}

bool ServerPublicKey::verify() const {
    return key_data.size() == PUBLIC_KEY_LENGTH &&
           crypto_core_ristretto255_is_valid_point(key_data.data()) == 1;
}

ClientCredentials::ClientCredentials() : envelope(ENVELOPE_LENGTH), server_public_key(PUBLIC_KEY_LENGTH) {}

ServerCredentials::ServerCredentials() : envelope(ENVELOPE_LENGTH), masking_key(PRIVATE_KEY_LENGTH) {}

}