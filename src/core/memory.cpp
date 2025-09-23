#include "opaque/opaque.h"
#include <stdexcept>
#include <algorithm>
#include <cstring>
#include <memory>
#include <sodium.h>
#include <new>
#ifdef _WIN32
#include <windows.h>
#elif defined(__APPLE__) || defined(__linux__)
#include <sys/mman.h>
#include <unistd.h>
#endif
namespace ecliptix::security::opaque {
namespace {
    void* secure_malloc(size_t size) {
        if (size == 0) return nullptr;
        size_t page_size = 4096; 
        size_t aligned_size = (size + page_size - 1) & ~(page_size - 1);
#ifdef _WIN32
        void* ptr = VirtualAlloc(nullptr, aligned_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!ptr) return nullptr;
#else
        void* ptr = aligned_alloc(page_size, aligned_size);
        if (!ptr) return nullptr;
        if (mlock(ptr, aligned_size) != 0) {
            free(ptr);
            return nullptr;
        }
#endif
        std::memset(ptr, 0, aligned_size);
        return ptr;
    }
    void secure_free(void* ptr, size_t size) {
        if (!ptr) return;
        std::memset(ptr, 0, size);
#ifdef _WIN32
        VirtualFree(ptr, 0, MEM_RELEASE);
#else
        size_t page_size = 4096;
        size_t aligned_size = (size + page_size - 1) & ~(page_size - 1);
        munlock(ptr, aligned_size);
        free(ptr);
#endif
    }
}
template<typename T>
T* SecureAllocator<T>::allocate(size_t n) {
    if (n > SIZE_MAX / sizeof(T)) {
        throw std::bad_alloc();
    }
    void* ptr = secure_malloc(n * sizeof(T));
    if (!ptr) {
        throw std::bad_alloc();
    }
    return static_cast<T*>(ptr);
}
template<typename T>
void SecureAllocator<T>::deallocate(T* p, size_t n) {
    if (p) {
        secure_free(p, n * sizeof(T));
    }
}
template class SecureAllocator<uint8_t>;
SecureBuffer::SecureBuffer(size_t size) : data_(nullptr), size_(size) {
    if (size == 0) {
        return;
    }
    data_ = static_cast<uint8_t*>(secure_malloc(size));
    if (!data_) {
        throw std::bad_alloc();
    }
}
SecureBuffer::~SecureBuffer() {
    if (data_) {
        secure_free(data_, size_);
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
            secure_free(data_, size_);
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
#ifdef _WIN32
        DWORD old_protect;
        VirtualProtect(data_, size_, PAGE_READONLY, &old_protect);
#else
        mprotect(data_, size_, PROT_READ);
#endif
    }
}
void SecureBuffer::make_readwrite() {
    if (data_ && size_ > 0) {
#ifdef _WIN32
        DWORD old_protect;
        VirtualProtect(data_, size_, PAGE_READWRITE, &old_protect);
#else
        mprotect(data_, size_, PROT_READ | PROT_WRITE);
#endif
    }
}
void SecureBuffer::make_noaccess() {
    if (data_ && size_ > 0) {
#ifdef _WIN32
        DWORD old_protect;
        VirtualProtect(data_, size_, PAGE_NOACCESS, &old_protect);
#else
        mprotect(data_, size_, PROT_NONE);
#endif
    }
}
Envelope::Envelope() : nonce(NONCE_LENGTH), auth_tag(crypto_secretbox_MACBYTES) {}
Envelope::Envelope(size_t auth_tag_size) : nonce(NONCE_LENGTH), auth_tag(auth_tag_size) {}
ServerPublicKey::ServerPublicKey() : key_data(PUBLIC_KEY_LENGTH) {}
ServerPublicKey::ServerPublicKey(const uint8_t* data, size_t size) : key_data(size) {
    if (data && size > 0) {
        std::copy(data, data + size, key_data.begin());
    }
}
bool ServerPublicKey::verify() const {
    if (key_data.size() != PUBLIC_KEY_LENGTH) {
        return false;
    }
    bool all_zero = true;
    for (size_t i = 0; i < key_data.size(); ++i) {
        if (key_data[i] != 0) {
            all_zero = false;
            break;
        }
    }
    return !all_zero;
}
ClientCredentials::ClientCredentials() : envelope(ENVELOPE_LENGTH), server_public_key(PUBLIC_KEY_LENGTH) {}
ServerCredentials::ServerCredentials() : envelope(ENVELOPE_LENGTH), masking_key(PRIVATE_KEY_LENGTH), client_public_key(PUBLIC_KEY_LENGTH) {}
}