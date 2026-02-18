#include "opaque/opaque.h"
#include <stdexcept>
#include <algorithm>
#include <ranges>
#include <cstring>
#include <memory>
#include <sodium.h>
#include <new>
#ifdef _WIN32
#include <windows.h>
#elif defined(__APPLE__) || defined(__linux__) || defined(__ANDROID__)
#include <sys/mman.h>
#include <unistd.h>
#include <cstdlib>
#endif
namespace ecliptix::security::opaque {
namespace {
    constexpr size_t kDefaultPageSize = 4096;
    size_t secure_page_size() {
#ifdef _WIN32
        SYSTEM_INFO sys_info;
        GetSystemInfo(&sys_info);
        return static_cast<size_t>(sys_info.dwPageSize);
#elif defined(__APPLE__) || defined(__linux__)
            const long page_size = sysconf(_SC_PAGESIZE);
        if (page_size > 0) {
            return static_cast<size_t>(page_size);
        }
        return kDefaultPageSize;
#else
        return kDefaultPageSize;
#endif
    }

        void *secure_malloc(const size_t size) {
            if (size == 0) return nullptr;
            const size_t page_size = secure_page_size();
            size_t aligned_size = (size + page_size - 1) & ~(page_size - 1);
#ifdef _WIN32
            void *ptr = VirtualAlloc(nullptr, aligned_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (!ptr) return nullptr;
            (void)VirtualLock(ptr, aligned_size);
#else
            void *ptr = nullptr;
            if (posix_memalign(&ptr, page_size, aligned_size) != 0) {
                return nullptr;
            }
            (void)mlock(ptr, aligned_size);
#endif
            std::memset(ptr, 0, aligned_size);
            return ptr;
        }

        void secure_free(void *ptr, const size_t size) {
            if (!ptr) return;
            const size_t page_size = secure_page_size();
            size_t aligned_size = (size + page_size - 1) & ~(page_size - 1);
            sodium_memzero(ptr, aligned_size);
#ifdef _WIN32
            VirtualUnlock(ptr, aligned_size);
            VirtualFree(ptr, 0, MEM_RELEASE);
#else
            munlock(ptr, aligned_size);
            free(ptr);
#endif
        }
    }

    template<SecurelyAllocatable T>
    T *SecureAllocator<T>::allocate(const size_t n) {
        if (n == 0) {
            return nullptr;
        }
        if (n > SIZE_MAX / sizeof(T)) [[unlikely]] {
            throw std::bad_alloc();
        }
        void *ptr = secure_malloc(n * sizeof(T));
        if (!ptr) [[unlikely]] {
            throw std::bad_alloc();
        }
        return static_cast<T *>(ptr);
    }

    template<SecurelyAllocatable T>
    void SecureAllocator<T>::deallocate(T *p, const size_t n) {
        if (p) [[likely]] {
            secure_free(p, n * sizeof(T));
        }
    }

    template class SecureAllocator<uint8_t>;

    SecureBuffer::SecureBuffer(const size_t size) : data_(nullptr), size_(size) {
        if (size == 0) {
            return;
        }
        data_ = static_cast<uint8_t *>(secure_malloc(size));
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

    SecureBuffer::SecureBuffer(SecureBuffer &&other) noexcept
        : data_(other.data_), size_(other.size_) {
        other.data_ = nullptr;
        other.size_ = 0;
    }

    SecureBuffer &SecureBuffer::operator=(SecureBuffer &&other) noexcept {
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

    uint8_t *SecureBuffer::data() noexcept {
        return data_;
    }

    const uint8_t *SecureBuffer::data() const noexcept {
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

    Envelope::Envelope() : nonce(NONCE_LENGTH), auth_tag(crypto_secretbox_MACBYTES) {
    }

    Envelope::Envelope(const size_t auth_tag_size) : nonce(NONCE_LENGTH), auth_tag(auth_tag_size) {
    }

    ResponderPublicKey::ResponderPublicKey() : key_data(PUBLIC_KEY_LENGTH) {
    }

    ResponderPublicKey::ResponderPublicKey(const uint8_t *data, const size_t size) : key_data(size) {
        if (data && size > 0) {
            std::copy_n(data, size, key_data.begin());
        }
    }

    bool ResponderPublicKey::verify() const {
        if (key_data.size() != PUBLIC_KEY_LENGTH) [[unlikely]] {
            return false;
        }
        return crypto::validate_public_key(key_data.data(), key_data.size()) == Result::Success;
    }

    InitiatorCredentials::InitiatorCredentials() : envelope(ENVELOPE_LENGTH), responder_public_key(PUBLIC_KEY_LENGTH) {
    }

    ResponderCredentials::ResponderCredentials() : envelope(ENVELOPE_LENGTH),
                                                   initiator_public_key(PUBLIC_KEY_LENGTH) {
    }
}
