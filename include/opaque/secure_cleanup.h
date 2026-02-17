#pragma once
/**
 * @file secure_cleanup.h
 * @brief RAII-based secure cleanup utilities for cryptographic operations.
 *
 * Replaces the error-prone `goto cleanup` pattern with deterministic,
 * exception-safe cleanup using C++ RAII idiom and scope guards.
 *
 * Usage:
 *   SecureLocal<32> dh1;          // stack buffer, auto-zeroed on destruction
 *   auto guard = make_cleanup([&] { sodium_memzero(buf, len); });
 *   OPAQUE_TRY(some_crypto_op()); // returns on failure, cleanup runs via RAII
 */

#include <sodium.h>
#include <cstdint>
#include <cstddef>
#include <utility>
#include <type_traits>
#include "opaque/opaque.h"

namespace ecliptix::security::opaque {

/**
 * ScopeGuard — executes a callable on destruction (scope exit).
 * Non-copyable, movable. Supports dismiss() to cancel cleanup.
 */
template<typename F>
class ScopeGuard {
public:
    explicit ScopeGuard(F&& fn) noexcept
        : fn_(std::move(fn)), active_(true) {}

    ScopeGuard(ScopeGuard&& other) noexcept
        : fn_(std::move(other.fn_)), active_(other.active_) {
        other.active_ = false;
    }

    ~ScopeGuard() {
        if (active_) {
            fn_();
        }
    }

    void dismiss() noexcept { active_ = false; }

    ScopeGuard(const ScopeGuard&) = delete;
    ScopeGuard& operator=(const ScopeGuard&) = delete;
    ScopeGuard& operator=(ScopeGuard&&) = delete;

private:
    F fn_;
    bool active_;
};

template<typename F>
[[nodiscard]] ScopeGuard<std::decay_t<F>> make_cleanup(F&& fn) noexcept {
    return ScopeGuard<std::decay_t<F>>(std::forward<F>(fn));
}


/**
 * SecureLocal<N> — fixed-size stack buffer that is automatically
 * zeroed via sodium_memzero on destruction. Replaces the pattern:
 *
 *   uint8_t dh1[32] = {};
 *   // ... use dh1 ...
 *   cleanup:
 *     sodium_memzero(dh1, sizeof(dh1));
 *
 * With:
 *   SecureLocal<32> dh1;
 *   // ... use dh1.data() ... (auto-zeroed on scope exit)
 */
template<size_t N>
class SecureLocal {
    static_assert(N > 0 && N <= 8192, "SecureLocal size must be in [1, 8192]");
public:
    SecureLocal() noexcept {
        sodium_memzero(buf_, N);
    }

    ~SecureLocal() {
        sodium_memzero(buf_, N);
    }

    SecureLocal(const SecureLocal&) = delete;
    SecureLocal& operator=(const SecureLocal&) = delete;
    SecureLocal(SecureLocal&&) = delete;
    SecureLocal& operator=(SecureLocal&&) = delete;

    [[nodiscard]] uint8_t* data() noexcept { return buf_; }
    [[nodiscard]] const uint8_t* data() const noexcept { return buf_; }
    [[nodiscard]] constexpr size_t size() const noexcept { return N; }

    uint8_t& operator[](size_t i) noexcept { return buf_[i]; }
    const uint8_t& operator[](size_t i) const noexcept { return buf_[i]; }

    /* Implicit conversion to pointer for C API compatibility */
    operator uint8_t*() noexcept { return buf_; }
    operator const uint8_t*() const noexcept { return buf_; }

private:
    uint8_t buf_[N];
};


/**
 * OPAQUE_TRY — macro for early-return on failure.
 * Replaces:
 *   result = some_op(); if (result != Result::Success) goto cleanup;
 * With:
 *   OPAQUE_TRY(some_op());
 *
 * Cleanup happens automatically via RAII destructors (SecureLocal, ScopeGuard).
 */
#define OPAQUE_TRY(expr)                          \
    do {                                           \
        if (auto _r = (expr); _r != Result::Success) \
            return _r;                             \
    } while (0)

/**
 * OPAQUE_TRY_ASSIGN — try an operation and assign result to variable.
 * Usage: OPAQUE_TRY_ASSIGN(result, some_op());
 */
#define OPAQUE_TRY_ASSIGN(var, expr)              \
    do {                                           \
        (var) = (expr);                            \
        if ((var) != Result::Success) return (var); \
    } while (0)


/**
 * Secure memory utilities for wiping and clearing sensitive buffers.
 */

/**
 * secure_wipe — zero out buffer contents but preserve capacity.
 * Use when you want to clear sensitive data but keep the buffer allocated.
 */
inline void secure_wipe(secure_bytes &buffer) noexcept {
    if (!buffer.empty()) {
        sodium_memzero(buffer.data(), buffer.size());
    }
}

/**
 * secure_clear — zero out buffer contents and deallocate.
 * Use when you're done with a buffer entirely.
 */
inline void secure_clear(secure_bytes &buffer) noexcept {
    if (!buffer.empty()) {
        sodium_memzero(buffer.data(), buffer.size());
        buffer.clear();
    }
}

} // namespace ecliptix::security::opaque
