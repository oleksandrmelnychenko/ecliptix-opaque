# Secure Coding Guidelines

**Document ID**: ISMS-SCG-001
**Version**: 1.0
**Last Updated**: 2025-02-01
**Classification**: Internal
**ISO 27001 Reference**: Clause A.8.25, A.8.26, A.8.27, A.8.28

---

## 1. Purpose and Scope

### 1.1 Purpose

This document establishes secure coding practices for Ecliptix.Security.OPAQUE development to prevent security vulnerabilities and ensure robust cryptographic implementation.

### 1.2 Scope

These guidelines apply to:
- All C++ source code
- C interoperability layer
- Build scripts and configuration
- Test code (where security-relevant)

### 1.3 Audience

- Core developers
- Contributors
- Code reviewers

---

## 2. General Principles

### 2.1 Security First

1. **Assume hostile input** - All external data is potentially malicious
2. **Fail securely** - Errors should not compromise security
3. **Defense in depth** - Multiple layers of protection
4. **Least privilege** - Minimum necessary access/permissions
5. **Keep it simple** - Complexity breeds vulnerabilities

### 2.2 Cryptographic Principles

1. **Never implement your own crypto** - Use libsodium/liboqs
2. **Constant-time operations** - Prevent timing side channels
3. **Secure memory handling** - Protect key material
4. **Explicit verification** - Always verify MACs before using data
5. **Domain separation** - Use unique contexts for different operations

---

## 3. Memory Management

### 3.1 Sensitive Data Handling

```cpp
// GOOD: Use SecureBuffer for sensitive data
SecureBuffer key_material(PRIVATE_KEY_LENGTH);
// Operations...
// Automatically zeroed on destruction

// BAD: Plain std::vector for keys
std::vector<uint8_t> key(32);  // Won't be zeroed!

// GOOD: Use secure_bytes (custom allocator)
secure_bytes secret_data(64);
// Uses SecureAllocator, zeroed on deallocation

// BAD: Stack buffer for secrets without zeroization
uint8_t temp_key[32];
// ... use temp_key ...
// MISSING: sodium_memzero(temp_key, sizeof(temp_key));
```

### 3.2 Zeroization Requirements

**All sensitive data MUST be zeroed before deallocation:**

```cpp
// REQUIRED: Always zero intermediate values
uint8_t intermediate_hash[64];
// ... compute hash ...
// Use the hash
sodium_memzero(intermediate_hash, sizeof(intermediate_hash));

// REQUIRED: Zero function-local secrets
void process_key(const uint8_t* key, size_t key_len) {
    uint8_t derived[32];
    // ... derive key ...
    use_derived_key(derived, sizeof(derived));
    sodium_memzero(derived, sizeof(derived));  // ALWAYS
}
```

### 3.3 Memory Protection

```cpp
// Use page-level protection for long-lived secrets
SecureBuffer master_key(32);
load_master_key(master_key.data());
master_key.make_readonly();  // Prevent modification

// Temporarily unlock for updates
master_key.make_readwrite();
update_key(master_key.data());
master_key.make_readonly();
```

### 3.4 Allocation Safety

```cpp
// GOOD: Check for overflow before allocation
if (n > SIZE_MAX / sizeof(T)) [[unlikely]] {
    throw std::bad_alloc();
}

// GOOD: Check allocation success
void* ptr = secure_malloc(size);
if (!ptr) [[unlikely]] {
    throw std::bad_alloc();
}

// BAD: Unchecked allocation
auto* data = new uint8_t[user_size];  // Could overflow
```

---

## 4. Input Validation

### 4.1 Null and Size Checks

```cpp
// GOOD: Validate all inputs at function entry
Result process_data(const uint8_t* input, size_t length,
                    uint8_t* output, size_t output_size) {
    // Null checks
    if (!input || !output) [[unlikely]] {
        return Result::InvalidInput;
    }

    // Size checks
    if (length == 0 || output_size < required_size) [[unlikely]] {
        return Result::InvalidInput;
    }

    // ... process ...
    return Result::Success;
}
```

### 4.2 Cryptographic Input Validation

```cpp
// GOOD: Validate public keys before use
Result validate_public_key(const uint8_t* key, size_t length) {
    if (!key || length != PUBLIC_KEY_LENGTH) [[unlikely]] {
        return Result::InvalidInput;
    }

    // Validate it's a valid curve point
    if (crypto_core_ristretto255_is_valid_point(key) != 1) {
        return Result::InvalidPublicKey;
    }

    // Reject identity element
    if (util::is_all_zero(key, length)) {
        return Result::InvalidPublicKey;
    }

    return Result::Success;
}
```

### 4.3 Length Constants

```cpp
// GOOD: Use named constants
if (mac_length != MAC_LENGTH) {
    return Result::InvalidInput;
}

// BAD: Magic numbers
if (mac_length != 64) {  // What is 64?
    return Result::InvalidInput;
}
```

---

## 5. Cryptographic Operations

### 5.1 Using libsodium

```cpp
// GOOD: Initialize libsodium
bool init() {
    static std::once_flag init_flag;
    static bool init_success = false;

    std::call_once(init_flag, [] {
        init_success = sodium_init() != -1;
    });

    return init_success;
}

// GOOD: Check initialization before crypto operations
Result random_bytes(uint8_t* buffer, size_t length) {
    if (!init()) {
        return Result::CryptoError;
    }
    randombytes_buf(buffer, length);
    return Result::Success;
}
```

### 5.2 Constant-Time Operations

```cpp
// GOOD: Use constant-time comparison
if (crypto_verify_64(computed_mac, received_mac) != 0) {
    return Result::AuthenticationError;
}

// BAD: Variable-time comparison (timing leak!)
if (memcmp(computed_mac, received_mac, 64) != 0) {
    return Result::AuthenticationError;
}

// GOOD: Constant-time conditional copy
sodium_memcpy_if_condition(dest, src, len, condition);

// BAD: Branching on secret data
if (secret_byte == 0) {  // Timing leak!
    // ...
}
```

### 5.3 MAC Verification

```cpp
// GOOD: Verify MAC before decryption (explicit authentication)
Result decrypt_with_mac(const uint8_t* ciphertext, size_t ct_len,
                        const uint8_t* mac,
                        const uint8_t* key,
                        uint8_t* plaintext) {
    // Verify MAC first
    uint8_t computed_mac[MAC_LENGTH];
    compute_mac(ciphertext, ct_len, key, computed_mac);

    if (crypto_verify_64(mac, computed_mac) != 0) {
        sodium_memzero(computed_mac, sizeof(computed_mac));
        return Result::AuthenticationError;
    }

    sodium_memzero(computed_mac, sizeof(computed_mac));

    // Only decrypt after MAC verification
    decrypt(ciphertext, ct_len, key, plaintext);
    return Result::Success;
}
```

### 5.4 Domain Separation

```cpp
// GOOD: Use unique context strings for different operations
namespace labels {
    constexpr char kOprfSeedInfo[] = "Ecliptix-OPAQUE-OprfSeed";
    constexpr char kOprfKeyInfo[] = "Ecliptix-OPAQUE-OprfKey";
    constexpr char kEnvelopeContext[] = "Ecliptix-OPAQUE-Envelope";
    constexpr char kKsfContext[] = "Ecliptix-OPAQUE-KSF";
}

// GOOD: Include context in key derivation
Result derive_key(const uint8_t* ikm, size_t ikm_len,
                  const char* context,
                  uint8_t* output, size_t output_len) {
    return key_derivation_expand(
        ikm, ikm_len,
        reinterpret_cast<const uint8_t*>(context), strlen(context),
        output, output_len);
}
```

---

## 6. Error Handling

### 6.1 Result Types

```cpp
// Use the Result enum for all fallible operations
enum class Result {
    Success = 0,
    InvalidInput = -1,
    CryptoError = -2,
    InvalidPublicKey = -3,
    EnvelopeError = -4,
    AuthenticationError = -5,
    ProtocolError = -6
};
```

### 6.2 Error Propagation

```cpp
// GOOD: Check and propagate errors
Result complex_operation() {
    if (auto result = step_one(); result != Result::Success) {
        return result;
    }

    if (auto result = step_two(); result != Result::Success) {
        cleanup_step_one();  // Don't forget cleanup!
        return result;
    }

    return Result::Success;
}

// GOOD: RAII for automatic cleanup
Result complex_operation_raii() {
    SecureBuffer temp1(32);
    if (auto result = step_one(temp1); result != Result::Success) {
        return result;  // temp1 automatically cleaned
    }

    SecureBuffer temp2(64);
    if (auto result = step_two(temp2); result != Result::Success) {
        return result;  // temp1 and temp2 automatically cleaned
    }

    return Result::Success;
}
```

### 6.3 Error Information Leakage

```cpp
// GOOD: Generic error for authentication failures
if (mac_invalid || decryption_failed || key_mismatch) {
    return Result::AuthenticationError;  // Same error for all
}

// BAD: Detailed errors leak information
if (mac_invalid) return Result::MacInvalid;      // Tells attacker MAC is wrong
if (key_mismatch) return Result::KeyMismatch;    // Tells attacker about key
```

---

## 7. Logging and Debug Output

### 7.1 Debug Logging Requirements

Two compile-time flags control debug logging:

| Flag | Purpose | Default |
|------|---------|---------|
| `OPAQUE_DEBUG_LOGGING` | Core cryptographic function logging | **Disabled** |
| `OPAQUE_INTEROP_LOGGING` | C API interop layer logging | **Disabled** |

```cpp
// Debug logging MUST be guarded
#ifdef OPAQUE_DEBUG_LOGGING
    log::hex("public_key", public_key, 32);  // Only in debug builds
#endif

#ifdef OPAQUE_INTEROP_LOGGING
    OPAQUE_CLIENT_LOG("Processing request");  // Only in debug builds
#endif

// Production code must not contain unguarded logging
log::hex("secret", data, len);  // BAD: Will be compiled out but shouldn't exist
```

### 7.2 What MUST NEVER Be Logged

**NEVER log the following, even in debug mode:**
- Private keys
- Session keys
- Master keys
- Passwords/secure keys
- KEM shared secrets
- OPRF blind values

This is enforced in the interop layer with explicit comments:
```cpp
// NOTE: session_key and master_key are NEVER logged for security
OPAQUE_CLIENT_LOG("SUCCESS: client finished (keys derived, not logged)");
```

### 7.3 Safe Logging

```cpp
// GOOD: Log non-sensitive protocol state
log::msg("Starting registration");
log::section("Authentication Phase 2");

// GOOD: Log public values only
log::hex("public_key", public_key, PUBLIC_KEY_LENGTH);
log::hex("nonce", nonce, NONCE_LENGTH);

// Document why sensitive logging exists
#ifdef OPAQUE_DEBUG_LOGGING
// NOTE: Following line logs sensitive key material for protocol debugging
// This MUST be disabled in production (default behavior)
log::hex("derived_key", derived, 32);
#endif
```

---

## 8. Concurrency

### 8.1 Thread Safety

```cpp
// GOOD: Use std::once_flag for one-time initialization
bool init() {
    static std::once_flag init_flag;
    static bool success = false;

    std::call_once(init_flag, [] {
        success = sodium_init() != -1;
    });

    return success;
}

// State objects should document thread safety
/**
 * @class InitiatorState
 * @note NOT thread-safe. Each authentication session requires
 *       its own state object.
 */
class InitiatorState { /* ... */ };
```

### 8.2 Shared State

```cpp
// Avoid shared mutable state where possible
// If necessary, use proper synchronization

// GOOD: State per session, no sharing needed
void handle_session() {
    InitiatorState state;  // Session-local
    // ... use state ...
}  // State destroyed with session

// BAD: Shared state without protection
static uint8_t shared_buffer[1024];  // Race condition!
```

---

## 9. Build Security

### 9.1 Compiler Flags

Always build with hardening flags (enabled by default):

```cmake
# GCC/Clang
-fstack-protector-strong    # Stack canaries
-fPIC                       # Position independent code
-D_FORTIFY_SOURCE=2         # Buffer overflow detection
-Wformat -Wformat-security  # Format string protection
-Wall -Wextra -Werror       # Warnings as errors
-Wconversion                # Type conversion warnings
```

### 9.2 Warnings Policy

```cpp
// ALL warnings must be resolved
// Use explicit casts when necessary

// GOOD: Explicit cast with comment
auto index = static_cast<size_t>(signed_value);  // Known non-negative

// BAD: Implicit conversion warning ignored
size_t index = signed_value;  // Warning suppressed elsewhere
```

---

## 10. Code Review Security Checklist

Before approving any PR, verify:

### Memory Safety
- [ ] All sensitive data uses SecureBuffer or secure_bytes
- [ ] All intermediate sensitive values are zeroed
- [ ] No unbounded allocations from user input
- [ ] Array bounds checked before access

### Input Validation
- [ ] All public API functions validate inputs
- [ ] Null pointers checked
- [ ] Size parameters validated
- [ ] Cryptographic inputs validated (points, scalars)

### Cryptographic Correctness
- [ ] libsodium/liboqs APIs used correctly
- [ ] No custom cryptographic implementations
- [ ] MAC verified before decryption
- [ ] Constant-time comparisons for secrets
- [ ] Domain separation contexts used

### Error Handling
- [ ] All errors propagated correctly
- [ ] Cleanup performed on error paths
- [ ] No information leakage in error messages

### Logging
- [ ] No debug logging without OPAQUE_DEBUG_LOGGING guard
- [ ] No interop logging without OPAQUE_INTEROP_LOGGING guard
- [ ] Session keys, master keys, and private keys are NEVER logged
- [ ] No sensitive data in production logs

### Build
- [ ] No new warnings introduced
- [ ] Tests pass on all platforms

---

## 11. References

- [libsodium Documentation](https://doc.libsodium.org/)
- [liboqs Documentation](https://openquantumsafe.org/)
- [OWASP Secure Coding Practices](https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/)
- [CERT C++ Coding Standard](https://wiki.sei.cmu.edu/confluence/display/cplusplus)
- [OPAQUE RFC Draft](https://datatracker.ietf.org/doc/draft-irtf-cfrg-opaque/)

---

## 12. Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-02-01 | Security Lead | Initial guidelines |

---

*This document is part of the Ecliptix Information Security Management System (ISMS) and is subject to regular review and updates.*
