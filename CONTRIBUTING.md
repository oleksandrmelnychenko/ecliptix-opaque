# Contributing to Ecliptix.Security.OPAQUE

Thank you for your interest in contributing to Ecliptix.Security.OPAQUE! This document provides guidelines and security requirements for contributors.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Security Requirements](#security-requirements)
- [Getting Started](#getting-started)
- [Development Process](#development-process)
- [Coding Standards](#coding-standards)
- [Testing Requirements](#testing-requirements)
- [Pull Request Process](#pull-request-process)

## Code of Conduct

By participating in this project, you agree to maintain a respectful, inclusive, and professional environment. We expect all contributors to:

- Be respectful and inclusive
- Accept constructive criticism gracefully
- Focus on what is best for the project
- Show empathy towards other community members

## Security Requirements

**This is a cryptographic security library. All contributors must adhere to strict security practices.**

### Before Contributing

1. **Read the security documentation**:
   - `docs/security-review/THREAT_MODEL.md`
   - `docs/security-review/PROTOCOL_SUMMARY.md`
   - `docs/security-review/LIMITATIONS.md`
   - `docs/isms/SECURE_CODING_GUIDELINES.md`

2. **Understand the security implications** of your changes

3. **Never commit sensitive data**:
   - Private keys
   - Passwords or secrets
   - API tokens
   - Test credentials (use constants like in tests/)

### Security Checklist for Contributions

All contributions involving code changes must satisfy:

- [ ] No sensitive data in commits
- [ ] No debug logging calls without `OPAQUE_DEBUG_LOGGING` guards
- [ ] All cryptographic operations use libsodium/liboqs APIs correctly
- [ ] Memory containing secrets is zeroed with `sodium_memzero()`
- [ ] Input validation for all public API functions
- [ ] No compiler warnings with `-Wall -Wextra -Werror`
- [ ] Tests pass on all supported platforms
- [ ] Security hardening flags remain enabled

### Reporting Security Issues

**Do NOT report security vulnerabilities through GitHub issues.**

See [SECURITY.md](SECURITY.md) for the vulnerability disclosure process.

## Getting Started

### Prerequisites

- C++23 compatible compiler (GCC 13+, Clang 17+, MSVC 19.36+)
- CMake 3.20+
- libsodium >= 1.0.20
- liboqs >= 0.12.0

### Building

```bash
# Clone the repository
git clone https://github.com/oleksandrmelnychenko/ecliptix-opaque.git
cd ecliptix-opaque

# Build with tests
./build.sh native Release ON

# Run tests
ctest --test-dir build-macos-release --output-on-failure
```

### Development Setup

```bash
# Debug build with additional checks
mkdir build-debug && cd build-debug
cmake .. -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=ON -DENABLE_HARDENING=ON
cmake --build .
```

## Development Process

### Branching Strategy

- `main` - Stable release branch
- `develop` - Integration branch for features
- `feature/*` - Feature branches
- `fix/*` - Bug fix branches
- `security/*` - Security-related changes (require additional review)

### Commit Messages

Use conventional commit format:

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `security`: Security-related change
- `docs`: Documentation
- `test`: Test changes
- `refactor`: Code refactoring
- `build`: Build system changes

Examples:
```
feat(initiator): add session key export function
fix(responder): correct MAC verification timing
security(memory): add zeroization for temporary buffers
docs(api): update C API documentation
```

## Coding Standards

### C++ Style

- Follow modern C++23 idioms
- Use `[[nodiscard]]`, `[[likely]]`, `[[unlikely]]` attributes appropriately
- Prefer `constexpr` where possible
- Use `secure_bytes` for sensitive data containers
- All public functions must validate inputs

### Naming Conventions

```cpp
namespace ecliptix::security::opaque {

// Types: PascalCase
class OpaqueInitiator;
struct RegistrationRequest;

// Functions: snake_case
Result create_registration_request(...);

// Constants: kPascalCase or UPPER_CASE
constexpr size_t kPrivateKeyLength = 32;
constexpr size_t PRIVATE_KEY_LENGTH = 32;

// Private members: trailing underscore
class Example {
    uint8_t* data_;
    size_t size_;
};

}
```

### Memory Management

```cpp
// ALWAYS zero sensitive data before deallocation
void cleanup_sensitive_data(uint8_t* buffer, size_t size) {
    sodium_memzero(buffer, size);
}

// Use SecureBuffer for automatic cleanup
SecureBuffer key_material(PRIVATE_KEY_LENGTH);
// ... use key_material ...
// Automatically zeroed on destruction

// Use RAII for all resources
{
    SecureBuffer temp(64);
    // ... operations ...
} // temp zeroed and freed here
```

### Error Handling

```cpp
// Return Result enum for all fallible operations
Result do_something() {
    if (!input) [[unlikely]] {
        return Result::InvalidInput;
    }
    // ...
    return Result::Success;
}

// Check results at call sites
if (auto result = do_something(); result != Result::Success) {
    // Handle error
    return result;
}
```

## Testing Requirements

### Test Coverage

- All new public API functions must have tests
- Test both success and failure paths
- Test edge cases and boundary conditions
- Test with invalid inputs

### Test Structure

```cpp
TEST_CASE("Feature description", "[module][category]") {
    // Setup
    REQUIRE(sodium_init() >= 0);

    SECTION("Specific scenario") {
        // Test code
        REQUIRE(result == expected);
    }

    SECTION("Error handling") {
        // Test error cases
        REQUIRE(result == Result::InvalidInput);
    }
}
```

### Running Tests

```bash
# Run all tests
ctest --test-dir build --output-on-failure

# Run specific test
./build/tests/test_opaque_protocol "[opaque][protocol]"

# Run with verbose output
ctest --test-dir build -V
```

## Pull Request Process

### Before Submitting

1. Ensure all tests pass locally
2. Run the full test suite on your platform
3. Update documentation if needed
4. Add CHANGELOG.md entry for notable changes
5. Review your changes for security implications

### PR Requirements

- Clear description of changes
- Reference related issues
- Security checklist completed
- Tests for new functionality
- Documentation updates

### Review Process

1. **Automated checks**: CI must pass
2. **Code review**: At least one maintainer approval
3. **Security review**: Required for `security/*` branches or cryptographic changes
4. **Merge**: Squash and merge to maintain clean history

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Security fix
- [ ] Documentation
- [ ] Refactoring

## Security Checklist
- [ ] No sensitive data committed
- [ ] Debug logging properly guarded
- [ ] Memory properly zeroed
- [ ] Input validation added
- [ ] No new compiler warnings

## Testing
- [ ] Unit tests added/updated
- [ ] All existing tests pass
- [ ] Tested on: [platforms]

## Related Issues
Fixes #(issue number)
```

## Questions?

- Open a GitHub Discussion for general questions
- See [SECURITY.md](SECURITY.md) for security-related inquiries
- Review existing issues before creating new ones

Thank you for contributing to Ecliptix.Security.OPAQUE!
