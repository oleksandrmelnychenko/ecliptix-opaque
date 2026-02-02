# Ecliptix.Security.OPAQUE

[![CI](https://github.com/oleksandrmelnychenko/ecliptix-opaque/actions/workflows/ci.yml/badge.svg)](https://github.com/oleksandrmelnychenko/ecliptix-opaque/actions/workflows/ci.yml)
[![Security Scan](https://github.com/oleksandrmelnychenko/ecliptix-opaque/actions/workflows/security-scan.yml/badge.svg)](https://github.com/oleksandrmelnychenko/ecliptix-opaque/actions/workflows/security-scan.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A modern C++23 implementation of the **OPAQUE** password-authenticated key exchange (PAKE) protocol with integrated **post-quantum cryptographic protection** via ML-KEM-768.

## Features

- **Zero-knowledge authentication** - Passwords are never transmitted to the server
- **Offline attack resistance** - Stored records don't permit dictionary attacks
- **Mutual authentication** - Both client and server verify each other
- **Forward secrecy** - Ephemeral keys protect past sessions
- **Post-quantum security** - ML-KEM-768 hybrid key encapsulation
- **Cross-platform** - macOS, Linux, Windows, iOS, Android

## Cryptographic Primitives

| Primitive | Algorithm | Library |
|-----------|-----------|---------|
| Elliptic Curve | Ristretto255 | libsodium |
| Key Encapsulation | ML-KEM-768 | liboqs |
| Key Stretching | Argon2id | libsodium |
| MAC | HMAC-SHA512 | libsodium |
| AEAD | XChaCha20-Poly1305 | libsodium |

## Quick Start

### Prerequisites

- CMake 3.20+
- C++23 compiler (GCC 13+, Clang 17+, MSVC 19.36+)
- libsodium >= 1.0.20
- liboqs >= 0.12.0

### Build

```bash
# macOS (Homebrew)
brew install libsodium liboqs cmake
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure

# Linux (Ubuntu/Debian)
sudo apt-get install build-essential cmake libsodium-dev
# Install liboqs from source (see BUILD.md)
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
```

See [BUILD.md](BUILD.md) for detailed build instructions.

## Usage

### C++ API

```cpp
#include <opaque/initiator.h>
#include <opaque/responder.h>

using namespace ecliptix::security::opaque;

// Server: Generate key pair
auto keypair = ResponderKeyPair::generate();

// Client: Create registration request
auto [request, state] = OpaqueInitiator::create_registration_request(
    password, password_len, keypair.public_key);

// Server: Process registration
auto response = OpaqueResponder::create_registration_response(
    server, request, account_id);

// Client: Finalize registration
auto record = OpaqueInitiator::finalize_registration(
    state, response, keypair.public_key);

// Store record on server...

// Authentication follows similar pattern with KE1, KE2, KE3 messages
```

### C API

```c
// Create client with server's public key
void* client;
opaque_client_create(server_public_key, key_len, &client);

// Registration and authentication functions available
// See docs/security-review/API_SURFACE.md for full API
```

### Platform SDKs

| Platform | Package | Installation |
|----------|---------|--------------|
| .NET | NuGet | `dotnet add package Ecliptix.OPAQUE.Agent` |
| iOS/macOS | Swift Package | Add XCFramework from releases |
| Android | Maven/AAR | Add AAR to libs folder |

## Documentation

| Document | Description |
|----------|-------------|
| [BUILD.md](BUILD.md) | Build instructions |
| [SECURITY.md](SECURITY.md) | Security policy & vulnerability reporting |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Contributor guidelines |
| [CHANGELOG.md](CHANGELOG.md) | Version history |
| [docs/security-review/](docs/security-review/) | External security review package |
| [docs/isms/](docs/isms/) | ISO 27001 compliance documentation |

## Security

This library implements security-critical cryptographic protocols. Please:

- **Report vulnerabilities** via [SECURITY.md](SECURITY.md) - not public issues
- **Keep dependencies updated** - monitor security advisories
- **Never enable debug logging** in production builds
- **Use TLS** for transport security

### Security Features

- Build hardening enabled by default (stack protection, FORTIFY_SOURCE, etc.)
- Secure memory allocation with automatic zeroization
- Memory locking to prevent swapping of secrets
- Constant-time operations for side-channel resistance

## Project Structure

```
├── include/opaque/     # Public headers
├── src/
│   ├── core/          # Cryptographic primitives
│   ├── initiator/     # Client-side protocol
│   ├── responder/     # Server-side protocol
│   └── interop/       # C API exports
├── tests/             # Unit tests
├── docs/
│   ├── security-review/   # External audit materials
│   └── isms/              # ISO 27001 documentation
├── nuget/             # .NET packages
├── android/           # Android AAR
└── swift/             # Swift package
```

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- [libsodium](https://libsodium.org/) - Cryptographic primitives
- [liboqs](https://openquantumsafe.org/) - Post-quantum algorithms
- [OPAQUE](https://datatracker.ietf.org/doc/draft-irtf-cfrg-opaque/) - Protocol specification

---

**Note**: This implementation is OPAQUE-like and has not been formally verified against the IETF OPAQUE standard. See [docs/security-review/LIMITATIONS.md](docs/security-review/LIMITATIONS.md) for known limitations.
