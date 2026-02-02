# Changelog

All notable changes to Ecliptix.Security.OPAQUE will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-02-02

### Added
- OPAQUE password-authenticated key exchange protocol implementation
- Ristretto255 elliptic curve operations via libsodium
- ML-KEM-768 post-quantum key encapsulation via liboqs
- Argon2id key stretching function
- HMAC-SHA512 message authentication
- XChaCha20-Poly1305 authenticated encryption
- C++ API with modern C++23 features
- C API for interoperability
- Multi-platform support (macOS, Linux, Windows, iOS, Android)
- iOS XCFramework with static dependencies
- Android AAR package with JNI bindings
- NuGet packages for .NET integration
- Swift package support
- ISO 27001/27002 compliance documentation
- Security policy and vulnerability disclosure process
- Secure coding guidelines

### Security
- Secure memory management with page-level protection
- Guaranteed zeroization of sensitive data
- Memory locking where supported
- Build-time hardening flags enabled by default
- Debug logging disabled by default (compile-time guards)
- Dependency versions locked

[1.0.0]: https://github.com/oleksandrmelnychenko/ecliptix-opaque/releases/tag/v1.0.0
