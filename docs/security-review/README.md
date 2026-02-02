# Ecliptix.Security.OPAQUE External Security Review Package

This package is intended for an external cryptographic and implementation security review of the Ecliptix OPAQUE library. The scope includes protocol design, cryptographic correctness, implementation safety, interop boundaries, and side-channel considerations.

## Scope
- Protocol and cryptographic design
- C++ core implementation
- C interop API
- C# bindings that call the C API
- Build configurations and deployment artifacts
- Side-channel and memory safety analysis

## Contents
- RFP.md
- THREAT_MODEL.md
- PROTOCOL_SUMMARY.md
- API_SURFACE.md
- BUILD_AND_TEST.md
- DEPENDENCIES.md
- TEST_VECTORS.md
- LIMITATIONS.md

## Quick Start
- Build: see BUILD_AND_TEST.md
- Tests: see BUILD_AND_TEST.md
- API surface: see API_SURFACE.md
- Protocol: see PROTOCOL_SUMMARY.md

## Version and Commit
- Library version: 1.0.3
- Commit: Run `git rev-parse HEAD` to get the exact commit hash for review
- Date: 2025-02

## Source Layout
- C++ headers: include/opaque
- C++ core: src/core
- C++ initiator: src/initiator
- C++ responder: src/responder
- C interop: src/interop
- Tests: tests

## Additional Documentation
- ISMS documentation: ../isms/
- Security policy: ../../SECURITY.md
- Changelog: ../../CHANGELOG.md
- Contributing guidelines: ../../CONTRIBUTING.md

## Security Notes
- Debug logging is now disabled by default and requires `OPAQUE_DEBUG_LOGGING` preprocessor flag to enable. Reviewers should verify this flag is not set in production builds.
- OPAQUE flow is implemented with Ristretto255, HMAC-SHA512, Argon2id, and ML-KEM-768 via libsodium and liboqs.
- All sensitive memory is zeroed using `sodium_memzero()` before deallocation.
- Build hardening is enabled by default (`-DENABLE_HARDENING=ON`).
