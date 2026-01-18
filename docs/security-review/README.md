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
- Library version: 1.0.0
- Commit: fill in the exact git commit hash used for review

## Source Layout
- C++ headers: include/opaque
- C++ core: src/core
- C++ initiator: src/initiator
- C++ responder: src/responder
- C interop: src/interop
- Tests: tests

## Security Notes
- Debug logging prints sensitive material. Reviewers should assume logging is for development only and assess risk if enabled in production builds.
- OPAQUE flow is implemented with Ristretto255, HMAC-SHA512, Argon2id, and ML-KEM-768 via libsodium and liboqs.
