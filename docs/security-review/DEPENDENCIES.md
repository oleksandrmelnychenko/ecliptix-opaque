# Dependencies

## Core Libraries
- libsodium (>= 1.0.20)
  - Ristretto255 operations
  - HMAC-SHA512
  - secretbox
  - Argon2id (crypto_pwhash)
- liboqs (>= 0.10.0)
  - ML-KEM-768 key encapsulation

## Test Framework
- Catch2 v3.4.0 (FetchContent)

## Build Tooling
- CMake 3.20+
- C++23 compiler

## Vcpkg Baseline
- vcpkg builtin-baseline: e6e4bc74aaf5c63dfc358810594f662f7e9bc4d4
