# C++ to Rust Migration Plan: Ecliptix.Security.OPAQUE

## Overview

Migrate the Hybrid PQ-OPAQUE protocol implementation from C++23 to Rust,
preserving wire-format compatibility, C FFI surface, and all security properties.

**Source:** ~7,500 LOC C++23 (src/ + include/ + interop/ + tests/ + benchmarks/)
**Target:** ~4,800 LOC Rust (estimated)

---

## Phase 1: Project Setup & Core Types

### 1.1 Create Rust workspace

```
ecliptix-opaque/rust/
├── Cargo.toml              # workspace root
├── crates/
│   ├── opaque-core/        # crypto primitives + types + protocol
│   ├── opaque-client/      # initiator (eop.agent)
│   ├── opaque-server/      # responder (eop.relay)
│   └── opaque-ffi/         # C API exports (cdylib)
├── tests/                  # integration tests
└── benches/                # criterion benchmarks
```

### 1.2 Dependencies (Cargo.toml)

Pure Rust implementation — no C library dependencies.

```toml
[workspace.dependencies]
curve25519-dalek = { version = "4", features = ["serde", "digest"] }
xsalsa20poly1305 = "0.9"       # XSalsa20-Poly1305 (crypto_secretbox equivalent)
hmac = "0.12"                   # HMAC
sha2 = "0.10"                   # SHA-512
argon2 = "0.5"                  # Argon2id
ml-kem = "0.2"                  # ML-KEM-768 (NIST FIPS 203)
zeroize = { version = "1", features = ["derive"] }
subtle = "2"                    # Constant-time operations
rand = "0.8"                    # CSPRNG
thiserror = "2"                 # Error types
```

> **Wire compatibility:** All algorithms follow published standards:
> - Ristretto255: RFC 9496 (curve25519-dalek + libsodium use same spec)
> - XSalsa20-Poly1305: NaCl spec (xsalsa20poly1305 crate)
> - HMAC-SHA512: RFC 2104 (deterministic)
> - Argon2id: RFC 9106 (deterministic for same params)
> - ML-KEM-768: NIST FIPS 203 (deterministic for same randomness)
>
> Test vectors from C++ implementation verify wire compatibility.

### 1.3 Core types (opaque-core/src/types.rs)

Port from `include/opaque/opaque.h`:
- All constants (OPRF_SEED_LENGTH, PRIVATE_KEY_LENGTH, etc.)
- `Result` enum → `OpaqueError` with `thiserror`
- `SecureBytes` → `Vec<u8>` with `Zeroize` derive
- `Envelope`, `ResponderPublicKey`, `InitiatorCredentials`, `ResponderCredentials`
- Protocol labels (kOprfContext, kEnvelopeContext, etc.) as `const &[u8]`
- PQ constants and PQ labels

---

## Phase 2: Core Cryptographic Module (opaque-core)

### 2.1 crypto.rs — port of src/core/crypto.cpp (380 LOC)

Functions to port:
- `init()` → `OnceLock`-based sodium_init
- `random_bytes()` → `randombytes_buf` wrapper
- `derive_key_pair()` → SHA-512 + scalar_reduce + scalarmult_base
- `scalar_mult()` → `crypto_scalarmult_ristretto255`
- `validate_ristretto_point()` / `validate_public_key()`
- `hash_to_scalar()`, `hash_to_group()`
- `hmac()` → HMAC-SHA512 streaming API
- `derive_oprf_key()` — OPRF key derivation with counter loop
- `derive_randomized_password()` — Argon2id with labeled hash
- `verify_hmac()` — constant-time MAC comparison
- `key_derivation_extract()` / `key_derivation_expand()` — HKDF-SHA512
- `encrypt_envelope()` / `decrypt_envelope()` — XSalsa20-Poly1305 detached

All functions return `Result<(), OpaqueError>` (Rust idiomatic).
All intermediate buffers use `Zeroizing<[u8; N]>` for auto-cleanup.

### 2.2 oprf.rs — port of src/core/oprf.cpp (153 LOC)

Functions:
- `hash_to_group()` — domain-separated SHA-512 → ristretto255_from_hash
- `blind()` — random non-zero scalar + scalarmult
- `evaluate()` — scalar multiplication
- `finalize()` — scalar inverse + unblind + domain-separated hash

### 2.3 envelope.rs — port of src/core/envelope.cpp (122 LOC)

Functions:
- `seal()` — derive auth_key from context+password, encrypt (rpk||isk||ipk)
- `open()` — decrypt and validate contents, verify derived public key

### 2.4 pq_kem.rs — port of src/core/pq_kem.cpp (214 LOC)

Functions (via oqs-sys):
- `init()` → OQS_init
- `keypair_generate()` → OQS_KEM_keypair
- `encapsulate()` → OQS_KEM_encaps
- `decapsulate()` → OQS_KEM_decaps
- `combine_key_material()` — classical + PQ IKM → HKDF extract

### 2.5 protocol.rs — port of src/core/protocol.cpp (140 LOC)

Zero-copy parsing with lifetime-bound views (Rust references):
- `parse_registration_response()` → `RegistrationResponseRef<'a>`
- `parse_ke1()` → `Ke1Ref<'a>`
- `parse_ke2()` → `Ke2Ref<'a>`
- `parse_ke3()` → `Ke3Ref<'a>`
- `write_registration_record()`, `write_ke1()`, `write_ke2()`, `write_ke3()`

### 2.6 memory.rs — port of src/core/memory.cpp (203 LOC)

Drastically simplified in Rust:
- `SecureBytes` = `Zeroizing<Vec<u8>>` (auto-zeroed on drop)
- `SecureLocal<N>` = `Zeroizing<[u8; N]>` (stack buffer, auto-zeroed)
- `SecureBuffer` = page-aligned allocation with mlock (thin wrapper)
- No `ScopeGuard` needed — Rust `Drop` handles cleanup automatically
- No `OPAQUE_TRY` macro — use `?` operator

---

## Phase 3: Client Module (opaque-client)

### 3.1 registration.rs — port of src/initiator/registration.cpp (150 LOC)

- `create_registration_request()` — generate EC keypair, OPRF blind
- `finalize_registration()` — OPRF finalize, derive randomized_pwd, seal envelope

### 3.2 authentication.rs — port of src/initiator/authentication.cpp (278 LOC)

- `generate_ke1()` — ephemeral EC keypair, PQ keypair, OPRF blind, nonce
- `generate_ke3()` — parse KE2, OPRF finalize, envelope open, 3-DH + PQ KEM,
  transcript hash, PRK derivation, MAC verify, initiator MAC generation

### 3.3 key_management.rs — port of src/initiator/key_management.cpp (142 LOC)

- `InitiatorState` struct with `Zeroize` derive
- `OpaqueInitiator` builder pattern
- `initiator_finish()` — export session_key + master_key

---

## Phase 4: Server Module (opaque-server)

### 4.1 registration.rs — port of src/responder/registration.cpp (95 LOC)

- `create_registration_response()` — derive OPRF key, evaluate, respond
- `build_credentials()` — parse registration record

### 4.2 authentication.rs — port of src/responder/authentication.cpp (292 LOC)

- `generate_ke2()` — ephemeral EC keypair, OPRF evaluate, credential response,
  3-DH + PQ encapsulate, transcript hash, PRK, MAC generation
- `responder_finish()` — verify initiator MAC, export keys

### 4.3 server.rs — port of src/responder/server.cpp (131 LOC)

- `ResponderKeyPair` with `Zeroize` derive
- `OpaqueResponder` struct
- Keypair generation + validation

---

## Phase 5: FFI Layer (opaque-ffi)

### 5.1 agent_ffi.rs — port of src/interop/initiator_exports.cpp (426 LOC)

C-compatible API using `#[no_mangle] pub unsafe extern "C"`:
- `opaque_agent_create()`
- `opaque_agent_destroy()`
- `opaque_agent_state_create()` / `opaque_agent_state_destroy()`
- `opaque_agent_create_registration_request()`
- `opaque_agent_finalize_registration()`
- `opaque_agent_generate_ke1()`
- `opaque_agent_generate_ke3()`
- `opaque_agent_finish()`
- Size query functions

Use `Box::into_raw` / `Box::from_raw` for opaque handles.
Generate C headers automatically with `cbindgen`.

### 5.2 relay_ffi.rs — port of src/interop/responder_exports.cpp (443 LOC)

C-compatible API:
- `opaque_relay_keypair_generate()` / `opaque_relay_keypair_destroy()`
- `opaque_relay_create()` / `opaque_relay_destroy()`
- `opaque_relay_state_create()` / `opaque_relay_state_destroy()`
- `opaque_relay_create_registration_response()`
- `opaque_relay_build_credentials()`
- `opaque_relay_generate_ke2()`
- `opaque_relay_finish()`
- `opaque_relay_create_with_keys()`
- `opaque_relay_derive_keypair_from_seed()`

### 5.3 cbindgen.toml

Auto-generate `opaque.h` from Rust code.

---

## Phase 6: Tests

### 6.1 Unit tests (inline #[cfg(test)])

Each module gets inline tests matching the C++ Catch2 tests:
- Registration flow (valid, tampering, account ID variants)
- Authentication flow (success, wrong password, tampered KE2)
- PQ integration (encapsulate/decapsulate)
- Protocol edge cases
- Individual crypto primitive tests

### 6.2 Integration tests (tests/)

Full registration + authentication flow tests:
- `test_full_protocol_flow` — end-to-end registration + authentication
- `test_wrong_password` — authentication with wrong password fails
- `test_tampered_ke2` — tampered KE2 message detected
- `test_tampered_ke3` — tampered KE3 message detected
- `test_c_api` — FFI surface tests via the C API

### 6.3 Wire compatibility tests

Generate test vectors from C++ implementation, verify Rust produces identical output.

---

## Phase 7: Benchmarks

Port benchmarks to `criterion`:
- Micro primitives (OPRF, key derivation, encrypt/decrypt)
- Protocol phases (registration, KE1/KE2/KE3)
- Throughput (end-to-end handshakes/sec)
- Wire overhead (message size analysis)

---

## Phase 8: CI/CD & Packaging

### 8.1 GitHub Actions

- Build + test on Linux, macOS, Windows
- Cross-compile for Android (NDK), iOS (aarch64-apple-ios)
- Security scan (cargo audit, cargo deny)
- Benchmark regression tracking

### 8.2 Build outputs

- `libeop_agent.so/.dylib/.dll` (cdylib)
- `libeop_relay.so/.dylib/.dll` (cdylib)
- C headers (auto-generated by cbindgen)
- NuGet packages (via existing .NET interop)

---

## Implementation Order

| Step | Module | Depends On | Description |
|------|--------|-----------|-------------|
| 1 | workspace setup | — | Cargo.toml, folder structure, CI skeleton |
| 2 | opaque-core/types | — | Constants, error types, SecureBytes |
| 3 | opaque-core/memory | types | Zeroizing wrappers |
| 4 | opaque-core/crypto | types, memory | Ristretto255, HMAC, HKDF, Argon2id, XSalsa20 |
| 5 | opaque-core/oprf | crypto | Blind, evaluate, finalize |
| 6 | opaque-core/envelope | crypto | Seal, open |
| 7 | opaque-core/pq_kem | crypto | ML-KEM-768 via oqs-sys |
| 8 | opaque-core/protocol | types | Wire format parse/write |
| 9 | opaque-client | opaque-core | Initiator registration + authentication |
| 10 | opaque-server | opaque-core | Responder registration + authentication |
| 11 | opaque-ffi | client + server | C API + cbindgen |
| 12 | tests | all | Unit + integration + wire compat |
| 13 | benchmarks | core + client + server | Criterion benchmarks |
| 14 | CI/CD | all | GitHub Actions workflows |

---

## Key Design Decisions

### 1. Pure Rust crates (no C dependencies)

**Decision: Use `curve25519-dalek` + `ml-kem` + RustCrypto ecosystem**

Rationale:
- No C build toolchain needed (simpler cross-compilation)
- Better Rust integration, `no_std` possible in future
- All crates follow the same RFCs/standards as libsodium/liboqs
- Actively audited (curve25519-dalek by Quarkslab, ml-kem by RustCrypto)
- Wire compatibility verified via test vectors from C++ implementation

### 2. Error handling

**Decision: `Result<T, OpaqueError>` with `thiserror`**

Replace C++ `Result` enum + `[[nodiscard]]` with Rust's native `Result` type.
The `?` operator replaces `OPAQUE_TRY` macro.
The compiler enforces error handling (no forgotten checks).

### 3. Memory safety

**Decision: `zeroize` crate + `Drop` trait**

Replace 203 LOC of manual memory management with:
- `#[derive(Zeroize, ZeroizeOnDrop)]` on state structs
- `Zeroizing<T>` wrapper for temporary buffers
- No `ScopeGuard`, no `SecureAllocator` — Rust ownership handles it

### 4. FFI strategy

**Decision: `#[no_mangle] extern "C"` + `cbindgen`**

- Same C function signatures as C++ interop layer
- `Box::into_raw` / `Box::from_raw` for opaque handles
- `cbindgen` auto-generates `opaque.h` (replaces manual header)
- Drop-in replacement for existing consumers (.NET, Android, Swift)
