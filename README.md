# Ecliptix OPAQUE

[![CI](https://github.com/oleksandrmelnychenko/ecliptix-opaque/actions/workflows/ci.yml/badge.svg)](https://github.com/oleksandrmelnychenko/ecliptix-opaque/actions/workflows/ci.yml)
[![Benchmarks](https://github.com/oleksandrmelnychenko/ecliptix-opaque/actions/workflows/benchmarks.yml/badge.svg)](https://github.com/oleksandrmelnychenko/ecliptix-opaque/actions/workflows/benchmarks.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Hybrid post-quantum **OPAQUE** implementation in Rust combining **3DH Ristretto255** with **ML-KEM-768** for quantum-resistant password-authenticated key exchange.

## Security Properties

All seven properties are formally verified (Tamarin 8/8 lemmas, ProVerif 5/5 queries) and validated by 39 Rust computational tests:

| Property | Tamarin | ProVerif | Rust |
|----------|---------|----------|------|
| Session key secrecy | verified | verified | 4 |
| Password secrecy | verified | verified | 7 |
| Classical forward secrecy | verified | - | 3 |
| Post-quantum forward secrecy | verified | - | 3 |
| Mutual authentication | verified | verified | 8 |
| AND-model hybrid security | verified | - | 4 |
| Offline dictionary resistance | verified | verified | 6 |

## Cryptographic Primitives

| Primitive | Algorithm | Source |
|-----------|-----------|--------|
| Elliptic Curve DH | Ristretto255 (3DH) | libsodium |
| Key Encapsulation | ML-KEM-768 | ml-kem (FIPS 203) |
| Key Stretching | Argon2id | libsodium |
| MAC | HMAC-SHA512 | libsodium |
| AEAD | XSalsa20-Poly1305 | libsodium |
| OPRF | Ristretto255 | libsodium |
| PQ Combiner | HKDF-SHA512 (AND-model) | libsodium |

## Architecture

```
rust/crates/
  opaque-core/     Cryptographic primitives, OPRF, KEM, envelope
  opaque-agent/    Agent (initiator) — registration & authentication
  opaque-relay/    Relay (responder) — registration & authentication
  opaque-ffi/      C FFI bindings (cdylib + staticlib)
```

## Build

```bash
cd rust
cargo build --release
```

No system dependencies required. `libsodium-sys-stable` builds libsodium from source automatically.

## Test

```bash
cd rust
cargo test --workspace
```

## Benchmarks

```bash
cd rust
cargo bench --workspace
```

Three Criterion benchmark suites:
- **Micro** — Ristretto255 keygen/DH, ML-KEM-768, OPRF, Argon2id, HMAC, HKDF, AEAD
- **Protocol** — registration and authentication phases end-to-end
- **Throughput** — relay KE2 generation and finish operations per second

## FFI

The `opaque-ffi` crate exports a C API via `cbindgen`. Swift bindings in `swift/` call the Rust FFI exports directly.

| Platform | Package |
|----------|---------|
| .NET | `Ecliptix.OPAQUE.Agent` / `Ecliptix.OPAQUE.Relay` (NuGet) |
| iOS/macOS | `EcliptixOPAQUE.xcframework` |
| Android | AAR via GitHub Packages |

## Formal Verification

Models and proof logs in `formal/`:

- `hybrid_pq_opaque.spthy` — Tamarin model (8 lemmas, verified in 22.83s)
- `hybrid_pq_opaque.pv` — ProVerif model (5 queries)
- `logs/` — full verification transcripts and reports

## License

MIT License — see [LICENSE](LICENSE).

Copyright (c) 2026 Oleksandr Melnychenko, Ukraine
