// Copyright (c) 2026 Oleksandr Melnychenko, Ukraine
// Ecliptix Security — Hybrid PQ-OPAQUE Protocol
// Licensed under the MIT License

//! Core library for the Ecliptix Hybrid PQ-OPAQUE protocol.
//!
//! Implements a post-quantum-resistant asymmetric PAKE (aPAKE) protocol that
//! combines a classical 4DH key exchange over Ristretto255 with ML-KEM-768
//! in an AND-composition, requiring an attacker to break **both** the elliptic
//! curve discrete-logarithm problem and Module-LWE simultaneously.
//!
//! # Crate layout
//!
//! * [`types`] -- shared constants, error types, and secure byte containers.
//! * [`crypto`] -- low-level cryptographic primitives (libsodium wrappers, HKDF, Argon2id).
//! * [`oprf`] -- oblivious pseudo-random function over Ristretto255.
//! * [`pq_kem`] -- ML-KEM-768 key encapsulation and hybrid key combiner.
//! * [`envelope`] -- credential envelope seal/open using authenticated encryption.
//! * [`protocol`] -- wire-format serialization and deserialization for KE1/KE2/KE3 messages.

/// Low-level cryptographic primitives wrapping libsodium.
pub mod crypto;
/// Credential envelope seal and open operations.
pub mod envelope;
/// Oblivious pseudo-random function (OPRF) over Ristretto255.
pub mod oprf;
/// ML-KEM-768 post-quantum key encapsulation and hybrid key combiner.
pub mod pq_kem;
/// Wire-format serialization and parsing for protocol messages.
pub mod protocol;
/// Shared constants, error types, and secure byte containers.
pub mod types;
