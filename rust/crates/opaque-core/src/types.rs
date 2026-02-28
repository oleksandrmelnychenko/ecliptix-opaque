// Copyright (c) 2026 Oleksandr Melnychenko, Ukraine
// Ecliptix Security — Hybrid PQ-OPAQUE
// Licensed under the MIT License

use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Length of the OPRF seed in bytes.
pub const OPRF_SEED_LENGTH: usize = 32;
/// Length of a Ristretto255 private (scalar) key in bytes.
pub const PRIVATE_KEY_LENGTH: usize = 32;
/// Length of a Ristretto255 public (group element) key in bytes.
pub const PUBLIC_KEY_LENGTH: usize = 32;
/// Length of the derived master key in bytes.
pub const MASTER_KEY_LENGTH: usize = 32;
/// Length of the XSalsa20 nonce in bytes.
pub const NONCE_LENGTH: usize = 24;
/// Length of an HMAC-SHA-512 tag in bytes.
pub const MAC_LENGTH: usize = 64;
/// Length of a SHA-512 digest in bytes.
pub const HASH_LENGTH: usize = 64;

/// Total serialized envelope length in bytes.
pub const ENVELOPE_LENGTH: usize = 136;
/// Length of a registration request (blinded OPRF element) in bytes.
pub const REGISTRATION_REQUEST_LENGTH: usize = 32;
/// Length of a registration response in bytes.
pub const REGISTRATION_RESPONSE_LENGTH: usize = 64;
/// Length of a credential request in bytes (same as registration request).
pub const CREDENTIAL_REQUEST_LENGTH: usize = REGISTRATION_REQUEST_LENGTH;
/// Length of a credential response in bytes.
pub const CREDENTIAL_RESPONSE_LENGTH: usize = 168;
/// Maximum allowed length for a secure key derivation output in bytes.
pub const MAX_SECURE_KEY_LENGTH: usize = 4096;

/// Length of the classical (non-PQ) portion of a KE1 message in bytes.
pub const KE1_BASE_LENGTH: usize = REGISTRATION_REQUEST_LENGTH + PUBLIC_KEY_LENGTH + NONCE_LENGTH;
/// Length of the classical (non-PQ) portion of a KE2 message in bytes.
pub const KE2_BASE_LENGTH: usize =
    NONCE_LENGTH + PUBLIC_KEY_LENGTH + CREDENTIAL_RESPONSE_LENGTH + MAC_LENGTH;
/// Length of a KE3 message in bytes.
pub const KE3_LENGTH: usize = MAC_LENGTH;
/// Length of a registration record (envelope + initiator public key) in bytes.
pub const REGISTRATION_RECORD_LENGTH: usize = ENVELOPE_LENGTH + PUBLIC_KEY_LENGTH;
/// Length of the stored responder credentials in bytes.
pub const RESPONDER_CREDENTIALS_LENGTH: usize = REGISTRATION_RECORD_LENGTH;

/// Constants for the ML-KEM-768 post-quantum KEM layer.
pub mod pq {
    /// Length of an ML-KEM-768 encapsulation (public) key in bytes.
    pub const KEM_PUBLIC_KEY_LENGTH: usize = 1184;
    /// Length of an ML-KEM-768 decapsulation (secret) key in bytes.
    pub const KEM_SECRET_KEY_LENGTH: usize = 2400;
    /// Length of an ML-KEM-768 ciphertext in bytes.
    pub const KEM_CIPHERTEXT_LENGTH: usize = 1088;
    /// Length of an ML-KEM-768 shared secret in bytes.
    pub const KEM_SHARED_SECRET_LENGTH: usize = 32;
    /// Length of the combined IKM fed into the hybrid key combiner (4 x 32-byte DH shares + KEM shared secret).
    pub const COMBINED_IKM_LENGTH: usize = 128 + KEM_SHARED_SECRET_LENGTH;
}

/// Total length of a hybrid KE1 message (classical base + ML-KEM public key) in bytes.
pub const KE1_LENGTH: usize = KE1_BASE_LENGTH + pq::KEM_PUBLIC_KEY_LENGTH;
/// Total length of a hybrid KE2 message (classical base + ML-KEM ciphertext) in bytes.
pub const KE2_LENGTH: usize = KE2_BASE_LENGTH + pq::KEM_CIPHERTEXT_LENGTH;

const _: () = assert!(PRIVATE_KEY_LENGTH == PUBLIC_KEY_LENGTH);
const _: () = assert!(PRIVATE_KEY_LENGTH == 32);
const _: () = assert!(NONCE_LENGTH == 24);
const _: () = assert!(MAC_LENGTH == 64);
const _: () = assert!(CREDENTIAL_REQUEST_LENGTH == REGISTRATION_REQUEST_LENGTH);
const _: () = assert!(CREDENTIAL_RESPONSE_LENGTH == PUBLIC_KEY_LENGTH + ENVELOPE_LENGTH);
const _: () = assert!(KE1_BASE_LENGTH == 88);
const _: () = assert!(KE2_BASE_LENGTH == 288);
const _: () = assert!(REGISTRATION_RECORD_LENGTH == 168);
const _: () = assert!(KE1_LENGTH == 1272);
const _: () = assert!(KE2_LENGTH == 1376);

/// Length of an XSalsa20-Poly1305 secret key in bytes.
pub const SECRETBOX_KEY_LENGTH: usize = 32;
/// Length of a Poly1305 authentication tag in bytes.
pub const SECRETBOX_MAC_LENGTH: usize = 16;

/// Domain-separation labels for classical OPAQUE operations.
pub mod labels {
    /// Domain separator for the OPRF hash-to-group and finalize steps.
    pub const OPRF_CONTEXT: &[u8] = b"ECLIPTIX-OPAQUE-v1/OPRF";
    /// Info string used when deriving per-account OPRF keys.
    pub const OPRF_KEY_INFO: &[u8] = b"ECLIPTIX-OPAQUE-v1/OPRF-Key";
    /// Info string used when deriving the OPRF seed from the relay secret.
    pub const OPRF_SEED_INFO: &[u8] = b"ECLIPTIX-OPAQUE-v1/OPRF-Seed";
    /// Context label for envelope key derivation.
    pub const ENVELOPE_CONTEXT: &[u8] = b"ECLIPTIX-OPAQUE-v1/EnvelopeKey";
    /// Salt label for HKDF-Extract.
    pub const HKDF_SALT: &[u8] = b"ECLIPTIX-OPAQUE-v1/HKDF-Salt";
    /// Context label for transcript hashing.
    pub const TRANSCRIPT_CONTEXT: &[u8] = b"ECLIPTIX-OPAQUE-v1/Transcript";
    /// Context label for the key stretching function (Argon2id) input.
    pub const KSF_CONTEXT: &[u8] = b"ECLIPTIX-OPAQUE-v1/KSF";
    /// Label used to derive the Argon2id salt.
    pub const KSF_SALT_LABEL: &[u8] = b"ECLIPTIX-OPAQUE-v1/KSF-Salt";
    /// Info string for session key derivation via HKDF-Expand.
    pub const SESSION_KEY_INFO: &[u8] = b"ECLIPTIX-OPAQUE-v1/SessionKey";
    /// Info string for master key derivation via HKDF-Expand.
    pub const MASTER_KEY_INFO: &[u8] = b"ECLIPTIX-OPAQUE-v1/MasterKey";
    /// Info string for the responder MAC key derivation.
    pub const RESPONDER_MAC_INFO: &[u8] = b"ECLIPTIX-OPAQUE-v1/ResponderMAC";
    /// Info string for the initiator MAC key derivation.
    pub const INITIATOR_MAC_INFO: &[u8] = b"ECLIPTIX-OPAQUE-v1/InitiatorMAC";
}

/// Domain-separation labels for post-quantum hybrid operations.
pub mod pq_labels {
    /// Context label for the hybrid HKDF-Extract combiner.
    pub const PQ_COMBINER_CONTEXT: &[u8] = b"ECLIPTIX-OPAQUE-PQ-v1/Combiner";
    /// Context label for ML-KEM encapsulation.
    pub const PQ_KEM_CONTEXT: &[u8] = b"ECLIPTIX-OPAQUE-PQ-v1/KEM";
    /// Info string for hybrid session key derivation.
    pub const PQ_SESSION_KEY_INFO: &[u8] = b"ECLIPTIX-OPAQUE-PQ-v1/SessionKey";
    /// Info string for hybrid master key derivation.
    pub const PQ_MASTER_KEY_INFO: &[u8] = b"ECLIPTIX-OPAQUE-PQ-v1/MasterKey";
    /// Info string for the hybrid responder MAC key derivation.
    pub const PQ_RESPONDER_MAC_INFO: &[u8] = b"ECLIPTIX-OPAQUE-PQ-v1/ResponderMAC";
    /// Info string for the hybrid initiator MAC key derivation.
    pub const PQ_INITIATOR_MAC_INFO: &[u8] = b"ECLIPTIX-OPAQUE-PQ-v1/InitiatorMAC";
}

/// Enumerates all error conditions that can arise during OPAQUE protocol operations.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum OpaqueError {
    /// An input parameter has an invalid value or length.
    #[error("invalid input parameter")]
    InvalidInput,
    /// A low-level cryptographic primitive returned an error code.
    #[error("cryptographic operation failed")]
    CryptoError,
    /// A protocol message has an unexpected format or length.
    #[error("protocol message has invalid format or length")]
    InvalidProtocolMessage,
    /// A validation check (e.g., point membership) failed.
    #[error("validation failed")]
    ValidationError,
    /// MAC verification or envelope decryption failed.
    #[error("authentication failed")]
    AuthenticationError,
    /// The supplied public key is not a valid Ristretto255 point.
    #[error("invalid public key")]
    InvalidPublicKey,
    /// The account identifier is already registered on the relay.
    #[error("account already registered")]
    AlreadyRegistered,
    /// An ML-KEM key or ciphertext has an invalid length or encoding.
    #[error("malformed ML-KEM key or ciphertext")]
    InvalidKemInput,
    /// The credential envelope has an invalid internal structure.
    #[error("envelope has invalid format")]
    InvalidEnvelope,
}

impl OpaqueError {
    /// Converts this error variant into a negative `i32` status code suitable for C FFI.
    pub fn to_c_int(self) -> i32 {
        match self {
            OpaqueError::InvalidInput => -1,
            OpaqueError::CryptoError => -2,
            OpaqueError::InvalidProtocolMessage => -3,
            OpaqueError::ValidationError => -4,
            OpaqueError::AuthenticationError => -5,
            OpaqueError::InvalidPublicKey => -6,
            OpaqueError::AlreadyRegistered => -7,
            OpaqueError::InvalidKemInput => -8,
            OpaqueError::InvalidEnvelope => -9,
        }
    }
}

/// Convenience alias for `Result<T, OpaqueError>`.
pub type OpaqueResult<T> = Result<T, OpaqueError>;

/// A heap-allocated byte buffer that is zeroized on drop.
///
/// Wraps a `Vec<u8>` and implements `Zeroize + ZeroizeOnDrop` so that
/// sensitive key material is scrubbed from memory when no longer needed.
/// The `Debug` implementation redacts the contents.
#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct SecureBytes(Vec<u8>);

impl SecureBytes {
    /// Creates a zero-filled buffer of the given length.
    pub fn new(len: usize) -> Self {
        Self(vec![0u8; len])
    }

    /// Creates a buffer by copying the given slice.
    pub fn from_slice(data: &[u8]) -> Self {
        Self(data.to_vec())
    }

    /// Returns an immutable reference to the underlying bytes.
    pub fn data(&self) -> &[u8] {
        &self.0
    }

    /// Returns a mutable reference to the underlying bytes.
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// Returns the number of bytes in the buffer.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns `true` if the buffer contains no bytes.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Resizes the buffer to `new_len`, zero-filling any new bytes.
    /// When shrinking, the truncated portion is zeroized before deallocation.
    pub fn resize(&mut self, new_len: usize) {
        if new_len < self.0.len() {
            self.0[new_len..].zeroize();
        }
        self.0.resize(new_len, 0);
    }

}

impl std::ops::Deref for SecureBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl std::ops::DerefMut for SecureBytes {
    fn deref_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl AsRef<[u8]> for SecureBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for SecureBytes {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl std::fmt::Debug for SecureBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecureBytes([REDACTED; {}])", self.0.len())
    }
}

/// An encrypted credential envelope containing the initiator's key material.
///
/// Sealed with XSalsa20-Poly1305 using a key derived from the randomized password
/// and the responder's public key. Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Envelope {
    /// XSalsa20 nonce (`NONCE_LENGTH` bytes).
    pub nonce: Vec<u8>,
    /// Encrypted initiator credentials.
    pub ciphertext: Vec<u8>,
    /// Poly1305 authentication tag (`SECRETBOX_MAC_LENGTH` bytes).
    pub auth_tag: Vec<u8>,
}

impl Envelope {
    /// Creates a new envelope with a zeroed nonce, empty ciphertext, and a zeroed authentication tag.
    pub fn new() -> Self {
        Self {
            nonce: vec![0u8; NONCE_LENGTH],
            ciphertext: Vec::new(),
            auth_tag: vec![0u8; SECRETBOX_MAC_LENGTH],
        }
    }
}

impl Default for Envelope {
    fn default() -> Self {
        Self::new()
    }
}

/// Compares two byte slices in constant time using libsodium's `sodium_memcmp`.
///
/// Returns `true` if the slices are equal, `false` otherwise. If the lengths
/// differ, returns `false` immediately (length itself is not secret).
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    // SAFETY: Both pointers come from valid slices. Length equality is verified before the call.
    unsafe {
        libsodium_sys::sodium_memcmp(
            a.as_ptr() as *const _,
            b.as_ptr() as *const _,
            a.len(),
        ) == 0
    }
}

/// Returns `true` if every byte in `data` is zero, checked in constant time.
pub fn is_all_zero(data: &[u8]) -> bool {
    // SAFETY: Pointer comes from a valid slice.
    unsafe { libsodium_sys::sodium_is_zero(data.as_ptr(), data.len()) == 1 }
}
