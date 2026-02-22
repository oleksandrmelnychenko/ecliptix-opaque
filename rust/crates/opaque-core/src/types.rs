// Copyright (c) 2026 Oleksandr Melnychenko, Ukraine
// Ecliptix Security — Hybrid PQ-OPAQUE
// Licensed under the MIT License

use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const OPRF_SEED_LENGTH: usize = 32;
pub const PRIVATE_KEY_LENGTH: usize = 32;
pub const PUBLIC_KEY_LENGTH: usize = 32;
pub const MASTER_KEY_LENGTH: usize = 32;
pub const NONCE_LENGTH: usize = 24;
pub const MAC_LENGTH: usize = 64;
pub const HASH_LENGTH: usize = 64;

pub const ENVELOPE_LENGTH: usize = 136;
pub const REGISTRATION_REQUEST_LENGTH: usize = 32;
pub const REGISTRATION_RESPONSE_LENGTH: usize = 64;
pub const CREDENTIAL_REQUEST_LENGTH: usize = REGISTRATION_REQUEST_LENGTH;
pub const CREDENTIAL_RESPONSE_LENGTH: usize = 168;
pub const MAX_SECURE_KEY_LENGTH: usize = 4096;

pub const KE1_BASE_LENGTH: usize = REGISTRATION_REQUEST_LENGTH + PUBLIC_KEY_LENGTH + NONCE_LENGTH;
pub const KE2_BASE_LENGTH: usize =
    NONCE_LENGTH + PUBLIC_KEY_LENGTH + CREDENTIAL_RESPONSE_LENGTH + MAC_LENGTH;
pub const KE3_LENGTH: usize = MAC_LENGTH;
pub const REGISTRATION_RECORD_LENGTH: usize = ENVELOPE_LENGTH + PUBLIC_KEY_LENGTH;
pub const RESPONDER_CREDENTIALS_LENGTH: usize = REGISTRATION_RECORD_LENGTH;

pub mod pq {
    pub const KEM_PUBLIC_KEY_LENGTH: usize = 1184;
    pub const KEM_SECRET_KEY_LENGTH: usize = 2400;
    pub const KEM_CIPHERTEXT_LENGTH: usize = 1088;
    pub const KEM_SHARED_SECRET_LENGTH: usize = 32;
    pub const COMBINED_IKM_LENGTH: usize = 96 + KEM_SHARED_SECRET_LENGTH;
}

pub const KE1_LENGTH: usize = KE1_BASE_LENGTH + pq::KEM_PUBLIC_KEY_LENGTH;
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

pub const SECRETBOX_KEY_LENGTH: usize = 32;
pub const SECRETBOX_MAC_LENGTH: usize = 16;

pub mod labels {
    pub const OPRF_CONTEXT: &[u8] = b"ECLIPTIX-OPAQUE-v1/OPRF";
    pub const OPRF_KEY_INFO: &[u8] = b"ECLIPTIX-OPAQUE-v1/OPRF-Key";
    pub const OPRF_SEED_INFO: &[u8] = b"ECLIPTIX-OPAQUE-v1/OPRF-Seed";
    pub const ENVELOPE_CONTEXT: &[u8] = b"ECLIPTIX-OPAQUE-v1/EnvelopeKey";
    pub const HKDF_SALT: &[u8] = b"ECLIPTIX-OPAQUE-v1/HKDF-Salt";
    pub const TRANSCRIPT_CONTEXT: &[u8] = b"ECLIPTIX-OPAQUE-v1/Transcript";
    pub const KSF_CONTEXT: &[u8] = b"ECLIPTIX-OPAQUE-v1/KSF";
    pub const KSF_SALT_LABEL: &[u8] = b"ECLIPTIX-OPAQUE-v1/KSF-Salt";
    pub const SESSION_KEY_INFO: &[u8] = b"ECLIPTIX-OPAQUE-v1/SessionKey";
    pub const MASTER_KEY_INFO: &[u8] = b"ECLIPTIX-OPAQUE-v1/MasterKey";
    pub const RESPONDER_MAC_INFO: &[u8] = b"ECLIPTIX-OPAQUE-v1/ResponderMAC";
    pub const INITIATOR_MAC_INFO: &[u8] = b"ECLIPTIX-OPAQUE-v1/InitiatorMAC";
}

pub mod pq_labels {
    pub const PQ_COMBINER_CONTEXT: &[u8] = b"ECLIPTIX-OPAQUE-PQ-v1/Combiner";
    pub const PQ_KEM_CONTEXT: &[u8] = b"ECLIPTIX-OPAQUE-PQ-v1/KEM";
    pub const PQ_SESSION_KEY_INFO: &[u8] = b"ECLIPTIX-OPAQUE-PQ-v1/SessionKey";
    pub const PQ_MASTER_KEY_INFO: &[u8] = b"ECLIPTIX-OPAQUE-PQ-v1/MasterKey";
    pub const PQ_RESPONDER_MAC_INFO: &[u8] = b"ECLIPTIX-OPAQUE-PQ-v1/ResponderMAC";
    pub const PQ_INITIATOR_MAC_INFO: &[u8] = b"ECLIPTIX-OPAQUE-PQ-v1/InitiatorMAC";
}

#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum OpaqueError {
    #[error("invalid input")]
    InvalidInput,
    #[error("cryptographic operation failed")]
    CryptoError,
    #[error("memory error")]
    MemoryError,
    #[error("validation error")]
    ValidationError,
    #[error("authentication error")]
    AuthenticationError,
    #[error("invalid public key")]
    InvalidPublicKey,
}

impl OpaqueError {
    pub fn to_c_int(self) -> i32 {
        match self {
            OpaqueError::InvalidInput => -1,
            OpaqueError::CryptoError => -2,
            OpaqueError::MemoryError => -3,
            OpaqueError::ValidationError => -4,
            OpaqueError::AuthenticationError => -5,
            OpaqueError::InvalidPublicKey => -6,
        }
    }
}

pub type OpaqueResult<T> = Result<T, OpaqueError>;

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecureBytes(Vec<u8>);

impl SecureBytes {
    pub fn new(len: usize) -> Self {
        Self(vec![0u8; len])
    }

    pub fn from_slice(data: &[u8]) -> Self {
        Self(data.to_vec())
    }

    pub fn data(&self) -> &[u8] {
        &self.0
    }

    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn resize(&mut self, new_len: usize) {
        self.0.resize(new_len, 0);
    }

    pub fn into_vec(self) -> Vec<u8> {
        let mut s = self;
        std::mem::take(&mut s.0)
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

impl Default for SecureBytes {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl std::fmt::Debug for SecureBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecureBytes([REDACTED; {}])", self.0.len())
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Envelope {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>,
    pub auth_tag: Vec<u8>,
}

impl Envelope {
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

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    unsafe {
        libsodium_sys::sodium_memcmp(
            a.as_ptr() as *const _,
            b.as_ptr() as *const _,
            a.len(),
        ) == 0
    }
}

pub fn is_all_zero(data: &[u8]) -> bool {
    unsafe { libsodium_sys::sodium_is_zero(data.as_ptr(), data.len()) == 1 }
}
