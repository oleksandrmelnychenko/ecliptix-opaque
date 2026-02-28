// Copyright (c) 2026 Oleksandr Melnychenko, Ukraine
// Ecliptix Security — Hybrid PQ-OPAQUE
// Licensed under the MIT License

use opaque_core::types::{
    pq, OpaqueResult, ENVELOPE_LENGTH, MAC_LENGTH, NONCE_LENGTH, PRIVATE_KEY_LENGTH,
    PUBLIC_KEY_LENGTH, REGISTRATION_REQUEST_LENGTH,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Tracks which protocol phase the initiator state is in.
///
/// Enforces that protocol functions are called in the correct order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitiatorPhase {
    /// State has been created but no protocol function has been called.
    Created,
    /// `generate_ke1` has completed; awaiting KE2 from the relay.
    Ke1Generated,
    /// `generate_ke3` has completed; session keys are available.
    Ke3Generated,
    /// `initiator_finish` has been called; keys have been extracted.
    Finished,
}

/// Mutable session state held by the initiator across registration and AKE phases.
///
/// All sensitive fields are zeroized on drop to prevent key material from lingering in memory.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct InitiatorState {
    /// Current protocol phase. Prevents out-of-order function calls.
    #[zeroize(skip)]
    pub phase: InitiatorPhase,
    /// User password or secret used as OPRF input.
    pub secure_key: Vec<u8>,
    /// Long-term Ristretto255 private key of the initiator.
    pub initiator_private_key: [u8; PRIVATE_KEY_LENGTH],
    /// Long-term Ristretto255 public key of the initiator.
    pub initiator_public_key: [u8; PUBLIC_KEY_LENGTH],
    /// Ephemeral Ristretto255 private key generated for a single AKE session.
    pub initiator_ephemeral_private_key: [u8; PRIVATE_KEY_LENGTH],
    /// Ephemeral Ristretto255 public key generated for a single AKE session.
    pub initiator_ephemeral_public_key: [u8; PUBLIC_KEY_LENGTH],
    /// Responder (relay) long-term Ristretto255 public key recovered from the envelope.
    pub responder_public_key: [u8; PUBLIC_KEY_LENGTH],
    /// Derived session key produced by the AKE phase.
    pub session_key: Vec<u8>,
    /// OPRF blinding scalar used to mask the password before sending it to the relay.
    pub oblivious_prf_blind_scalar: [u8; PRIVATE_KEY_LENGTH],
    /// Random nonce contributed by the initiator during AKE.
    pub initiator_nonce: [u8; NONCE_LENGTH],
    /// Master key derived alongside the session key.
    pub master_key: Vec<u8>,
    /// Ephemeral ML-KEM-768 public (encapsulation) key for the post-quantum layer.
    pub pq_ephemeral_public_key: Vec<u8>,
    /// Ephemeral ML-KEM-768 secret (decapsulation) key for the post-quantum layer.
    pub pq_ephemeral_secret_key: Vec<u8>,
    /// ML-KEM-768 shared secret produced by decapsulation.
    pub pq_shared_secret: Vec<u8>,
}

impl InitiatorState {
    /// Creates a zero-initialized initiator state.
    pub fn new() -> Self {
        Self {
            phase: InitiatorPhase::Created,
            secure_key: Vec::new(),
            initiator_private_key: [0u8; PRIVATE_KEY_LENGTH],
            initiator_public_key: [0u8; PUBLIC_KEY_LENGTH],
            initiator_ephemeral_private_key: [0u8; PRIVATE_KEY_LENGTH],
            initiator_ephemeral_public_key: [0u8; PUBLIC_KEY_LENGTH],
            responder_public_key: [0u8; PUBLIC_KEY_LENGTH],
            session_key: Vec::new(),
            oblivious_prf_blind_scalar: [0u8; PRIVATE_KEY_LENGTH],
            initiator_nonce: [0u8; NONCE_LENGTH],
            master_key: Vec::new(),
            pq_ephemeral_public_key: Vec::new(),
            pq_ephemeral_secret_key: Vec::new(),
            pq_shared_secret: Vec::new(),
        }
    }
}

impl Default for InitiatorState {
    fn default() -> Self {
        Self::new()
    }
}

/// Blinded OPRF element sent by the initiator to begin password registration.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RegistrationRequest {
    /// Serialized blinded Ristretto255 point.
    pub data: [u8; REGISTRATION_REQUEST_LENGTH],
}

impl RegistrationRequest {
    /// Creates a zero-initialized registration request.
    pub fn new() -> Self {
        Self {
            data: [0u8; REGISTRATION_REQUEST_LENGTH],
        }
    }
}

impl Default for RegistrationRequest {
    fn default() -> Self {
        Self::new()
    }
}

/// Record produced by the initiator at the end of registration.
///
/// Contains the sealed envelope and the initiator public key. The relay
/// stores this record and uses it during subsequent authentication attempts.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RegistrationRecord {
    /// Sealed envelope containing encrypted key material (nonce + ciphertext + auth tag).
    pub envelope: Vec<u8>,
    /// Long-term Ristretto255 public key of the initiator.
    pub initiator_public_key: [u8; PUBLIC_KEY_LENGTH],
}

impl RegistrationRecord {
    /// Creates a zero-initialized registration record.
    pub fn new() -> Self {
        Self {
            envelope: vec![0u8; ENVELOPE_LENGTH],
            initiator_public_key: [0u8; PUBLIC_KEY_LENGTH],
        }
    }
}

impl Default for RegistrationRecord {
    fn default() -> Self {
        Self::new()
    }
}

/// First key-exchange message sent from the initiator to the relay.
///
/// Carries the ephemeral public keys (classical and post-quantum), a random
/// nonce, and the blinded OPRF credential request.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Ke1Message {
    /// Random nonce contributed by the initiator.
    pub initiator_nonce: [u8; NONCE_LENGTH],
    /// Ephemeral Ristretto255 public key of the initiator.
    pub initiator_public_key: [u8; PUBLIC_KEY_LENGTH],
    /// Blinded OPRF element derived from the user password.
    pub credential_request: [u8; REGISTRATION_REQUEST_LENGTH],
    /// Ephemeral ML-KEM-768 encapsulation key for the post-quantum layer.
    pub pq_ephemeral_public_key: Vec<u8>,
}

impl Ke1Message {
    /// Creates a zero-initialized KE1 message.
    pub fn new() -> Self {
        Self {
            initiator_nonce: [0u8; NONCE_LENGTH],
            initiator_public_key: [0u8; PUBLIC_KEY_LENGTH],
            credential_request: [0u8; REGISTRATION_REQUEST_LENGTH],
            pq_ephemeral_public_key: vec![0u8; pq::KEM_PUBLIC_KEY_LENGTH],
        }
    }
}

impl Default for Ke1Message {
    fn default() -> Self {
        Self::new()
    }
}

/// Third key-exchange message sent from the initiator to the relay.
///
/// Contains only the initiator MAC that proves the initiator successfully
/// decrypted the envelope and derived the same session keys.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Ke3Message {
    /// HMAC-SHA-512 tag authenticating the initiator to the relay.
    pub initiator_mac: [u8; MAC_LENGTH],
}

impl Ke3Message {
    /// Creates a zero-initialized KE3 message.
    pub fn new() -> Self {
        Self {
            initiator_mac: [0u8; MAC_LENGTH],
        }
    }
}

impl Default for Ke3Message {
    fn default() -> Self {
        Self::new()
    }
}

/// High-level handle for an OPAQUE initiator (client) bound to a specific relay.
///
/// Stores the relay public key so that every registration and authentication
/// attempt can verify the relay identity.
#[derive(Zeroize)]
pub struct OpaqueInitiator {
    responder_public_key: [u8; PUBLIC_KEY_LENGTH],
}

impl OpaqueInitiator {
    /// Creates a new initiator handle bound to the given relay public key.
    ///
    /// # Errors
    ///
    /// Returns an error if `responder_public_key` is not a valid Ristretto255 point.
    pub fn new(responder_public_key: &[u8]) -> OpaqueResult<Self> {
        opaque_core::crypto::validate_public_key(responder_public_key)?;
        let mut key = [0u8; PUBLIC_KEY_LENGTH];
        key.copy_from_slice(responder_public_key);
        Ok(Self {
            responder_public_key: key,
        })
    }

    /// Returns a reference to the relay long-term public key.
    pub fn responder_public_key(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        &self.responder_public_key
    }
}
