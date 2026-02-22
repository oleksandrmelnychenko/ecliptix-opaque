// Copyright (c) 2026 Oleksandr Melnychenko, Ukraine
// Ecliptix Security — Hybrid PQ-OPAQUE
// Licensed under the MIT License

use opaque_core::types::{
    pq, OpaqueResult, ENVELOPE_LENGTH, MAC_LENGTH, NONCE_LENGTH, PRIVATE_KEY_LENGTH,
    PUBLIC_KEY_LENGTH, REGISTRATION_REQUEST_LENGTH,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct InitiatorState {
    pub secure_key: Vec<u8>,
    pub initiator_private_key: [u8; PRIVATE_KEY_LENGTH],
    pub initiator_public_key: [u8; PUBLIC_KEY_LENGTH],
    pub initiator_ephemeral_private_key: [u8; PRIVATE_KEY_LENGTH],
    pub initiator_ephemeral_public_key: [u8; PUBLIC_KEY_LENGTH],
    pub responder_public_key: [u8; PUBLIC_KEY_LENGTH],
    pub session_key: Vec<u8>,
    pub oblivious_prf_blind_scalar: [u8; PRIVATE_KEY_LENGTH],
    pub initiator_nonce: [u8; NONCE_LENGTH],
    pub master_key: Vec<u8>,
    pub pq_ephemeral_public_key: Vec<u8>,
    pub pq_ephemeral_secret_key: Vec<u8>,
    pub pq_shared_secret: Vec<u8>,
}

impl InitiatorState {
    pub fn new() -> Self {
        Self {
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

pub struct RegistrationRequest {
    pub data: [u8; REGISTRATION_REQUEST_LENGTH],
}

impl RegistrationRequest {
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

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RegistrationRecord {
    pub envelope: Vec<u8>,
    pub initiator_public_key: [u8; PUBLIC_KEY_LENGTH],
}

impl RegistrationRecord {
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

pub struct Ke1Message {
    pub initiator_nonce: [u8; NONCE_LENGTH],
    pub initiator_public_key: [u8; PUBLIC_KEY_LENGTH],
    pub credential_request: [u8; REGISTRATION_REQUEST_LENGTH],
    pub pq_ephemeral_public_key: Vec<u8>,
}

impl Ke1Message {
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

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Ke3Message {
    pub initiator_mac: [u8; MAC_LENGTH],
}

impl Ke3Message {
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

pub struct OpaqueInitiator {
    responder_public_key: [u8; PUBLIC_KEY_LENGTH],
}

impl OpaqueInitiator {
    pub fn new(responder_public_key: &[u8]) -> OpaqueResult<Self> {
        opaque_core::crypto::validate_public_key(responder_public_key)?;
        let mut key = [0u8; PUBLIC_KEY_LENGTH];
        key.copy_from_slice(responder_public_key);
        Ok(Self {
            responder_public_key: key,
        })
    }

    pub fn responder_public_key(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        &self.responder_public_key
    }
}
