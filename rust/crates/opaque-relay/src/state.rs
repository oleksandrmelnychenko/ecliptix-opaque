// Copyright (c) 2026 Oleksandr Melnychenko, Ukraine
// Ecliptix Security — Hybrid PQ-OPAQUE
// Licensed under the MIT License

use opaque_core::types::{
    constant_time_eq, pq, CREDENTIAL_RESPONSE_LENGTH, ENVELOPE_LENGTH, MAC_LENGTH, NONCE_LENGTH,
    OpaqueError, OpaqueResult, PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH, REGISTRATION_RESPONSE_LENGTH,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ResponderState {
    pub responder_private_key: [u8; PRIVATE_KEY_LENGTH],
    pub responder_public_key: [u8; PUBLIC_KEY_LENGTH],
    pub responder_ephemeral_private_key: [u8; PRIVATE_KEY_LENGTH],
    pub responder_ephemeral_public_key: [u8; PUBLIC_KEY_LENGTH],
    pub initiator_public_key: [u8; PUBLIC_KEY_LENGTH],
    pub session_key: Vec<u8>,
    pub expected_initiator_mac: [u8; MAC_LENGTH],
    pub master_key: Vec<u8>,
    #[zeroize(skip)]
    pub handshake_complete: bool,
    pub pq_shared_secret: Vec<u8>,
}

impl ResponderState {
    pub fn new() -> Self {
        Self {
            responder_private_key: [0u8; PRIVATE_KEY_LENGTH],
            responder_public_key: [0u8; PUBLIC_KEY_LENGTH],
            responder_ephemeral_private_key: [0u8; PRIVATE_KEY_LENGTH],
            responder_ephemeral_public_key: [0u8; PUBLIC_KEY_LENGTH],
            initiator_public_key: [0u8; PUBLIC_KEY_LENGTH],
            session_key: Vec::new(),
            expected_initiator_mac: [0u8; MAC_LENGTH],
            master_key: Vec::new(),
            handshake_complete: false,
            pq_shared_secret: Vec::new(),
        }
    }
}

impl Default for ResponderState {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ResponderKeyPair {
    pub private_key: [u8; PRIVATE_KEY_LENGTH],
    pub public_key: [u8; PUBLIC_KEY_LENGTH],
}

impl ResponderKeyPair {
    pub fn generate() -> OpaqueResult<Self> {
        let private_key = opaque_core::crypto::random_nonzero_scalar();
        let public_key = opaque_core::crypto::scalarmult_base(&private_key);
        Ok(Self {
            private_key,
            public_key,
        })
    }

    pub fn from_keys(private_key: &[u8], public_key: &[u8]) -> OpaqueResult<Self> {
        if private_key.len() != PRIVATE_KEY_LENGTH || public_key.len() != PUBLIC_KEY_LENGTH {
            return Err(OpaqueError::InvalidInput);
        }
        opaque_core::crypto::validate_public_key(public_key)?;

        let sk: &[u8; PRIVATE_KEY_LENGTH] = private_key
            .try_into()
            .map_err(|_| OpaqueError::InvalidInput)?;
        let derived = opaque_core::crypto::scalarmult_base(sk);
        if !constant_time_eq(public_key, &derived) {
            return Err(OpaqueError::InvalidPublicKey);
        }

        let mut kp = Self {
            private_key: [0u8; PRIVATE_KEY_LENGTH],
            public_key: [0u8; PUBLIC_KEY_LENGTH],
        };
        kp.private_key.copy_from_slice(private_key);
        kp.public_key.copy_from_slice(public_key);
        Ok(kp)
    }
}

pub struct RegistrationResponse {
    pub data: [u8; REGISTRATION_RESPONSE_LENGTH],
}

impl RegistrationResponse {
    pub fn new() -> Self {
        Self {
            data: [0u8; REGISTRATION_RESPONSE_LENGTH],
        }
    }
}

impl Default for RegistrationResponse {
    fn default() -> Self {
        Self::new()
    }
}

pub struct Ke2Message {
    pub responder_nonce: [u8; NONCE_LENGTH],
    pub responder_public_key: [u8; PUBLIC_KEY_LENGTH],
    pub credential_response: [u8; CREDENTIAL_RESPONSE_LENGTH],
    pub responder_mac: [u8; MAC_LENGTH],
    pub kem_ciphertext: Vec<u8>,
}

impl Ke2Message {
    pub fn new() -> Self {
        Self {
            responder_nonce: [0u8; NONCE_LENGTH],
            responder_public_key: [0u8; PUBLIC_KEY_LENGTH],
            credential_response: [0u8; CREDENTIAL_RESPONSE_LENGTH],
            responder_mac: [0u8; MAC_LENGTH],
            kem_ciphertext: vec![0u8; pq::KEM_CIPHERTEXT_LENGTH],
        }
    }
}

impl Default for Ke2Message {
    fn default() -> Self {
        Self::new()
    }
}

pub struct ResponderCredentials {
    pub envelope: Vec<u8>,
    pub initiator_public_key: [u8; PUBLIC_KEY_LENGTH],
}

impl ResponderCredentials {
    pub fn new() -> Self {
        Self {
            envelope: vec![0u8; ENVELOPE_LENGTH],
            initiator_public_key: [0u8; PUBLIC_KEY_LENGTH],
        }
    }
}

impl Default for ResponderCredentials {
    fn default() -> Self {
        Self::new()
    }
}

pub struct OpaqueResponder {
    keypair: ResponderKeyPair,
}

impl OpaqueResponder {
    pub fn new(keypair: ResponderKeyPair) -> OpaqueResult<Self> {
        opaque_core::crypto::validate_public_key(&keypair.public_key)?;
        Ok(Self { keypair })
    }

    pub fn keypair(&self) -> &ResponderKeyPair {
        &self.keypair
    }

    pub fn public_key(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        &self.keypair.public_key
    }
}
