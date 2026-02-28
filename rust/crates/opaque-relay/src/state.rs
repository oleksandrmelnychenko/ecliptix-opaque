// Copyright (c) 2026 Oleksandr Melnychenko, Ukraine
// Ecliptix Security — Hybrid PQ-OPAQUE
// Licensed under the MIT License

use opaque_core::types::{
    constant_time_eq, is_all_zero, pq, CREDENTIAL_RESPONSE_LENGTH, ENVELOPE_LENGTH, MAC_LENGTH,
    NONCE_LENGTH, OpaqueError, OpaqueResult, OPRF_SEED_LENGTH, PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH,
    REGISTRATION_RESPONSE_LENGTH,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Tracks which protocol phase the responder state is in.
///
/// Enforces that protocol functions are called in the correct order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponderPhase {
    /// State has been created but no protocol function has been called.
    Created,
    /// `generate_ke2` has completed; awaiting KE3 from the initiator.
    Ke2Generated,
    /// `responder_finish` has been called; keys have been extracted.
    Finished,
}

/// Mutable session state held by the responder across the AKE phase.
///
/// All sensitive fields are zeroized on drop to prevent key material from lingering in memory.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ResponderState {
    /// Current protocol phase. Prevents out-of-order function calls.
    #[zeroize(skip)]
    pub phase: ResponderPhase,
    /// Long-term Ristretto255 private key of the responder.
    pub responder_private_key: [u8; PRIVATE_KEY_LENGTH],
    /// Long-term Ristretto255 public key of the responder.
    pub responder_public_key: [u8; PUBLIC_KEY_LENGTH],
    /// Ephemeral Ristretto255 private key generated for a single AKE session.
    pub responder_ephemeral_private_key: [u8; PRIVATE_KEY_LENGTH],
    /// Ephemeral Ristretto255 public key generated for a single AKE session.
    pub responder_ephemeral_public_key: [u8; PUBLIC_KEY_LENGTH],
    /// Initiator ephemeral Ristretto255 public key received in KE1.
    pub initiator_public_key: [u8; PUBLIC_KEY_LENGTH],
    /// Derived session key produced by the AKE phase.
    pub session_key: Vec<u8>,
    /// Expected initiator MAC value used to verify the KE3 message.
    pub expected_initiator_mac: [u8; MAC_LENGTH],
    /// Master key derived alongside the session key.
    pub master_key: Vec<u8>,
    /// Indicates whether the three-message handshake has completed successfully.
    #[zeroize(skip)]
    pub handshake_complete: bool,
    /// ML-KEM-768 shared secret produced by encapsulation.
    pub pq_shared_secret: Vec<u8>,
}

impl ResponderState {
    /// Creates a zero-initialized responder state.
    pub fn new() -> Self {
        Self {
            phase: ResponderPhase::Created,
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

/// Long-term Ristretto255 keypair of the responder (relay).
///
/// Must be persisted to stable storage at provisioning time and reloaded on
/// each restart.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ResponderKeyPair {
    /// Ristretto255 private (scalar) key.
    pub private_key: [u8; PRIVATE_KEY_LENGTH],
    /// Ristretto255 public (group element) key.
    pub public_key: [u8; PUBLIC_KEY_LENGTH],
}

impl ResponderKeyPair {
    /// Generates a fresh random Ristretto255 keypair.
    ///
    /// # Errors
    ///
    /// Returns an error if the scalar-to-basepoint multiplication fails.
    pub fn generate() -> OpaqueResult<Self> {
        let private_key = opaque_core::crypto::random_nonzero_scalar();
        let public_key = opaque_core::crypto::scalarmult_base(&private_key)?;
        Ok(Self {
            private_key,
            public_key,
        })
    }

    /// Reconstructs a keypair from raw private and public key bytes.
    ///
    /// Validates that the public key is a well-formed Ristretto255 point and
    /// that it matches the given private key.
    ///
    /// # Errors
    ///
    /// Returns an error if the key lengths are incorrect, the public key is
    /// invalid, or the private-to-public derivation does not match.
    pub fn from_keys(private_key: &[u8], public_key: &[u8]) -> OpaqueResult<Self> {
        if private_key.len() != PRIVATE_KEY_LENGTH || public_key.len() != PUBLIC_KEY_LENGTH {
            return Err(OpaqueError::InvalidInput);
        }
        opaque_core::crypto::validate_public_key(public_key)?;

        let sk: &[u8; PRIVATE_KEY_LENGTH] = private_key
            .try_into()
            .map_err(|_| OpaqueError::InvalidInput)?;
        let derived = opaque_core::crypto::scalarmult_base(sk)?;
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

/// Response sent by the relay during the registration phase.
///
/// Contains the evaluated OPRF element and the relay long-term public key.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RegistrationResponse {
    /// Serialized registration response (evaluated OPRF element || responder public key).
    pub data: [u8; REGISTRATION_RESPONSE_LENGTH],
}

impl RegistrationResponse {
    /// Creates a zero-initialized registration response.
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

/// Second key-exchange message sent from the relay to the initiator.
///
/// Carries the responder ephemeral public key, a random nonce, the credential
/// response (evaluated OPRF element + encrypted envelope), the responder MAC,
/// and the ML-KEM-768 ciphertext.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Ke2Message {
    /// Random nonce contributed by the responder.
    pub responder_nonce: [u8; NONCE_LENGTH],
    /// Ephemeral Ristretto255 public key of the responder.
    pub responder_public_key: [u8; PUBLIC_KEY_LENGTH],
    /// Credential response containing the evaluated OPRF element and the sealed envelope.
    pub credential_response: [u8; CREDENTIAL_RESPONSE_LENGTH],
    /// HMAC-SHA-512 tag authenticating the responder to the initiator.
    pub responder_mac: [u8; MAC_LENGTH],
    /// ML-KEM-768 ciphertext encapsulating the post-quantum shared secret.
    pub kem_ciphertext: Vec<u8>,
}

impl Ke2Message {
    /// Creates a zero-initialized KE2 message.
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

/// Per-account credentials stored by the relay after a successful registration.
///
/// Contains the sealed envelope and the initiator long-term public key needed
/// to run the AKE phase. All sensitive fields are zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ResponderCredentials {
    /// Sealed envelope (nonce + ciphertext + auth tag) created by the initiator.
    pub envelope: Vec<u8>,
    /// Long-term Ristretto255 public key of the initiator.
    pub initiator_public_key: [u8; PUBLIC_KEY_LENGTH],
    /// Indicates whether [`build_credentials`](crate::build_credentials) has been called. Prevents accidental overwrite.
    #[zeroize(skip)]
    pub registered: bool,
}

impl ResponderCredentials {
    /// Creates an empty, unregistered credentials container.
    pub fn new() -> Self {
        Self {
            envelope: vec![0u8; ENVELOPE_LENGTH],
            initiator_public_key: [0u8; PUBLIC_KEY_LENGTH],
            registered: false,
        }
    }
}

impl Default for ResponderCredentials {
    fn default() -> Self {
        Self::new()
    }
}

/// High-level handle for an OPAQUE responder (relay / server).
///
/// Bundles a long-term Ristretto255 keypair with an independent OPRF seed.
/// Both values must be persisted to stable storage and reloaded together on
/// each restart.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct OpaqueResponder {
    keypair: ResponderKeyPair,
    /// Independent random seed for per-account OPRF key derivation.
    /// Must be stored separately from the signing keypair so that
    /// compromise of one does not directly expose the other.
    oprf_seed: [u8; OPRF_SEED_LENGTH],
}

impl OpaqueResponder {
    /// Constructs a responder from an existing keypair and OPRF seed.
    ///
    /// Both values must be stored at provisioning time and reloaded together
    /// on each restart.
    ///
    /// # Errors
    ///
    /// Returns an error if the keypair public key is not a valid Ristretto255
    /// point or the OPRF seed is all zeros.
    pub fn new(keypair: ResponderKeyPair, oprf_seed: [u8; OPRF_SEED_LENGTH]) -> OpaqueResult<Self> {
        opaque_core::crypto::validate_public_key(&keypair.public_key)?;
        if is_all_zero(&oprf_seed) {
            return Err(OpaqueError::InvalidInput);
        }
        Ok(Self { keypair, oprf_seed })
    }

    /// Generates a brand-new responder with a fresh random keypair and OPRF seed.
    ///
    /// Persist both [`keypair()`](Self::keypair) and [`oprf_seed()`](Self::oprf_seed)
    /// to stable storage before accepting any registrations. Losing the seed
    /// makes all registered accounts unrecoverable.
    ///
    /// # Errors
    ///
    /// Returns an error if keypair generation fails.
    pub fn generate() -> OpaqueResult<Self> {
        let keypair = ResponderKeyPair::generate()?;
        let mut oprf_seed = [0u8; OPRF_SEED_LENGTH];
        opaque_core::crypto::random_bytes(&mut oprf_seed)?;
        Ok(Self { keypair, oprf_seed })
    }

    /// Returns a reference to the responder long-term keypair.
    pub fn keypair(&self) -> &ResponderKeyPair {
        &self.keypair
    }

    /// Returns a reference to the responder long-term public key.
    pub fn public_key(&self) -> &[u8; PUBLIC_KEY_LENGTH] {
        &self.keypair.public_key
    }

    /// Returns a reference to the OPRF seed used for per-account key derivation.
    pub fn oprf_seed(&self) -> &[u8; OPRF_SEED_LENGTH] {
        &self.oprf_seed
    }
}
