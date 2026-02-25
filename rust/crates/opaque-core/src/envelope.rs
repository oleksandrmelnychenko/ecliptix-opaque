// Copyright (c) 2026 Oleksandr Melnychenko, Ukraine
// Ecliptix Security — Hybrid PQ-OPAQUE
// Licensed under the MIT License

use crate::crypto;
use crate::types::{
    constant_time_eq, Envelope, HASH_LENGTH, NONCE_LENGTH, OpaqueError, OpaqueResult,
    PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH, SECRETBOX_KEY_LENGTH, SECRETBOX_MAC_LENGTH, labels,
};
use zeroize::Zeroize;

/// Seals the initiator's credentials into an encrypted envelope.
///
/// Derives an encryption key from the randomized password and responder public key,
/// encrypts the credential triple (responder public key, initiator private key,
/// initiator public key) with XSalsa20-Poly1305, and stores the result in `envelope`.
///
/// # Errors
///
/// Returns [`OpaqueError::InvalidInput`] if `randomized_pwd` is empty.
/// Returns [`OpaqueError::InvalidEnvelope`] if the envelope nonce has an incorrect length.
/// Returns [`OpaqueError::CryptoError`] if encryption fails.
pub fn seal(
    randomized_pwd: &[u8],
    responder_public_key: &[u8; PUBLIC_KEY_LENGTH],
    initiator_private_key: &[u8; PRIVATE_KEY_LENGTH],
    initiator_public_key: &[u8; PUBLIC_KEY_LENGTH],
    envelope: &mut Envelope,
) -> OpaqueResult<()> {
    if randomized_pwd.is_empty() {
        return Err(OpaqueError::InvalidInput);
    }
    if envelope.nonce.len() != NONCE_LENGTH {
        return Err(OpaqueError::InvalidEnvelope);
    }

    crypto::random_bytes(&mut envelope.nonce)?;

    let mut hash = [0u8; HASH_LENGTH];
    crypto::sha512_multi(
        &[labels::ENVELOPE_CONTEXT, responder_public_key, randomized_pwd],
        &mut hash,
    );
    let mut auth_key = [0u8; SECRETBOX_KEY_LENGTH];
    auth_key.copy_from_slice(&hash[..SECRETBOX_KEY_LENGTH]);

    const PLAINTEXT_LEN: usize = PUBLIC_KEY_LENGTH + PRIVATE_KEY_LENGTH + PUBLIC_KEY_LENGTH;
    let mut plaintext = [0u8; PLAINTEXT_LEN];
    plaintext[..PUBLIC_KEY_LENGTH].copy_from_slice(responder_public_key);
    plaintext[PUBLIC_KEY_LENGTH..PUBLIC_KEY_LENGTH + PRIVATE_KEY_LENGTH]
        .copy_from_slice(initiator_private_key);
    plaintext[PUBLIC_KEY_LENGTH + PRIVATE_KEY_LENGTH..].copy_from_slice(initiator_public_key);

    envelope.ciphertext.resize(PLAINTEXT_LEN, 0);
    envelope.auth_tag.resize(SECRETBOX_MAC_LENGTH, 0);
    let nonce: &[u8; NONCE_LENGTH] = envelope.nonce.as_slice().try_into()
        .map_err(|_| OpaqueError::InvalidEnvelope)?;
    let tag: &mut [u8; SECRETBOX_MAC_LENGTH] = envelope.auth_tag.as_mut_slice().try_into()
        .map_err(|_| OpaqueError::InvalidEnvelope)?;

    crypto::encrypt_envelope(
        &auth_key,
        &plaintext,
        nonce,
        &mut envelope.ciphertext,
        tag,
    )?;

    auth_key.zeroize();
    plaintext.zeroize();
    Ok(())
}

/// Opens a sealed credential envelope and recovers the initiator's key material.
///
/// Derives the decryption key, authenticates and decrypts the ciphertext, then
/// verifies that the recovered initiator public key matches the recovered private key.
///
/// # Errors
///
/// Returns [`OpaqueError::InvalidInput`] if `randomized_pwd` is empty.
/// Returns [`OpaqueError::InvalidEnvelope`] if the envelope fields have incorrect lengths.
/// Returns [`OpaqueError::AuthenticationError`] if the Poly1305 tag does not verify
/// or the recovered key pair is inconsistent.
/// Returns [`OpaqueError::CryptoError`] if decryption or key derivation fails.
pub fn open(
    envelope: &Envelope,
    randomized_pwd: &[u8],
    known_responder_public_key: &[u8; PUBLIC_KEY_LENGTH],
    responder_public_key: &mut [u8; PUBLIC_KEY_LENGTH],
    initiator_private_key: &mut [u8; PRIVATE_KEY_LENGTH],
    initiator_public_key: &mut [u8; PUBLIC_KEY_LENGTH],
) -> OpaqueResult<()> {
    if randomized_pwd.is_empty() {
        return Err(OpaqueError::InvalidInput);
    }

    const PLAINTEXT_LEN: usize = PUBLIC_KEY_LENGTH + PRIVATE_KEY_LENGTH + PUBLIC_KEY_LENGTH;
    if envelope.nonce.len() != NONCE_LENGTH
        || envelope.ciphertext.len() != PLAINTEXT_LEN
        || envelope.auth_tag.len() != SECRETBOX_MAC_LENGTH
    {
        return Err(OpaqueError::InvalidEnvelope);
    }

    let mut hash = [0u8; HASH_LENGTH];
    crypto::sha512_multi(
        &[labels::ENVELOPE_CONTEXT, known_responder_public_key, randomized_pwd],
        &mut hash,
    );
    let mut auth_key = [0u8; SECRETBOX_KEY_LENGTH];
    auth_key.copy_from_slice(&hash[..SECRETBOX_KEY_LENGTH]);

    let mut plaintext = [0u8; PLAINTEXT_LEN];
    let nonce: &[u8; NONCE_LENGTH] = envelope.nonce.as_slice().try_into()
        .map_err(|_| OpaqueError::InvalidEnvelope)?;
    let tag: &[u8; SECRETBOX_MAC_LENGTH] = envelope.auth_tag.as_slice().try_into()
        .map_err(|_| OpaqueError::InvalidEnvelope)?;

    let result = crypto::decrypt_envelope(
        &auth_key,
        &envelope.ciphertext,
        nonce,
        tag,
        &mut plaintext,
    );

    auth_key.zeroize();

    let Ok(()) = result else {
        plaintext.zeroize();
        return result;
    };

    responder_public_key.copy_from_slice(&plaintext[..PUBLIC_KEY_LENGTH]);
    initiator_private_key
        .copy_from_slice(&plaintext[PUBLIC_KEY_LENGTH..PUBLIC_KEY_LENGTH + PRIVATE_KEY_LENGTH]);
    initiator_public_key.copy_from_slice(&plaintext[PUBLIC_KEY_LENGTH + PRIVATE_KEY_LENGTH..]);

    let derived_pk = crypto::scalarmult_base(initiator_private_key)?;

    if !constant_time_eq(initiator_public_key, &derived_pk) {
        plaintext.zeroize();
        return Err(OpaqueError::AuthenticationError);
    }

    plaintext.zeroize();
    Ok(())
}
