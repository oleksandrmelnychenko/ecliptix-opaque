// Copyright (c) 2026 Oleksandr Melnychenko, Ukraine
// Ecliptix Security — Hybrid PQ-OPAQUE
// Licensed under the MIT License

use crate::crypto;
use crate::types::{
    constant_time_eq, Envelope, HASH_LENGTH, NONCE_LENGTH, OpaqueError, OpaqueResult,
    PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH, SECRETBOX_KEY_LENGTH, SECRETBOX_MAC_LENGTH, labels,
};
use zeroize::Zeroize;

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
        return Err(OpaqueError::InvalidInput);
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
        .map_err(|_| OpaqueError::InvalidInput)?;
    let tag: &mut [u8; SECRETBOX_MAC_LENGTH] = envelope.auth_tag.as_mut_slice().try_into()
        .map_err(|_| OpaqueError::InvalidInput)?;

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
        return Err(OpaqueError::InvalidInput);
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
        .map_err(|_| OpaqueError::InvalidInput)?;
    let tag: &[u8; SECRETBOX_MAC_LENGTH] = envelope.auth_tag.as_slice().try_into()
        .map_err(|_| OpaqueError::InvalidInput)?;

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

    let derived_pk = crypto::scalarmult_base(initiator_private_key);

    if !constant_time_eq(initiator_public_key, &derived_pk) {
        plaintext.zeroize();
        return Err(OpaqueError::AuthenticationError);
    }

    plaintext.zeroize();
    Ok(())
}
