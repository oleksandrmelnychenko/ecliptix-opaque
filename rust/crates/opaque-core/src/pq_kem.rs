// Copyright (c) 2026 Oleksandr Melnychenko, Ukraine
// Ecliptix Security — Hybrid PQ-OPAQUE
// Licensed under the MIT License

use crate::crypto;
use crate::types::{
    pq, pq_labels, HASH_LENGTH, OpaqueError, OpaqueResult,
};
use ml_kem::{EncodedSizeUser, KemCore, MlKem768};
use zeroize::Zeroize;

/// Type alias for the ML-KEM-768 encapsulation (public) key.
type EK = <MlKem768 as KemCore>::EncapsulationKey;
/// Type alias for the ML-KEM-768 decapsulation (secret) key.
type DK = <MlKem768 as KemCore>::DecapsulationKey;

/// Generates a fresh ML-KEM-768 key pair using the OS random number generator.
///
/// # Errors
///
/// Returns [`OpaqueError::InvalidKemInput`] if `public_key` or `secret_key` has
/// an incorrect length.
pub fn keypair_generate(
    public_key: &mut [u8],
    secret_key: &mut [u8],
) -> OpaqueResult<()> {
    if public_key.len() != pq::KEM_PUBLIC_KEY_LENGTH
        || secret_key.len() != pq::KEM_SECRET_KEY_LENGTH
    {
        return Err(OpaqueError::InvalidKemInput);
    }

    let mut rng = rand::rngs::OsRng;
    let (dk, ek) = MlKem768::generate(&mut rng);

    public_key.copy_from_slice(ek.as_bytes().as_ref());
    secret_key.copy_from_slice(dk.as_bytes().as_ref());

    Ok(())
}

/// Encapsulates a shared secret against an ML-KEM-768 public key.
///
/// Writes the KEM ciphertext to `ciphertext` and the shared secret to `shared_secret`.
///
/// # Errors
///
/// Returns [`OpaqueError::InvalidKemInput`] if any buffer has an incorrect length or
/// the public key cannot be decoded.
/// Returns [`OpaqueError::CryptoError`] if encapsulation fails.
pub fn encapsulate(
    public_key: &[u8],
    ciphertext: &mut [u8],
    shared_secret: &mut [u8],
) -> OpaqueResult<()> {
    use ml_kem::kem::Encapsulate;

    if public_key.len() != pq::KEM_PUBLIC_KEY_LENGTH
        || ciphertext.len() != pq::KEM_CIPHERTEXT_LENGTH
        || shared_secret.len() != pq::KEM_SHARED_SECRET_LENGTH
    {
        return Err(OpaqueError::InvalidKemInput);
    }

    let ek_array: ml_kem::Encoded<EK> = public_key.try_into().map_err(|_| OpaqueError::InvalidKemInput)?;
    let ek = EK::from_bytes(&ek_array);

    let mut rng = rand::rngs::OsRng;
    let (ct, ss) = ek.encapsulate(&mut rng).map_err(|_| OpaqueError::CryptoError)?;

    ciphertext.copy_from_slice(ct.as_ref());
    shared_secret.copy_from_slice(ss.as_ref());

    Ok(())
}

/// Decapsulates a shared secret from an ML-KEM-768 ciphertext using the secret key.
///
/// # Errors
///
/// Returns [`OpaqueError::InvalidKemInput`] if any buffer has an incorrect length or
/// the secret key / ciphertext cannot be decoded.
/// Returns [`OpaqueError::CryptoError`] if decapsulation fails.
pub fn decapsulate(
    secret_key: &[u8],
    ciphertext: &[u8],
    shared_secret: &mut [u8],
) -> OpaqueResult<()> {
    use ml_kem::kem::Decapsulate;

    if secret_key.len() != pq::KEM_SECRET_KEY_LENGTH
        || ciphertext.len() != pq::KEM_CIPHERTEXT_LENGTH
        || shared_secret.len() != pq::KEM_SHARED_SECRET_LENGTH
    {
        return Err(OpaqueError::InvalidKemInput);
    }

    let dk_array: ml_kem::Encoded<DK> = secret_key.try_into().map_err(|_| OpaqueError::InvalidKemInput)?;
    let dk = DK::from_bytes(&dk_array);

    let ct: ml_kem::Ciphertext<MlKem768> = ciphertext.try_into().map_err(|_| OpaqueError::InvalidKemInput)?;

    let ss = dk.decapsulate(&ct).map_err(|_| OpaqueError::CryptoError)?;
    shared_secret.copy_from_slice(ss.as_ref());

    Ok(())
}

/// Combines classical 4DH and post-quantum KEM key material into a single PRK.
///
/// Concatenates the 128-byte classical IKM (four 32-byte DH shares) with the
/// 32-byte ML-KEM shared secret, then runs `HKDF-Extract` using the labeled
/// transcript hash as salt.
///
/// # Errors
///
/// Returns [`OpaqueError::InvalidInput`] if `classical_ikm` is not 128 bytes,
/// `pq_shared_secret` is not [`pq::KEM_SHARED_SECRET_LENGTH`] bytes, or
/// `transcript_hash` is not [`HASH_LENGTH`] bytes.
/// Returns [`OpaqueError::CryptoError`] if the HKDF-Extract step fails.
pub fn combine_key_material(
    classical_ikm: &[u8],
    pq_shared_secret: &[u8],
    transcript_hash: &[u8],
    prk: &mut [u8; HASH_LENGTH],
) -> OpaqueResult<()> {
    if classical_ikm.len() != 128
        || pq_shared_secret.len() != pq::KEM_SHARED_SECRET_LENGTH
        || transcript_hash.len() != HASH_LENGTH
    {
        return Err(OpaqueError::InvalidInput);
    }

    let mut combined_ikm = vec![0u8; pq::COMBINED_IKM_LENGTH];
    combined_ikm[..classical_ikm.len()].copy_from_slice(classical_ikm);
    combined_ikm[classical_ikm.len()..].copy_from_slice(pq_shared_secret);

    let mut labeled_transcript =
        Vec::with_capacity(pq_labels::PQ_COMBINER_CONTEXT.len() + transcript_hash.len());
    labeled_transcript.extend_from_slice(pq_labels::PQ_COMBINER_CONTEXT);
    labeled_transcript.extend_from_slice(transcript_hash);

    let result = crypto::key_derivation_extract(&labeled_transcript, &combined_ikm, prk);

    combined_ikm.zeroize();
    labeled_transcript.zeroize();

    result
}
