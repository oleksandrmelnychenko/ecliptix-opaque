// Copyright (c) 2026 Oleksandr Melnychenko, Ukraine
// Ecliptix Security — Hybrid PQ-OPAQUE
// Licensed under the MIT License

use crate::crypto;
use crate::types::{
    labels, HASH_LENGTH, OpaqueError, OpaqueResult, PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH,
};
use zeroize::Zeroize;

const HASH_TO_GROUP_DOMAIN: u8 = 0x00;
const FINALIZE_DOMAIN: u8 = 0x01;

pub fn hash_to_group(input: &[u8], point_out: &mut [u8; PUBLIC_KEY_LENGTH]) -> OpaqueResult<()> {
    if input.is_empty() {
        return Err(OpaqueError::InvalidInput);
    }

    let mut full_input = Vec::with_capacity(labels::OPRF_CONTEXT.len() + 1 + input.len());
    full_input.extend_from_slice(labels::OPRF_CONTEXT);
    full_input.push(HASH_TO_GROUP_DOMAIN);
    full_input.extend_from_slice(input);

    let mut hash = [0u8; HASH_LENGTH];
    crypto::sha512(&full_input, &mut hash);

    unsafe {
        if libsodium_sys::crypto_core_ristretto255_from_hash(
            point_out.as_mut_ptr(),
            hash.as_ptr(),
        ) != 0
        {
            hash.zeroize();
            full_input.zeroize();
            return Err(OpaqueError::CryptoError);
        }
    }

    hash.zeroize();
    full_input.zeroize();
    Ok(())
}

pub fn blind(
    input: &[u8],
    blinded_element: &mut [u8; PUBLIC_KEY_LENGTH],
    blind_scalar: &mut [u8; PRIVATE_KEY_LENGTH],
) -> OpaqueResult<()> {
    if input.is_empty() {
        return Err(OpaqueError::InvalidInput);
    }

    *blind_scalar = crypto::random_nonzero_scalar();

    let mut element = [0u8; PUBLIC_KEY_LENGTH];
    hash_to_group(input, &mut element)?;

    crypto::scalar_mult(blind_scalar, &element, blinded_element)
}

pub fn evaluate(
    blinded_element: &[u8; PUBLIC_KEY_LENGTH],
    private_key: &[u8; PRIVATE_KEY_LENGTH],
    evaluated_element: &mut [u8; PUBLIC_KEY_LENGTH],
) -> OpaqueResult<()> {
    crypto::scalar_mult(private_key, blinded_element, evaluated_element)
}

pub fn finalize(
    input: &[u8],
    blind_scalar: &[u8; PRIVATE_KEY_LENGTH],
    evaluated_element: &[u8; PUBLIC_KEY_LENGTH],
    oprf_output: &mut [u8; HASH_LENGTH],
) -> OpaqueResult<()> {
    if input.is_empty() {
        return Err(OpaqueError::InvalidInput);
    }

    let mut scalar_inv = [0u8; PRIVATE_KEY_LENGTH];
    crypto::scalar_invert(blind_scalar, &mut scalar_inv)?;

    let mut unblinded_bytes = [0u8; PUBLIC_KEY_LENGTH];
    crypto::scalar_mult(&scalar_inv, evaluated_element, &mut unblinded_bytes)?;
    scalar_inv.zeroize();

    let mut hash_input =
        Vec::with_capacity(labels::OPRF_CONTEXT.len() + 1 + input.len() + PUBLIC_KEY_LENGTH);
    hash_input.extend_from_slice(labels::OPRF_CONTEXT);
    hash_input.push(FINALIZE_DOMAIN);
    hash_input.extend_from_slice(input);
    hash_input.extend_from_slice(&unblinded_bytes);

    crypto::sha512(&hash_input, oprf_output);

    hash_input.zeroize();
    Ok(())
}
