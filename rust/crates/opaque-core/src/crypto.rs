// Copyright (c) 2026 Oleksandr Melnychenko, Ukraine
// Ecliptix Security — Hybrid PQ-OPAQUE
// Licensed under the MIT License

use crate::types::{
    is_all_zero, labels, HASH_LENGTH, MAC_LENGTH, NONCE_LENGTH, OpaqueError, OpaqueResult,
    OPRF_SEED_LENGTH, PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH, SECRETBOX_KEY_LENGTH,
    SECRETBOX_MAC_LENGTH,
};
use zeroize::Zeroize;

const KSF_OPSLIMIT: u64 = 3;
const KSF_MEMLIMIT: usize = 268_435_456;
const ARGON2_SALT_BYTES: usize = 16;
const ARGON2_ALG_ARGON2ID13: i32 = 2;

pub fn random_bytes(buf: &mut [u8]) -> OpaqueResult<()> {
    if buf.is_empty() {
        return Err(OpaqueError::InvalidInput);
    }
    unsafe {
        libsodium_sys::randombytes_buf(buf.as_mut_ptr() as *mut _, buf.len());
    }
    Ok(())
}

pub fn derive_key_pair(
    seed: &[u8],
    private_key: &mut [u8; PRIVATE_KEY_LENGTH],
    public_key: &mut [u8; PUBLIC_KEY_LENGTH],
) -> OpaqueResult<()> {
    if seed.is_empty() {
        return Err(OpaqueError::InvalidInput);
    }

    let mut hash = [0u8; HASH_LENGTH];
    unsafe {
        libsodium_sys::crypto_hash_sha512(hash.as_mut_ptr(), seed.as_ptr(), seed.len() as u64);
        libsodium_sys::crypto_core_ristretto255_scalar_reduce(
            private_key.as_mut_ptr(),
            hash.as_ptr(),
        );
    }
    hash.zeroize();

    if is_all_zero(private_key) {
        return Err(OpaqueError::InvalidInput);
    }

    unsafe {
        if libsodium_sys::crypto_scalarmult_ristretto255_base(
            public_key.as_mut_ptr(),
            private_key.as_ptr(),
        ) != 0
        {
            return Err(OpaqueError::CryptoError);
        }
    }
    Ok(())
}

pub fn scalar_mult(
    scalar_bytes: &[u8; PRIVATE_KEY_LENGTH],
    point_bytes: &[u8; PUBLIC_KEY_LENGTH],
    result: &mut [u8; PUBLIC_KEY_LENGTH],
) -> OpaqueResult<()> {
    unsafe {
        if libsodium_sys::crypto_scalarmult_ristretto255(
            result.as_mut_ptr(),
            scalar_bytes.as_ptr(),
            point_bytes.as_ptr(),
        ) != 0
        {
            return Err(OpaqueError::CryptoError);
        }
    }
    Ok(())
}

pub fn validate_ristretto_point(point: &[u8]) -> OpaqueResult<()> {
    if point.len() != PUBLIC_KEY_LENGTH {
        return Err(OpaqueError::InvalidInput);
    }
    if is_all_zero(point) {
        return Err(OpaqueError::InvalidInput);
    }
    unsafe {
        if libsodium_sys::crypto_core_ristretto255_is_valid_point(point.as_ptr()) != 1 {
            return Err(OpaqueError::InvalidInput);
        }
    }
    Ok(())
}

pub fn validate_public_key(key: &[u8]) -> OpaqueResult<()> {
    if key.len() != PUBLIC_KEY_LENGTH {
        return Err(OpaqueError::InvalidPublicKey);
    }
    if is_all_zero(key) {
        return Err(OpaqueError::InvalidPublicKey);
    }
    unsafe {
        if libsodium_sys::crypto_core_ristretto255_is_valid_point(key.as_ptr()) != 1 {
            return Err(OpaqueError::InvalidPublicKey);
        }
    }
    Ok(())
}

pub fn hash_to_scalar(input: &[u8], scalar_out: &mut [u8; PRIVATE_KEY_LENGTH]) -> OpaqueResult<()> {
    if input.is_empty() {
        return Err(OpaqueError::InvalidInput);
    }
    let mut hash = [0u8; HASH_LENGTH];
    unsafe {
        libsodium_sys::crypto_hash_sha512(hash.as_mut_ptr(), input.as_ptr(), input.len() as u64);
        libsodium_sys::crypto_core_ristretto255_scalar_reduce(
            scalar_out.as_mut_ptr(),
            hash.as_ptr(),
        );
    }
    hash.zeroize();
    Ok(())
}

pub fn hash_to_group(input: &[u8], point_out: &mut [u8; PUBLIC_KEY_LENGTH]) -> OpaqueResult<()> {
    if input.is_empty() {
        return Err(OpaqueError::InvalidInput);
    }
    let mut hash = [0u8; HASH_LENGTH];
    unsafe {
        libsodium_sys::crypto_hash_sha512(hash.as_mut_ptr(), input.as_ptr(), input.len() as u64);
        if libsodium_sys::crypto_core_ristretto255_from_hash(
            point_out.as_mut_ptr(),
            hash.as_ptr(),
        ) != 0
        {
            hash.zeroize();
            return Err(OpaqueError::CryptoError);
        }
    }
    hash.zeroize();
    Ok(())
}

pub fn hmac_sha512(key: &[u8], message: &[u8], mac_out: &mut [u8; MAC_LENGTH]) -> OpaqueResult<()> {
    if key.is_empty() || message.is_empty() {
        return Err(OpaqueError::InvalidInput);
    }
    unsafe {
        let mut state =
            std::mem::MaybeUninit::<libsodium_sys::crypto_auth_hmacsha512_state>::uninit();
        if libsodium_sys::crypto_auth_hmacsha512_init(
            state.as_mut_ptr(),
            key.as_ptr(),
            key.len(),
        ) != 0
        {
            return Err(OpaqueError::CryptoError);
        }
        let state_ptr = state.as_mut_ptr();
        if libsodium_sys::crypto_auth_hmacsha512_update(
            state_ptr,
            message.as_ptr(),
            message.len() as u64,
        ) != 0
        {
            return Err(OpaqueError::CryptoError);
        }
        if libsodium_sys::crypto_auth_hmacsha512_final(state_ptr, mac_out.as_mut_ptr()) != 0 {
            return Err(OpaqueError::CryptoError);
        }
    }
    Ok(())
}

pub fn verify_hmac(key: &[u8], message: &[u8], expected_mac: &[u8]) -> OpaqueResult<()> {
    if key.is_empty() || message.is_empty() || expected_mac.len() != MAC_LENGTH {
        return Err(OpaqueError::InvalidInput);
    }
    let mut computed = [0u8; MAC_LENGTH];
    hmac_sha512(key, message, &mut computed)?;
    unsafe {
        if libsodium_sys::sodium_memcmp(
            computed.as_ptr() as *const _,
            expected_mac.as_ptr() as *const _,
            MAC_LENGTH,
        ) != 0
        {
            computed.zeroize();
            return Err(OpaqueError::AuthenticationError);
        }
    }
    computed.zeroize();
    Ok(())
}

pub fn key_derivation_extract(
    salt: &[u8],
    ikm: &[u8],
    prk: &mut [u8; HASH_LENGTH],
) -> OpaqueResult<()> {
    if salt.is_empty() || ikm.is_empty() {
        return Err(OpaqueError::InvalidInput);
    }
    hmac_sha512(salt, ikm, prk)
}

pub fn key_derivation_expand(
    prk: &[u8],
    info: &[u8],
    okm: &mut [u8],
) -> OpaqueResult<()> {
    if prk.is_empty() || okm.is_empty() {
        return Err(OpaqueError::InvalidInput);
    }

    const HASH_LEN: usize = HASH_LENGTH;
    const MAX_BLOCKS: usize = 255;

    let n = (okm.len() + HASH_LEN - 1) / HASH_LEN;
    if n > MAX_BLOCKS {
        return Err(OpaqueError::InvalidInput);
    }

    let mut t_prev = [0u8; HASH_LEN];
    let mut t_current = [0u8; HASH_LEN];
    let mut input = Vec::with_capacity(HASH_LEN + info.len() + 1);

    for i in 1..=n {
        input.clear();
        if i > 1 {
            input.extend_from_slice(&t_prev);
        }
        input.extend_from_slice(info);
        input.push(i as u8);

        hmac_sha512(prk, &input, &mut t_current)?;

        let copy_len = std::cmp::min(HASH_LEN, okm.len() - (i - 1) * HASH_LEN);
        okm[(i - 1) * HASH_LEN..(i - 1) * HASH_LEN + copy_len]
            .copy_from_slice(&t_current[..copy_len]);

        std::mem::swap(&mut t_prev, &mut t_current);
    }

    t_prev.zeroize();
    t_current.zeroize();
    input.zeroize();
    Ok(())
}

pub fn derive_oprf_key(
    relay_secret: &[u8],
    account_id: &[u8],
    oprf_key: &mut [u8; PRIVATE_KEY_LENGTH],
) -> OpaqueResult<()> {
    if relay_secret.is_empty() || account_id.is_empty() {
        return Err(OpaqueError::InvalidInput);
    }

    let mut oprf_seed_full = [0u8; MAC_LENGTH];
    hmac_sha512(relay_secret, labels::OPRF_SEED_INFO, &mut oprf_seed_full)?;
    let mut oprf_seed = [0u8; OPRF_SEED_LENGTH];
    oprf_seed.copy_from_slice(&oprf_seed_full[..OPRF_SEED_LENGTH]);
    oprf_seed_full.zeroize();

    let mut input = Vec::with_capacity(labels::OPRF_KEY_INFO.len() + account_id.len() + 1);
    input.extend_from_slice(labels::OPRF_KEY_INFO);
    input.extend_from_slice(account_id);
    input.push(0u8);

    let counter_offset = labels::OPRF_KEY_INFO.len() + account_id.len();
    let mut mac = [0u8; MAC_LENGTH];

    for counter in 0u16..255 {
        input[counter_offset] = counter as u8;
        hmac_sha512(&oprf_seed, &input, &mut mac)?;

        unsafe {
            libsodium_sys::crypto_core_ristretto255_scalar_reduce(
                oprf_key.as_mut_ptr(),
                mac.as_ptr(),
            );
        }

        if !is_all_zero(oprf_key) {
            mac.zeroize();
            oprf_seed.zeroize();
            input.zeroize();
            return Ok(());
        }
    }

    mac.zeroize();
    oprf_seed.zeroize();
    input.zeroize();
    Err(OpaqueError::CryptoError)
}

pub fn derive_randomized_password(
    oprf_output: &[u8],
    secure_key: &[u8],
    randomized_pwd: &mut [u8],
) -> OpaqueResult<()> {
    if oprf_output.is_empty() || secure_key.is_empty() || randomized_pwd.is_empty() {
        return Err(OpaqueError::InvalidInput);
    }

    let mut rwd_input = [0u8; HASH_LENGTH];
    sha512_multi(&[labels::KSF_CONTEXT, oprf_output, secure_key], &mut rwd_input);

    let mut salt_full = [0u8; HASH_LENGTH];
    sha512_multi(&[labels::KSF_SALT_LABEL, oprf_output], &mut salt_full);
    let mut salt = [0u8; ARGON2_SALT_BYTES];
    salt.copy_from_slice(&salt_full[..ARGON2_SALT_BYTES]);

    unsafe {
        if libsodium_sys::crypto_pwhash(
            randomized_pwd.as_mut_ptr(),
            randomized_pwd.len() as u64,
            rwd_input.as_ptr() as *const i8,
            rwd_input.len() as u64,
            salt.as_ptr(),
            KSF_OPSLIMIT,
            KSF_MEMLIMIT,
            ARGON2_ALG_ARGON2ID13,
        ) != 0
        {
            rwd_input.zeroize();
            salt.zeroize();
            return Err(OpaqueError::CryptoError);
        }
    }

    rwd_input.zeroize();
    salt.zeroize();
    Ok(())
}

pub fn encrypt_envelope(
    key: &[u8],
    plaintext: &[u8],
    nonce: &[u8; NONCE_LENGTH],
    ciphertext: &mut [u8],
    auth_tag: &mut [u8; SECRETBOX_MAC_LENGTH],
) -> OpaqueResult<()> {
    if key.len() != SECRETBOX_KEY_LENGTH || plaintext.is_empty() {
        return Err(OpaqueError::InvalidInput);
    }
    if ciphertext.len() < plaintext.len() {
        return Err(OpaqueError::InvalidInput);
    }

    unsafe {
        libsodium_sys::crypto_secretbox_detached(
            ciphertext.as_mut_ptr(),
            auth_tag.as_mut_ptr(),
            plaintext.as_ptr(),
            plaintext.len() as u64,
            nonce.as_ptr(),
            key.as_ptr(),
        );
    }
    Ok(())
}

pub fn decrypt_envelope(
    key: &[u8],
    ciphertext: &[u8],
    nonce: &[u8; NONCE_LENGTH],
    auth_tag: &[u8; SECRETBOX_MAC_LENGTH],
    plaintext: &mut [u8],
) -> OpaqueResult<()> {
    if key.len() != SECRETBOX_KEY_LENGTH || ciphertext.is_empty() {
        return Err(OpaqueError::InvalidInput);
    }
    if plaintext.len() < ciphertext.len() {
        return Err(OpaqueError::InvalidInput);
    }

    unsafe {
        if libsodium_sys::crypto_secretbox_open_detached(
            plaintext.as_mut_ptr(),
            ciphertext.as_ptr(),
            auth_tag.as_ptr(),
            ciphertext.len() as u64,
            nonce.as_ptr(),
            key.as_ptr(),
        ) != 0
        {
            return Err(OpaqueError::AuthenticationError);
        }
    }
    Ok(())
}

pub fn random_nonzero_scalar() -> [u8; PRIVATE_KEY_LENGTH] {
    loop {
        let mut scalar = [0u8; PRIVATE_KEY_LENGTH];
        unsafe {
            libsodium_sys::crypto_core_ristretto255_scalar_random(scalar.as_mut_ptr());
        }
        if !is_all_zero(&scalar) {
            return scalar;
        }
    }
}

pub fn scalarmult_base(scalar: &[u8; PRIVATE_KEY_LENGTH]) -> [u8; PUBLIC_KEY_LENGTH] {
    let mut result = [0u8; PUBLIC_KEY_LENGTH];
    unsafe {
        libsodium_sys::crypto_scalarmult_ristretto255_base(result.as_mut_ptr(), scalar.as_ptr());
    }
    result
}

pub fn scalar_invert(
    scalar: &[u8; PRIVATE_KEY_LENGTH],
    result: &mut [u8; PRIVATE_KEY_LENGTH],
) -> OpaqueResult<()> {
    unsafe {
        if libsodium_sys::crypto_core_ristretto255_scalar_invert(
            result.as_mut_ptr(),
            scalar.as_ptr(),
        ) != 0
        {
            return Err(OpaqueError::CryptoError);
        }
    }
    Ok(())
}

pub fn sha512(input: &[u8], out: &mut [u8; HASH_LENGTH]) {
    unsafe {
        libsodium_sys::crypto_hash_sha512(out.as_mut_ptr(), input.as_ptr(), input.len() as u64);
    }
}

pub fn sha512_multi(parts: &[&[u8]], out: &mut [u8; HASH_LENGTH]) {
    unsafe {
        let mut state =
            std::mem::MaybeUninit::<libsodium_sys::crypto_hash_sha512_state>::uninit();
        libsodium_sys::crypto_hash_sha512_init(state.as_mut_ptr());
        let state_ptr = state.as_mut_ptr();
        for part in parts {
            libsodium_sys::crypto_hash_sha512_update(
                state_ptr,
                part.as_ptr(),
                part.len() as u64,
            );
        }
        libsodium_sys::crypto_hash_sha512_final(state_ptr, out.as_mut_ptr());
    }
}
