// Copyright (c) 2026 Oleksandr Melnychenko, Ukraine
// Ecliptix Security — Hybrid PQ-OPAQUE
// Licensed under the MIT License

use crate::types::{
    is_all_zero, labels, HASH_LENGTH, MAC_LENGTH, NONCE_LENGTH, OpaqueError, OpaqueResult,
    OPRF_SEED_LENGTH, PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH, SECRETBOX_KEY_LENGTH,
    SECRETBOX_MAC_LENGTH,
};
use zeroize::Zeroize;

/// Argon2id iteration count (MODERATE profile).
const KSF_OPSLIMIT: u64 = 3;
/// Argon2id memory limit in bytes (256 MiB).
const KSF_MEMLIMIT: usize = 268_435_456;
/// Required salt length for Argon2id.
const ARGON2_SALT_BYTES: usize = 16;
/// Algorithm identifier for Argon2id v1.3 in libsodium.
const ARGON2_ALG_ARGON2ID13: i32 = 2;

/// Fills `buf` with cryptographically secure random bytes.
///
/// # Errors
///
/// Returns [`OpaqueError::InvalidInput`] if `buf` is empty.
pub fn random_bytes(buf: &mut [u8]) -> OpaqueResult<()> {
    if buf.is_empty() {
        return Err(OpaqueError::InvalidInput);
    }
    // SAFETY: buf is a valid mutable slice; length matches buf.len().
    unsafe {
        libsodium_sys::randombytes_buf(buf.as_mut_ptr() as *mut _, buf.len());
    }
    Ok(())
}

/// Derives a Ristretto255 key pair deterministically from a seed.
///
/// Hashes the seed with SHA-512, reduces modulo the group order to obtain
/// the private scalar, and computes the corresponding public point.
///
/// # Errors
///
/// Returns [`OpaqueError::InvalidInput`] if `seed` is empty or the
/// derived scalar is zero.
/// Returns [`OpaqueError::CryptoError`] if the base-point multiplication fails.
pub fn derive_key_pair(
    seed: &[u8],
    private_key: &mut [u8; PRIVATE_KEY_LENGTH],
    public_key: &mut [u8; PUBLIC_KEY_LENGTH],
) -> OpaqueResult<()> {
    if seed.is_empty() {
        return Err(OpaqueError::InvalidInput);
    }

    let mut hash = [0u8; HASH_LENGTH];
    // SAFETY: Output is a 64-byte array, input is a valid slice. Length is cast from usize.
    // hash is a 64-byte aligned array, out is a 32-byte array as required by libsodium.
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

    // SAFETY: All arrays are 32-byte aligned as required. Return code is checked.
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

/// Performs Ristretto255 scalar multiplication: `result = scalar * point`.
///
/// # Errors
///
/// Returns [`OpaqueError::CryptoError`] if the underlying libsodium call fails
/// (e.g., the point is not canonical).
pub fn scalar_mult(
    scalar_bytes: &[u8; PRIVATE_KEY_LENGTH],
    point_bytes: &[u8; PUBLIC_KEY_LENGTH],
    result: &mut [u8; PUBLIC_KEY_LENGTH],
) -> OpaqueResult<()> {
    // SAFETY: All arrays are 32-byte aligned as required. Return code is checked.
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

/// Validates that `point` is a canonical, non-identity Ristretto255 group element.
///
/// # Errors
///
/// Returns [`OpaqueError::InvalidInput`] if `point` has the wrong length,
/// is all zeros, or is not a valid Ristretto255 encoding.
pub fn validate_ristretto_point(point: &[u8]) -> OpaqueResult<()> {
    if point.len() != PUBLIC_KEY_LENGTH {
        return Err(OpaqueError::InvalidInput);
    }
    if is_all_zero(point) {
        return Err(OpaqueError::InvalidInput);
    }
    // SAFETY: Pointer comes from a valid slice of PUBLIC_KEY_LENGTH bytes.
    unsafe {
        if libsodium_sys::crypto_core_ristretto255_is_valid_point(point.as_ptr()) != 1 {
            return Err(OpaqueError::InvalidInput);
        }
    }
    Ok(())
}

/// Validates that `key` is a canonical, non-identity Ristretto255 public key.
///
/// Behaves identically to [`validate_ristretto_point`] but returns
/// [`OpaqueError::InvalidPublicKey`] for clearer error semantics.
///
/// # Errors
///
/// Returns [`OpaqueError::InvalidPublicKey`] if `key` has the wrong length,
/// is all zeros, or is not a valid Ristretto255 encoding.
pub fn validate_public_key(key: &[u8]) -> OpaqueResult<()> {
    if key.len() != PUBLIC_KEY_LENGTH {
        return Err(OpaqueError::InvalidPublicKey);
    }
    if is_all_zero(key) {
        return Err(OpaqueError::InvalidPublicKey);
    }
    // SAFETY: Pointer comes from a valid slice of PUBLIC_KEY_LENGTH bytes.
    unsafe {
        if libsodium_sys::crypto_core_ristretto255_is_valid_point(key.as_ptr()) != 1 {
            return Err(OpaqueError::InvalidPublicKey);
        }
    }
    Ok(())
}

/// Hashes arbitrary input to a Ristretto255 scalar via SHA-512 + modular reduction.
///
/// # Errors
///
/// Returns [`OpaqueError::InvalidInput`] if `input` is empty.
pub fn hash_to_scalar(input: &[u8], scalar_out: &mut [u8; PRIVATE_KEY_LENGTH]) -> OpaqueResult<()> {
    if input.is_empty() {
        return Err(OpaqueError::InvalidInput);
    }
    let mut hash = [0u8; HASH_LENGTH];
    // SAFETY: Output is a 64-byte array, input is a valid slice. Length is cast from usize.
    // hash is a 64-byte aligned array, out is a 32-byte array as required by libsodium.
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

/// Hashes arbitrary input to a Ristretto255 group element via SHA-512 + Elligator.
///
/// # Errors
///
/// Returns [`OpaqueError::InvalidInput`] if `input` is empty.
/// Returns [`OpaqueError::CryptoError`] if the hash-to-point mapping fails.
pub fn hash_to_group(input: &[u8], point_out: &mut [u8; PUBLIC_KEY_LENGTH]) -> OpaqueResult<()> {
    if input.is_empty() {
        return Err(OpaqueError::InvalidInput);
    }
    let mut hash = [0u8; HASH_LENGTH];
    // SAFETY: Output is a 64-byte array, input is a valid slice. Length is cast from usize.
    // hash is a 64-byte array, out is a 32-byte array. Return code is checked.
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

/// Computes HMAC-SHA-512 over `message` using the given `key`.
///
/// # Errors
///
/// Returns [`OpaqueError::InvalidInput`] if `key` or `message` is empty.
/// Returns [`OpaqueError::CryptoError`] if the HMAC init, update, or final step fails.
pub fn hmac_sha512(key: &[u8], message: &[u8], mac_out: &mut [u8; MAC_LENGTH]) -> OpaqueResult<()> {
    if key.is_empty() || message.is_empty() {
        return Err(OpaqueError::InvalidInput);
    }
    // SAFETY: State is initialized by _init before use. Subsequent calls use the
    // initialized state pointer. Return codes are checked. State is zeroized after use
    // to scrub the HMAC key material (ipad/opad) from the stack.
    unsafe {
        let mut state =
            std::mem::MaybeUninit::<libsodium_sys::crypto_auth_hmacsha512_state>::uninit();
        let state_ptr = state.as_mut_ptr();
        if libsodium_sys::crypto_auth_hmacsha512_init(
            state_ptr,
            key.as_ptr(),
            key.len(),
        ) != 0
        {
            libsodium_sys::sodium_memzero(
                state_ptr as *mut _,
                std::mem::size_of::<libsodium_sys::crypto_auth_hmacsha512_state>(),
            );
            return Err(OpaqueError::CryptoError);
        }
        if libsodium_sys::crypto_auth_hmacsha512_update(
            state_ptr,
            message.as_ptr(),
            message.len() as u64,
        ) != 0
        {
            libsodium_sys::sodium_memzero(
                state_ptr as *mut _,
                std::mem::size_of::<libsodium_sys::crypto_auth_hmacsha512_state>(),
            );
            return Err(OpaqueError::CryptoError);
        }
        if libsodium_sys::crypto_auth_hmacsha512_final(state_ptr, mac_out.as_mut_ptr()) != 0 {
            libsodium_sys::sodium_memzero(
                state_ptr as *mut _,
                std::mem::size_of::<libsodium_sys::crypto_auth_hmacsha512_state>(),
            );
            return Err(OpaqueError::CryptoError);
        }
        libsodium_sys::sodium_memzero(
            state_ptr as *mut _,
            std::mem::size_of::<libsodium_sys::crypto_auth_hmacsha512_state>(),
        );
    }
    Ok(())
}

/// Computes HMAC-SHA-512 and compares it to `expected_mac` in constant time.
///
/// # Errors
///
/// Returns [`OpaqueError::InvalidInput`] if `key` or `message` is empty, or
/// `expected_mac` is not exactly [`MAC_LENGTH`] bytes.
/// Returns [`OpaqueError::AuthenticationError`] if the computed MAC does not match.
pub fn verify_hmac(key: &[u8], message: &[u8], expected_mac: &[u8]) -> OpaqueResult<()> {
    if key.is_empty() || message.is_empty() || expected_mac.len() != MAC_LENGTH {
        return Err(OpaqueError::InvalidInput);
    }
    let mut computed = [0u8; MAC_LENGTH];
    hmac_sha512(key, message, &mut computed)?;
    // SAFETY: Both pointers come from valid slices. Length equality is verified before the call.
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

/// Performs the HKDF-Extract step: `PRK = HMAC-SHA-512(salt, IKM)`.
///
/// # Errors
///
/// Returns [`OpaqueError::InvalidInput`] if `salt` or `ikm` is empty.
/// Returns [`OpaqueError::CryptoError`] if the underlying HMAC operation fails.
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

/// Performs the HKDF-Expand step, producing output keying material of arbitrary length.
///
/// Uses HMAC-SHA-512 as the underlying PRF. The output length must not
/// exceed `255 * 64` bytes.
///
/// # Errors
///
/// Returns [`OpaqueError::InvalidInput`] if `prk` or `okm` is empty, or if the
/// requested output length exceeds the HKDF-Expand maximum.
/// Returns [`OpaqueError::CryptoError`] if the underlying HMAC operation fails.
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

    let n = okm.len().div_ceil(HASH_LEN);
    if n > MAX_BLOCKS {
        return Err(OpaqueError::InvalidInput);
    }

    let mut t_prev = [0u8; HASH_LEN];
    let mut t_current = [0u8; HASH_LEN];
    let mut input = Vec::with_capacity(HASH_LEN + info.len() + 1);

    let result = (|| {
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
        Ok(())
    })();

    t_prev.zeroize();
    t_current.zeroize();
    input.zeroize();
    result
}

/// Derives a per-account OPRF scalar key from the relay secret and account identifier.
///
/// Uses a counter-based try-and-increment strategy to ensure the resulting
/// scalar is non-zero modulo the group order.
///
/// # Errors
///
/// Returns [`OpaqueError::InvalidInput`] if `relay_secret` or `account_id` is empty.
/// Returns [`OpaqueError::CryptoError`] if a non-zero scalar cannot be found after
/// 255 attempts or if the underlying HMAC operation fails.
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

        // SAFETY: hash is a 64-byte aligned array, out is a 32-byte array as required by libsodium.
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

/// Derives a randomized password by running Argon2id over the OPRF output and secure key.
///
/// The KSF input is `SHA-512(KSF_CONTEXT || oprf_output || secure_key)` and the
/// salt is the first 16 bytes of `SHA-512(KSF_SALT_LABEL || oprf_output)`.
///
/// # Errors
///
/// Returns [`OpaqueError::InvalidInput`] if any input slice is empty.
/// Returns [`OpaqueError::CryptoError`] if Argon2id fails (e.g., insufficient memory).
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

    // SAFETY: All buffers are valid and correctly sized. opslimit/memlimit are constant.
    // Algorithm is Argon2id13. Return code is checked.
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
            salt_full.zeroize();
            salt.zeroize();
            return Err(OpaqueError::CryptoError);
        }
    }

    rwd_input.zeroize();
    salt_full.zeroize();
    salt.zeroize();
    Ok(())
}

/// Encrypts `plaintext` with XSalsa20-Poly1305 in detached mode.
///
/// Writes the ciphertext to `ciphertext` and the Poly1305 tag to `auth_tag`.
///
/// # Errors
///
/// Returns [`OpaqueError::InvalidInput`] if `key` is not [`SECRETBOX_KEY_LENGTH`] bytes,
/// `plaintext` is empty, or `ciphertext` is shorter than `plaintext`.
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

    // SAFETY: Key is SECRETBOX_KEY_LENGTH, nonce is NONCE_LENGTH, buffers are correctly sized.
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

/// Decrypts `ciphertext` with XSalsa20-Poly1305 in detached mode.
///
/// Verifies the Poly1305 `auth_tag` before writing the plaintext.
///
/// # Errors
///
/// Returns [`OpaqueError::InvalidInput`] if `key` is not [`SECRETBOX_KEY_LENGTH`] bytes,
/// `ciphertext` is empty, or `plaintext` is shorter than `ciphertext`.
/// Returns [`OpaqueError::AuthenticationError`] if the authentication tag does not verify.
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

    // SAFETY: Key is SECRETBOX_KEY_LENGTH, nonce is NONCE_LENGTH, buffers are correctly sized.
    // Return code is checked for open_detached.
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

/// Generates a uniformly random, non-zero Ristretto255 scalar.
///
/// Loops until a non-zero scalar is obtained (overwhelmingly likely on the first try).
pub fn random_nonzero_scalar() -> [u8; PRIVATE_KEY_LENGTH] {
    loop {
        let mut scalar = [0u8; PRIVATE_KEY_LENGTH];
        // SAFETY: Output is a 32-byte aligned array.
        unsafe {
            libsodium_sys::crypto_core_ristretto255_scalar_random(scalar.as_mut_ptr());
        }
        if !is_all_zero(&scalar) {
            return scalar;
        }
    }
}

/// Computes the Ristretto255 base-point multiplication: `result = scalar * G`.
///
/// # Errors
///
/// Returns [`OpaqueError::CryptoError`] if the libsodium call fails.
pub fn scalarmult_base(scalar: &[u8; PRIVATE_KEY_LENGTH]) -> OpaqueResult<[u8; PUBLIC_KEY_LENGTH]> {
    let mut result = [0u8; PUBLIC_KEY_LENGTH];
    // SAFETY: All arrays are 32-byte aligned as required. Return code is checked.
    unsafe {
        if libsodium_sys::crypto_scalarmult_ristretto255_base(
            result.as_mut_ptr(),
            scalar.as_ptr(),
        ) != 0
        {
            return Err(OpaqueError::CryptoError);
        }
    }
    Ok(result)
}

/// Computes the modular inverse of a Ristretto255 scalar.
///
/// # Errors
///
/// Returns [`OpaqueError::CryptoError`] if the scalar is zero or the inversion fails.
pub fn scalar_invert(
    scalar: &[u8; PRIVATE_KEY_LENGTH],
    result: &mut [u8; PRIVATE_KEY_LENGTH],
) -> OpaqueResult<()> {
    // SAFETY: Both arrays are 32-byte. Return code is checked.
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

/// Computes the SHA-512 digest of `input`.
pub fn sha512(input: &[u8], out: &mut [u8; HASH_LENGTH]) {
    // SAFETY: Output is a 64-byte array, input is a valid slice. Length is cast from usize.
    unsafe {
        libsodium_sys::crypto_hash_sha512(out.as_mut_ptr(), input.as_ptr(), input.len() as u64);
    }
}

/// Computes the SHA-512 digest of the concatenation of all `parts`.
///
/// Uses the streaming SHA-512 API to avoid allocating a contiguous buffer.
pub fn sha512_multi(parts: &[&[u8]], out: &mut [u8; HASH_LENGTH]) {
    // SAFETY: State is initialized by _init before use. Subsequent _update and _final
    // calls use the initialized state pointer.
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
