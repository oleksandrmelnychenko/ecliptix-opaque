// Copyright (c) 2026 Oleksandr Melnychenko, Ukraine
// Ecliptix Security — Hybrid PQ-OPAQUE
// Licensed under the MIT License

use std::ptr;

use zeroize::Zeroize;

use opaque_core::protocol;
use opaque_core::types::{
    pq, OpaqueError, HASH_LENGTH, KE1_LENGTH, KE2_LENGTH, KE3_LENGTH,
    MASTER_KEY_LENGTH, OPRF_SEED_LENGTH, PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH,
    REGISTRATION_RECORD_LENGTH, REGISTRATION_REQUEST_LENGTH, REGISTRATION_RESPONSE_LENGTH,
    RESPONDER_CREDENTIALS_LENGTH,
};
use opaque_relay::{
    build_credentials, create_registration_response, generate_ke2, responder_finish,
    Ke2Message, OpaqueResponder, RegistrationResponse, ResponderCredentials, ResponderKeyPair,
    ResponderState,
};

use crate::result_to_int;

struct RelayHandle {
    responder: OpaqueResponder,
}

struct RelayStateHandle {
    state: ResponderState,
}

struct RelayKeypairHandle {
    keypair: ResponderKeyPair,
    oprf_seed: [u8; OPRF_SEED_LENGTH],
}

/// Generates a new relay keypair and OPRF seed.
///
/// # Safety
///
/// - `handle` must point to a valid `*mut c_void` location where the result is stored.
/// - The returned handle must be freed with `opaque_relay_keypair_destroy`.
#[no_mangle]
pub unsafe extern "C" fn opaque_relay_keypair_generate(
    handle: *mut *mut std::ffi::c_void,
) -> i32 {
    if handle.is_null() {
        return OpaqueError::InvalidInput.to_c_int();
    }
    let Ok(keypair) = ResponderKeyPair::generate() else {
        return OpaqueError::CryptoError.to_c_int();
    };
    let oprf_seed = opaque_core::crypto::random_nonzero_scalar();
    let boxed = Box::new(RelayKeypairHandle { keypair, oprf_seed });
    *handle = Box::into_raw(boxed) as *mut std::ffi::c_void;
    0
}

/// Destroys a relay keypair handle and zeroizes sensitive key material.
///
/// # Safety
///
/// - `handle` must be a pointer previously returned by `opaque_relay_keypair_generate`, or null.
/// - Must not be called more than once on the same handle.
#[no_mangle]
pub unsafe extern "C" fn opaque_relay_keypair_destroy(handle: *mut std::ffi::c_void) {
    if !handle.is_null() {
        drop(Box::from_raw(handle as *mut RelayKeypairHandle));
    }
}

/// Retrieves the OPRF seed generated alongside the keypair.
///
/// The seed **must be persisted to stable storage** along with the private key.
/// Losing the seed makes all registered accounts unrecoverable.
///
/// # Safety
///
/// - `handle` must be a valid handle from `opaque_relay_keypair_generate`.
/// - `oprf_seed` must point to a writable buffer of at least `seed_buffer_size` bytes.
/// - `seed_buffer_size` must be at least `OPRF_SEED_LENGTH`.
#[no_mangle]
pub unsafe extern "C" fn opaque_relay_keypair_get_oprf_seed(
    handle: *mut std::ffi::c_void,
    oprf_seed: *mut u8,
    seed_buffer_size: usize,
) -> i32 {
    if handle.is_null() || oprf_seed.is_null() || seed_buffer_size < OPRF_SEED_LENGTH {
        return OpaqueError::InvalidInput.to_c_int();
    }
    let RelayKeypairHandle { oprf_seed: seed, .. } = &*(handle as *mut RelayKeypairHandle);
    ptr::copy_nonoverlapping(seed.as_ptr(), oprf_seed, OPRF_SEED_LENGTH);
    0
}

/// Copies the relay's public key from the keypair handle into the provided buffer.
///
/// # Safety
///
/// - `handle` must be a valid handle from `opaque_relay_keypair_generate`.
/// - `public_key` must point to a writable buffer of at least `key_buffer_size` bytes.
/// - `key_buffer_size` must be at least `PUBLIC_KEY_LENGTH` (32).
#[no_mangle]
pub unsafe extern "C" fn opaque_relay_keypair_get_public_key(
    handle: *mut std::ffi::c_void,
    public_key: *mut u8,
    key_buffer_size: usize,
) -> i32 {
    if handle.is_null() || public_key.is_null() || key_buffer_size < PUBLIC_KEY_LENGTH {
        return OpaqueError::InvalidInput.to_c_int();
    }
    let RelayKeypairHandle { keypair, .. } = &*(handle as *mut RelayKeypairHandle);
    ptr::copy_nonoverlapping(keypair.public_key.as_ptr(), public_key, PUBLIC_KEY_LENGTH);
    0
}

/// Creates a new relay handle from a previously generated keypair.
///
/// # Safety
///
/// - `keypair_handle` must be a valid handle from `opaque_relay_keypair_generate`.
/// - `handle` must point to a valid `*mut c_void` location where the result is stored.
/// - The returned handle must be freed with `opaque_relay_destroy`.
#[no_mangle]
pub unsafe extern "C" fn opaque_relay_create(
    keypair_handle: *mut std::ffi::c_void,
    handle: *mut *mut std::ffi::c_void,
) -> i32 {
    if keypair_handle.is_null() || handle.is_null() {
        return OpaqueError::InvalidInput.to_c_int();
    }
    let RelayKeypairHandle { keypair, oprf_seed } = &*(keypair_handle as *mut RelayKeypairHandle);
    let Ok(responder) = OpaqueResponder::new(keypair.clone(), *oprf_seed) else {
        return OpaqueError::InvalidInput.to_c_int();
    };
    let boxed = Box::new(RelayHandle { responder });
    *handle = Box::into_raw(boxed) as *mut std::ffi::c_void;
    0
}

/// Destroys a relay handle and zeroizes sensitive data.
///
/// # Safety
///
/// - `handle` must be a pointer previously returned by `opaque_relay_create` or
///   `opaque_relay_create_with_keys`, or null.
/// - Must not be called more than once on the same handle.
#[no_mangle]
pub unsafe extern "C" fn opaque_relay_destroy(handle: *mut std::ffi::c_void) {
    if !handle.is_null() {
        drop(Box::from_raw(handle as *mut RelayHandle));
    }
}

/// Creates a new relay state handle for tracking protocol progress.
///
/// # Safety
///
/// - `handle` must point to a valid `*mut c_void` location where the result is stored.
/// - The returned handle must be freed with `opaque_relay_state_destroy`.
#[no_mangle]
pub unsafe extern "C" fn opaque_relay_state_create(
    handle: *mut *mut std::ffi::c_void,
) -> i32 {
    if handle.is_null() {
        return OpaqueError::InvalidInput.to_c_int();
    }
    let boxed = Box::new(RelayStateHandle {
        state: ResponderState::new(),
    });
    *handle = Box::into_raw(boxed) as *mut std::ffi::c_void;
    0
}

/// Destroys a relay state handle and zeroizes sensitive data.
///
/// # Safety
///
/// - `handle` must be a pointer previously returned by `opaque_relay_state_create`, or null.
/// - Must not be called more than once on the same handle.
#[no_mangle]
pub unsafe extern "C" fn opaque_relay_state_destroy(handle: *mut std::ffi::c_void) {
    if !handle.is_null() {
        drop(Box::from_raw(handle as *mut RelayStateHandle));
    }
}

/// Creates a registration response for the given registration request and account identifier.
///
/// # Safety
///
/// - `relay_handle` must be a valid handle from `opaque_relay_create` or
///   `opaque_relay_create_with_keys`.
/// - `request_data` must point to a valid buffer of `request_length` bytes.
/// - `request_length` must be exactly `REGISTRATION_REQUEST_LENGTH`.
/// - `account_id` must point to a valid buffer of `account_id_length` bytes.
/// - `account_id_length` must be greater than zero.
/// - `response_data` must point to a writable buffer of at least `response_buffer_size` bytes.
/// - `response_buffer_size` must be at least `REGISTRATION_RESPONSE_LENGTH`.
#[no_mangle]
pub unsafe extern "C" fn opaque_relay_create_registration_response(
    relay_handle: *const std::ffi::c_void,
    request_data: *const u8,
    request_length: usize,
    account_id: *const u8,
    account_id_length: usize,
    response_data: *mut u8,
    response_buffer_size: usize,
) -> i32 {
    if relay_handle.is_null()
        || request_data.is_null()
        || request_length != REGISTRATION_REQUEST_LENGTH
        || account_id.is_null()
        || account_id_length == 0
        || response_data.is_null()
        || response_buffer_size < REGISTRATION_RESPONSE_LENGTH
    {
        return OpaqueError::InvalidInput.to_c_int();
    }

    let RelayHandle { responder } = &*(relay_handle as *const RelayHandle);
    let req = std::slice::from_raw_parts(request_data, request_length);
    let aid = std::slice::from_raw_parts(account_id, account_id_length);
    let mut response = RegistrationResponse::new();

    match create_registration_response(responder, req, aid, &mut response) {
        Ok(()) => {
            ptr::copy_nonoverlapping(
                response.data.as_ptr(),
                response_data,
                REGISTRATION_RESPONSE_LENGTH,
            );
            0
        }
        Err(e) => e.to_c_int(),
    }
}

/// Builds responder credentials from a stored registration record.
///
/// # Safety
///
/// - `registration_record` must point to a valid buffer of at least `record_length` bytes.
/// - `record_length` must be at least `REGISTRATION_RECORD_LENGTH`.
/// - `credentials_out` must point to a writable buffer of at least `credentials_out_length` bytes.
/// - `credentials_out_length` must be at least `RESPONDER_CREDENTIALS_LENGTH`.
#[no_mangle]
pub unsafe extern "C" fn opaque_relay_build_credentials(
    registration_record: *const u8,
    record_length: usize,
    credentials_out: *mut u8,
    credentials_out_length: usize,
) -> i32 {
    if registration_record.is_null()
        || record_length < REGISTRATION_RECORD_LENGTH
        || credentials_out.is_null()
        || credentials_out_length < RESPONDER_CREDENTIALS_LENGTH
    {
        return OpaqueError::InvalidInput.to_c_int();
    }

    let record = std::slice::from_raw_parts(registration_record, record_length);
    let mut creds = ResponderCredentials::new();

    match build_credentials(record, &mut creds) {
        Ok(()) => {},
        Err(e) => return e.to_c_int(),
    }
    let out = std::slice::from_raw_parts_mut(credentials_out, credentials_out_length);
    result_to_int(protocol::write_registration_record(
        &creds.envelope,
        &creds.initiator_public_key,
        out,
    ))
}

/// Generates the KE2 (second key-exchange) message by processing the agent's KE1 message.
///
/// # Safety
///
/// - `relay_handle` must be a valid handle from `opaque_relay_create` or
///   `opaque_relay_create_with_keys`.
/// - `ke1_data` must point to a valid buffer of `ke1_length` bytes.
/// - `ke1_length` must be exactly `KE1_LENGTH`.
/// - `account_id` must point to a valid buffer of `account_id_length` bytes.
/// - `account_id_length` must be greater than zero.
/// - `credentials_data` must point to a valid buffer of at least `credentials_length` bytes.
/// - `credentials_length` must be at least `RESPONDER_CREDENTIALS_LENGTH`.
/// - `ke2_data` must point to a writable buffer of at least `ke2_buffer_size` bytes.
/// - `ke2_buffer_size` must be at least `KE2_LENGTH`.
/// - `state_handle` must be a valid handle from `opaque_relay_state_create`.
#[no_mangle]
pub unsafe extern "C" fn opaque_relay_generate_ke2(
    relay_handle: *const std::ffi::c_void,
    ke1_data: *const u8,
    ke1_length: usize,
    account_id: *const u8,
    account_id_length: usize,
    credentials_data: *const u8,
    credentials_length: usize,
    ke2_data: *mut u8,
    ke2_buffer_size: usize,
    state_handle: *mut std::ffi::c_void,
) -> i32 {
    if relay_handle.is_null()
        || ke1_data.is_null()
        || ke1_length != KE1_LENGTH
        || account_id.is_null()
        || account_id_length == 0
        || credentials_data.is_null()
        || credentials_length < RESPONDER_CREDENTIALS_LENGTH
        || ke2_data.is_null()
        || ke2_buffer_size < KE2_LENGTH
        || state_handle.is_null()
    {
        return OpaqueError::InvalidInput.to_c_int();
    }

    let RelayHandle { responder } = &*(relay_handle as *const RelayHandle);
    let ke1 = std::slice::from_raw_parts(ke1_data, ke1_length);
    let aid = std::slice::from_raw_parts(account_id, account_id_length);
    let cred_data = std::slice::from_raw_parts(credentials_data, credentials_length);

    let record_view = match protocol::parse_registration_record(cred_data) {
        Ok(v) => v,
        Err(e) => return e.to_c_int(),
    };

    let mut creds = ResponderCredentials::new();
    creds.envelope = record_view.envelope.to_vec();
    creds.initiator_public_key.copy_from_slice(record_view.initiator_public_key);

    let state = &mut (*(state_handle as *mut RelayStateHandle)).state;
    let mut ke2 = Ke2Message::new();

    match generate_ke2(responder, ke1, aid, &creds, &mut ke2, state) {
        Ok(()) => {},
        Err(e) => return e.to_c_int(),
    }
    let out = std::slice::from_raw_parts_mut(ke2_data, ke2_buffer_size);
    result_to_int(protocol::write_ke2(
        &ke2.responder_nonce,
        &ke2.responder_public_key,
        &ke2.credential_response,
        &ke2.responder_mac,
        &ke2.kem_ciphertext,
        out,
    ))
}

/// Finishes the AKE protocol on the relay side and extracts the session key and master key.
///
/// # Safety
///
/// - `_relay_handle` is currently unused but reserved; may be null.
/// - `ke3_data` must point to a valid buffer of `ke3_length` bytes.
/// - `ke3_length` must be exactly `KE3_LENGTH`.
/// - `state_handle` must be a valid handle from `opaque_relay_state_create`.
/// - `session_key` must point to a writable buffer of at least `session_key_buffer_size` bytes.
/// - `session_key_buffer_size` must be at least `HASH_LENGTH`.
/// - `master_key_out` must point to a writable buffer of at least `master_key_buffer_size` bytes.
/// - `master_key_buffer_size` must be at least `MASTER_KEY_LENGTH`.
#[no_mangle]
pub unsafe extern "C" fn opaque_relay_finish(
    _relay_handle: *const std::ffi::c_void,
    ke3_data: *const u8,
    ke3_length: usize,
    state_handle: *mut std::ffi::c_void,
    session_key: *mut u8,
    session_key_buffer_size: usize,
    master_key_out: *mut u8,
    master_key_buffer_size: usize,
) -> i32 {
    if ke3_data.is_null()
        || ke3_length != KE3_LENGTH
        || state_handle.is_null()
        || session_key.is_null()
        || session_key_buffer_size < HASH_LENGTH
        || master_key_out.is_null()
        || master_key_buffer_size < MASTER_KEY_LENGTH
    {
        return OpaqueError::InvalidInput.to_c_int();
    }

    let ke3 = std::slice::from_raw_parts(ke3_data, ke3_length);
    let state = &mut (*(state_handle as *mut RelayStateHandle)).state;
    let mut sk = Vec::new();
    let mut mk = Vec::new();

    match responder_finish(ke3, state, &mut sk, &mut mk) {
        Ok(()) => {},
        Err(e) => return e.to_c_int(),
    }
    let copy_len = std::cmp::min(session_key_buffer_size, sk.len());
    ptr::copy_nonoverlapping(sk.as_ptr(), session_key, copy_len);
    ptr::copy_nonoverlapping(mk.as_ptr(), master_key_out, MASTER_KEY_LENGTH);
    sk.zeroize();
    mk.zeroize();
    0
}

/// Creates a relay handle from previously stored private key, public key, and OPRF seed.
///
/// # Safety
///
/// - `private_key` must point to a valid buffer of `private_key_len` bytes.
/// - `private_key_len` must be exactly `PRIVATE_KEY_LENGTH`.
/// - `public_key` must point to a valid buffer of `public_key_len` bytes.
/// - `public_key_len` must be exactly `PUBLIC_KEY_LENGTH`.
/// - `oprf_seed_ptr` must point to a valid buffer of `oprf_seed_len` bytes.
/// - `oprf_seed_len` must be exactly `OPRF_SEED_LENGTH`.
/// - `handle` must point to a valid `*mut c_void` location where the result is stored.
/// - The returned handle must be freed with `opaque_relay_destroy`.
#[no_mangle]
pub unsafe extern "C" fn opaque_relay_create_with_keys(
    private_key: *const u8,
    private_key_len: usize,
    public_key: *const u8,
    public_key_len: usize,
    oprf_seed_ptr: *const u8,
    oprf_seed_len: usize,
    handle: *mut *mut std::ffi::c_void,
) -> i32 {
    if private_key.is_null()
        || private_key_len != PRIVATE_KEY_LENGTH
        || public_key.is_null()
        || public_key_len != PUBLIC_KEY_LENGTH
        || oprf_seed_ptr.is_null()
        || oprf_seed_len != OPRF_SEED_LENGTH
        || handle.is_null()
    {
        return OpaqueError::InvalidInput.to_c_int();
    }

    let sk = std::slice::from_raw_parts(private_key, private_key_len);
    let pk = std::slice::from_raw_parts(public_key, public_key_len);
    let seed_slice = std::slice::from_raw_parts(oprf_seed_ptr, OPRF_SEED_LENGTH);
    let mut oprf_seed = [0u8; OPRF_SEED_LENGTH];
    oprf_seed.copy_from_slice(seed_slice);

    let Ok(keypair) = ResponderKeyPair::from_keys(sk, pk) else {
        return OpaqueError::InvalidInput.to_c_int();
    };
    let Ok(responder) = OpaqueResponder::new(keypair, oprf_seed) else {
        return OpaqueError::InvalidInput.to_c_int();
    };
    let boxed = Box::new(RelayHandle { responder });
    *handle = Box::into_raw(boxed) as *mut std::ffi::c_void;
    0
}

/// Returns the byte length of a KE2 protocol message.
#[no_mangle]
pub extern "C" fn opaque_relay_get_ke2_length() -> usize {
    KE2_LENGTH
}

/// Returns the byte length of a registration record.
#[no_mangle]
pub extern "C" fn opaque_relay_get_registration_record_length() -> usize {
    REGISTRATION_RECORD_LENGTH
}

/// Returns the byte length of responder credentials.
#[no_mangle]
pub extern "C" fn opaque_relay_get_credentials_length() -> usize {
    RESPONDER_CREDENTIALS_LENGTH
}

/// Returns the byte length of a post-quantum KEM ciphertext.
#[no_mangle]
pub extern "C" fn opaque_relay_get_kem_ciphertext_length() -> usize {
    pq::KEM_CIPHERTEXT_LENGTH
}

/// Returns the byte length of an OPRF seed.
#[no_mangle]
pub extern "C" fn opaque_relay_get_oprf_seed_length() -> usize {
    OPRF_SEED_LENGTH
}
