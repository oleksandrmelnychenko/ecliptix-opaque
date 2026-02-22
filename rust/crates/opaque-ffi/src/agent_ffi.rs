// Copyright (c) 2026 Oleksandr Melnychenko, Ukraine
// Ecliptix Security — Hybrid PQ-OPAQUE
// Licensed under the MIT License

use std::ptr;

use opaque_agent::{
    create_registration_request, finalize_registration, generate_ke1, generate_ke3,
    initiator_finish, InitiatorState, Ke1Message, Ke3Message, OpaqueInitiator,
    RegistrationRecord, RegistrationRequest,
};
use opaque_core::protocol;
use opaque_core::types::{
    pq, OpaqueError, OpaqueResult, HASH_LENGTH, KE1_LENGTH, KE2_LENGTH, KE3_LENGTH,
    MASTER_KEY_LENGTH, PUBLIC_KEY_LENGTH, REGISTRATION_RECORD_LENGTH,
    REGISTRATION_REQUEST_LENGTH, REGISTRATION_RESPONSE_LENGTH,
};

struct AgentHandle {
    initiator: OpaqueInitiator,
}

struct AgentStateHandle {
    state: InitiatorState,
}

fn result_to_int(r: OpaqueResult<()>) -> i32 {
    match r {
        Ok(()) => 0,
        Err(e) => e.to_c_int(),
    }
}

#[no_mangle]
pub extern "C" fn opaque_init() -> i32 {
    unsafe { libsodium_sys::sodium_init() }
}

#[no_mangle]
pub unsafe extern "C" fn opaque_agent_create(
    relay_public_key: *const u8,
    key_length: usize,
    handle: *mut *mut std::ffi::c_void,
) -> i32 {
    if relay_public_key.is_null() || key_length != PUBLIC_KEY_LENGTH || handle.is_null() {
        return OpaqueError::InvalidInput.to_c_int();
    }
    let key = std::slice::from_raw_parts(relay_public_key, key_length);
    let Ok(initiator) = OpaqueInitiator::new(key) else {
        return OpaqueError::InvalidInput.to_c_int();
    };
    let boxed = Box::new(AgentHandle { initiator });
    *handle = Box::into_raw(boxed) as *mut std::ffi::c_void;
    0
}

#[no_mangle]
pub unsafe extern "C" fn opaque_agent_destroy(handle: *mut std::ffi::c_void) {
    if !handle.is_null() {
        drop(Box::from_raw(handle as *mut AgentHandle));
    }
}

#[no_mangle]
pub unsafe extern "C" fn opaque_agent_state_create(handle: *mut *mut std::ffi::c_void) -> i32 {
    if handle.is_null() {
        return OpaqueError::InvalidInput.to_c_int();
    }
    let boxed = Box::new(AgentStateHandle {
        state: InitiatorState::new(),
    });
    *handle = Box::into_raw(boxed) as *mut std::ffi::c_void;
    0
}

#[no_mangle]
pub unsafe extern "C" fn opaque_agent_state_destroy(handle: *mut std::ffi::c_void) {
    if !handle.is_null() {
        drop(Box::from_raw(handle as *mut AgentStateHandle));
    }
}

#[no_mangle]
pub unsafe extern "C" fn opaque_agent_create_registration_request(
    agent_handle: *mut std::ffi::c_void,
    secure_key: *const u8,
    secure_key_length: usize,
    state_handle: *mut std::ffi::c_void,
    request_out: *mut u8,
    request_length: usize,
) -> i32 {
    if agent_handle.is_null()
        || secure_key.is_null()
        || secure_key_length == 0
        || state_handle.is_null()
        || request_out.is_null()
        || request_length < REGISTRATION_REQUEST_LENGTH
    {
        return OpaqueError::InvalidInput.to_c_int();
    }

    let state = &mut (*(state_handle as *mut AgentStateHandle)).state;
    let key = std::slice::from_raw_parts(secure_key, secure_key_length);
    let mut request = RegistrationRequest::new();

    let result = create_registration_request(key, &mut request, state);
    if result.is_ok() {
        ptr::copy_nonoverlapping(request.data.as_ptr(), request_out, REGISTRATION_REQUEST_LENGTH);
    }
    result_to_int(result)
}

#[no_mangle]
pub unsafe extern "C" fn opaque_agent_finalize_registration(
    agent_handle: *mut std::ffi::c_void,
    response: *const u8,
    response_length: usize,
    state_handle: *mut std::ffi::c_void,
    record_out: *mut u8,
    record_length: usize,
) -> i32 {
    if agent_handle.is_null()
        || response.is_null()
        || response_length != REGISTRATION_RESPONSE_LENGTH
        || state_handle.is_null()
        || record_out.is_null()
        || record_length < REGISTRATION_RECORD_LENGTH
    {
        return OpaqueError::InvalidInput.to_c_int();
    }

    let agent = &*(agent_handle as *mut AgentHandle);
    let state = &mut (*(state_handle as *mut AgentStateHandle)).state;
    let resp = std::slice::from_raw_parts(response, response_length);
    let mut record = RegistrationRecord::new();

    match finalize_registration(&agent.initiator, resp, state, &mut record) {
        Ok(()) => {},
        Err(e) => return e.to_c_int(),
    }
    let out = std::slice::from_raw_parts_mut(record_out, record_length);
    result_to_int(protocol::write_registration_record(
        &record.envelope,
        &record.initiator_public_key,
        out,
    ))
}

#[no_mangle]
pub unsafe extern "C" fn opaque_agent_generate_ke1(
    _agent_handle: *mut std::ffi::c_void,
    secure_key: *const u8,
    secure_key_length: usize,
    state_handle: *mut std::ffi::c_void,
    ke1_out: *mut u8,
    ke1_length: usize,
) -> i32 {
    if secure_key.is_null()
        || secure_key_length == 0
        || state_handle.is_null()
        || ke1_out.is_null()
        || ke1_length < KE1_LENGTH
    {
        return OpaqueError::InvalidInput.to_c_int();
    }

    let state = &mut (*(state_handle as *mut AgentStateHandle)).state;
    let key = std::slice::from_raw_parts(secure_key, secure_key_length);
    let mut ke1 = Ke1Message::new();

    match generate_ke1(key, &mut ke1, state) {
        Ok(()) => {},
        Err(e) => return e.to_c_int(),
    }
    let out = std::slice::from_raw_parts_mut(ke1_out, ke1_length);
    result_to_int(protocol::write_ke1(
        &ke1.credential_request,
        &ke1.initiator_public_key,
        &ke1.initiator_nonce,
        &ke1.pq_ephemeral_public_key,
        out,
    ))
}

#[no_mangle]
pub unsafe extern "C" fn opaque_agent_generate_ke3(
    agent_handle: *mut std::ffi::c_void,
    ke2: *const u8,
    ke2_length: usize,
    state_handle: *mut std::ffi::c_void,
    ke3_out: *mut u8,
    ke3_length: usize,
) -> i32 {
    if agent_handle.is_null()
        || ke2.is_null()
        || ke2_length != KE2_LENGTH
        || state_handle.is_null()
        || ke3_out.is_null()
        || ke3_length < KE3_LENGTH
    {
        return OpaqueError::InvalidInput.to_c_int();
    }

    let agent = &*(agent_handle as *mut AgentHandle);
    let state = &mut (*(state_handle as *mut AgentStateHandle)).state;
    let ke2 = std::slice::from_raw_parts(ke2, ke2_length);
    let mut ke3 = Ke3Message::new();

    match generate_ke3(&agent.initiator, ke2, state, &mut ke3) {
        Ok(()) => {},
        Err(e) => return e.to_c_int(),
    }
    let out = std::slice::from_raw_parts_mut(ke3_out, ke3_length);
    result_to_int(protocol::write_ke3(&ke3.initiator_mac, out))
}

#[no_mangle]
pub unsafe extern "C" fn opaque_agent_finish(
    _agent_handle: *mut std::ffi::c_void,
    state_handle: *mut std::ffi::c_void,
    session_key_out: *mut u8,
    session_key_length: usize,
    master_key_out: *mut u8,
    master_key_length: usize,
) -> i32 {
    if state_handle.is_null()
        || session_key_out.is_null()
        || session_key_length < HASH_LENGTH
        || master_key_out.is_null()
        || master_key_length < MASTER_KEY_LENGTH
    {
        return OpaqueError::InvalidInput.to_c_int();
    }

    let state = &mut (*(state_handle as *mut AgentStateHandle)).state;
    let mut session_key = Vec::new();
    let mut master_key = Vec::new();

    match initiator_finish(state, &mut session_key, &mut master_key) {
        Ok(()) => {},
        Err(e) => return e.to_c_int(),
    }
    let copy_len = std::cmp::min(session_key_length, session_key.len());
    ptr::copy_nonoverlapping(session_key.as_ptr(), session_key_out, copy_len);
    ptr::copy_nonoverlapping(master_key.as_ptr(), master_key_out, MASTER_KEY_LENGTH);
    0
}

#[no_mangle]
pub extern "C" fn opaque_get_ke1_length() -> usize {
    KE1_LENGTH
}

#[no_mangle]
pub extern "C" fn opaque_get_ke2_length() -> usize {
    KE2_LENGTH
}

#[no_mangle]
pub extern "C" fn opaque_get_ke3_length() -> usize {
    KE3_LENGTH
}

#[no_mangle]
pub extern "C" fn opaque_get_registration_record_length() -> usize {
    REGISTRATION_RECORD_LENGTH
}

#[no_mangle]
pub extern "C" fn opaque_get_kem_public_key_length() -> usize {
    pq::KEM_PUBLIC_KEY_LENGTH
}

#[no_mangle]
pub extern "C" fn opaque_get_kem_ciphertext_length() -> usize {
    pq::KEM_CIPHERTEXT_LENGTH
}
