// Copyright (c) 2026 Oleksandr Melnychenko, Ukraine
// Ecliptix Security — Hybrid PQ-OPAQUE
// Licensed under the MIT License

use opaque_core::types::{
    OpaqueError, OpaqueResult, PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH, REGISTRATION_REQUEST_LENGTH,
};
use opaque_core::{crypto, oprf, protocol};
use zeroize::Zeroize;

use crate::state::{OpaqueResponder, RegistrationResponse, ResponderCredentials};

pub fn create_registration_response(
    responder: &OpaqueResponder,
    registration_request: &[u8],
    account_id: &[u8],
    response: &mut RegistrationResponse,
) -> OpaqueResult<()> {
    if registration_request.len() != REGISTRATION_REQUEST_LENGTH
        || account_id.is_empty()
    {
        return Err(OpaqueError::InvalidInput);
    }

    crypto::validate_ristretto_point(registration_request)?;

    let mut oprf_key = [0u8; PRIVATE_KEY_LENGTH];
    crypto::derive_oprf_key(
        responder.oprf_seed(),
        account_id,
        &mut oprf_key,
    )?;

    let blinded: &[u8; PUBLIC_KEY_LENGTH] = registration_request
        .try_into()
        .map_err(|_| OpaqueError::InvalidInput)?;
    let mut evaluated = [0u8; PUBLIC_KEY_LENGTH];
    oprf::evaluate(blinded, &oprf_key, &mut evaluated)?;
    oprf_key.zeroize();

    response.data[..PUBLIC_KEY_LENGTH].copy_from_slice(&evaluated);
    response.data[PUBLIC_KEY_LENGTH..].copy_from_slice(responder.public_key());

    Ok(())
}

pub fn build_credentials(
    registration_record: &[u8],
    credentials: &mut ResponderCredentials,
) -> OpaqueResult<()> {
    if credentials.registered {
        return Err(OpaqueError::AlreadyRegistered);
    }

    let view = protocol::parse_registration_record(registration_record)?;

    crypto::validate_public_key(view.initiator_public_key)?;

    credentials.envelope = view.envelope.to_vec();
    credentials
        .initiator_public_key
        .copy_from_slice(view.initiator_public_key);
    credentials.registered = true;

    Ok(())
}
