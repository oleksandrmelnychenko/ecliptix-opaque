// Copyright (c) 2026 Oleksandr Melnychenko, Ukraine
// Ecliptix Security — Hybrid PQ-OPAQUE
// Licensed under the MIT License

use opaque_core::types::{
    constant_time_eq, Envelope, OpaqueError, OpaqueResult, HASH_LENGTH, MAX_SECURE_KEY_LENGTH,
    PUBLIC_KEY_LENGTH, REGISTRATION_RESPONSE_LENGTH,
};
use opaque_core::{crypto, envelope, oprf, protocol};
use zeroize::Zeroize;

use crate::state::{InitiatorState, OpaqueInitiator, RegistrationRecord, RegistrationRequest};

/// Creates a registration request by blinding the user password with a random OPRF scalar.
///
/// Generates a fresh long-term Ristretto255 keypair for the initiator and stores it in
/// `state`. The blinded element is written into `request`.
///
/// # Errors
///
/// Returns [`OpaqueError::InvalidInput`] if `secure_key` is empty or exceeds the
/// maximum allowed length.
pub fn create_registration_request(
    secure_key: &[u8],
    request: &mut RegistrationRequest,
    state: &mut InitiatorState,
) -> OpaqueResult<()> {
    if secure_key.is_empty() || secure_key.len() > MAX_SECURE_KEY_LENGTH {
        return Err(OpaqueError::InvalidInput);
    }

    state.initiator_private_key = crypto::random_nonzero_scalar();
    state.initiator_public_key = crypto::scalarmult_base(&state.initiator_private_key)?;

    state.secure_key = secure_key.to_vec();

    oprf::blind(
        secure_key,
        &mut request.data,
        &mut state.oblivious_prf_blind_scalar,
    )?;

    Ok(())
}

/// Finalizes registration by unblinding the OPRF output and sealing an envelope.
///
/// Verifies that the responder public key in the response matches the one stored
/// in `initiator`, derives a randomized password, and seals the initiator key
/// material into an encrypted envelope. The resulting [`RegistrationRecord`] is
/// written to `record` and should be sent to the relay for storage.
///
/// # Errors
///
/// Returns an error if the response has an invalid length, the responder public key
/// does not match, or any cryptographic operation fails.
pub fn finalize_registration(
    initiator: &OpaqueInitiator,
    registration_response: &[u8],
    state: &mut InitiatorState,
    record: &mut RegistrationRecord,
) -> OpaqueResult<()> {
    if registration_response.len() != REGISTRATION_RESPONSE_LENGTH {
        return Err(OpaqueError::InvalidProtocolMessage);
    }

    let protocol::RegistrationResponseRef {
        evaluated_element,
        responder_public_key,
    } = protocol::parse_registration_response(registration_response)?;
    let expected_rpk = initiator.responder_public_key();

    crypto::validate_public_key(responder_public_key)?;
    if !constant_time_eq(responder_public_key, expected_rpk) {
        return Err(OpaqueError::AuthenticationError);
    }

    let mut oprf_output = [0u8; HASH_LENGTH];
    oprf::finalize(
        &state.secure_key,
        &state.oblivious_prf_blind_scalar,
        evaluated_element.try_into().map_err(|_| OpaqueError::InvalidProtocolMessage)?,
        &mut oprf_output,
    )?;

    let mut randomized_pwd = [0u8; HASH_LENGTH];
    crypto::derive_randomized_password(&oprf_output, &state.secure_key, &mut randomized_pwd)?;

    let rpk: &[u8; PUBLIC_KEY_LENGTH] = responder_public_key
        .try_into()
        .map_err(|_| OpaqueError::InvalidProtocolMessage)?;
    let mut env = Envelope::new();
    envelope::seal(
        &randomized_pwd,
        rpk,
        &state.initiator_private_key,
        &state.initiator_public_key,
        &mut env,
    )?;

    state.responder_public_key.copy_from_slice(rpk);

    record.envelope.clear();
    record.envelope.extend_from_slice(&env.nonce);
    record.envelope.extend_from_slice(&env.ciphertext);
    record.envelope.extend_from_slice(&env.auth_tag);
    record.initiator_public_key = state.initiator_public_key;

    oprf_output.zeroize();
    randomized_pwd.zeroize();
    state.secure_key.zeroize();
    state.oblivious_prf_blind_scalar.zeroize();

    Ok(())
}
