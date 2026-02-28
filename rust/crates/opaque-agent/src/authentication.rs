// Copyright (c) 2026 Oleksandr Melnychenko, Ukraine
// Ecliptix Security — Hybrid PQ-OPAQUE
// Licensed under the MIT License

use opaque_core::types::{
    constant_time_eq, labels, pq, pq_labels, Envelope, OpaqueError, OpaqueResult,
    CREDENTIAL_RESPONSE_LENGTH, ENVELOPE_LENGTH, HASH_LENGTH, KE2_LENGTH, MAC_LENGTH,
    MASTER_KEY_LENGTH, MAX_SECURE_KEY_LENGTH, NONCE_LENGTH, PRIVATE_KEY_LENGTH, PUBLIC_KEY_LENGTH,
    SECRETBOX_MAC_LENGTH,
};
use opaque_core::{crypto, envelope, oprf, pq_kem, protocol};
use zeroize::Zeroize;

use crate::state::{InitiatorPhase, InitiatorState, Ke1Message, Ke3Message, OpaqueInitiator};

/// Generates the first key-exchange message (KE1) to begin authentication.
///
/// Creates an ephemeral Ristretto255 keypair, an ephemeral ML-KEM-768 keypair,
/// a random nonce, and blinds the user password into a credential request.
/// All ephemeral material is stored in `state`; the outgoing message is written
/// to `ke1`.
///
/// # Errors
///
/// Returns [`OpaqueError::InvalidInput`] if `secure_key` is empty or exceeds the
/// maximum allowed length.
pub fn generate_ke1(
    secure_key: &[u8],
    ke1: &mut Ke1Message,
    state: &mut InitiatorState,
) -> OpaqueResult<()> {
    if secure_key.is_empty() || secure_key.len() > MAX_SECURE_KEY_LENGTH {
        return Err(OpaqueError::InvalidInput);
    }
    if state.phase != InitiatorPhase::Created {
        return Err(OpaqueError::ValidationError);
    }

    state.secure_key = secure_key.to_vec();

    state.initiator_ephemeral_private_key = crypto::random_nonzero_scalar();
    state.initiator_ephemeral_public_key = crypto::scalarmult_base(&state.initiator_ephemeral_private_key)?;

    state.pq_ephemeral_public_key = vec![0u8; pq::KEM_PUBLIC_KEY_LENGTH];
    state.pq_ephemeral_secret_key = vec![0u8; pq::KEM_SECRET_KEY_LENGTH];
    pq_kem::keypair_generate(
        &mut state.pq_ephemeral_public_key,
        &mut state.pq_ephemeral_secret_key,
    )?;

    crypto::random_bytes(&mut ke1.initiator_nonce)?;
    state.initiator_nonce = ke1.initiator_nonce;

    ke1.initiator_public_key = state.initiator_ephemeral_public_key;

    oprf::blind(
        secure_key,
        &mut ke1.credential_request,
        &mut state.oblivious_prf_blind_scalar,
    )?;

    ke1.pq_ephemeral_public_key = state.pq_ephemeral_public_key.clone();

    state.phase = InitiatorPhase::Ke1Generated;
    Ok(())
}

/// Processes the relay KE2 message and produces the KE3 confirmation.
///
/// Performs the full initiator-side AKE: unblinds the OPRF output, derives the
/// randomized password, opens the envelope to recover key material, executes the
/// 4DH exchange and ML-KEM-768 decapsulation, combines both shared secrets via
/// HKDF-Extract, verifies the responder MAC, and computes the initiator MAC for
/// KE3. On success the session key and master key are stored in `state`.
///
/// # Errors
///
/// Returns an error if `ke2_data` has an invalid length, any public key is
/// malformed, the envelope cannot be opened, or the responder MAC verification
/// fails.
pub fn generate_ke3(
    initiator: &OpaqueInitiator,
    ke2_data: &[u8],
    state: &mut InitiatorState,
    ke3: &mut Ke3Message,
) -> OpaqueResult<()> {
    if ke2_data.len() != KE2_LENGTH {
        return Err(OpaqueError::InvalidProtocolMessage);
    }
    if state.phase != InitiatorPhase::Ke1Generated {
        return Err(OpaqueError::ValidationError);
    }

    let responder_public_key = initiator.responder_public_key();
    crypto::validate_public_key(responder_public_key)?;

    let protocol::Ke2Ref {
        responder_nonce,
        responder_public_key: responder_ephemeral_public_key,
        credential_response,
        responder_mac,
        kem_ciphertext,
    } = protocol::parse_ke2(ke2_data)?;

    crypto::validate_public_key(responder_ephemeral_public_key)?;

    let evaluated_elem = &credential_response[..PUBLIC_KEY_LENGTH];
    let envelope_data = &credential_response[PUBLIC_KEY_LENGTH..];

    let mut oprf_output = [0u8; HASH_LENGTH];
    oprf::finalize(
        &state.secure_key,
        &state.oblivious_prf_blind_scalar,
        evaluated_elem.try_into().map_err(|_| OpaqueError::InvalidProtocolMessage)?,
        &mut oprf_output,
    )?;

    let mut randomized_pwd = [0u8; HASH_LENGTH];
    crypto::derive_randomized_password(&oprf_output, &state.secure_key, &mut randomized_pwd)?;

    let ct_size = ENVELOPE_LENGTH - NONCE_LENGTH - SECRETBOX_MAC_LENGTH;
    let env = Envelope {
        nonce: envelope_data[..NONCE_LENGTH].to_vec(),
        ciphertext: envelope_data[NONCE_LENGTH..NONCE_LENGTH + ct_size].to_vec(),
        auth_tag: envelope_data[NONCE_LENGTH + ct_size..].to_vec(),
    };

    let mut recovered_rpk = [0u8; PUBLIC_KEY_LENGTH];
    let mut recovered_isk = [0u8; PRIVATE_KEY_LENGTH];
    let mut recovered_ipk = [0u8; PUBLIC_KEY_LENGTH];

    envelope::open(
        &env,
        &randomized_pwd,
        responder_public_key,
        &mut recovered_rpk,
        &mut recovered_isk,
        &mut recovered_ipk,
    )?;

    if !constant_time_eq(&recovered_rpk, responder_public_key) {
        recovered_isk.zeroize();
        recovered_rpk.zeroize();
        recovered_ipk.zeroize();
        return Err(OpaqueError::AuthenticationError);
    }

    let resp_eph_pk: &[u8; PUBLIC_KEY_LENGTH] = responder_ephemeral_public_key
        .try_into()
        .map_err(|_| OpaqueError::InvalidProtocolMessage)?;

    let mut dh1 = [0u8; PUBLIC_KEY_LENGTH];
    let mut dh2 = [0u8; PUBLIC_KEY_LENGTH];
    let mut dh3 = [0u8; PUBLIC_KEY_LENGTH];
    // 4th DH: init_eph × resp_eph — provides unknown key share (UKS) resistance
    let mut dh4 = [0u8; PUBLIC_KEY_LENGTH];

    crypto::scalar_mult(&recovered_isk, &recovered_rpk, &mut dh1)?;
    crypto::scalar_mult(&state.initiator_ephemeral_private_key, &recovered_rpk, &mut dh2)?;
    crypto::scalar_mult(&recovered_isk, resp_eph_pk, &mut dh3)?;
    crypto::scalar_mult(&state.initiator_ephemeral_private_key, resp_eph_pk, &mut dh4)?;

    let mut kem_ss = [0u8; pq::KEM_SHARED_SECRET_LENGTH];
    pq_kem::decapsulate(
        &state.pq_ephemeral_secret_key,
        kem_ciphertext,
        &mut kem_ss,
    )?;

    state.pq_ephemeral_secret_key.zeroize();
    state.pq_shared_secret = kem_ss.to_vec();

    let mut classical_ikm = [0u8; 4 * PUBLIC_KEY_LENGTH];
    classical_ikm[..PUBLIC_KEY_LENGTH].copy_from_slice(&dh1);
    classical_ikm[PUBLIC_KEY_LENGTH..2 * PUBLIC_KEY_LENGTH].copy_from_slice(&dh2);
    classical_ikm[2 * PUBLIC_KEY_LENGTH..3 * PUBLIC_KEY_LENGTH].copy_from_slice(&dh3);
    classical_ikm[3 * PUBLIC_KEY_LENGTH..].copy_from_slice(&dh4);

    let mac_input_size = 2 * NONCE_LENGTH
        + 4 * PUBLIC_KEY_LENGTH
        + CREDENTIAL_RESPONSE_LENGTH
        + pq::KEM_CIPHERTEXT_LENGTH
        + pq::KEM_PUBLIC_KEY_LENGTH;
    let mut mac_input = vec![0u8; mac_input_size];
    let mut off = 0;

    let mut append = |data: &[u8]| {
        mac_input[off..off + data.len()].copy_from_slice(data);
        off += data.len();
    };
    append(&state.initiator_ephemeral_public_key);
    append(resp_eph_pk);
    append(&state.initiator_nonce);
    append(responder_nonce);
    append(&recovered_ipk);
    append(&recovered_rpk);
    append(credential_response);
    append(&state.pq_ephemeral_public_key);
    append(kem_ciphertext);

    let mut transcript_hash = [0u8; HASH_LENGTH];
    crypto::sha512_multi(&[labels::TRANSCRIPT_CONTEXT, &mac_input], &mut transcript_hash);

    let mut prk = [0u8; HASH_LENGTH];
    pq_kem::combine_key_material(&classical_ikm, &kem_ss, &transcript_hash, &mut prk)?;

    let mut session_key = vec![0u8; HASH_LENGTH];
    crypto::key_derivation_expand(&prk, pq_labels::PQ_SESSION_KEY_INFO, &mut session_key)?;

    let mut master_key = [0u8; MASTER_KEY_LENGTH];
    crypto::key_derivation_expand(&prk, pq_labels::PQ_MASTER_KEY_INFO, &mut master_key)?;

    let mut resp_mac_key = [0u8; MAC_LENGTH];
    crypto::key_derivation_expand(&prk, pq_labels::PQ_RESPONDER_MAC_INFO, &mut resp_mac_key)?;

    let mut expected_resp_mac = [0u8; MAC_LENGTH];
    crypto::hmac_sha512(&resp_mac_key, &mac_input, &mut expected_resp_mac)?;

    if !constant_time_eq(responder_mac, &expected_resp_mac) {
        classical_ikm.zeroize();
        mac_input.zeroize();
        prk.zeroize();
        dh1.zeroize();
        dh2.zeroize();
        dh3.zeroize();
        dh4.zeroize();
        kem_ss.zeroize();
        oprf_output.zeroize();
        randomized_pwd.zeroize();
        resp_mac_key.zeroize();
        expected_resp_mac.zeroize();
        transcript_hash.zeroize();
        session_key.zeroize();
        master_key.zeroize();
        recovered_isk.zeroize();
        recovered_rpk.zeroize();
        recovered_ipk.zeroize();
        state.pq_shared_secret.zeroize();
        return Err(OpaqueError::AuthenticationError);
    }

    let mut init_mac_key = [0u8; MAC_LENGTH];
    crypto::key_derivation_expand(&prk, pq_labels::PQ_INITIATOR_MAC_INFO, &mut init_mac_key)?;
    crypto::hmac_sha512(&init_mac_key, &mac_input, &mut ke3.initiator_mac)?;

    state.responder_public_key = recovered_rpk;
    state.initiator_private_key = recovered_isk;
    state.initiator_public_key = recovered_ipk;
    state.master_key = master_key.to_vec();
    state.session_key = session_key;

    classical_ikm.zeroize();
    mac_input.zeroize();
    prk.zeroize();
    dh1.zeroize();
    dh2.zeroize();
    dh3.zeroize();
    dh4.zeroize();
    kem_ss.zeroize();
    oprf_output.zeroize();
    randomized_pwd.zeroize();
    resp_mac_key.zeroize();
    expected_resp_mac.zeroize();
    init_mac_key.zeroize();
    transcript_hash.zeroize();
    master_key.zeroize();

    state.phase = InitiatorPhase::Ke3Generated;
    Ok(())
}

/// Extracts the session key and master key from the initiator state after a successful AKE.
///
/// Moves both keys out of `state` and zeroizes remaining sensitive material.
/// This function should be called only after [`generate_ke3`] succeeds.
///
/// # Errors
///
/// Returns [`OpaqueError::InvalidInput`] if the session key or master key has not
/// been derived (i.e., the AKE has not completed).
pub fn initiator_finish(
    state: &mut InitiatorState,
    session_key: &mut Vec<u8>,
    master_key: &mut Vec<u8>,
) -> OpaqueResult<()> {
    if state.phase != InitiatorPhase::Ke3Generated {
        return Err(OpaqueError::ValidationError);
    }
    if state.session_key.is_empty() || state.master_key.len() != MASTER_KEY_LENGTH {
        return Err(OpaqueError::InvalidInput);
    }

    *session_key = std::mem::take(&mut state.session_key);
    *master_key = std::mem::take(&mut state.master_key);

    state.pq_shared_secret.zeroize();
    state.pq_ephemeral_secret_key.zeroize();
    state.secure_key.zeroize();
    state.oblivious_prf_blind_scalar.zeroize();

    state.phase = InitiatorPhase::Finished;
    Ok(())
}
