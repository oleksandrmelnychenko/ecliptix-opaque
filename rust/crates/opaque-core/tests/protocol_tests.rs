use opaque_core::protocol;
use opaque_core::types::*;

#[test]
fn write_parse_registration_record_roundtrip() {
    let envelope = [0x42u8; ENVELOPE_LENGTH];
    let ipk = [0x43u8; PUBLIC_KEY_LENGTH];

    let mut buf = vec![0u8; REGISTRATION_RECORD_LENGTH];
    protocol::write_registration_record(&envelope, &ipk, &mut buf).unwrap();

    let parsed = protocol::parse_registration_record(&buf).unwrap();
    assert_eq!(parsed.envelope, &envelope[..]);
    assert_eq!(parsed.initiator_public_key, &ipk[..]);
}

#[test]
fn write_parse_ke1_roundtrip() {
    let cred_req = [0x01u8; REGISTRATION_REQUEST_LENGTH];
    let ipk = [0x02u8; PUBLIC_KEY_LENGTH];
    let nonce = [0x03u8; NONCE_LENGTH];
    let pq_pk = vec![0x04u8; pq::KEM_PUBLIC_KEY_LENGTH];

    let mut buf = vec![0u8; KE1_LENGTH];
    protocol::write_ke1(&cred_req, &ipk, &nonce, &pq_pk, &mut buf).unwrap();

    let parsed = protocol::parse_ke1(&buf).unwrap();
    assert_eq!(parsed.credential_request, &cred_req[..]);
    assert_eq!(parsed.initiator_public_key, &ipk[..]);
    assert_eq!(parsed.initiator_nonce, &nonce[..]);
    assert_eq!(parsed.pq_ephemeral_public_key, &pq_pk[..]);
}

#[test]
fn write_parse_ke2_roundtrip() {
    let nonce = [0x01u8; NONCE_LENGTH];
    let rpk = [0x02u8; PUBLIC_KEY_LENGTH];
    let cred_resp = [0x03u8; CREDENTIAL_RESPONSE_LENGTH];
    let mac = [0x04u8; MAC_LENGTH];
    let kem_ct = vec![0x05u8; pq::KEM_CIPHERTEXT_LENGTH];

    let mut buf = vec![0u8; KE2_LENGTH];
    protocol::write_ke2(&nonce, &rpk, &cred_resp, &mac, &kem_ct, &mut buf).unwrap();

    let parsed = protocol::parse_ke2(&buf).unwrap();
    assert_eq!(parsed.responder_nonce, &nonce[..]);
    assert_eq!(parsed.responder_public_key, &rpk[..]);
    assert_eq!(parsed.credential_response, &cred_resp[..]);
    assert_eq!(parsed.responder_mac, &mac[..]);
    assert_eq!(parsed.kem_ciphertext, &kem_ct[..]);
}

#[test]
fn write_parse_ke3_roundtrip() {
    let mac = [0x42u8; MAC_LENGTH];
    let mut buf = vec![0u8; KE3_LENGTH];
    protocol::write_ke3(&mac, &mut buf).unwrap();

    let parsed = protocol::parse_ke3(&buf).unwrap();
    assert_eq!(parsed.initiator_mac, &mac[..]);
}

#[test]
fn parse_ke1_wrong_length_fails() {
    let short = vec![0u8; KE1_LENGTH - 1];
    assert!(protocol::parse_ke1(&short).is_err());

    let long = vec![0u8; KE1_LENGTH + 1];
    assert!(protocol::parse_ke1(&long).is_err());
}

#[test]
fn parse_ke2_wrong_length_fails() {
    let short = vec![0u8; KE2_LENGTH - 1];
    assert!(protocol::parse_ke2(&short).is_err());
}

#[test]
fn parse_ke3_wrong_length_fails() {
    let short = vec![0u8; KE3_LENGTH - 1];
    assert!(protocol::parse_ke3(&short).is_err());
}

#[test]
fn parse_registration_response_wrong_length_fails() {
    let short = vec![0u8; REGISTRATION_RESPONSE_LENGTH - 1];
    assert!(protocol::parse_registration_response(&short).is_err());
}

#[test]
fn parse_registration_record_wrong_length_fails() {
    let short = vec![0u8; REGISTRATION_RECORD_LENGTH - 1];
    assert!(protocol::parse_registration_record(&short).is_err());
}

#[test]
fn write_ke1_wrong_component_length_fails() {
    let mut buf = vec![0u8; KE1_LENGTH];
    let cred_req = [0u8; REGISTRATION_REQUEST_LENGTH];
    let ipk = [0u8; PUBLIC_KEY_LENGTH];
    let nonce = [0u8; NONCE_LENGTH];
    let wrong_pq = vec![0u8; 100]; // wrong size

    assert!(protocol::write_ke1(&cred_req, &ipk, &nonce, &wrong_pq, &mut buf).is_err());
}

#[test]
fn write_ke2_buffer_too_small_fails() {
    let mut buf = vec![0u8; KE2_LENGTH - 1]; // too small
    let nonce = [0u8; NONCE_LENGTH];
    let rpk = [0u8; PUBLIC_KEY_LENGTH];
    let cred = [0u8; CREDENTIAL_RESPONSE_LENGTH];
    let mac = [0u8; MAC_LENGTH];
    let ct = vec![0u8; pq::KEM_CIPHERTEXT_LENGTH];

    assert!(protocol::write_ke2(&nonce, &rpk, &cred, &mac, &ct, &mut buf).is_err());
}
