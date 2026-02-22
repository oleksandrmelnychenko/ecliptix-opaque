use opaque_core::pq_kem;
use opaque_core::types::*;

#[test]
fn keypair_generate_produces_valid_keys() {
    let mut pk = vec![0u8; pq::KEM_PUBLIC_KEY_LENGTH];
    let mut sk = vec![0u8; pq::KEM_SECRET_KEY_LENGTH];
    pq_kem::keypair_generate(&mut pk, &mut sk).unwrap();

    assert!(!pk.iter().all(|&b| b == 0));
    assert!(!sk.iter().all(|&b| b == 0));
}

#[test]
fn keypair_generate_wrong_size_fails() {
    let mut pk = vec![0u8; 32];
    let mut sk = vec![0u8; pq::KEM_SECRET_KEY_LENGTH];
    assert!(pq_kem::keypair_generate(&mut pk, &mut sk).is_err());
}

#[test]
fn encapsulate_decapsulate_roundtrip() {
    let mut pk = vec![0u8; pq::KEM_PUBLIC_KEY_LENGTH];
    let mut sk = vec![0u8; pq::KEM_SECRET_KEY_LENGTH];
    pq_kem::keypair_generate(&mut pk, &mut sk).unwrap();

    let mut ct = vec![0u8; pq::KEM_CIPHERTEXT_LENGTH];
    let mut ss_enc = vec![0u8; pq::KEM_SHARED_SECRET_LENGTH];
    pq_kem::encapsulate(&pk, &mut ct, &mut ss_enc).unwrap();

    assert!(!ct.iter().all(|&b| b == 0));
    assert!(!ss_enc.iter().all(|&b| b == 0));

    let mut ss_dec = vec![0u8; pq::KEM_SHARED_SECRET_LENGTH];
    pq_kem::decapsulate(&sk, &ct, &mut ss_dec).unwrap();

    assert_eq!(ss_enc, ss_dec, "shared secrets must match");
}

#[test]
fn different_encapsulations_different_shared_secrets() {
    let mut pk = vec![0u8; pq::KEM_PUBLIC_KEY_LENGTH];
    let mut sk = vec![0u8; pq::KEM_SECRET_KEY_LENGTH];
    pq_kem::keypair_generate(&mut pk, &mut sk).unwrap();

    let mut ct1 = vec![0u8; pq::KEM_CIPHERTEXT_LENGTH];
    let mut ss1 = vec![0u8; pq::KEM_SHARED_SECRET_LENGTH];
    pq_kem::encapsulate(&pk, &mut ct1, &mut ss1).unwrap();

    let mut ct2 = vec![0u8; pq::KEM_CIPHERTEXT_LENGTH];
    let mut ss2 = vec![0u8; pq::KEM_SHARED_SECRET_LENGTH];
    pq_kem::encapsulate(&pk, &mut ct2, &mut ss2).unwrap();

    assert_ne!(ct1, ct2);
    assert_ne!(ss1, ss2);
}

#[test]
fn wrong_secret_key_different_shared_secret() {
    let mut pk1 = vec![0u8; pq::KEM_PUBLIC_KEY_LENGTH];
    let mut sk1 = vec![0u8; pq::KEM_SECRET_KEY_LENGTH];
    pq_kem::keypair_generate(&mut pk1, &mut sk1).unwrap();

    let mut pk2 = vec![0u8; pq::KEM_PUBLIC_KEY_LENGTH];
    let mut sk2 = vec![0u8; pq::KEM_SECRET_KEY_LENGTH];
    pq_kem::keypair_generate(&mut pk2, &mut sk2).unwrap();

    let mut ct = vec![0u8; pq::KEM_CIPHERTEXT_LENGTH];
    let mut ss_enc = vec![0u8; pq::KEM_SHARED_SECRET_LENGTH];
    pq_kem::encapsulate(&pk1, &mut ct, &mut ss_enc).unwrap();

    let mut ss_wrong = vec![0u8; pq::KEM_SHARED_SECRET_LENGTH];
    pq_kem::decapsulate(&sk2, &ct, &mut ss_wrong).unwrap();
    assert_ne!(ss_enc, ss_wrong);
}

#[test]
fn combine_key_material_produces_nonzero_prk() {
    let classical_ikm = [0x42u8; 96];
    let pq_ss = [0x43u8; pq::KEM_SHARED_SECRET_LENGTH];
    let transcript_hash = [0x44u8; HASH_LENGTH];

    let mut prk = [0u8; HASH_LENGTH];
    pq_kem::combine_key_material(&classical_ikm, &pq_ss, &transcript_hash, &mut prk).unwrap();
    assert!(!prk.iter().all(|&b| b == 0));
}

#[test]
fn combine_key_material_deterministic() {
    let classical_ikm = [0x42u8; 96];
    let pq_ss = [0x43u8; pq::KEM_SHARED_SECRET_LENGTH];
    let transcript_hash = [0x44u8; HASH_LENGTH];

    let mut prk1 = [0u8; HASH_LENGTH];
    let mut prk2 = [0u8; HASH_LENGTH];
    pq_kem::combine_key_material(&classical_ikm, &pq_ss, &transcript_hash, &mut prk1).unwrap();
    pq_kem::combine_key_material(&classical_ikm, &pq_ss, &transcript_hash, &mut prk2).unwrap();
    assert_eq!(prk1, prk2);
}

#[test]
fn combine_key_material_wrong_sizes_fail() {
    let mut prk = [0u8; HASH_LENGTH];

    assert!(pq_kem::combine_key_material(
        &[0u8; 64],
        &[0u8; pq::KEM_SHARED_SECRET_LENGTH],
        &[0u8; HASH_LENGTH],
        &mut prk,
    )
    .is_err());

    assert!(pq_kem::combine_key_material(
        &[0u8; 96],
        &[0u8; 16],
        &[0u8; HASH_LENGTH],
        &mut prk,
    )
    .is_err());

    assert!(pq_kem::combine_key_material(
        &[0u8; 96],
        &[0u8; pq::KEM_SHARED_SECRET_LENGTH],
        &[0u8; 32],
        &mut prk,
    )
    .is_err());
}
