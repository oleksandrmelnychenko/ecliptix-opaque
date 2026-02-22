use opaque_core::crypto;
use opaque_core::envelope;
use opaque_core::types::*;

fn setup_keys() -> ([u8; PRIVATE_KEY_LENGTH], [u8; PUBLIC_KEY_LENGTH]) {
    let sk = crypto::random_nonzero_scalar();
    let pk = crypto::scalarmult_base(&sk);
    (sk, pk)
}

#[test]
fn seal_open_roundtrip() {
    let randomized_pwd = [0x42u8; HASH_LENGTH];
    let (_, rpk) = setup_keys();
    let (isk, ipk) = setup_keys();

    let mut env = Envelope::new();
    envelope::seal(&randomized_pwd, &rpk, &isk, &ipk, &mut env).unwrap();

    let mut recovered_rpk = [0u8; PUBLIC_KEY_LENGTH];
    let mut recovered_isk = [0u8; PRIVATE_KEY_LENGTH];
    let mut recovered_ipk = [0u8; PUBLIC_KEY_LENGTH];

    envelope::open(
        &env,
        &randomized_pwd,
        &rpk,
        &mut recovered_rpk,
        &mut recovered_isk,
        &mut recovered_ipk,
    )
    .unwrap();

    assert_eq!(recovered_rpk, rpk);
    assert_eq!(recovered_isk, isk);
    assert_eq!(recovered_ipk, ipk);
}

#[test]
fn open_wrong_password_fails() {
    let pwd1 = [0x42u8; HASH_LENGTH];
    let pwd2 = [0x43u8; HASH_LENGTH];
    let (_, rpk) = setup_keys();
    let (isk, ipk) = setup_keys();

    let mut env = Envelope::new();
    envelope::seal(&pwd1, &rpk, &isk, &ipk, &mut env).unwrap();

    let mut r_rpk = [0u8; PUBLIC_KEY_LENGTH];
    let mut r_isk = [0u8; PRIVATE_KEY_LENGTH];
    let mut r_ipk = [0u8; PUBLIC_KEY_LENGTH];

    assert!(envelope::open(&env, &pwd2, &rpk, &mut r_rpk, &mut r_isk, &mut r_ipk).is_err());
}

#[test]
fn open_tampered_ciphertext_fails() {
    let pwd = [0x42u8; HASH_LENGTH];
    let (_, rpk) = setup_keys();
    let (isk, ipk) = setup_keys();

    let mut env = Envelope::new();
    envelope::seal(&pwd, &rpk, &isk, &ipk, &mut env).unwrap();

    env.ciphertext[0] ^= 0xFF;

    let mut r_rpk = [0u8; PUBLIC_KEY_LENGTH];
    let mut r_isk = [0u8; PRIVATE_KEY_LENGTH];
    let mut r_ipk = [0u8; PUBLIC_KEY_LENGTH];

    assert!(envelope::open(&env, &pwd, &rpk, &mut r_rpk, &mut r_isk, &mut r_ipk).is_err());
}

#[test]
fn open_tampered_auth_tag_fails() {
    let pwd = [0x42u8; HASH_LENGTH];
    let (_, rpk) = setup_keys();
    let (isk, ipk) = setup_keys();

    let mut env = Envelope::new();
    envelope::seal(&pwd, &rpk, &isk, &ipk, &mut env).unwrap();

    env.auth_tag[0] ^= 0xFF;

    let mut r_rpk = [0u8; PUBLIC_KEY_LENGTH];
    let mut r_isk = [0u8; PRIVATE_KEY_LENGTH];
    let mut r_ipk = [0u8; PUBLIC_KEY_LENGTH];

    assert!(envelope::open(&env, &pwd, &rpk, &mut r_rpk, &mut r_isk, &mut r_ipk).is_err());
}

#[test]
fn envelope_size_matches_constant() {
    let pwd = [0x42u8; HASH_LENGTH];
    let (_, rpk) = setup_keys();
    let (isk, ipk) = setup_keys();

    let mut env = Envelope::new();
    envelope::seal(&pwd, &rpk, &isk, &ipk, &mut env).unwrap();

    let total = env.nonce.len() + env.ciphertext.len() + env.auth_tag.len();
    assert_eq!(total, ENVELOPE_LENGTH);
}

#[test]
fn seal_empty_password_fails() {
    let (_, rpk) = setup_keys();
    let (isk, ipk) = setup_keys();
    let mut env = Envelope::new();
    assert!(envelope::seal(b"", &rpk, &isk, &ipk, &mut env).is_err());
}
