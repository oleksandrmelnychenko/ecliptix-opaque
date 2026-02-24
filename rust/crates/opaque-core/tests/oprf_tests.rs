use opaque_core::crypto;
use opaque_core::oprf;
use opaque_core::types::*;

#[test]
fn hash_to_group_produces_valid_point() {
    let input = b"oprf hash to group test";
    let mut point = [0u8; PUBLIC_KEY_LENGTH];
    oprf::hash_to_group(input, &mut point).unwrap();
    crypto::validate_ristretto_point(&point).unwrap();
}

#[test]
fn hash_to_group_deterministic() {
    let input = b"deterministic input";
    let mut p1 = [0u8; PUBLIC_KEY_LENGTH];
    let mut p2 = [0u8; PUBLIC_KEY_LENGTH];
    oprf::hash_to_group(input, &mut p1).unwrap();
    oprf::hash_to_group(input, &mut p2).unwrap();
    assert_eq!(p1, p2);
}

#[test]
fn hash_to_group_different_inputs() {
    let mut p1 = [0u8; PUBLIC_KEY_LENGTH];
    let mut p2 = [0u8; PUBLIC_KEY_LENGTH];
    oprf::hash_to_group(b"input one", &mut p1).unwrap();
    oprf::hash_to_group(b"input two", &mut p2).unwrap();
    assert_ne!(p1, p2);
}

#[test]
fn hash_to_group_empty_fails() {
    let mut point = [0u8; PUBLIC_KEY_LENGTH];
    assert!(oprf::hash_to_group(b"", &mut point).is_err());
}

#[test]
fn blind_produces_valid_output() {
    let input = b"password to blind";
    let mut blinded = [0u8; PUBLIC_KEY_LENGTH];
    let mut blind_scalar = [0u8; PRIVATE_KEY_LENGTH];
    oprf::blind(input, &mut blinded, &mut blind_scalar).unwrap();

    crypto::validate_ristretto_point(&blinded).unwrap();
    assert!(!blind_scalar.iter().all(|&b| b == 0));
}

#[test]
fn blind_randomized() {
    let input = b"password to blind";
    let mut b1 = [0u8; PUBLIC_KEY_LENGTH];
    let mut s1 = [0u8; PRIVATE_KEY_LENGTH];
    let mut b2 = [0u8; PUBLIC_KEY_LENGTH];
    let mut s2 = [0u8; PRIVATE_KEY_LENGTH];
    oprf::blind(input, &mut b1, &mut s1).unwrap();
    oprf::blind(input, &mut b2, &mut s2).unwrap();

    assert_ne!(s1, s2);
    assert_ne!(b1, b2);
}

#[test]
fn blind_empty_input_fails() {
    let mut blinded = [0u8; PUBLIC_KEY_LENGTH];
    let mut blind_scalar = [0u8; PRIVATE_KEY_LENGTH];
    assert!(oprf::blind(b"", &mut blinded, &mut blind_scalar).is_err());
}

#[test]
fn evaluate_produces_valid_output() {
    let input = b"test input for evaluate";
    let mut blinded = [0u8; PUBLIC_KEY_LENGTH];
    let mut blind_scalar = [0u8; PRIVATE_KEY_LENGTH];
    oprf::blind(input, &mut blinded, &mut blind_scalar).unwrap();

    let server_key = crypto::random_nonzero_scalar();
    let mut evaluated = [0u8; PUBLIC_KEY_LENGTH];
    oprf::evaluate(&blinded, &server_key, &mut evaluated).unwrap();

    crypto::validate_ristretto_point(&evaluated).unwrap();
}

#[test]
fn full_oprf_flow_deterministic_with_same_blind() {
    let input = b"consistent oprf input";

    let mut blinded = [0u8; PUBLIC_KEY_LENGTH];
    let mut blind_scalar = [0u8; PRIVATE_KEY_LENGTH];
    oprf::blind(input, &mut blinded, &mut blind_scalar).unwrap();

    let server_key = crypto::random_nonzero_scalar();

    let mut evaluated = [0u8; PUBLIC_KEY_LENGTH];
    oprf::evaluate(&blinded, &server_key, &mut evaluated).unwrap();

    let mut output1 = [0u8; HASH_LENGTH];
    let mut output2 = [0u8; HASH_LENGTH];
    oprf::finalize(input, &blind_scalar, &evaluated, &mut output1).unwrap();
    oprf::finalize(input, &blind_scalar, &evaluated, &mut output2).unwrap();

    assert_eq!(output1, output2);
}

#[test]
fn oprf_different_keys_different_output() {
    let input = b"oprf input";
    let mut blinded = [0u8; PUBLIC_KEY_LENGTH];
    let mut blind_scalar = [0u8; PRIVATE_KEY_LENGTH];
    oprf::blind(input, &mut blinded, &mut blind_scalar).unwrap();

    let key1 = crypto::random_nonzero_scalar();
    let key2 = crypto::random_nonzero_scalar();

    let mut eval1 = [0u8; PUBLIC_KEY_LENGTH];
    let mut eval2 = [0u8; PUBLIC_KEY_LENGTH];
    oprf::evaluate(&blinded, &key1, &mut eval1).unwrap();
    oprf::evaluate(&blinded, &key2, &mut eval2).unwrap();

    let mut out1 = [0u8; HASH_LENGTH];
    let mut out2 = [0u8; HASH_LENGTH];
    oprf::finalize(input, &blind_scalar, &eval1, &mut out1).unwrap();
    oprf::finalize(input, &blind_scalar, &eval2, &mut out2).unwrap();

    assert_ne!(out1, out2);
}

#[test]
fn oprf_different_inputs_different_output() {
    let server_key = crypto::random_nonzero_scalar();

    let run = |input: &[u8]| -> [u8; HASH_LENGTH] {
        let mut blinded = [0u8; PUBLIC_KEY_LENGTH];
        let mut blind_scalar = [0u8; PRIVATE_KEY_LENGTH];
        oprf::blind(input, &mut blinded, &mut blind_scalar).unwrap();

        let mut evaluated = [0u8; PUBLIC_KEY_LENGTH];
        oprf::evaluate(&blinded, &server_key, &mut evaluated).unwrap();

        let mut output = [0u8; HASH_LENGTH];
        oprf::finalize(input, &blind_scalar, &evaluated, &mut output).unwrap();
        output
    };

    let out1 = run(b"password1");
    let out2 = run(b"password2");
    assert_ne!(out1, out2);
}

#[test]
fn finalize_empty_input_fails() {
    let blind = [1u8; PRIVATE_KEY_LENGTH];
    let eval = crypto::scalarmult_base(&crypto::random_nonzero_scalar()).unwrap();
    let mut output = [0u8; HASH_LENGTH];
    assert!(oprf::finalize(b"", &blind, &eval, &mut output).is_err());
}
