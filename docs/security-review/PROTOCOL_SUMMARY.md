# Protocol Summary

This implementation follows an OPAQUE-like flow with a Ristretto255 OPRF, a 3DH style classical key agreement, and a post-quantum ML-KEM-768 key encapsulation combined via HKDF-Extract.

## Constants (from include/opaque/opaque.h)
- PRIVATE_KEY_LENGTH = 32
- PUBLIC_KEY_LENGTH = 32
- NONCE_LENGTH = 24
- MAC_LENGTH = 64
- HASH_LENGTH = 64
- ENVELOPE_LENGTH = 136
- REGISTRATION_REQUEST_LENGTH = 32
- REGISTRATION_RESPONSE_LENGTH = 64
- CREDENTIAL_RESPONSE_LENGTH = 168
- REGISTRATION_RECORD_LENGTH = 168
- KE1_LENGTH = 1272
- KE2_LENGTH = 1376
- KE3_LENGTH = 64
- KEM_PUBLIC_KEY_LENGTH = 1184
- KEM_CIPHERTEXT_LENGTH = 1088
- KEM_SHARED_SECRET_LENGTH = 32

## Registration
1) Client
- Generates static Ristretto key pair (initiator_private, initiator_public)
- OPRF blind: credential_request = Blind(secure_key)
- Sends registration_request = credential_request

2) Server
- Derives OPRF key from responder_private_key and account_id
- Evaluates OPRF: evaluated_element = OPRF.Evaluate(credential_request)
- Sends registration_response = evaluated_element || responder_public_key

3) Client
- OPRF finalize to obtain oprf_output
- Derives randomized password with Argon2id KSF
- Seals envelope using responder_public_key and initiator key material
- Stores registration_record = envelope || initiator_public_key

## Authentication
1) Client (KE1)
- Generates ephemeral Ristretto key pair
- Generates random nonce
- OPRF blind on secure_key
- Generates ML-KEM-768 key pair
- Sends KE1 = credential_request || initiator_ephemeral_public || initiator_nonce || kem_public_key

2) Server (KE2)
- Validates inputs (public keys and sizes)
- OPRF evaluate to produce evaluated_element
- Generates responder ephemeral key pair and nonce
- Computes DH values:
  - dh1 = responder_static_private * initiator_static_public
  - dh2 = responder_static_private * initiator_ephemeral_public
  - dh3 = responder_ephemeral_private * initiator_static_public
- ML-KEM encapsulate to initiator kem_public_key
- Builds credential_response = evaluated_element || envelope
- Computes transcript hash over mac_input (see below)
- Combines classical IKM (dh1||dh2||dh3) with KEM shared secret via HKDF-Extract
- Derives session_key, master_key, responder_mac_key, initiator_mac_key via HKDF-Expand
- Computes responder_mac and expected_initiator_mac
- Sends KE2 = responder_nonce || responder_ephemeral_public || credential_response || responder_mac || kem_ciphertext

3) Client (KE3)
- Validates inputs and responder public key
- OPRF finalize and derive randomized password
- Opens envelope and verifies responder public key
- Computes DH values:
  - dh1 = initiator_static_private * responder_static_public
  - dh2 = initiator_ephemeral_private * responder_static_public
  - dh3 = initiator_static_private * responder_ephemeral_public
- ML-KEM decapsulate kem_ciphertext
- Computes transcript hash over mac_input (see below)
- Combines classical IKM and KEM shared secret via HKDF-Extract
- Derives session_key, master_key, responder_mac_key, initiator_mac_key via HKDF-Expand
- Verifies responder_mac
- Computes KE3 initiator_mac and sends KE3

4) Server Finish
- Verifies initiator_mac
- Returns session_key and master_key

## Transcript and MAC Input
mac_input is the concatenation of:
- initiator_ephemeral_public
- responder_ephemeral_public
- initiator_nonce
- responder_nonce
- initiator_static_public
- responder_static_public
- credential_response
- initiator_kem_public_key
- kem_ciphertext

transcript_hash = SHA-512(TranscriptContext || mac_input)

## Key Derivation
- KSF: Argon2id from libsodium using moderate parameters
- HKDF-Extract uses HMAC-SHA512
- HKDF-Expand uses HMAC-SHA512 with labeled info strings

## Post-Quantum Combiner
- combined_ikm = dh1 || dh2 || dh3 || kem_shared_secret
- prk = HKDF-Extract(salt = PqCombinerContext || transcript_hash, ikm = combined_ikm)
