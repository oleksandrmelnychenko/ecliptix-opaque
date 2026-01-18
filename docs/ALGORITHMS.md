# OPAQUE Protocol (Kyber-enabled)

## Contents

1. Overview
2. Cryptographic primitives
3. Registration flow
4. Authentication flow
5. Message formats and sizes
6. Key derivation and transcript binding
7. C# API examples
8. Security properties
9. Constants reference
10. Domain separators

## 1. Overview

OPAQUE is a password-authenticated key exchange protocol. This implementation uses Ristretto255 for the classical OPAQUE core and ML-KEM-768 for post-quantum protection. There is a single supported mode that always includes ML-KEM-768; no classical-only fallback is provided.

## 2. Cryptographic primitives

| Primitive | Purpose | Output size |
| --- | --- | --- |
| Ristretto255 | Group operations and DH | 32 bytes |
| SHA-512 | Hashing and transcript | 64 bytes |
| HMAC-SHA512 | MACs and HKDF | 64 bytes |
| HKDF-SHA512 | Key derivation | variable |
| XChaCha20-Poly1305 | Envelope encryption | 24 byte nonce, 16 byte tag |
| Argon2id | Password stretching | 64 bytes output |
| ML-KEM-768 | PQ KEM | 1184 pk, 2400 sk, 1088 ct, 32 ss |

## 3. Registration flow

1. Client creates an OPRF blind and sends a RegistrationRequest.
2. Server evaluates the OPRF and returns a RegistrationResponse.
3. Client finalizes the OPRF, opens the envelope, and produces a RegistrationRecord.
4. Server stores the RegistrationRecord for future authentication.

## 4. Authentication flow

1. Client creates KE1 with an OPRF blind, ephemeral Ristretto255 key, nonce, and ML-KEM-768 public key.
2. Server creates KE2 with OPRF evaluation, credential response, MAC, and ML-KEM-768 ciphertext.
3. Client verifies KE2 and returns KE3 (initiator MAC).
4. Both sides derive session and master keys from the combined transcript.

## 5. Message formats and sizes

Registration:

| Message | Size | Fields |
| --- | --- | --- |
| RegistrationRequest | 32 | credential_request |
| RegistrationResponse | 64 | evaluated_element (32) || responder_public_key (32) |
| RegistrationRecord | 168 | envelope (136) || initiator_public_key (32) |

Authentication:

| Message | Size | Fields |
| --- | --- | --- |
| KE1 | 1272 | credential_request (32) || initiator_ephemeral_public_key (32) || initiator_nonce (24) || kem_public_key (1184) |
| KE2 | 1376 | responder_nonce (24) || responder_ephemeral_public_key (32) || credential_response (168) || responder_mac (64) || kem_ciphertext (1088) |
| KE3 | 64 | initiator_mac (64) |

## 6. Key derivation and transcript binding

The protocol derives classical and post-quantum material and then combines them.

Inputs:

- dh1 = DH(initiator_eph_priv, responder_eph_pub)
- dh2 = DH(initiator_static_priv, responder_eph_pub)
- dh3 = DH(initiator_eph_priv, responder_static_pub)
- pq_shared_secret from ML-KEM-768

IKM and HKDF:

- ikm_classical = dh1 || dh2 || dh3
- ikm_combined = ikm_classical || pq_shared_secret
- transcript_hash = H(KE1 fields || KE2 fields)
- prk = HKDF-Extract(transcript_hash, ikm_combined)
- session_key = HKDF-Expand(prk, "ECLIPTIX-OPAQUE-PQ-v1/SessionKey", 64)
- master_key = HKDF-Expand(prk, "ECLIPTIX-OPAQUE-PQ-v1/MasterKey", 32)

MAC keys use the same PRK with the responder and initiator MAC labels.

## 7. C# API examples

Client registration:

```csharp
using System.Text;
using Ecliptix.OPAQUE.Agent;

byte[] serverPublicKey = await FetchServerPublicKeyAsync();
using var client = new OpaqueClient(serverPublicKey);

byte[] password = Encoding.UTF8.GetBytes("correct horse battery staple");
using var regState = client.CreateRegistrationRequest(password);
byte[] request = regState.GetRequestCopy();

byte[] response = await SendRegistrationRequestAsync(request);
byte[] record = client.FinalizeRegistration(response, regState);
await StoreRegistrationRecordAsync(record);
```

Server registration:

```csharp
using System.Text;
using Ecliptix.OPAQUE.Relay;

using var keyPair = ServerKeyPair.Generate();
using var server = OpaqueServer.Create(keyPair);

byte[] request = await ReceiveRegistrationRequestAsync();
byte[] accountId = Encoding.UTF8.GetBytes("user@example.com");
byte[] response = server.CreateRegistrationResponse(request, accountId);
await SendRegistrationResponseAsync(response);
```

Client authentication:

```csharp
using System.Text;
using Ecliptix.OPAQUE.Agent;

byte[] serverPublicKey = await FetchServerPublicKeyAsync();
using var client = new OpaqueClient(serverPublicKey);

byte[] password = Encoding.UTF8.GetBytes("correct horse battery staple");
using var keState = client.GenerateKe1(password);
byte[] ke1 = keState.GetKeyExchangeDataCopy();

byte[] ke2 = await SendKe1Async(ke1);
byte[] ke3 = client.GenerateKe3(ke2, keState);
await SendKe3Async(ke3);

var (sessionKey, masterKey) = client.DeriveBaseMasterKey(keState);
```

Server authentication:

```csharp
using System.Text;
using Ecliptix.OPAQUE.Relay;

using var server = OpaqueServer.Create(keyPair);

byte[] ke1 = await ReceiveKe1Async();
byte[] accountId = Encoding.UTF8.GetBytes("user@example.com");
byte[] credentials = await LoadRegistrationRecordAsync(accountId);

using var authState = AuthenticationState.Create();
byte[] ke2 = server.GenerateKe2(ke1, accountId, credentials, authState);
await SendKe2Async(ke2);

byte[] ke3 = await ReceiveKe3Async();
DerivedKeys keys = server.FinishAuthentication(ke3, authState);
```

## 8. Security properties

- Passwords are never sent to the server.
- Stored records are not password hashes and do not allow offline guessing.
- Mutual authentication with explicit MACs.
- Forward secrecy from ephemeral DH keys.
- Post-quantum protection through ML-KEM-768.

## 9. Constants reference

| Constant | Value |
| --- | --- |
| OPRF_SEED_LENGTH | 32 |
| PRIVATE_KEY_LENGTH | 32 |
| PUBLIC_KEY_LENGTH | 32 |
| MASTER_KEY_LENGTH | 32 |
| NONCE_LENGTH | 24 |
| MAC_LENGTH | 64 |
| HASH_LENGTH | 64 |
| ENVELOPE_LENGTH | 136 |
| REGISTRATION_REQUEST_LENGTH | 32 |
| REGISTRATION_RESPONSE_LENGTH | 64 |
| REGISTRATION_RECORD_LENGTH | 168 |
| KE1_BASE_LENGTH | 88 |
| KE2_BASE_LENGTH | 288 |
| KE1_LENGTH | 1272 |
| KE2_LENGTH | 1376 |
| KE3_LENGTH | 64 |
| KEM_PUBLIC_KEY_LENGTH | 1184 |
| KEM_SECRET_KEY_LENGTH | 2400 |
| KEM_CIPHERTEXT_LENGTH | 1088 |
| KEM_SHARED_SECRET_LENGTH | 32 |

## 10. Domain separators

OPAQUE labels:

- ECLIPTIX-OPAQUE-v1/OPRF
- ECLIPTIX-OPAQUE-v1/OPRF-Key
- ECLIPTIX-OPAQUE-v1/OPRF-Seed
- ECLIPTIX-OPAQUE-v1/EnvelopeKey
- ECLIPTIX-OPAQUE-v1/HKDF-Salt
- ECLIPTIX-OPAQUE-v1/Transcript
- ECLIPTIX-OPAQUE-v1/KSF
- ECLIPTIX-OPAQUE-v1/KSF-Salt
- ECLIPTIX-OPAQUE-v1/SessionKey
- ECLIPTIX-OPAQUE-v1/MasterKey
- ECLIPTIX-OPAQUE-v1/ResponderMAC
- ECLIPTIX-OPAQUE-v1/InitiatorMAC

Post-quantum labels:

- ECLIPTIX-OPAQUE-PQ-v1/Combiner
- ECLIPTIX-OPAQUE-PQ-v1/KEM
- ECLIPTIX-OPAQUE-PQ-v1/SessionKey
- ECLIPTIX-OPAQUE-PQ-v1/MasterKey
- ECLIPTIX-OPAQUE-PQ-v1/ResponderMAC
- ECLIPTIX-OPAQUE-PQ-v1/InitiatorMAC
