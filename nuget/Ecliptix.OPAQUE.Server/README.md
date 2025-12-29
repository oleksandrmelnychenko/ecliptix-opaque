# Ecliptix.Security.OPAQUE.Server

High-performance native implementation of the **OPAQUE Password-Authenticated Key Exchange (PAKE)** protocol for server/backend applications.

## Features

- **Zero-Knowledge Verification**: Server never sees or stores actual passwords
- **Strong Cryptography**: Ristretto255 elliptic curve, XChaCha20-Poly1305, HMAC-SHA512
- **Cross-Platform**: Windows (x64), Linux (x64/arm64), macOS (x64/arm64)
- **Native Performance**: C++ core with C# wrapper
- **Database Agnostic**: Store credentials in any database

## Installation

```bash
dotnet add package Ecliptix.Security.OPAQUE.Server
```

## Quick Start

### Server Setup

```csharp
using Ecliptix.Security.OPAQUE.Server;

// Generate or load server keypair (do this once, store securely)
using var keyPair = ServerKeyPair.Generate();
byte[] publicKey = keyPair.GetPublicKeyCopy();
// Share 'publicKey' with clients

// Or derive from a seed for deterministic keys
byte[] seed = /* secure 32-byte seed */;
using var keyPair = ServerKeyPair.DeriveFromSeed(seed);
```

### Registration Handler

```csharp
using var server = OpaqueServer.Create(keyPair);

// Receive registration request from client
byte[] request = await ReceiveFromClient();
byte[] accountId = Encoding.UTF8.GetBytes("user@example.com");

// Generate response
byte[] response = server.CreateRegistrationResponse(request, accountId);

// Send 'response' to client, then receive the registration record
await SendToClient(response);
byte[] registrationRecord = await ReceiveRegistrationRecord();

// Store 'registrationRecord' in database for this user
await database.StoreCredentials(accountId, registrationRecord);
```

### Authentication Handler

```csharp
using var server = OpaqueServer.Create(keyPair);

// Receive KE1 from client
byte[] ke1 = await ReceiveKe1();
byte[] accountId = Encoding.UTF8.GetBytes("user@example.com");

// Load stored credentials
byte[] storedCredentials = await database.GetCredentials(accountId);

// Create authentication state and generate KE2
using var authState = AuthenticationState.Create();
byte[] ke2 = server.GenerateKe2(ke1, accountId, storedCredentials, authState);

// Send KE2, receive KE3
await SendKe2(ke2);
byte[] ke3 = await ReceiveKe3();

// Verify KE3 and derive session keys
DerivedKeys? keys = server.FinishAuthentication(ke3, authState);
if (keys == null)
{
    throw new AuthenticationException("Authentication failed");
}

// Use keys.Value.SessionKey for encrypted communication
// Use keys.Value.MasterKey if needed for user-specific encryption
```

## Protocol Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `PRIVATE_KEY_LENGTH` | 32 | Server private key size |
| `PUBLIC_KEY_LENGTH` | 32 | Server public key size |
| `REGISTRATION_REQUEST_LENGTH` | 32 | Client registration request |
| `REGISTRATION_RESPONSE_LENGTH` | 64 | Server registration response |
| `SERVER_CREDENTIALS_LENGTH` | 168 | Stored user credentials |
| `KE1_LENGTH` | 88 | Key exchange message 1 |
| `KE2_LENGTH` | 288 | Key exchange message 2 |
| `KE3_LENGTH` | 64 | Key exchange message 3 |

## Key Management Best Practices

1. **Generate keys once** during initial server setup
2. **Store private keys securely** using HSM, Azure Key Vault, or similar
3. **Derive from seed** for reproducible keys (useful for key rotation planning)
4. **Rotate keys periodically** by re-registering users with new keys

## Security

- Server stores only password verifiers (168 bytes per user)
- Verifiers cannot be used to recover passwords
- Compromised database doesn't expose passwords
- Forward secrecy protects past sessions

## Requirements

- .NET 6.0+ / .NET Standard 2.0+
- Windows x64, Linux x64/arm64, or macOS x64/arm64

## License

MIT License - Copyright (c) 2024-2025 Ecliptix
