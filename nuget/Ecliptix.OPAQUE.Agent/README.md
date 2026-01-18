# Ecliptix.OPAQUE.Agent

High-performance native implementation of the **OPAQUE Password-Authenticated Key Exchange (PAKE)** protocol for client/desktop applications.

## Features

- **Zero-Knowledge Password Proof**: Passwords never leave the client device
- **Strong Cryptography**: Ristretto255 elliptic curve, XChaCha20-Poly1305, HMAC-SHA512
- **Cross-Platform**: Windows (x64/x86), Linux (x64/arm64), macOS (x64/arm64)
- **Native Performance**: C++ core with C# wrapper
- **Secure by Default**: Memory is securely zeroed after use

## Installation

```bash
dotnet add package Ecliptix.OPAQUE.Agent
```

## Quick Start

### Registration (One-Time Setup)

```csharp
using Ecliptix.OPAQUE.Agent;

// Server's public key (obtained from server configuration)
byte[] serverPublicKey = /* 32 bytes */;

using var client = new OpaqueClient(serverPublicKey);

// Step 1: Create registration request
byte[] password = Encoding.UTF8.GetBytes("user_password");
using var regState = client.CreateRegistrationRequest(password);
byte[] request = regState.GetRequestCopy();

// Send 'request' to server, receive 'response'
byte[] serverResponse = await SendToServer(request);

// Step 2: Finalize registration
byte[] registrationRecord = client.FinalizeRegistration(serverResponse, regState);

// Send 'registrationRecord' to server for storage
await SendRegistrationRecord(registrationRecord);
```

### Authentication

```csharp
using var client = new OpaqueClient(serverPublicKey);

// Step 1: Generate KE1
byte[] password = Encoding.UTF8.GetBytes("user_password");
using var keState = client.GenerateKe1(password);
byte[] ke1 = keState.GetKe1Copy();

// Send 'ke1' to server, receive 'ke2'
byte[] ke2 = await SendKe1ToServer(ke1);

// Step 2: Generate KE3
byte[]? ke3 = client.GenerateKe3(ke2, keState);
if (ke3 == null)
{
    throw new AuthenticationException("Invalid server response");
}

// Send 'ke3' to server for verification
await SendKe3ToServer(ke3);

// Step 3: Derive session keys
DerivedKeys keys = client.FinishAuthentication(keState);

// Use keys.SessionKey for encrypted communication
// Use keys.MasterKey for deriving encryption keys for stored data
```

## Protocol Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `PUBLIC_KEY_LENGTH` | 32 | Server public key size |
| `REGISTRATION_REQUEST_LENGTH` | 32 | Client registration request |
| `REGISTRATION_RESPONSE_LENGTH` | 64 | Server registration response |
| `REGISTRATION_RECORD_LENGTH` | 168 | Stored credentials |
| `KE1_LENGTH` | 1272 | Key exchange message 1 |
| `KE2_LENGTH` | 1376 | Key exchange message 2 |
| `KE3_LENGTH` | 64 | Key exchange message 3 |

## Security

This library implements the OPAQUE protocol as specified in the IETF draft (draft-irtf-cfrg-opaque).

- Passwords are converted to curve points using password hashing
- Server stores only a password verifier that cannot be reversed
- Mutual authentication with forward secrecy
- Protection against offline dictionary attacks

## Requirements

- .NET 6.0+ / .NET Standard 2.0+
- Windows x64/x86, Linux x64/arm64, or macOS x64/arm64

## License

MIT License - Copyright (c) 2024-2025 Ecliptix
