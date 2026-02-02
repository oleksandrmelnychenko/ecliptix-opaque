# Ecliptix.OPAQUE.Relay

Native OPAQUE server package for .NET. The managed wrapper loads the native library `eop.relay` and exposes a Kyber-enabled OPAQUE API.

## Install

```bash
dotnet add package Ecliptix.OPAQUE.Relay
```

## Server Setup

```csharp
using Ecliptix.OPAQUE.Relay;

using var keyPair = ServerKeyPair.Generate();
byte[] publicKey = keyPair.GetPublicKeyCopy();
```

## Registration

```csharp
using System.Text;
using Ecliptix.OPAQUE.Relay;

using var server = OpaqueServer.Create(keyPair);

byte[] request = await ReceiveRegistrationRequestAsync();
byte[] accountId = Encoding.UTF8.GetBytes("user@example.com");

byte[] response = server.CreateRegistrationResponse(request, accountId);
await SendRegistrationResponseAsync(response);

byte[] record = await ReceiveRegistrationRecordAsync();
await StoreRegistrationRecordAsync(accountId, record);
```

## Authentication

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

## Constants

| Constant | Value |
| --- | --- |
| PRIVATE_KEY_LENGTH | 32 |
| PUBLIC_KEY_LENGTH | 32 |
| REGISTRATION_REQUEST_LENGTH | 32 |
| REGISTRATION_RESPONSE_LENGTH | 64 |
| SERVER_CREDENTIALS_LENGTH | 168 |
| KE1_LENGTH | 1272 |
| KE2_LENGTH | 1376 |
| KE3_LENGTH | 64 |

## Targets

- net8.0
- net9.0
- net10.0
