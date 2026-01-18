# Ecliptix.OPAQUE.Agent

Native OPAQUE client package for .NET. The managed wrapper loads the native library `eop.agent` and exposes a Kyber-enabled OPAQUE API.

## Install

```bash
dotnet add package Ecliptix.OPAQUE.Agent
```

## Registration

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

## Authentication

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

## Constants

| Constant | Value |
| --- | --- |
| PUBLIC_KEY_LENGTH | 32 |
| REGISTRATION_REQUEST_LENGTH | 32 |
| REGISTRATION_RESPONSE_LENGTH | 64 |
| REGISTRATION_RECORD_LENGTH | 168 |
| KE1_LENGTH | 1272 |
| KE2_LENGTH | 1376 |
| KE3_LENGTH | 64 |

## Targets

- net8.0
- net9.0
- net10.0
