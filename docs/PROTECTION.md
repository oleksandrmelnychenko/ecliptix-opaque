# Native Code Protection

This document summarizes hardening, optional obfuscation, and signing for the native libraries.

## Built-in Hardening

Hardening is controlled by `-DENABLE_HARDENING=ON` (default). The build adds defensive flags:

GCC/Clang:
- -fstack-protector-strong
- -fPIC
- -D_FORTIFY_SOURCE=2
- -Wformat -Wformat-security -Wall -Wextra -Wpedantic -Werror
- -Wconversion -Wsign-conversion -Wnull-dereference
- Linker: -Wl,-z,relro,-z,now (Linux)

MSVC:
- /W4 /WX /GS /sdl
- Linker: /DYNAMICBASE /NXCOMPAT

## LLVM Obfuscation

LLVM obfuscation is controlled by `-DENABLE_OBFUSCATION=ON` and `-DOBFUSCATION_LEVEL=light|standard|aggressive`.

Example:

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release -DENABLE_OBFUSCATION=ON -DOBFUSCATION_LEVEL=standard
```

Clang is required when obfuscation is enabled.

## Commercial Protectors

The NuGet packaging scripts support VMProtect and Themida if you set the tool paths:

- VMPROTECT_PATH
- THEMIDA_PATH

These are used by `nuget/build-packages.sh` and `nuget/build-nuget.sh` when protection is enabled.

## Code Signing

Windows Authenticode (signtool):

```bash
signtool sign /fd SHA256 /f certificate.pfx /p password /tr http://timestamp.digicert.com /td SHA256 library.dll
```

Windows Authenticode (osslsigncode):

```bash
osslsigncode sign -pkcs12 certificate.pfx -pass password -n "Ecliptix Security OPAQUE" -h sha256 -t http://timestamp.digicert.com -in library.dll -out library_signed.dll
```

macOS codesign:

```bash
codesign --force --sign "Developer ID Application: Company Name" --options runtime --timestamp libeop.agent.dylib
```

NuGet signing:

```bash
dotnet nuget sign Package.nupkg --certificate-path certificate.pfx --certificate-password password --timestamper http://timestamp.digicert.com
```

Environment variables used by the scripts:

- WINDOWS_SIGN_CERT_PATH
- WINDOWS_SIGN_CERT_PASSWORD
- APPLE_SIGN_IDENTITY
- NUGET_SIGN_CERT_PATH
- NUGET_SIGN_CERT_PASSWORD

## Packaging Scripts

`nuget/build-packages.sh` builds Agent and Relay packages and can copy native libraries, strip symbols, and sign binaries.

Common options:

```bash
./build-packages.sh --version 1.0.0 --config Release
./build-packages.sh --agent-only
./build-packages.sh --relay-only
./build-packages.sh --skip-native --skip-protect --skip-sign
```
