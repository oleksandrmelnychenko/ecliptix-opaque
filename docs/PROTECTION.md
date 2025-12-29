# Native Code Protection & Obfuscation Guide

This document describes the code protection and obfuscation options available for the Ecliptix Security OPAQUE native libraries.

## Overview

Native C/C++ code protection differs significantly from managed code (.NET/Java) obfuscation. While managed code can be decompiled back to readable source, native code requires reverse engineering through disassembly. However, determined attackers with tools like IDA Pro, Ghidra, or x64dbg can still analyze native binaries.

## Protection Levels

### Level 1: Compile-Time Hardening (Built-in, Always Applied)

These protections are applied automatically during compilation:

| Protection | Compiler Flag | Description |
|------------|---------------|-------------|
| Stack Protector | `-fstack-protector-strong` | Detects stack buffer overflows |
| Stack Clash Protection | `-fstack-clash-protection` | Prevents stack clash attacks |
| FORTIFY_SOURCE | `-D_FORTIFY_SOURCE=2` | Runtime buffer overflow checks |
| Position Independent Code | `-fPIC` | Required for ASLR |
| Full RELRO | `-Wl,-z,relro,-z,now` | Protects GOT from overwrites |
| No Executable Stack | `-Wl,-z,noexecstack` | Prevents shellcode on stack |
| Symbol Stripping | `-s` | Removes debug symbols |

**MSVC equivalents:**
- `/GS` - Buffer security check
- `/sdl` - SDL checks
- `/guard:cf` - Control Flow Guard
- `/DYNAMICBASE` - ASLR
- `/NXCOMPAT` - DEP
- `/HIGHENTROPYVA` - High entropy ASLR (64-bit)

### Level 2: LLVM-Based Obfuscation (Open Source)

For Clang-based builds, these obfuscation passes are available:

```cmake
# Enable in CMake
cmake -DUSE_LLVM_OBFUSCATOR=ON -DPROTECTION_LEVEL=standard ..
```

| Technique | Flag | Description |
|-----------|------|-------------|
| Instruction Substitution | `-mllvm -sub` | Replaces instructions with equivalent sequences |
| Bogus Control Flow | `-mllvm -bcf` | Adds fake branches and dead code |
| Control Flow Flattening | `-mllvm -fla` | Obfuscates function control flow |
| Basic Block Splitting | `-mllvm -split` | Splits basic blocks to complicate analysis |
| String Encryption | `-mllvm -sobf` | Encrypts string literals |

**Compatible LLVM Obfuscators:**
- [Hikari](https://github.com/HikariObfuscator/Hikari) - Most maintained fork
- [obfuscator-llvm](https://github.com/obfuscator-llvm/obfuscator) - Original O-LLVM

### Level 3: Commercial Protection Tools

#### VMProtect (Recommended for Maximum Protection)

[VMProtect](https://vmpsoft.com/) is the industry standard for native code protection.

**Features:**
- Code Virtualization - Converts code to bytecode for custom VM
- Code Mutation - Transforms instructions while preserving behavior
- Anti-Debug - Detects and responds to debuggers
- Anti-VM - Detects virtual machine environments
- Import Protection - Hides API calls
- Resource Protection - Encrypts embedded resources

**Integration:**
```bash
# Environment variable
export VMPROTECT_PATH=/path/to/vmprotect_con

# CMake
cmake -DVMPROTECT_PATH=/path/to/vmprotect_con ..

# Or post-build
vmprotect_con input.dll output.dll --vm-code-level ultra --anti-debug
```

**Protection Levels:**
| Level | VM Code | Mutation | Anti-Debug | Anti-VM | Use Case |
|-------|---------|----------|------------|---------|----------|
| Minimal | Low | Low | No | No | Development |
| Standard | Medium | Medium | Yes | No | Production |
| Maximum | Ultra | Ultra | Yes | Yes | High-security |

#### Themida / Code Virtualizer

[Themida](https://www.oreans.com/Themida.php) offers similar protection to VMProtect.

**Virtual Machines:**
- FISH (Lite, White, Red, Black) - Increasing complexity
- TIGER (White, Red, Black) - Maximum protection
- PUMA, SHARK, DOLPHIN - Alternative VM architectures

**Integration:**
```bash
# Post-build protection
themida /protect input.dll /output output.dll /virtualmachine TIGER_BLACK /antidebug CHECK_DEBUGGER
```

## Code Signing

### Windows Authenticode Signing

```bash
# Using signtool (Windows SDK)
signtool sign /fd SHA256 /f certificate.pfx /p password \
    /tr http://timestamp.digicert.com /td SHA256 \
    /d "Ecliptix Security OPAQUE" library.dll

# Using osslsigncode (Linux/macOS)
osslsigncode sign -pkcs12 certificate.pfx -pass password \
    -n "Ecliptix Security OPAQUE" -h sha256 \
    -t http://timestamp.digicert.com \
    -in library.dll -out library_signed.dll
```

### macOS Code Signing

```bash
# Sign with Developer ID
codesign --force --sign "Developer ID Application: Company Name" \
    --options runtime --timestamp libopaque_client.dylib

# Notarize for distribution
xcrun notarytool submit libopaque_client.dylib \
    --apple-id "developer@example.com" \
    --team-id "TEAMID" --password "@keychain:notarization"
```

### NuGet Package Signing

```bash
# Sign with certificate
dotnet nuget sign Package.nupkg \
    --certificate-path certificate.pfx \
    --certificate-password password \
    --timestamper http://timestamp.digicert.com
```

## Recommended Configuration

### For Desktop Applications (Client)

```cmake
cmake -DCMAKE_BUILD_TYPE=Release \
      -DENABLE_CODE_PROTECTION=ON \
      -DPROTECTION_LEVEL=standard \
      -DUSE_LLVM_OBFUSCATOR=ON \
      -DVMPROTECT_PATH=/path/to/vmprotect ..
```

Then sign with Authenticode (Windows) or codesign (macOS).

### For Server Applications

```cmake
cmake -DCMAKE_BUILD_TYPE=Release \
      -DENABLE_CODE_PROTECTION=ON \
      -DPROTECTION_LEVEL=minimal \
      ..
```

Server binaries typically run in controlled environments where obfuscation provides less benefit but can complicate debugging.

## Build Pipeline

```
┌─────────────────┐
│  Source Code    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Compile with    │
│ Hardening Flags │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ LLVM Obfuscator │ (Optional)
│ Passes          │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ VMProtect/      │ (Optional)
│ Themida         │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Strip Debug     │
│ Symbols         │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Code Signing    │
│ (Authenticode)  │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ NuGet Package   │
│ + Package Sign  │
└─────────────────┘
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `VMPROTECT_PATH` | Path to VMProtect CLI executable |
| `THEMIDA_PATH` | Path to Themida CLI executable |
| `WINDOWS_SIGN_CERT_PATH` | Path to Windows code signing certificate (.pfx) |
| `WINDOWS_SIGN_CERT_PASSWORD` | Certificate password |
| `APPLE_SIGN_IDENTITY` | macOS signing identity |
| `NUGET_SIGN_CERT_PATH` | NuGet package signing certificate |
| `NUGET_SIGN_CERT_PASSWORD` | NuGet certificate password |

## Security Considerations

1. **Obfuscation is not security** - It raises the bar but doesn't prevent determined attackers
2. **Protect your secrets** - Never embed API keys or passwords in binaries
3. **Use HSMs** - Store signing keys in Hardware Security Modules
4. **Validate integrity** - Implement runtime integrity checks in your application
5. **Monitor for cracks** - Watch for unauthorized redistribution

## Cost/Benefit Analysis

| Protection | Cost | Setup Effort | Effectiveness | Performance Impact |
|------------|------|--------------|---------------|-------------------|
| Compile Hardening | Free | Low | Medium | Negligible |
| LLVM Obfuscator | Free | Medium | Medium | 5-20% |
| VMProtect | ~$300-800 | Low | High | 10-50%* |
| Themida | ~$200-600 | Low | High | 10-50%* |

*Performance impact depends on protection level and which functions are protected.

## Getting Started

1. **Development**: Use compile-time hardening only
2. **Beta Testing**: Add LLVM obfuscation (standard level)
3. **Production**: Add VMProtect/Themida + code signing
4. **High Security**: Maximum protection + runtime integrity checks
