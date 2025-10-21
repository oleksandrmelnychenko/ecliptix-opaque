# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a world-class C++ implementation of the OPAQUE protocol (RFC 9807) for password-authenticated key exchange. The library provides separate client and server builds with .NET interoperability, using libsodium for cryptographic operations and secure memory management.

### Key Features
- Full RFC 9807 OPAQUE protocol implementation with 3DH key exchange
- Separate client and server libraries for security isolation
- libsodium integration for secure memory management and cryptographic primitives
- .NET P/Invoke compatible C exports
- Enterprise-grade security with memory protection and hardening flags

## Build System

The project uses CMake with C++20 standard. Note that the CMakeLists.txt specifies CMake version 4.0, but most systems have CMake 3.x installed.

### Build Commands

### Quick Start (Recommended)

#### Client Builds (Avalonia Desktop + Future Mobile)
```bash
# Build client for current platform (macOS)
./build.sh client

# Build client for specific platforms
./build.sh client-macos     # macOS for Avalonia Desktop
./build.sh client-windows   # Windows for Avalonia Desktop
./build.sh client-linux     # Linux for Avalonia Desktop
./build.sh client-all       # All desktop platforms
```

#### Server Builds (ASP.NET Core - Linux Only)
```bash
# Build server for Linux (production deployment)
./build.sh server           # Builds for Linux via Docker
./build.sh server-linux     # Same as above (explicit)

# Note: Server builds are Linux-only
# Servers are designed to run on Linux (Docker/Cloud/VPS)
# Windows server builds are not supported
```

#### Complete Builds
```bash
# Build everything for all platforms
./build.sh all-platforms
```

### Manual CMake Build
```bash
# Build client library for .NET (Debug)
cmake -B build-client -DCMAKE_BUILD_TYPE=Debug -DBUILD_CLIENT=ON -DBUILD_DOTNET_INTEROP=ON -DBUILD_TESTS=ON
cmake --build build-client
ctest --test-dir build-client --output-on-failure

# Build server library for .NET (Release)
cmake -B build-server -DCMAKE_BUILD_TYPE=Release -DBUILD_SERVER=ON -DBUILD_DOTNET_INTEROP=ON -DBUILD_TESTS=ON
cmake --build build-server
ctest --test-dir build-server --output-on-failure

# Build both libraries
cmake -B build-all -DCMAKE_BUILD_TYPE=Release -DBUILD_CLIENT=ON -DBUILD_SERVER=ON -DBUILD_DOTNET_INTEROP=ON -DBUILD_TESTS=ON
cmake --build build-all
ctest --test-dir build-all --output-on-failure
```

### Docker Cross-Platform Builds
```bash
# Linux build
docker-compose --profile linux build
docker-compose --profile linux up ecliptix-opaque-linux

# Windows build
docker-compose --profile windows build
docker-compose --profile windows up ecliptix-opaque-windows
```

## Development Environment

- IDE: JetBrains CLion (configuration in `.idea/` directory)
- C++ Standard: C++20
- Build tool: CMake + Ninja (default in CLion)

## Project Structure

```
├── include/opaque/         # Public API headers
│   ├── opaque.h           # Core types and secure memory management
│   ├── client.h           # Client-side OPAQUE operations
│   └── server.h           # Server-side OPAQUE operations
├── src/
│   ├── core/              # Core cryptographic implementation
│   │   ├── memory.cpp     # Secure memory allocators using libsodium
│   │   ├── crypto.cpp     # Cryptographic primitives wrapper
│   │   ├── oprf.cpp       # OPRF implementation with ristretto255
│   │   └── envelope.cpp   # Envelope encryption/decryption
│   ├── client/            # Client implementation
│   │   ├── registration.cpp
│   │   ├── authentication.cpp
│   │   └── key_management.cpp
│   ├── server/            # Server implementation
│   │   ├── registration.cpp
│   │   ├── authentication.cpp
│   │   └── credential_store.cpp
│   └── interop/           # .NET interop layer
│       ├── client_exports.cpp
│       └── server_exports.cpp
├── cmake/                 # Build configurations
│   ├── client/CMakeLists.txt
│   └── server/CMakeLists.txt
└── CMakeLists.txt         # Root build configuration
```

## Important Notes

### Dependencies
- **libsodium**: Required for cryptographic operations and secure memory management
- **CMake 3.20+**: Build system (Note: CMakeLists.txt shows 4.0 for future compatibility)
- **C++20 Compiler**: GCC 10+, Clang 12+, or MSVC 2022+
- **Docker**: Required for cross-platform Windows/Linux builds

### Security Features
- All sensitive data uses `sodium_malloc`/`sodium_free` for secure memory management
- Memory protection with `sodium_mprotect_*` functions
- Stack protection and control flow integrity
- Zero memory on destruction for all cryptographic material

### Architecture
- **Complete separation**: Client and server code are completely isolated
- **Professional APIs**: C exports provide P/Invoke compatible interface for .NET
- **Cross-platform clients**: Native builds for macOS, Docker builds for Windows/Linux
- **Linux-only servers**: Server builds are Linux-only (production deployment target)
- **Test-driven**: Comprehensive unit and integration tests run before each build

### .NET Integration
- **Client libraries**: For Avalonia Desktop applications (macOS, Windows, Linux)
- **Server libraries**: For ASP.NET Core server applications (Linux-only)
- **P/Invoke ready**: All exports use proper calling conventions and marshaling
- **Memory safe**: Handles manage C++ object lifetimes safely

### Output Structure
```
dist/
├── client/
│   ├── macos/lib/libopaque_client.dylib
│   ├── windows/bin/opaque_client.dll
│   └── linux/lib/libopaque_client.so
└── server/
    └── linux/lib/libopaque_server.so    # Linux-only
```