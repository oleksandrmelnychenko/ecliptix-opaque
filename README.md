# Ecliptix Security OPAQUE

A world-class C++ implementation of the OPAQUE protocol (RFC 9807) for password-authenticated key exchange, designed for enterprise .NET applications.

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![Platform](https://img.shields.io/badge/platform-Windows%20|%20Linux%20|%20macOS-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![C++](https://img.shields.io/badge/C%2B%2B-20-blue)

## 🚀 Features

- **RFC 9807 Compliant**: Full OPAQUE protocol implementation with 3DH key exchange
- **Enterprise Security**: libsodium-based cryptography with secure memory management
- **Cross-Platform**: Native builds for macOS, Docker builds for Windows/Linux
- **Separate Libraries**: Dedicated client and server builds for optimal deployment
- **Memory Safe**: Secure allocators and automatic cleanup of sensitive data
- **.NET Ready**: P/Invoke compatible exports for seamless .NET integration
- **Test-Driven**: Comprehensive unit and integration test suite

## 🎯 Target Platforms

### Client Libraries (Avalonia Desktop + Future Mobile)
- **macOS**: Native build for Avalonia Desktop applications
- **Windows**: Cross-compiled for Avalonia Desktop applications
- **Linux**: Cross-compiled for Avalonia Desktop applications

### Server Libraries (ASP.NET Core)
- **Linux**: Primary server deployment platform (Docker/Cloud)
- **Windows**: Windows Server and IIS deployments

## 🛠️ Quick Start

### Prerequisites
- **macOS**: CMake 3.20+, libsodium (`brew install libsodium`)
- **Cross-platform**: Docker for Windows/Linux builds
- **Compiler**: C++20 compatible (GCC 10+, Clang 12+, MSVC 2022+)

### Build Commands

#### Client Libraries (Avalonia Desktop)
```bash
# Build for current platform (macOS)
./build.sh client

# Build for specific platforms
./build.sh client-macos     # macOS Desktop
./build.sh client-windows   # Windows Desktop
./build.sh client-linux     # Linux Desktop
./build.sh client-all       # All desktop platforms
```

#### Server Libraries (ASP.NET Core)
```bash
# Build for Linux servers (default)
./build.sh server

# Build for specific platforms
./build.sh server-linux     # Linux servers
./build.sh server-windows   # Windows servers
./build.sh server-all       # All server platforms
```

#### Complete Build
```bash
# Build everything for all platforms
./build.sh all-platforms
```

## 📦 Output Structure

```
dist/
├── client/                 # For Avalonia Desktop
│   ├── macos/lib/libopaque_client.dylib
│   ├── windows/bin/opaque_client.dll
│   └── linux/lib/libopaque_client.so
└── server/                 # For ASP.NET Core
    ├── linux/lib/libopaque_server.so
    └── windows/bin/opaque_server.dll
```

## 🔐 Security Features

- **RFC 9807 OPAQUE Protocol**: Augmented PAKE with mutual authentication
- **libsodium Integration**: Industry-standard cryptographic library
- **Secure Memory Management**: Protected allocation with `sodium_malloc`/`sodium_free`
- **Memory Protection**: Runtime protection with `sodium_mprotect_*` functions
- **Constant-Time Operations**: Resistant to timing attacks
- **Stack Protection**: Compiler-level security hardening
- **Zero Memory**: Automatic cleanup of all cryptographic material

## 🧪 Testing

The project includes comprehensive test coverage:

- **Unit Tests**: Core cryptographic primitives, memory management, OPRF operations
- **Integration Tests**: Complete protocol flows, error handling, security properties
- **Cross-Platform Tests**: Validation across all target platforms

Tests are automatically executed before each build to ensure quality.

## 🏗️ Architecture

### Core Components
- **OPRF Implementation**: RFC-compliant Oblivious Pseudorandom Function
- **Envelope Cryptography**: Secure credential storage and recovery
- **3DH Key Exchange**: Three-message Diffie-Hellman protocol
- **Secure Memory**: Protected allocators and cleanup

### Client Implementation
- Registration request generation
- Authentication flow (KE1, KE3)
- Session key derivation
- Server public key pinning support

### Server Implementation
- Registration response generation
- Authentication flow (KE2, ServerFinish)
- Credential storage and retrieval
- Session key validation

## 📋 .NET Integration

The libraries provide C-style exports compatible with .NET P/Invoke:

```csharp
// Example P/Invoke declarations
[DllImport("opaque_client")]
public static extern int opaque_client_create(byte[] serverPublicKey, int keyLength, out IntPtr handle);

[DllImport("opaque_server")]
public static extern int opaque_server_create(IntPtr keypair, out IntPtr handle);
```

## 🐳 Docker Support

Cross-platform builds use optimized Docker containers:

- **Linux**: Ubuntu 22.04 with Clang/GCC toolchain
- **Windows**: Windows Server Core with MSVC Build Tools
- **Dependencies**: Automated libsodium installation and configuration

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📚 Documentation

- [Protocol Specification](https://datatracker.ietf.org/doc/rfc9807/)
- [libsodium Documentation](https://doc.libsodium.org/)
- [Build System Guide](CLAUDE.md)

## 🏢 Enterprise Support

This implementation is designed for enterprise deployment with:
- Professional code quality and documentation
- Comprehensive test coverage
- Security-first design principles
- Cross-platform compatibility
- Long-term maintenance considerations

---

**Built with ❤️ for secure authentication**