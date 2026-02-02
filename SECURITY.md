# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take the security of Ecliptix.Security.OPAQUE seriously. If you believe you have found a security vulnerability, please report it to us as described below.

### Reporting Process

**Please do NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via email to: **security@ecliptix.com**

You should receive a response within 48 hours. If for some reason you do not, please follow up via email to ensure we received your original message.

### What to Include

Please include the following information in your report:

- Type of issue (e.g., buffer overflow, cryptographic weakness, authentication bypass, information disclosure)
- Full paths of source file(s) related to the issue
- Location of the affected source code (tag/branch/commit or direct URL)
- Any special configuration required to reproduce the issue
- Step-by-step instructions to reproduce the issue
- Proof-of-concept or exploit code (if possible)
- Impact of the issue, including how an attacker might exploit it

### Response Timeline

- **Initial Response**: Within 48 hours
- **Vulnerability Confirmation**: Within 7 days
- **Patch Development**: Varies based on complexity
- **Security Advisory**: Published with fix release

### Disclosure Policy

- We follow coordinated disclosure practices
- We will work with you to understand and resolve the issue quickly
- We will credit reporters in security advisories (unless you prefer to remain anonymous)
- We ask that you give us reasonable time to address the issue before public disclosure

## Security Measures

### Cryptographic Implementation

This library implements the OPAQUE password-authenticated key exchange protocol with:

- **Ristretto255** elliptic curve operations via libsodium
- **ML-KEM-768** post-quantum key encapsulation via liboqs
- **Argon2id** key stretching function
- **HMAC-SHA512** for message authentication
- **XChaCha20-Poly1305** for authenticated encryption

### Build Security

- Security hardening flags enabled by default (`-DENABLE_HARDENING=ON`)
- Stack protection, FORTIFY_SOURCE, and position-independent code
- RELRO and immediate binding on Linux
- ASLR and DEP support on Windows

### Memory Security

- Secure memory allocation with page-level protection
- Guaranteed zeroization of sensitive data via `sodium_memzero()`
- Memory locking to prevent swapping where supported

## Security Considerations for Users

### Production Deployment

1. **Never enable debug logging** in production builds
2. **Always use TLS** for transport layer security
3. **Implement rate limiting** at the application layer
4. **Secure storage** for server private keys and registration records
5. **Regular updates** to stay current with security patches

### Dependencies

- Keep libsodium updated (currently pinned to 1.0.20)
- Keep liboqs updated (currently pinned to 0.12.0)
- Monitor security advisories for both dependencies

## Security Audit

For external security review materials, see the `docs/security-review/` directory which includes:

- Threat model documentation
- Protocol specification
- API surface documentation
- Known limitations

## References

- [OPAQUE Draft Specification](https://datatracker.ietf.org/doc/draft-irtf-cfrg-opaque/)
- [libsodium Security](https://doc.libsodium.org/)
- [liboqs Security](https://openquantumsafe.org/)
- [ISO 27001:2022](https://www.iso.org/standard/27001)
