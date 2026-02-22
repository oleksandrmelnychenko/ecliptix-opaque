# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

**Do NOT report security vulnerabilities through public GitHub issues.**

Report them via email to: **security@ecliptix.com**

You should receive a response within 48 hours.

### What to Include

- Type of issue (cryptographic weakness, authentication bypass, information disclosure)
- Full paths of source file(s) related to the issue
- Location of the affected source code (tag/branch/commit or direct URL)
- Step-by-step instructions to reproduce the issue
- Impact of the issue, including how an attacker might exploit it

### Response Timeline

- **Initial Response**: Within 48 hours
- **Vulnerability Confirmation**: Within 7 days
- **Patch Development**: Varies based on complexity
- **Security Advisory**: Published with fix release

### Disclosure Policy

- Coordinated disclosure
- Credit to reporters in security advisories (unless you prefer to remain anonymous)
- Reasonable time to address the issue before public disclosure

## Security Measures

### Cryptographic Implementation

- **Ristretto255** elliptic curve operations via libsodium
- **ML-KEM-768** post-quantum key encapsulation (FIPS 203)
- **Argon2id** key stretching
- **HMAC-SHA512** message authentication
- **XSalsa20-Poly1305** authenticated encryption

### Memory Security

- Zeroization of sensitive data via `zeroize` crate
- No heap allocation of raw secrets
- Ephemeral keys destroyed immediately after use

### Build Security

- Release profile: LTO enabled, single codegen unit, symbols stripped
- `cargo audit` in CI for known vulnerabilities
- `cargo clippy` with `-D warnings` enforced

## Production Deployment

1. **Always use TLS** for transport layer security
2. **Implement rate limiting** at the application layer
3. **Secure storage** for relay private keys and registration records
4. **Regular updates** via `cargo audit`

## Formal Verification

Seven security properties verified by Tamarin Prover (8/8 lemmas) and ProVerif (5/5 queries). See `formal/logs/` for verification transcripts.

## References

- [OPAQUE Draft Specification](https://datatracker.ietf.org/doc/draft-irtf-cfrg-opaque/)
- [libsodium](https://doc.libsodium.org/)
- [ML-KEM (FIPS 203)](https://csrc.nist.gov/pubs/fips/203/final)
