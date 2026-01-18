# Known Limitations and Review Notes

- Debug logging prints sensitive material. This must be disabled or restricted for production builds.
- Deployment target mismatch warnings may occur if system libs are built for newer macOS versions.
- The protocol is OPAQUE-like and does not claim conformance to the IETF OPAQUE standard without formal verification.
- Side-channel resistance relies on underlying libsodium/liboqs implementations.
- No built-in rate limiting or account lockout (application-layer concern).
- No deterministic test vectors are provided by default.
- MAX_SECURE_KEY_LENGTH is 4096 bytes; larger inputs are rejected.

Reviewers should pay special attention to:
- OPRF correctness and domain separation
- HKDF and transcript binding
- Interop boundary validation
- Memory handling and zeroization
