# Known Limitations and Review Notes

## Debug Logging Controls

All debug logging is **disabled by default** for security. Two compile-time flags control logging:

- **`OPAQUE_DEBUG_LOGGING`**: Enables internal debug logging in core cryptographic functions. Production builds must NOT define this flag.
- **`OPAQUE_INTEROP_LOGGING`**: Enables logging in C interop exports (initiator_exports.cpp, responder_exports.cpp). Production builds must NOT define this flag.

**Important**: Even when logging is enabled, session keys, master keys, and private keys are NEVER logged to prevent credential exposure.
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
