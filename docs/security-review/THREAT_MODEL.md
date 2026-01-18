# Threat Model

## Assets
- User secure key (password or secret)
- Initiator private keys (static and ephemeral)
- Responder private key (static and ephemeral)
- Registration record (envelope + initiator public key)
- Session keys and master keys
- ML-KEM shared secrets

## Trust Boundaries
- Client device (initiator) is untrusted by server
- Network is untrusted
- Server stores registration records and account identifiers
- Native libraries and dependencies must be trusted

## Adversaries
- Network attacker (active MITM, replay, tampering)
- Malicious client attempting credential misuse
- Malicious or compromised server attempting password recovery
- Passive eavesdropper
- Local attacker with access to logs or memory

## Assumptions
- libsodium and liboqs are correct and securely configured
- Transport security (TLS) is used for message confidentiality and integrity
- Server securely stores registration records and private keys
- Logging of sensitive material is disabled in production

## Security Goals
- Password secrecy against server compromise
- Mutual authentication between client and server
- Forward secrecy for session keys
- Resistance to offline dictionary attacks
- Detection of tampering on KE1/KE2/KE3

## Out of Scope
- Application-level rate limiting and lockout policies
- Physical device compromise
- Host OS hardening and sandboxing
