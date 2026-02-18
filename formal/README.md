# Formal Verification of Hybrid PQ-OPAQUE

This directory contains formal models of the Hybrid PQ-OPAQUE protocol
for automated security verification.

## Models

### Tamarin Prover (`hybrid_pq_opaque.spthy`)

Symbolic model in the Tamarin framework. Provides fine-grained control
over execution traces and supports lemma-by-lemma verification.

**Properties verified:**
- P1: Session key secrecy
- P2: Password secrecy (even under server DB compromise)
- P3: Classical forward secrecy
- P4: Post-quantum forward secrecy
- P5: Mutual authentication (injective agreement, both directions)
- P6: AND-model hybrid security
- P7: Offline dictionary attack resistance
- Sanity: Protocol can complete (existential trace)

**Threat model includes:**
- Dolev-Yao adversary (full network control)
- Long-term key compromise (client + server)
- Server database compromise
- Quantum DH oracle (models Shor's algorithm)
- Ephemeral key reveal

**Run:**
```bash
# Using the helper script (saves output to logs/)
./run-tamarin.sh                    # Full verification (30–120 min)
./run-tamarin.sh --lemma=protocol_completion   # Single lemma (faster)
./run-tamarin.sh --background       # Run in background

# Or directly:
tamarin-prover hybrid_pq_opaque.spthy --prove -v
tamarin-prover hybrid_pq_opaque.spthy --prove=protocol_completion -v
```

**Interactive mode:**
```bash
tamarin-prover interactive hybrid_pq_opaque.spthy
# Open http://localhost:3001 in browser
```

### ProVerif (`hybrid_pq_opaque.pv`)

Automated model in ProVerif. Faster than Tamarin for most queries,
provides fully automated proofs.

**Properties verified:**
- Session key secrecy
- Password secrecy
- Mutual authentication (correspondence assertions)

**Run:**
```bash
proverif hybrid_pq_opaque.pv
```

## Installation

### Tamarin
```bash
brew install tamarin-prover    # macOS
# or from https://tamarin-prover.github.io/
```

### ProVerif
```bash
brew install proverif           # macOS
# or from https://bblanche.gitlabpages.inria.fr/proverif/
```

## Cryptographic Primitives Modeled

| Protocol Component | Tamarin Model | ProVerif Model |
|---|---|---|
| OPRF (Ristretto255) | Equational theory | Rewrite rules |
| 3DH key exchange | DH builtins | Custom equations |
| ML-KEM-768 | Functional KEM | Functional KEM |
| HKDF-Extract/Expand | Uninterpreted functions | Uninterpreted functions |
| HMAC-SHA-512 | Uninterpreted function | Uninterpreted function |
| Argon2id | One-way function | One-way function |
| XChaCha20-Poly1305 | Symmetric encryption | Authenticated encryption |

## Relation to Paper

These models correspond to Section 5 (Security Analysis) of the paper.
The Tamarin lemmas directly map to Theorems 1–4:

- Theorem 1 (Password Secrecy) → `password_secrecy`, `offline_dictionary_resistance`
- Theorem 2 (Forward Secrecy) → `forward_secrecy_classical`, `pq_forward_secrecy`
- Theorem 3 (Mutual Authentication) → `mutual_auth_initiator`, `mutual_auth_responder`
- Theorem 4 (AND-model) → `and_model_security`
