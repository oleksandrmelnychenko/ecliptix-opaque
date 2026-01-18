# Request for Proposal: Security Review of Ecliptix.Security.OPAQUE

## Background
Ecliptix.Security.OPAQUE is a C++23 implementation of an OPAQUE-like PAKE protocol with Ristretto255-based OPRF and ML-KEM-768 post-quantum key encapsulation. It exposes a C API for interop and a C# wrapper for .NET usage.

## Scope (All)
- Protocol design and security properties
- Cryptographic constructions and parameter choices
- Implementation correctness and memory safety
- Side-channel resistance and constant-time behavior
- C API and .NET interop correctness
- Build flags and dependency usage

## Objectives
- Validate that the protocol flow achieves intended authentication and key agreement properties
- Identify cryptographic misuse, logic flaws, or unsafe assumptions
- Identify implementation bugs and memory safety risks
- Review side-channel leakage risks, including logging and timing
- Provide prioritized remediation guidance

## Deliverables
- Written report with findings (severity, impact, evidence, and recommendations)
- Reproduction steps or proof of concept when applicable
- Optional retest report after fixes

## Exclusions
- Operational security of deployment environments
- Transport layer (TLS) configuration
- Application-level account policy (rate limits, lockouts)

## Requested Methodology
- Design review against OPAQUE and PAKE best practices
- Source review of cryptographic operations and data flow
- Threat model validation
- Static analysis and targeted fuzzing
- Side-channel analysis (timing, logging, memory access)

## Proposal Requirements
- Team experience and relevant prior audits
- Proposed approach and tools
- Schedule and estimated effort
- Cost estimate
- Required access or data beyond this package

## Contacts
- Provide a primary technical contact and a security lead in your proposal.
