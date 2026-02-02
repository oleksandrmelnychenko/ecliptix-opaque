# Information Asset Inventory

**Document ID**: ISMS-AI-001
**Version**: 1.0
**Last Updated**: 2025-02-01
**Classification**: Internal
**ISO 27001 Reference**: Clause A.5.9, A.5.10, A.5.12

---

## 1. Introduction

This document provides a comprehensive inventory of information assets associated with Ecliptix.Security.OPAQUE in accordance with ISO 27001:2022 requirements.

### 1.1 Purpose

- Identify all information assets within scope
- Classify assets by criticality and sensitivity
- Assign ownership and accountability
- Support risk assessment and control selection

### 1.2 Scope

This inventory covers all assets related to the OPAQUE cryptographic library development, build, release, and maintenance.

---

## 2. Asset Classification Scheme

### 2.1 Confidentiality Classification

| Level | Label | Description |
|-------|-------|-------------|
| C1 | Public | Information intended for public release |
| C2 | Internal | Internal use only, not for public distribution |
| C3 | Confidential | Sensitive business information |
| C4 | Secret | Critical secrets, maximum protection required |

### 2.2 Integrity Classification

| Level | Label | Description |
|-------|-------|-------------|
| I1 | Low | Errors have minimal impact |
| I2 | Medium | Errors may cause moderate problems |
| I3 | High | Errors could cause significant harm |
| I4 | Critical | Errors could be catastrophic |

### 2.3 Availability Classification

| Level | Label | Description |
|-------|-------|-------------|
| A1 | Low | Extended downtime acceptable |
| A2 | Medium | Downtime should be limited |
| A3 | High | Minimal downtime acceptable |
| A4 | Critical | Continuous availability required |

---

## 3. Asset Register

### 3.1 Source Code Assets

| Asset ID | Asset Name | Description | Owner | Location | C | I | A | Criticality |
|----------|------------|-------------|-------|----------|---|---|---|-------------|
| SRC-001 | Core Library Source | C++ source files in src/core/ | Lead Developer | GitHub Repository | C2 | I4 | A3 | Critical |
| SRC-002 | Initiator Module | Client-side implementation in src/initiator/ | Lead Developer | GitHub Repository | C2 | I4 | A3 | Critical |
| SRC-003 | Responder Module | Server-side implementation in src/responder/ | Lead Developer | GitHub Repository | C2 | I4 | A3 | Critical |
| SRC-004 | Interop Layer | C API exports in src/interop/ | Lead Developer | GitHub Repository | C2 | I3 | A3 | High |
| SRC-005 | Public Headers | API definitions in include/opaque/ | Lead Developer | GitHub Repository | C1 | I4 | A3 | Critical |
| SRC-006 | Test Suite | Unit tests in tests/ | QA Lead | GitHub Repository | C2 | I3 | A2 | Medium |
| SRC-007 | Build Scripts | CMake and shell scripts | DevOps Lead | GitHub Repository | C2 | I3 | A3 | High |

### 3.2 Cryptographic Material (Design-Time)

| Asset ID | Asset Name | Description | Owner | Location | C | I | A | Criticality |
|----------|------------|-------------|-------|----------|---|---|---|-------------|
| CRY-001 | Domain Separators | Protocol-specific context strings | Lead Developer | Source code constants | C1 | I4 | A3 | Critical |
| CRY-002 | Protocol Constants | Key lengths, sizes, parameters | Lead Developer | include/opaque/opaque.h | C1 | I4 | A3 | Critical |
| CRY-003 | Test Vectors | Sample protocol transcripts | QA Lead | tests/ directory | C2 | I3 | A2 | Medium |

### 3.3 Documentation Assets

| Asset ID | Asset Name | Description | Owner | Location | C | I | A | Criticality |
|----------|------------|-------------|-------|----------|---|---|---|-------------|
| DOC-001 | Threat Model | Security threat documentation | Security Lead | docs/security-review/THREAT_MODEL.md | C2 | I3 | A2 | High |
| DOC-002 | Protocol Specification | OPAQUE protocol details | Lead Developer | docs/security-review/PROTOCOL_SUMMARY.md | C2 | I4 | A2 | High |
| DOC-003 | API Documentation | Public API reference | Lead Developer | docs/security-review/API_SURFACE.md | C1 | I3 | A2 | Medium |
| DOC-004 | Build Documentation | Build instructions | DevOps Lead | BUILD.md | C1 | I2 | A2 | Medium |
| DOC-005 | ISMS Documentation | Security management docs | ISMS Manager | docs/isms/ | C2 | I3 | A2 | High |
| DOC-006 | Security Policy | Vulnerability disclosure | Security Lead | SECURITY.md | C1 | I3 | A3 | High |

### 3.4 Build and Release Assets

| Asset ID | Asset Name | Description | Owner | Location | C | I | A | Criticality |
|----------|------------|-------------|-------|----------|---|---|---|-------------|
| BLD-001 | CI/CD Pipeline | GitHub Actions workflows | DevOps Lead | .github/workflows/ | C2 | I4 | A3 | Critical |
| BLD-002 | Docker Build Images | Linux/Android build containers | DevOps Lead | Dockerfile.* | C2 | I3 | A2 | Medium |
| BLD-003 | Release Binaries | Compiled library artifacts | DevOps Lead | GitHub Releases | C1 | I4 | A3 | Critical |
| BLD-004 | NuGet Packages | .NET packages | DevOps Lead | GitHub Packages | C1 | I4 | A3 | Critical |
| BLD-005 | XCFramework | iOS/macOS framework | DevOps Lead | GitHub Releases | C1 | I4 | A3 | Critical |
| BLD-006 | Android AAR | Android library package | DevOps Lead | GitHub Packages | C1 | I4 | A3 | Critical |

### 3.5 Infrastructure Assets

| Asset ID | Asset Name | Description | Owner | Location | C | I | A | Criticality |
|----------|------------|-------------|-------|----------|---|---|---|-------------|
| INF-001 | GitHub Repository | Source code repository | Repository Owner | github.com | C2 | I4 | A3 | Critical |
| INF-002 | GitHub Actions | CI/CD execution environment | DevOps Lead | GitHub | C2 | I3 | A3 | High |
| INF-003 | GitHub Packages | Package registry | DevOps Lead | GitHub | C2 | I3 | A3 | High |
| INF-004 | GitHub Releases | Release artifact storage | DevOps Lead | GitHub | C1 | I4 | A3 | High |

### 3.6 Dependency Assets

| Asset ID | Asset Name | Description | Owner | Location | C | I | A | Criticality |
|----------|------------|-------------|-------|----------|---|---|---|-------------|
| DEP-001 | libsodium | Cryptographic primitives library | Upstream | vcpkg/homebrew/apt | C1 | I4 | A3 | Critical |
| DEP-002 | liboqs | Post-quantum cryptography library | Upstream | vcpkg/homebrew/apt | C1 | I4 | A3 | Critical |
| DEP-003 | Catch2 | Test framework | Upstream | FetchContent | C1 | I2 | A2 | Low |
| DEP-004 | vcpkg | Package manager | Microsoft | GitHub | C1 | I3 | A2 | Medium |

### 3.7 Credentials and Secrets

| Asset ID | Asset Name | Description | Owner | Location | C | I | A | Criticality |
|----------|------------|-------------|-------|----------|---|---|---|-------------|
| SEC-001 | Code Signing Certificate | Windows Authenticode cert | Security Lead | Secure Storage | C4 | I4 | A3 | Critical |
| SEC-002 | Apple Signing Identity | macOS/iOS code signing | Security Lead | Keychain | C4 | I4 | A3 | Critical |
| SEC-003 | NuGet Signing Certificate | Package signing cert | Security Lead | Secure Storage | C4 | I4 | A3 | Critical |
| SEC-004 | GitHub Tokens | API access tokens | Repository Owner | GitHub Secrets | C4 | I3 | A3 | Critical |
| SEC-005 | NuGet Publish Token | Package publish credential | DevOps Lead | GitHub Secrets | C4 | I3 | A3 | High |

---

## 4. Asset Ownership

### 4.1 Role Definitions

| Role | Responsibilities |
|------|------------------|
| **Repository Owner** | Overall accountability for repository assets |
| **Lead Developer** | Technical ownership of source code and design |
| **Security Lead** | Security documentation and credential management |
| **DevOps Lead** | Build infrastructure and release management |
| **QA Lead** | Test assets and quality documentation |
| **ISMS Manager** | Security management documentation |

### 4.2 Ownership Matrix

| Owner Role | Asset Categories |
|------------|------------------|
| Lead Developer | SRC-001 to SRC-005, CRY-001, CRY-002, DOC-002, DOC-003 |
| Security Lead | DOC-001, DOC-006, SEC-001, SEC-002, SEC-003 |
| DevOps Lead | SRC-007, BLD-001 to BLD-006, INF-002 to INF-004, SEC-005 |
| QA Lead | SRC-006, CRY-003 |
| ISMS Manager | DOC-005 |
| Repository Owner | INF-001, SEC-004 |

---

## 5. Asset Handling Requirements

### 5.1 By Classification Level

| Classification | Storage | Transmission | Disposal |
|----------------|---------|--------------|----------|
| Public (C1) | No restrictions | No restrictions | No restrictions |
| Internal (C2) | Access-controlled repository | Over HTTPS | Delete from repositories |
| Confidential (C3) | Encrypted storage | Encrypted channels | Secure deletion |
| Secret (C4) | Hardware security module | Encrypted, need-to-know | Cryptographic erasure |

### 5.2 Code Signing Assets

All code signing certificates and keys (SEC-001, SEC-002, SEC-003):
- Store in hardware security module or encrypted keychain
- Limit access to authorized personnel only
- Rotate annually or upon compromise
- Log all usage

### 5.3 API Tokens

All API tokens (SEC-004, SEC-005):
- Store only in GitHub Secrets
- Never commit to repository
- Use minimum required permissions
- Rotate quarterly

---

## 6. Asset Review

### 6.1 Review Schedule

| Review Type | Frequency | Responsible |
|-------------|-----------|-------------|
| Full Inventory Review | Annual | ISMS Manager |
| Classification Review | Semi-annual | Asset Owners |
| Access Rights Review | Quarterly | Security Lead |
| New Asset Registration | As needed | Asset Owners |

### 6.2 Change Management

All changes to critical assets must:
1. Be documented in change log
2. Be reviewed by asset owner
3. Follow version control procedures
4. Update this inventory if classification changes

---

## 7. Revision History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-02-01 | ISMS Manager | Initial inventory |

---

*This document is part of the Ecliptix Information Security Management System (ISMS) and is subject to regular review and updates.*
