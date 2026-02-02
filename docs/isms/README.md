# Information Security Management System (ISMS) Documentation

**ISO 27001:2022 Compliance Documentation for Ecliptix.Security.OPAQUE**

---

## Overview

This directory contains the Information Security Management System (ISMS) documentation for the Ecliptix.Security.OPAQUE project. These documents are aligned with ISO 27001:2022 and ISO 27002:2022 requirements.

## Document Index

| Document | ISO 27001 Reference | Description |
|----------|---------------------|-------------|
| [INFORMATION_SECURITY_POLICY.md](INFORMATION_SECURITY_POLICY.md) | A.5.1 | Top-level security policy framework |
| [RISK_ASSESSMENT_REGISTER.md](RISK_ASSESSMENT_REGISTER.md) | 6.1.2, 8.2 | Risk identification, assessment, and treatment |
| [ASSET_INVENTORY.md](ASSET_INVENTORY.md) | A.5.9, A.5.10 | Information asset register |
| [INCIDENT_RESPONSE_PLAN.md](INCIDENT_RESPONSE_PLAN.md) | A.5.24-A.5.28 | Security incident management procedures |
| [SECURE_CODING_GUIDELINES.md](SECURE_CODING_GUIDELINES.md) | A.8.25-A.8.28 | Secure development practices |

## Related Project Documents

| Document | Location | Purpose |
|----------|----------|---------|
| SECURITY.md | Repository root | Vulnerability disclosure policy |
| CONTRIBUTING.md | Repository root | Contributor security requirements |
| CHANGELOG.md | Repository root | Version history and audit trail |
| THREAT_MODEL.md | docs/security-review/ | Security threat documentation |
| PROTOCOL_SUMMARY.md | docs/security-review/ | Cryptographic protocol specification |

## ISMS Scope

The ISMS covers:
- OPAQUE cryptographic library source code and binaries
- Build and release infrastructure
- Development processes and procedures
- Third-party dependencies
- Documentation and intellectual property

## Compliance Status

| ISO 27001 Area | Status |
|----------------|--------|
| Information Security Policy (A.5.1) | Implemented |
| Risk Assessment (6.1.2) | Implemented |
| Asset Management (A.5.9-5.13) | Implemented |
| Access Control (A.5.15-5.18) | Documented |
| Cryptography (A.8.24) | Implemented |
| Secure Development (A.8.25-8.31) | Implemented |
| Incident Management (A.5.24-5.28) | Implemented |

## Review Schedule

| Document | Review Frequency | Next Review |
|----------|------------------|-------------|
| Information Security Policy | Annual | 2026-02-01 |
| Risk Assessment Register | Quarterly | 2025-05-01 |
| Asset Inventory | Semi-annual | 2025-08-01 |
| Incident Response Plan | Annual | 2026-02-01 |
| Secure Coding Guidelines | Annual | 2026-02-01 |

## Maintenance

These documents should be reviewed and updated:
- According to the scheduled review cycle
- After significant security incidents
- When project scope or architecture changes
- When new compliance requirements are identified

## Contact

For questions regarding ISMS documentation:
- Security issues: See SECURITY.md
- General inquiries: Open a GitHub Discussion

---

*Last Updated: 2025-02-01*
