# Branch Protection Rules

This document describes the recommended branch protection rules for the Ecliptix.Security.OPAQUE repository.

## GitHub Branch Protection Settings

### Main Branch (`main`)

Navigate to: **Settings → Branches → Add branch protection rule**

**Branch name pattern**: `main`

#### Protect matching branches

- [x] **Require a pull request before merging**
  - [x] Require approvals: **1** (minimum)
  - [x] Dismiss stale pull request approvals when new commits are pushed
  - [x] Require review from Code Owners
  - [ ] Restrict who can dismiss pull request reviews

- [x] **Require status checks to pass before merging**
  - [x] Require branches to be up to date before merging
  - Required status checks:
    - `Build & Test (Linux)`
    - `Build & Test (macOS)`
    - `CodeQL Analysis`
    - `Security Policy Verification`
    - `Lint & Format`

- [x] **Require conversation resolution before merging**

- [x] **Require signed commits** (recommended for cryptographic projects)

- [ ] **Require linear history** (optional, enables squash/rebase only)

- [x] **Do not allow bypassing the above settings**

- [ ] **Restrict who can push to matching branches** (optional)

#### Rules applied to everyone including administrators

- [x] **Do not allow force pushes**
- [x] **Do not allow deletions**

### Develop Branch (`develop`)

**Branch name pattern**: `develop`

Similar to `main` but with slightly relaxed rules:

- [x] Require a pull request before merging
  - [x] Require approvals: **1**
  - [x] Dismiss stale approvals
  - [ ] Require Code Owners review (optional for develop)

- [x] Require status checks to pass
  - `Build & Test (Linux)`
  - `Build & Test (macOS)`

- [x] Do not allow force pushes
- [x] Do not allow deletions

### Feature Branches

Feature branches (`feature/*`, `fix/*`) typically don't need protection rules, but consider:

- Naming convention enforcement via GitHub Actions
- Automatic deletion after merge

## Security-Related Branch Rules

### For `security/*` branches

These branches contain security fixes and require additional scrutiny:

1. **Must be reviewed by security-designated maintainer**
2. **Must pass all security scans**
3. **Should be merged with minimal delay once approved**
4. **Consider using draft PRs until ready**

## Recommended Workflow

```
feature/xyz  →  develop  →  main
fix/abc      →  develop  →  main
security/cve →  main (direct, with expedited review)
```

## Enforcement

To enable these rules:

1. Go to repository **Settings**
2. Click **Branches** in the left sidebar
3. Click **Add branch protection rule**
4. Enter the branch name pattern
5. Configure the options as described above
6. Click **Create** or **Save changes**

## CODEOWNERS Integration

The `.github/CODEOWNERS` file automatically requires reviews from designated owners:

```
# Cryptographic core requires security review
/src/core/           @security-team
/include/opaque/     @security-team

# Security documentation
/SECURITY.md         @security-team
/docs/isms/          @security-team
```

## Status Checks

The following status checks are configured in CI:

| Check | Workflow | Required |
|-------|----------|----------|
| Build & Test (Linux) | `ci.yml` | Yes |
| Build & Test (macOS) | `ci.yml` | Yes |
| CodeQL Analysis | `security-scan.yml` | Yes |
| Dependency Review | `security-scan.yml` | PRs only |
| Security Policy Verification | `security-scan.yml` | Yes |
| Lint & Format | `ci.yml` | Yes |
| Documentation Check | `ci.yml` | Yes |

## Emergency Procedures

In case of critical security issues requiring immediate fixes:

1. Create a `security/` branch from `main`
2. Implement minimal fix
3. Request expedited review from security maintainer
4. Merge directly to `main` (bypassing develop)
5. Cherry-pick to `develop` after release
6. Document in post-incident report

**Note**: Even emergency fixes should go through PR review when possible. Only bypass in extreme circumstances with post-facto documentation.
