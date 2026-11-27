# P4 evidence audit

Audit date: 2026-11-22

Latest RC addendum: 2026-11-26

Latest finalization addendum: 2026-11-27

## Result

P4 is **NOT CLOSED**. The repository evidence package is internally consistent,
the local verification automation passes with **0 errors and 0 warnings**, and
no externally blocked requirement was promoted.

This audit validates the local evidence package only. It does not create external
evidence, contact assessors or registries, run the release workflow, or approve
P4.

## Scope and method

The audit covers:

- `docs/p4-closure-checklist.md`
- `docs/p4-closure-evidence.json`
- local P4 signing, SBOM, checksum, and validation artifacts
- `.github/workflows/ci.yml` and `.github/workflows/release.yml`
- P4, compatibility, signing, release, runner, SBOM, external-evidence
  coordination, security policy, and package-distribution documents
- local package metadata templates, generator, tests, and captured evidence
- the blank P4-2 external evidence intake and approval packet and its
  machine-readable template and validator
- authorized live-validation reports and evidence for Garfield, RedEye,
  Unclaimed, and Scaffold
- evidence paths, Markdown links, requirement statuses, and local prerequisites

`make p4-evidence-check` runs `scripts/p4_evidence_check.py`, which validates:

- JSON shape, canonical paths, requirement IDs, and top-level status fields
- checklist/JSON title and status consistency
- evidence paths inside the repository and on disk
- links in the configured P4, security, and release documents
- CycloneDX SBOM format, component count, and evidence metadata
- checksum manifest syntax, archive/SBOM coverage, and artifact digests
- GitHub Action commit-SHA pins and version comments
- versioned runner labels and release-runner documentation
- release signing, SBOM, attestation, and CI controls
- package archive checksums/layout, generated metadata, and local syntax checks
- accidental production-key material in the repository

The audit does not validate external account ownership, package registry
control, clean package installs, production key custody, GitHub OIDC
attestations, clean-runner isolation, or an independent assessment.

## Local verification results

| Check | Result |
|---|---|
| `make p4-evidence-check` | Pass: 0 errors, 0 warnings |
| `python3 scripts/p4_evidence_check.py --require-closed` | Expected failure: exit 1, P4 not closed |
| `make p4-local-check` | Pass: ephemeral signatures verified, SBOM 280 components, checksum_manifest=archives+sbom |
| `sha256sum -c dist/SHA256SUMS` | Pass: Linux archive, Windows archive, and SBOM |
| `cargo fmt --all -- --check` | Pass |
| `cargo clippy --all-targets --all-features -- -D warnings` | Pass |
| `cargo test --all-targets --all-features` | Pass: 440 lib, 43 CLI, 3 official tests |
| `python3 -m unittest discover -s bench/tests -t . -v` | Pass: 63 tests |
| `make p4-external-evidence-status` | Pass: 0 structural errors; template incomplete with 252 missing fields |
| `make p4-external-evidence-check` | Expected failure: exit 1 until all external channels are accepted |
| `make package-check` | Pass: metadata rendered, archives verified, 10 packaging tests pass; installs not executed |
| `choco pack dist/packages/chocolatey/rayscan.nuspec` | Pass: package created locally; not installed |
| `python3 -m py_compile scripts/p4_evidence_check.py` | Pass |
| `python3 -m py_compile scripts/p4_external_evidence_check.py` | Pass |
| `python3 -m py_compile scripts/generate_package_metadata.py` | Pass |
| `actionlint` | Pass |
| `git diff --check` | Pass |
| `python3 -m json.tool docs/p4-closure-evidence.json` | Pass |
| `make release-check` | Not run: worktree is intentionally dirty |

The `make p4-local-check` output uses ephemeral test keys and records
`external_key_custody=not verified`. It is local tooling evidence, not production
custody, signing, or attestation evidence.

## RC addendum (2026-11-26)

The `1.0.0-rc.1` candidate was committed as
`b543303da8923d0ba259a919c038a6bb2880380b`; the worktree was clean and
`scripts/release-check.sh` passed. The RC record
[`docs/releases/1.0.0-rc.1-attestation.md`](releases/1.0.0-rc.1-attestation.md)
documents local artifact hashes and explicitly records that no tag, publication,
production signature, or GitHub OIDC attestation exists.

The P4 validator was updated to validate the current release SBOM at
`dist/portensor-1.0.0-rc.1.cdx.json` (CycloneDX 1.5, 280 components) and its
`dist/SHA256SUMS` entry instead of the historical 0.7.0 tooling SBOM. The
historical `bench/p4/rayscan-0.7.0.cdx.json` and
`bench/p4/p4-local-check.txt` remain local 0.7.0 tooling evidence and are not
represented as RC signatures or attestations.

RC validation results:

| Check | Result |
|---|---|
| `python3 scripts/p4_evidence_check.py` | Pass: 0 errors, 0 warnings; P4 NOT CLOSED |
| `scripts/release-check.sh` | Pass from clean commit `b543303` |
| Rust tests | Pass: 444 lib, 43 CLI, 3 official |
| RC SBOM | CycloneDX 1.5, 280 components, covered by `dist/SHA256SUMS` |
| Production signatures | None |
| GitHub OIDC attestations | None |
| PingPong evidence | 15/15 cooldown inventory; latest scripted 6 open + 9 silent; latest nmap 18 open |

This addendum does not close P4. P4-1, P4-3, and P4-4 remain
`external-pending`; P4-2 and P4-5 remain `blocked`; P4-6 remains `local-ready`
pending review and sign-off. Final `1.0.0` promotion remains blocked.

## Finalization addendum (2026-11-27)

Local `1.0.0` artifacts were built from commit `180b93d` with Rust `1.99.1` and
`--locked` for Linux glibc, Linux static-musl, and Windows GNU. The final CycloneDX 1.5 SBOM contains
280 components and is covered by `dist/SHA256SUMS`. The
[1.0.0 attestation record](releases/1.0.0-attestation.md) records the artifact
digests and explicitly states that no tag, publication, production signature, or
GitHub OIDC attestation exists. The
[risk acceptance](releases/1.0.0-risk-acceptance.md) is an unapproved draft.

Final validation results:

| Check | Result |
|---|---|
| `python3 scripts/p4_evidence_check.py` | Pass: 0 errors, 0 warnings, 9 notes; P4 NOT CLOSED |
| P4 evidence and packaging tests | Pass: 24 tests |
| Final SBOM | CycloneDX 1.5, 280 components, covered by `dist/SHA256SUMS` |
| Final archives | Linux and Windows archives present; digests recorded in the attestation record |
| Rust tests | Pass: 444 lib, 43 CLI, 3 official |
| Python tests | Pass: 63 |
| `make release-check` | Pass from clean `180b93d` |
| Production signatures | None |
| GitHub OIDC attestations | None |

This addendum does not close P4 or approve the risk acceptance. P4-1, P4-3, and
P4-4 remain `external-pending`; P4-2 and P4-5 remain `blocked`; P4-6 remains
`local-ready`.

## Findings

### 1. Local SBOM checksum coverage resolved

`dist/SHA256SUMS` now covers the Linux archive, Windows archive, and
`rayscan-0.7.0.cdx.json`. `make p4-local-check` regenerates the CycloneDX SBOM,
rebuilds and verifies the manifest, and records
`checksum_manifest=archives+sbom`. `scripts/release-check.sh` rejects a missing
SBOM, a missing checksum entry, an invalid document, or a digest mismatch.

The release workflow also validates the CycloneDX document, checks for the SBOM,
asserts its manifest entry, and runs `sha256sum -c` before signing. This resolves
the local warning, but P4-4
remains `external-pending` until a published release includes the SBOM in the
signed and attested set and the attestations are independently verified.

### 2. Release actions and runners pinned and documented

All GitHub Action references in the workflows use full commit SHAs with version
comments. Release and CI jobs use versioned `ubuntu-24.04` and `windows-2022`
labels; release jobs log `RUNNER_OS`, `ImageOS`, and `ImageVersion`.
`docs/release-runners.md` records the labels, action pins, and hosted-image
limitations.

This resolves the floating-action and floating-label warning, but P4-3 remains
`external-pending`. Hosted runner images are still mutable within an image
family, so a clean-run release dry run must retain the resolved image versions,
toolchains, commands, artifact hashes, and separate-host verification results.

### 3. Local signing evidence is explicitly non-production

The local P4 evidence records an ephemeral GPG fingerprint and verifies local
signatures, but also records production key custody, registry ownership,
clean-runner execution, and OT assessment approval as `not verified`.

P4-1 and P4-4 remain open. A local signature does not establish production
signer identity, custody, rotation, revocation, or published verification.

### 4. External records are absent

The following cannot be closed from this host:

- P4-1: production key ceremony, public fingerprint, custody approval, and clean-host verification
- P4-2: Homebrew, Scoop, Chocolatey, AUR, GHCR, and Docker Compose ownership and clean-install evidence
- P4-3: clean-runner release execution, logs, and resolved runner versions
- P4-4: published OIDC build-provenance and SBOM attestations with independent verification
- P4-5: assessor confirmation, legal scope, budget, assessment plan, final report, and remediation closure
- P4-6: documentation and security review sign-off

Owners, acceptable evidence, and unblock actions are tracked in
[the external blocker report](p4-external-blockers.md) and
[the evidence ownership matrix](p4-external-evidence-owners.md). Those records
contain no external evidence and do not change any status.

### 5. Windows raw runtime remains unverified

Native Windows Npcap raw runtime verification is still required or must be
explicitly waived with the affected features and limitations recorded in the P4
sign-off.

### 6. Key-material scan found only intentional test fixtures

The repository scan found private-key-like files under `tests/fixtures/tls/`.
These are test fixtures and are excluded from the production-key check. No
private-key markers were found under `.github`, `scripts`, or `docs`.

### 7. Evidence inventory alignment

The checklist listed `docs/architecture.md` and the release workflow as local
evidence, but the JSON inventory did not. They were added to P4-6 and P4-2
respectively.

The release runner documentation, SBOM procedure, and SBOM checksum coverage
were added to the P4-3 and P4-4 inventories. No requirement status changed.

The checklist and JSON now agree on all six requirement titles and statuses.
No U+FFFD replacement characters were found in the audited documents; the
earlier odd console rendering was a PowerShell display artifact for an en dash,
not file corruption.

### 8. External evidence coordination records added

The evidence ownership matrix, external blocker report, and formal sign-off
readiness report were added to document who must supply each external record and
why closure is still blocked. They are coordination records only. They do not
contain external evidence, named approvals, credentials, or status changes.

## Requirement audit

| ID | Checklist and JSON status | Local evidence | Audit conclusion |
|---|---|---|---|
| P4-1 | `external-pending` | ADR, production signing policy, key custody procedure, signature verification procedure, evidence register, secure submission procedure, clean-host verification procedure, blocked acceptance report, release process, release workflow, local signing script/output | Open: production identity, custody, public fingerprint, and clean-host verification absent; evidence register contains no external claims |
| P4-2 | `blocked` | Readiness table, registry ownership requirements, maintenance policy, clean-install procedure, package templates/generator, 10 packaging tests, local metadata/archive evidence, external evidence packet and validator, Makefile, Dockerfile, release workflow | Open: registry ownership, account control, channel approvals, container digest, and clean-install evidence absent |
| P4-3 | `external-pending` | CI and release workflows, SHA-pinned actions, versioned runner labels, runner documentation, pinned toolchain, workflow lint | Open: clean-runner logs and resolved image versions absent |
| P4-4 | `external-pending` | CycloneDX SBOM with 280 components, locally signed checksum copy covering archives and SBOM, signing/attestation controls, SBOM procedure | Open: published attestations and independent verification absent |
| P4-5 | `blocked` | No local substitute | Open: assessor, legal scope, budget, report, and remediation absent |
| P4-6 | `local-ready` | SECURITY, ADRs 0001-0005, compatibility/release/architecture/threat-model documents | Open: review and sign-off absent |

## Audit changes

- Added `scripts/p4_evidence_check.py` and the `make p4-evidence-check` target.
- Added the release workflow to P4-2 evidence and `docs/architecture.md` to
  P4-6 evidence in the JSON inventory.
- Added this report to the local P4 tooling evidence inventory and referenced it
  from the checklist, readiness document, README, and changelog.
- Pinned every workflow action to a full commit SHA with a version comment.
- Replaced floating release/CI runner labels with `ubuntu-24.04` and
  `windows-2022`; release jobs now log `ImageOS` and `ImageVersion`.
- Added `docs/release-runners.md` and `docs/sbom.md`.
- Integrated the CycloneDX SBOM into local checksum generation, release
  preflight, and release-workflow checks.
- Extended the audit for checksum coverage, action pins, runner labels, and
  runner documentation; added seven focused regression tests.
- Added external evidence ownership, blocker, and sign-off readiness reports.
- Added the P4-1 production signing policy, key custody procedure, independent
  signature verification procedure, and evidence register under
  `docs/security/`; the register separates local tooling evidence from
  unobtained external evidence and records no approval.
- Added the secure evidence submission procedure, clean-host verification
  procedure, and acceptance report. The report records the blocked decision and
  exact missing owner inputs; it does not promote P4-1.
- Added local P4-2 package metadata for Homebrew, Scoop, Chocolatey, AUR, and
  Docker Compose, with archive-layout and checksum validation, static syntax
  checks, 10 regression tests, and registry/account/clean-install evidence
  requirements. No registry was contacted and P4-2 remains `blocked`.
- Added a blank P4-2 external evidence intake and approval packet for channel
  ownership, 2FA/recovery, token decisions, clean installs, and container
  digest records. It contains no external evidence and does not change status.
- Added a machine-readable P4-2 evidence template, validator, and seven
  regression tests. The validator rejects missing channels, incomplete
  ownership/token/install records, invalid container digests, version
  mismatches, and embedded secret material. The template is intentionally
  incomplete; no external status changed.
- Added authorized Unclaimed live-validation evidence: 13/13 confirmed TCP
  ports through two-pass recovery, Windows member-server fingerprint,
  HTTP/WinRM/SMB service evidence, and scope-denial exit 2. No exploitation was
  performed, and this does not satisfy any external P4-2 registry or clean-install
  requirement.
- Added authorized Scaffold live-validation evidence: 30/30 discovered TCP
  ports confirmed on a Windows domain controller, anonymous LDAP rootDSE, SMB
  signing, IIS/LDAPS certificates, a documented high-rate nmap all-filtered
  false negative, and a slow-scan timeout. Independent full-port completeness
  was not established. No authentication or exploitation was attempted. This
  is supporting scanner evidence only.

No requirement was marked closed or approved. No external approval, registry,
account-control, or release action was performed. The historical audit predates
the `1.0.0-rc.1` commit; see the RC addendum for the current commit and local
release record. No tag, push, publication, production signature, attestation,
or release was created.

## Closure decision

P4 remains **NOT CLOSED** and final `1.0.0` promotion is blocked. The
`1.0.0-rc.1` candidate is validation-only.

Closure requires all external records listed in
`docs/p4-closure-checklist.md`, plus formal sign-off. After the external records
exist, rerun `make p4-evidence-check`, `make p4-local-check` with approved
production material where applicable, and `make release-check` from a clean
worktree or the approved clean-runner equivalent.
