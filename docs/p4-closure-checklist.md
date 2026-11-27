# P4 closure checklist

Status: **in progress; not closed**. This checklist is the authoritative
requirement-by-requirement record for the P4 external-evidence gate. Local
tooling can pass while P4 remains open.

The machine-readable companion is
[`p4-closure-evidence.json`](p4-closure-evidence.json). Update both together.
A requirement is `closed` only when every acceptance criterion has reviewable
evidence. Local test keys, planned work, and unverified claims do not close a
requirement.

## Release candidate context

`1.0.0-rc.1` was prepared at commit
`b543303da8923d0ba259a919c038a6bb2880380b` on 2026-11-26 for validation. It is
not tagged, published, production-signed, or covered by GitHub OIDC
attestations. The local record is
[1.0.0-rc.1-attestation.md](releases/1.0.0-rc.1-attestation.md).

Open status: P4-1 `external-pending`, P4-2 `blocked`, P4-3 `external-pending`,
P4-4 `external-pending`, P4-5 `blocked`, P4-6 `local-ready`. Final `1.0.0`
promotion is conditional on closing these items and recording formal approval,
or on a recorded risk acceptance naming the owner, scope, affected artifacts,
and expiry.

## Final 1.0.0 finalization context

`1.0.0` was published on 2026-11-27 under the recorded
[risk acceptance](releases/1.0.0-risk-acceptance.md). The signed release
workflow completed successfully, and its checksums, GPG signature, SBOM, and
OIDC provenance/SBOM attestations were verified from the downloaded release
assets. The record is [1.0.0-attestation.md](releases/1.0.0-attestation.md).
Publication does not close P4 or change any requirement status; P4-1 still
requires approved custody, and P4-3/P4-4 still require the remaining independent
verification.

## Status legend

| Status | Meaning |
|---|---|
| `local-ready` | Local implementation and tests exist; external or reviewer evidence is still required |
| `external-pending` | The remaining evidence must be produced outside this development host |
| `blocked` | A named dependency has not been approved or supplied |
| `closed` | Acceptance criteria met and evidence reviewed |

## Requirements

| ID | Requirement | Acceptance criteria | Local evidence | Remaining evidence | Status |
|---|---|---|---|---|---|
| P4-1 | Release signing and key custody | Production signing identity selected; private key generated and held in approved custody; owner, access control, backup, rotation, revocation, and emergency replacement documented; public fingerprint and verification commands published; signed artifact verified from a separate clean host | [ADR 0005](decisions/0005-release-signing-and-provenance.md), [production signing policy](security/production-signing-policy.md), [key custody procedure](security/key-custody-procedure.md), [signature verification](security/release-signature-verification.md), [evidence register](security/p4-1-evidence-register.md), [evidence submission](security/p4-1-evidence-submission.md), [clean-host verification](security/p4-1-clean-host-verification.md), [clean-host transcript](releases/1.0.0-clean-host-verification.txt), [acceptance report](security/p4-1-acceptance-report.md), [release process](release-process.md), [`release.yml`](../.github/workflows/release.yml), [`p4-local-check.sh`](../scripts/p4-local-check.sh), [`p4-local-check.txt`](../bench/p4/p4-local-check.txt) | Production key ceremony record; approved public key/fingerprint; approved custody, rotation, and revocation evidence; independent clean-host verification transcript; formally approved evidence register | `external-pending` |
| P4-2 | Package registry ownership | Official accounts and namespaces confirmed for Homebrew, Scoop, Chocolatey, AUR, GHCR, and Docker Compose; 2FA/recovery and least-privilege publishing access verified; maintainer responsibilities documented; clean-environment install tests pass for every approved channel | [Registry evidence requirements](distribution/registry-ownership.md), [maintenance policy](distribution/package-maintenance-policy.md), [clean-install procedure](distribution/clean-install-verification.md), [external evidence intake packet](distribution/p4-2-external-evidence-intake.md), [machine-readable packet](distribution/p4-2-external-evidence.template.json), [external evidence validator](../scripts/p4_external_evidence_check.py), [validator tests](../bench/tests/test_p4_external_evidence.py), [packaging templates/generator](../packaging/README.md), [`generate_package_metadata.py`](../scripts/generate_package_metadata.py), [`test_p4_packaging.py`](../bench/tests/test_p4_packaging.py), local metadata/archive evidence in `bench/p4/`, plus ownership table in [P4 readiness](p4-release-readiness.md#registry-ownership), `Makefile`, `Dockerfile`, and release workflow | Owner confirmations, account-control evidence, publishing credentials/token plan (not the secrets), clean-install results, channel publication approvals, and published container image digest | `blocked` |
| P4-3 | Clean CI runner attestation | Runner images and resolved versions documented; release build runs from a clean checkout with declared toolchains and `--locked`; no undeclared local dependencies; artifact hashes are reproducible; build and verification logs retained; runner isolation documented | [`.github/workflows/ci.yml`](../.github/workflows/ci.yml), [`.github/workflows/release.yml`](../.github/workflows/release.yml), [release runners](release-runners.md), [1.0.0 attestation record](releases/1.0.0-attestation.md), [clean-host transcript](releases/1.0.0-clean-host-verification.txt), SHA-pinned actions, pinned `rust-toolchain.toml`, workflow lint and local checks | Independent review of the signed `v1.0.0` workflow logs, resolved `ImageVersion` values, build commands, artifact hashes, and the operator clean-host transcript; hosted runner images remain mutable within the versioned label family | `external-pending` |
| P4-4 | SBOM and build provenance | SBOM generated for all release artifacts; SBOM included in checksums; build-provenance and SBOM attestations created; signer identity documented; attestations and SBOM verified from published material | Local CycloneDX 1.5 SBOM with 280 components in [`portensor-1.0.0.cdx.json`](../dist/portensor-1.0.0.cdx.json); published workflow SBOM with 321 components and OIDC attestations recorded in the [1.0.0 attestation record](releases/1.0.0-attestation.md) and [clean-host transcript](releases/1.0.0-clean-host-verification.txt); historical RC SBOM in [`portensor-1.0.0-rc.1.cdx.json`](../dist/portensor-1.0.0-rc.1.cdx.json); historical 0.7.0 local tooling SBOM in [`rayscan-0.7.0.cdx.json`](../bench/p4/rayscan-0.7.0.cdx.json); current local SBOM covered by [`SHA256SUMS`](../dist/SHA256SUMS); historical 0.7.0 locally signed checksum copy (ephemeral keys); SBOM procedure in [sbom.md](sbom.md); signing/attestation controls in [`release.yml`](../.github/workflows/release.yml); [ADR 0005](decisions/0005-release-signing-and-provenance.md) | Independent verification of the published OIDC provenance/SBOM attestations and reviewer acceptance | `external-pending` |
| P4-5 | OT/ICS external security assessment | Independent assessor confirmed; scope and rules of engagement approved; legal authorization obtained; budget and schedule confirmed; assessment plan, acceptance criteria, and remediation owner documented; final report has no unresolved critical/high findings | No local substitute; assessment inputs are not yet approved | Partner agreement, signed scope/legal authorization, budget approval, assessment plan, final report, and remediation closure or approved exceptions | `blocked` |
| P4-6 | v1.0 security and documentation assets | Comprehensive private-reporting and disclosure policy; required ADRs accepted; security model and boundaries documented; compatibility, deprecation, platform-support, and release policies documented; documentation review completed | [`SECURITY.md`](../SECURITY.md), ADRs [0001](decisions/0001-script-capability-model.md)–[0005](decisions/0005-release-signing-and-provenance.md), [compatibility policy](compatibility-policy.md), [release process](release-process.md), [architecture](architecture.md), [script threat model](security/script-threat-model.md) | Documentation/security review sign-off and resolution of any review findings | `local-ready` |

## Supporting validation and platform blockers

These are not substitutes for the six requirements above, but they remain part
of the v1.0 platform gate.

| Item | Evidence | Status |
|---|---|---|
| Authorized live validation | Garfield: 22/22 confirmed TCP ports via two-pass discovery. RedEye v2: exact 4/4 nmap/rayscan port match, explicit SNI, and endpoint-aware `mixed OS: linux (22, 80), windows (443)`. Unclaimed: 13/13 via two-pass recovery and scope denial exit 2. Scaffold: 30/30 discovered ports confirmed on a Windows domain controller; high-rate nmap produced an invalid all-filtered result and a slower pass timed out, so independent full-port completeness was not established. See [bench/htb/README.md](../bench/htb/README.md), [redeye.md](../bench/htb/redeye.md), [unclaimed.md](../bench/htb/unclaimed.md), and [scaffold.md](../bench/htb/scaffold.md). | `local-ready` |
| Windows Npcap raw runtime | WSL host-NAT raw SYN failed and produced a false tarpit classification; native Windows raw path is not installed here. | `external-pending` |
| Local P4 tooling | `make p4-local-check` passes with ephemeral keys, generates a CycloneDX SBOM, and verifies a checksum manifest covering both archives and the SBOM; `make p4-evidence-check` reports 0 errors and 0 warnings. See the [evidence audit](p4-evidence-audit.md). This is not production custody evidence. | `local-ready` |

The Windows Npcap runtime must be verified or explicitly waived before v1.0.
An explicit waiver must be recorded in the P4 sign-off, with the affected
Windows raw features and user-facing limitations called out.

## External evidence coordination

The external evidence request is tracked in:

- [Evidence ownership and responsibility matrix](p4-external-evidence-owners.md)
- [External blocker report](p4-external-blockers.md)
- [Formal sign-off readiness report](p4-signoff-readiness.md)

These are coordination records only. They do not satisfy an acceptance
criterion, establish ownership, or record an approval. No external evidence has
been obtained in this environment, and no requirement status has changed.

## Final closure criteria

- [ ] P4-1 through P4-6 are `closed` in this checklist and the JSON evidence file.
- [ ] Every evidence link resolves and every external record is reviewable.
- [ ] The evidence owner matrix and external blocker report are reviewed with
      named owners and reviewers.
- [ ] `make p4-evidence-check`, `make p4-local-check`, `make release-check` (or
      the approved clean-runner equivalent), Rust/Python tests, workflow lint,
      and dependency audit pass.
- [ ] No unresolved critical or high-severity release blocker remains; accepted
      exceptions are documented with an owner and expiry.
- [ ] The Windows Npcap runtime is verified or explicitly waived.
- [ ] A named reviewer approves P4 and records the decision below.
- [ ] No final `1.0.0` tag, package publication, or release is created before
      that approval; `1.0.0-rc.1` remains a validation-only record.

## Sign-off

| Role | Name | Decision | Date | Evidence reviewed |
|---|---|---|---|---|
| P4 reviewer |  |  |  |  |
| Security reviewer |  |  |  |  |
| Release owner |  |  |  |  |

Until the sign-off is complete, P4 is **not complete** and final `1.0.0`
promotion is blocked. The `1.0.0-rc.1` candidate may be prepared and tested but
must not be represented as a closed or production-approved release.
