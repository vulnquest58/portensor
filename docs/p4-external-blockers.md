# P4 external blocker report

Status: **P4 remains NOT CLOSED.** The signed `v1.0.0` workflow produced
checksums, a GPG signature, SBOM, and OIDC provenance/SBOM attestations that were
verified from downloaded release assets. P4-1 custody approval, P4-2 registry
evidence, P4-5 OT/ICS assessment, and P4-6 formal sign-off remain absent;
P4-3/P4-4 still require the remaining independent clean-host verification.

Release candidate context: `1.0.0-rc.1` at commit
`b543303da8923d0ba259a919c038a6bb2880380b` is a local validation artifact. It
is not tagged, published, production-signed, or covered by GitHub OIDC
attestations. The [RC attestation record](releases/1.0.0-rc.1-attestation.md)
documents that status; it does not change any requirement below.

Final `1.0.0` context: the release was published on 2026-11-27 under the
recorded [risk acceptance](releases/1.0.0-risk-acceptance.md). The
[1.0.0 attestation record](releases/1.0.0-attestation.md) documents the
published assets, signed workflow, and verification results. The risk
acceptance and signed workflow do not change any requirement status below.

## Summary

| ID | Current status | External blocker | Missing evidence | Unblock action | Risk if unverified |
|---|---|---|---|---|---|
| P4-1 | `external-pending` | Production signing custody is not established on this host | Custody attestation, public fingerprint, signer identity, approved custody/backup/rotation/revocation procedure, clean-host signature verification | Approve a signer and custody process; approve and exercise the draft key custody procedure; publish public verification material; verify from a separate clean host | Release identity and artifact authenticity cannot be trusted |
| P4-2 | `blocked` | Registry ownership and maintainer authority are unconfirmed | Owner confirmations, 2FA/recovery/least-privilege confirmation, approved token plan, channel review/publication approvals, clean-install results, published container digest | Obtain approved owner attestations and verify publishing permissions without exposing credentials; local package metadata, blank intake packet, and acceptance validator are prepared | Unauthorized or broken package distribution remains possible |
| P4-3 | `external-pending` | No clean-run release evidence has been produced | Workflow run URL and logs, resolved runner image versions, commands, artifact hashes, isolation evidence, independent verification | Run an authorized release dry run on a clean runner and retain the complete verification record | Build reproducibility and runner isolation remain unproven |
| P4-4 | `external-pending` | No published production attestations exist | Production SBOM, signer identity, build-provenance and SBOM attestations, artifact-to-SBOM association, verification output | Publish a signed release with OIDC attestations and verify them from published material | Artifact provenance and SBOM trust remain unproven |
| P4-5 | `blocked` | No independent OT/ICS assessment has been authorized or performed | Partner agreement, scope/ROE, legal authorization, budget, plan, final report, remediation closure | Approve an assessor, scope, legal basis, budget, and schedule; complete and review the assessment | OT/ICS security claims lack independent validation |
| P4-6 | `local-ready` | Documentation review and formal sign-off have not occurred | Named reviewer decisions, resolution of findings, completed approval fields and evidence review | Review all evidence and documentation, resolve findings, and record formal approval | P4 cannot be formally closed |

P4-3 has not been started. Its only acceptable evidence is an authorized
clean-run release dry run with retained logs, resolved runner images, artifact
hashes, and separate-host verification; no local substitute is accepted.

## Cross-cutting blockers

- Production key custody and accountable signer identity are not available here.
- Registry ownership, 2FA/recovery controls, and publishing permissions are not
  available here.
- An authorized clean-runner release execution and separate verification host
  have not been supplied.
- An independent OT/ICS assessor, legal authorization, budget, and report have
  not been supplied.
- The formal P4/security/release review has not been completed.

These are external trust dependencies. They cannot be replaced with local test
keys, synthetic records, fabricated attestations, or unverified statements. The
`1.0.0-rc.1` and `1.0.0` records are local validation evidence only.

## Local status that must be preserved

- `make p4-evidence-check` reports 0 errors and 0 warnings.
- `make p4-local-check` passes with ephemeral keys and a 280-component CycloneDX
  SBOM; the local checksum manifest covers both archives and the SBOM.
- `make package-check` renders package metadata from checksum-verified
  archives, passes static syntax/pack tests, and records that registry
  ownership and clean installs were not verified.
- Release actions are SHA-pinned, runner labels are versioned, and runner
  reproducibility limits are documented.
- Local signatures and attestation controls are tooling validation only, not
  production evidence.
- `make release-check` passed from the clean `180b93d` final `1.0.0` worktree;
  it also passed from the clean `b543303` RC worktree.

## Required evidence acceptance

1. Evidence must identify the exact requirement, release, artifact, account, or
   assessment it supports.
2. Evidence must be reviewable by someone other than the person who produced it.
3. Redacted evidence must preserve enough information to verify the claim while
   excluding secrets and personal data.
4. Evidence must be retained at an approved location with source, date, version,
   and reviewer recorded.
5. A requirement becomes `closed` only after all acceptance criteria are
   satisfied and the formal approval is recorded in the checklist and JSON.

## Prohibited actions

- Do not fabricate SBOMs, signatures, provenance, custody records, ownership
  confirmations, runner logs, assessment findings, or approvals.
- Do not expose or request private signing keys, registry credentials, recovery
  codes, or other secrets.
- Do not promote local ephemeral evidence to external status.
- Do not represent `1.0.0-rc.1` as externally evidenced or production-approved.
  Final `1.0.0` publication is authorized only under the recorded risk
  acceptance, with the required label and limitations.
- Do not treat the risk acceptance as P4 closure. P4-1, P4-3, and P4-4 require
  verified signed-workflow evidence before they can be described as satisfied.

## Exit condition

P4 closes only when all six requirements are independently verified, the
checklist and JSON statuses agree, all evidence links resolve, the Windows Npcap
runtime is verified or explicitly waived, and named reviewers record formal
approval. Until then, P4 remains **NOT CLOSED** and final `1.0.0` promotion is
blocked.
