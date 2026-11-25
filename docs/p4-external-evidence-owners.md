# P4 external evidence ownership and responsibility matrix

Status: **coordination record only; P4 remains not closed.** This document does
not record external evidence, ownership confirmations, approvals, or sign-off.
All external requirement statuses remain unchanged.

No private signing keys, registry passwords, API tokens, recovery codes, VPN
credentials, or other secrets may be submitted as evidence. Redact account
identifiers and security settings before storing evidence outside the repository.

## Ownership matrix

| ID | Evidence owner role | Reviewer / approver role | Required evidence | Acceptable format | Status |
|---|---|---|---|---|---|
| P4-1 | Release owner with security lead | Security reviewer and executive approver | Custody attestation; production public fingerprint; signer identity; rotation, revocation, and emergency-replacement procedure; clean-host verification transcript | Signed or approved custody statement; public key and policy; redacted command transcript with versions and results | Awaiting external owner |
| P4-2 | Release or packaging maintainer | Release owner | Ownership or maintainer confirmation for every required channel; 2FA, recovery, and least-privilege publishing confirmation; approved token plan without secrets; channel review/publication approvals; clean-environment install results; published container image digest | Owner attestation; redacted account-control evidence; install logs; review records; digest; no credentials | Awaiting external owner |
| P4-3 | CI or release engineer | Security reviewer | Clean-run workflow URL and retained logs; resolved `ImageOS`/`ImageVersion`; build commands; artifact digests; runner isolation; separate-host verification | Workflow run URL, logs, checksum transcript, isolation notes, independent verification record | Awaiting external owner |
| P4-4 | Release engineer with security reviewer | Security reviewer | Production SBOM from the release run; signer identity; build-provenance and SBOM attestation references; artifact-to-SBOM association; verification output | Published release links, attestation URLs or bundles, SBOM, `gh attestation verify` and checksum output | Awaiting external owner |
| P4-5 | Security or GRC lead | Executive sponsor / approval authority | Independent assessor agreement; approved scope and rules of engagement; legal authorization; budget and schedule; assessment plan; final report; remediation closure | Redacted signed agreements and approvals; final report reference; findings and remediation record | Blocked until partner and authorization exist |
| P4-6 | P4 reviewer with security reviewer and release owner | Executive approver | Review of all security and compatibility documentation; evidence-link verification; resolution of findings; formal approval record | Signed review record, completed checklist, approved evidence JSON fields | Awaiting named reviewers |

All owner and approver cells intentionally name roles, not people. Named
assignments must be recorded through the project's approved governance process,
not invented in this repository.

## Responsibilities

- The evidence owner collects the evidence, confirms its source and date,
  redacts sensitive material, and records where the authoritative copy is held.
- The reviewer checks that the evidence satisfies the acceptance criteria and is
  attributable to the claimed system, release, or account.
- The release owner prevents status changes, tags, publications, and releases
  until the evidence has been independently reviewed.
- The P4 reviewer updates `docs/p4-closure-checklist.md` and
  `docs/p4-closure-evidence.json` together only after verification.
- Any reviewer with a conflict of interest must be replaced or the conflict
  recorded and approved.

## Evidence intake rules
Use the [P4-2 external evidence intake and approval
packet](distribution/p4-2-external-evidence-intake.md)
and its [machine-readable template](distribution/p4-2-external-evidence.template.json)
for registry ownership, token approvals, clean installs, and container digest
records. Run `make p4-external-evidence-check` before acceptance. The packet is
blank until completed from reviewable evidence.

1. Do not place production private keys, credentials, recovery codes, or
   unredacted account sessions in the repository or an issue.
2. Prefer public artifacts and redacted attestations stored in the approved
   evidence location.
3. Record the artifact version, source URL or custody reference, collection
   date, and the verifier who accepted it.
4. Preserve the original evidence outside the repository; link only to the
   approved record when it can be shared safely.
5. Local ephemeral signatures are not production custody evidence and cannot
   satisfy P4-1 or P4-4.

## Status rule

The evidence owner role and reviewer role may be assigned without changing a
requirement status. A requirement remains `external-pending` or `blocked` until
the acceptance criteria are satisfied by reviewable evidence and formal approval
is recorded.
