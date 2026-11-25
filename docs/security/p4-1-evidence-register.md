# P4-1 evidence register

Status: **external evidence not obtained; P4-1 remains `external-pending`.**
No production identity, custody confirmation, signature, or approval is recorded
here.

This register follows the project evidence-integrity fields. Placeholder values
mean the evidence has not been supplied; they are not assertions of completion.
Submission requirements are defined in the
[secure evidence submission procedure](p4-1-evidence-submission.md); independent
verification is defined in the
[clean-host procedure](p4-1-clean-host-verification.md). The current decision is
recorded in the [P4-1 acceptance report](p4-1-acceptance-report.md).

## Local tooling evidence

| Field | Value |
|---|---|
| Requirement ID | P4-1 |
| Evidence identifier | P4-1-L1 |
| Description | Local ephemeral GPG/cosign signing, verification, SBOM, and checksum mechanics |
| Issuing organization or responsible owner | Local project validation |
| Date obtained | 2026-11-21 |
| Verification method | `make p4-local-check`; `sha256sum -c dist/SHA256SUMS` |
| Verification result | Pass; ephemeral keys only; 280-component CycloneDX SBOM |
| Evidence storage reference | `bench/p4/p4-local-check.txt`; `bench/p4/rayscan-0.7.0.cdx.json` |
| Reviewer and approval status | Not applicable to production custody; no approval |

This local evidence does not establish production identity, key custody,
rotation, revocation, or independent release verification.

## Required external evidence

| ID | Requirement | Description | Responsible owner | Date obtained | Verification method | Result | Storage reference | Reviewer / approval |
|---|---|---|---|---|---|---|---|---|
| P4-1-E1 | Signing architecture and identity | Approved production signing technology, identity, and ownership | Not assigned | Not obtained | Review of signed approval record and public identity | Not verified | Not recorded | Not reviewed / not approved |
| P4-1-E2 | Key custody | Custody, access-control, and separation-of-duties attestation | Not assigned | Not obtained | Review of custody attestation and access record | Not verified | Not recorded | Not reviewed / not approved |
| P4-1-E3 | Public verification material | Public key, fingerprint, and verification commands published through an approved channel | Not assigned | Not obtained | Fingerprint comparison and clean-host verification | Not verified | Not recorded | Not reviewed / not approved |
| P4-1-E4 | Backup and recovery | Approved backup/recovery design and successful restoration test | Not assigned | Not obtained | Review of test transcript and custody approval | Not verified | Not recorded | Not reviewed / not approved |
| P4-1-E5 | Rotation and revocation | Approved rotation/revocation procedure and drill or rehearsal record | Not assigned | Not obtained | Review of approval and redacted drill record | Not verified | Not recorded | Not reviewed / not approved |
| P4-1-E6 | Independent verification | Clean-host signature, checksum, SBOM, and attestation verification transcript | Not assigned | Not obtained | Re-run published verification procedure on separate host | Not verified | Not recorded | Not reviewed / not approved |
| P4-1-E7 | Formal approval | Project owner and security lead acceptance of P4-1 evidence | Not assigned | Not obtained | Review of all P4-1 evidence and risk acceptance | Not approved | Not recorded | Not approved |

## Exact owner inputs still required

| ID | Missing input | Acceptance condition | Submission reference |
|---|---|---|---|
| P4-1-E1 | Written owner authorization; selected GPG/cosign identity; approval of the signing policy and custody procedure; named signer, key owner, custodian, backup custodian, and security lead | Authorization is independently confirmed; approver names, roles, and dates are recorded | [Submission package A](p4-1-evidence-submission.md#a-authorization-and-identity-p4-1-e1) |
| P4-1-E2 | Signed custody and access-control attestation, including generation environment, least privilege, dual control, separation of duties, and no private material in the repository | Attestation is complete, internally consistent, and reviewed against the approved custody procedure | [Submission package C](p4-1-evidence-submission.md#c-custody-evidence-p4-1-e2-p4-1-e4-p4-1-e5) |
| P4-1-E3 | Production public key and/or cosign public key, full fingerprint, key ID, algorithm, dates, publication location, and independent fingerprint confirmation | Observed fingerprint matches the owner-approved record; key is approved, unexpired, and not revoked | [Submission package B](p4-1-evidence-submission.md#b-public-signing-identity-p4-1-e3) |
| P4-1-E4 | Approved backup/recovery design and successful restoration test record, redacted | Test result is reproducible, stored in the approved location, and approved by the security lead | [Submission package C](p4-1-evidence-submission.md#c-custody-evidence-p4-1-e2-p4-1-e4-p4-1-e5) |
| P4-1-E5 | Approved rotation, revocation, and emergency-replacement procedure and drill record, redacted | Procedure is approved and a drill or rehearsal is evidenced without exposing private material | [Submission package C](p4-1-evidence-submission.md#c-custody-evidence-p4-1-e2-p4-1-e4-p4-1-e5) |
| P4-1-E6 | Production-signed release and completed clean-host verification transcript | Signature, checksums, SBOM association, and attestations verify on an isolated host using the approved fingerprint | [Submission packages D and E](p4-1-evidence-submission.md#d-production-signed-release-p4-1-e3-p4-1-e6) |
| P4-1-E7 | Independent reviewer recommendation and project-owner/security-lead acceptance | All prior evidence is complete and approved; dates and evidence version are recorded | [Submission package F](p4-1-evidence-submission.md#f-formal-acceptance-p4-1-e7) |

## Closure rule

P4-1 remains open until every required external evidence item is obtained,
verified by an independent reviewer, and formally approved. No local ephemeral
key or placeholder record may be promoted to production evidence.
