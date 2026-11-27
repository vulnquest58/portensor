# P4-1 acceptance report

Report date: 2026-11-21

## Verdict

**NOT ACCEPTED. P4-1 remains `external-pending`.** The local documentation and
automated checks are present. A release GPG signature and public fingerprint are
published with `v1.0.0`, but the key is not custody-approved and no P4-1
production signing identity approval, custody attestation, independent
clean-host transcript, or formal P4-1 approval is recorded. The project owner
authorized a risk-accepted release, not P4-1 acceptance.

No external party was contacted, no production credential was created, and no
status was promoted. P4-2 external evidence was not started; local package
preparation exists but P4-2 remains `blocked`.

Release candidate context: `1.0.0-rc.1` at commit
`b543303da8923d0ba259a919c038a6bb2880380b` has a local
[attestation record](../releases/1.0.0-rc.1-attestation.md). It is not tagged,
published, production-signed, or covered by GitHub OIDC attestations. The
verdict below is unchanged.

Final `1.0.0` context: the release was published on 2026-11-27 under the
[risk acceptance](../releases/1.0.0-risk-acceptance.md). The
[1.0.0 attestation record](../releases/1.0.0-attestation.md) records the
published signature, fingerprint, checksums, and OIDC attestations. The key is
not custody-approved and the formal independent clean-host procedure is pending,
so P4-1 is not satisfied. The verdict below is unchanged.

## Acceptance criteria

| Criterion | Result | Basis |
|---|---|---|
| Production signing identity selected and documented | Not met | No authorized signer or identity supplied |
| Private key generated and held in approved custody | Not verified | No custody attestation or access-control evidence supplied |
| Owner, access control, backup, rotation, revocation, and emergency replacement documented | Draft only | Policy and procedure are drafts; owner approval and exercised evidence absent |
| Public fingerprint and verification commands published | Partially met | Public key and fingerprint published with `v1.0.0`; not an approved production identity |
| Signed artifact verified from a separate clean host | Partially met | Operator-run Debian 12.5 VM passed checksum/GPG/SBOM/binary checks; no independent verifier or out-of-band fingerprint approval |
| Independent review and formal approval | Not met | No reviewer acceptance or project-owner/security-lead decision recorded |

## Actual verification results

| Check | Result | Evidence reference |
|---|---|---|
| `make p4-evidence-check` | Pass: 0 errors, 0 warnings; P4 NOT_CLOSED | `docs/p4-evidence-audit.md`; command output |
| P4 evidence unit tests | Pass: 7 tests | `bench/tests/test_p4_evidence.py` |
| Local ephemeral signing check | Pass for tooling only; not production | `bench/p4/p4-local-check.txt` |
| Public-key fingerprint verification | Published with `v1.0.0`; not approved | Release assets `SHA256SUMS.gpg.pub`, `SHA256SUMS.asc` |
| Production signature verification | Pass on this host; not independent | `SHA256SUMS.asc` verified against `SHA256SUMS.gpg.pub` |
| Clean-host verification | Operator-run pass on separate Debian 12.5 VM; formal P4-1 procedure not executed | `docs/releases/1.0.0-clean-host-verification.txt` |
| Formal approval | Not recorded | Not available |

The local checksum manifest and ephemeral signatures demonstrate workflow
mechanics only. The published release signature and operator-run clean-host
checks demonstrate release mechanics, but they do not establish approved
production custody, independently confirmed signer identity, or formal P4-1
acceptance.

## Release records

The `1.0.0-rc.1` record documents local artifact hashes and the explicit absence
of production signatures and OIDC attestations. The `1.0.0` record documents the
published signature, SBOM, and OIDC attestations plus operator-run clean-host
checks. These are release evidence only and do not satisfy P4-1 or P4-4 without
approved custody and independent verification. P4-1 remains `external-pending`.

## Exact missing inputs from the project owner

The owner must provide or authorize the following through the
[secure evidence submission procedure](p4-1-evidence-submission.md):

1. Written project-owner authorization naming the submitter, production signer,
   key owner, and accountable release owner.
2. Explicit approval of the
   [production signing policy](production-signing-policy.md) and
   [key custody procedure](key-custody-procedure.md), including approver names,
   roles, dates, and evidence references.
3. Selection of GPG, cosign, or both as the production signing technology.
4. Public signing identity: ASCII-armored public key and/or cosign public key,
   full fingerprint, key identifier, algorithm, creation date, expiry, and
   approved publication location.
5. Out-of-band fingerprint confirmation record verified through an independent
   channel.
6. Signed custody and access-control attestation covering the generation
   environment, least privilege, dual control, separation of duties, and
   confirmation that private material is outside this repository.
7. Successful backup/recovery test record and approved rotation, revocation, and
   emergency-replacement procedure or drill record, redacted for sensitive
   details.
8. A production-signed release package: immutable tag, source commit, Linux and
   Windows archives, CycloneDX SBOM, `SHA256SUMS` covering every artifact,
   signature or cosign bundle, public key, and attestation references.
9. A completed clean-host verification transcript produced under the
   [clean-host procedure](p4-1-clean-host-verification.md), including host
   isolation, tool versions, commands, outputs, fingerprint comparison,
   signature/checksum/SBOM/attestation results, and storage reference.
10. Independent reviewer recommendation and project-owner/security-lead
    acceptance with dates.

## Evidence register state

The [P4-1 evidence register](p4-1-evidence-register.md) records local tooling
evidence separately from external evidence. External entries remain `Not
obtained`, `Not verified`, and `Not approved`. Placeholder fields are not
evidence.

## Approval

No approval is recorded. This report is a blocked acceptance review, not a
sign-off.

| Role | Name | Decision | Date |
|---|---|---|---|
| Independent reviewer |  |  |  |
| Project owner |  |  |  |
| Security lead |  |  |  |

## Resume condition

P4-1 execution may resume only when the project owner supplies the inputs above
or authorizes their collection through an approved channel. P4-2 external
evidence must not begin until P4-1 is formally accepted; local P4-2 preparation
does not change its `blocked` status.
