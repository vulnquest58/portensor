# P4-1 acceptance report

Report date: 2026-11-21

## Verdict

**NOT ACCEPTED. P4-1 remains `external-pending`.** The local documentation and
automated checks are present, but production signing evidence has not been
supplied. No project-owner authorization, production signing identity, key
custody attestation, public fingerprint, production-signed release, clean-host
transcript, or formal approval is recorded.

No external party was contacted, no production credential was created, and no
status was promoted. P4-2 was not started.

## Acceptance criteria

| Criterion | Result | Basis |
|---|---|---|
| Production signing identity selected and documented | Not met | No authorized signer or identity supplied |
| Private key generated and held in approved custody | Not verified | No custody attestation or access-control evidence supplied |
| Owner, access control, backup, rotation, revocation, and emergency replacement documented | Draft only | Policy and procedure are drafts; owner approval and exercised evidence absent |
| Public fingerprint and verification commands published | Not met | No approved production public key or fingerprint supplied |
| Signed artifact verified from a separate clean host | Not met | No production-signed release or clean-host transcript supplied |
| Independent review and formal approval | Not met | No reviewer acceptance or project-owner/security-lead decision recorded |

## Actual verification results

| Check | Result | Evidence reference |
|---|---|---|
| `make p4-evidence-check` | Pass: 0 errors, 0 warnings; P4 NOT_CLOSED | `docs/p4-evidence-audit.md`; command output |
| P4 evidence unit tests | Pass: 7 tests | `bench/tests/test_p4_evidence.py` |
| Local ephemeral signing check | Pass for tooling only; not production | `bench/p4/p4-local-check.txt` |
| Public-key fingerprint verification | Not executed: no production public key or approved fingerprint | Not available |
| Production signature verification | Not executed: no production-signed release | Not available |
| Clean-host verification | Not executed: no production-signed release, approved fingerprint, or authorized clean host | `docs/security/p4-1-clean-host-verification.md` |
| Formal approval | Not recorded | Not available |

The local checksum manifest and ephemeral signatures demonstrate workflow
mechanics only. They do not establish production custody, signer identity, or
release authenticity.

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
or authorizes their collection through an approved channel. P4-2 must not begin
until P4-1 is formally accepted.
