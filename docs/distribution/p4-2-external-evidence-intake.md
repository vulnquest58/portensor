# P4-2 external evidence intake and approval packet

Status: **blank intake packet with validator ready; no evidence recorded.**
P4-2 remains `blocked`.

This packet is a template for the project owner, channel maintainers, and
reviewers. It does not confirm ownership, authorize publication, create or
approve tokens, run a clean install, or verify a container digest. No registry
has been contacted. P4-3 must not start until every transition gate below is
satisfied and P4-2 is formally closed.

## Authoritative requirements

- [Registry ownership requirements](registry-ownership.md)
- [Package maintenance policy](package-maintenance-policy.md)
- [Clean-install verification](clean-install-verification.md)
- [External evidence owners](../p4-external-evidence-owners.md)
- [External blockers](../p4-external-blockers.md)
- [P4 closure checklist](../p4-closure-checklist.md)

## Machine-readable packet

The structured companion is
[`p4-2-external-evidence.template.json`](p4-2-external-evidence.template.json).
It is intentionally incomplete, contains only references and decisions, and
does not record secrets.

```bash
# Inspect completeness without failing on missing external evidence.
make p4-external-evidence-status

# Enforce acceptance after all four evidence items are supplied and reviewed.
make p4-external-evidence-check

# List every incomplete field while drafting the packet.
python3 scripts/p4_external_evidence_check.py \
  --packet docs/distribution/p4-2-external-evidence.template.json \
  --allow-incomplete --verbose
```

The acceptance check fails on structural errors, secret material, missing
channels, unapproved tokens, incomplete installs, or missing container digests.
Neither command changes P4 status automatically.

## Evidence handling

1. Complete a copy of this packet only in the approved evidence location.
2. Record references to retained evidence; do not paste secrets or unredacted
   account data.
3. Redact personal information that is not required to establish accountability.
4. Keep the repository copy and machine-readable evidence inventory consistent.
5. Do not change a requirement status until the reviewer accepts the evidence.
6. Do not store 2FA seeds, recovery codes, API tokens, SSH private keys, cookies,
   or session data in this packet or the repository.

## Packet control

| Field | Entry |
|---|---|
| Packet identifier | `P4-2-INTAKE-<channel>-<YYYYMMDD>-<sequence>` |
| Requirement | P4-2 |
| Release version and tag | `<owner to provide>` |
| Channel | `<Homebrew / Scoop / Chocolatey / AUR / GHCR / Docker Hub>` |
| Evidence owner role | `<role>` |
| Reviewer role | `<role>` |
| Date opened | `<date>` |
| Authoritative evidence location | `<approved storage reference>` |
| Packet status | `template` / `not provided` / `in review` / `accepted` / `rejected` |

## Required channels

| Channel | Exact namespace, package, tap, or bucket | Ownership and account-control evidence | Clean install | Status |
|---|---|---|---|---|
| Homebrew | `<owner to provide>` | Not provided | Not executed | `blocked` |
| Scoop | `<owner to provide>` | Not provided | Not executed | `blocked` |
| Chocolatey | `<owner to provide>` | Not provided | Not executed | `blocked` |
| AUR | `<owner to provide>` | Not provided | Not executed | `blocked` |
| GHCR | `ghcr.io/vulnquest58/portensor` | Not provided | Not executed | `blocked` |
| Docker Hub / Compose | `<owner to provide>` | Not provided | Not executed | `blocked` |

## Channel ownership and account-control record

Complete one record for every approved channel.

| Field | Entry |
|---|---|
| Channel | `<channel>` |
| Exact namespace or package | `<namespace, package, tap, bucket, or repository>` |
| Accountable owner | `<named role or person in the approved governance record>` |
| Maintainer | `<named role or person>` |
| Written authorization reference | `<reference and date>` |
| 2FA enabled | `no` / `yes`; evidence reference: `<reference>` |
| Recovery owner or mechanism | `<reference>` |
| Least-privilege publishing access | `<roles and evidence reference>` |
| Maintainer responsibilities accepted | `no` / `yes`; reference: `<reference>` |
| Token plan approved | `no` / `yes`; approval reference: `<reference>` |
| Channel review approval | `<reference and date>` |
| Publication approval | `<reference and date>` |
| Evidence identifier | `<stable identifier>` |
| Source or custody reference | `<URL or approved storage reference>` |
| Date collected | `<date>` |
| Reviewer | `<role or person>` |
| Reviewer decision | `accepted` / `rejected` / `missing evidence` |
| Review date | `<date>` |

Do not enter account passwords, 2FA secrets, recovery codes, API tokens, SSH
private keys, cookies, or session data.

## Token approval record

Token approval is a decision record, not a request to disclose a token. Use one
record per channel.

| Field | Entry |
|---|---|
| Channel | `<channel>` |
| Requested by role | `<role>` |
| Publishing action | `<exact package or image action>` |
| Token type and scope | `<least-privilege scope>` |
| Lifetime or rotation interval | `<interval>` |
| Secret storage reference | `<approved secret store reference>` |
| Rotation owner | `<role>` |
| Revocation method | `<procedure reference>` |
| Approver role | `<role>` |
| Approval decision | `approved` / `rejected` / `pending` |
| Approval date and reference | `<date and reference>` |
| Conditions or limitations | `<conditions>` |

The token itself must never appear in this packet, repository, issue, chat, or
evidence transcript.

## Clean-install verification record

Use the exact commands and preconditions in
[clean-install verification](clean-install-verification.md). One record is
required per approved channel.

| Field | Entry |
|---|---|
| Channel and version | `<channel and exact version>` |
| Clean environment identifier | `<VM, image, or host identifier>` |
| OS, version, and architecture | `<values>` |
| Package source URL or registry reference | `<reference>` |
| Installed package version | `<version>` |
| Formula, manifest, package, or image digest | `<reference>` |
| `portensor --version` expected / actual | `<expected>` / `<actual>` |
| Localhost gate result | `<pass / fail / limitation>` |
| Installed binary or shim path | `<path>` |
| Install log or transcript reference | `<reference>` |
| Uninstall or cleanup result | `<result>` |
| Known limitations | `<limitations>` |
| Evidence identifier | `<stable identifier>` |
| Date obtained | `<date>` |
| Reviewer and decision | `<role>` / `accepted` / `rejected` |

Current clean-install state: **not executed for every channel.** Local metadata
rendering, `choco pack`, and archive extraction are not clean-install evidence.

## Container digest verification record

Required before the GHCR or Docker Hub/Compose channel can pass.

| Field | Entry |
|---|---|
| Image reference and tag | `<registry>/<image>:<version>` |
| Published digest | `<sha256:... or not provided>` |
| Source release tag and commit | `<tag and commit>` |
| Digest inspection command and reference | `<command and evidence reference>` |
| Compose file hash | `<sha256>` |
| Compose pull and version check result | `<reference>` |
| Container-aware localhost check result | `<reference>` |
| Clean environment identifier | `<identifier>` |
| Reviewer and decision | `<role>` / `accepted` / `rejected` |
| Date verified | `<date>` |

No published image digest has been verified in this repository.

## Transition gate

P4-2 may close only when all applicable items are checked and recorded in
`docs/p4-closure-checklist.md` and `docs/p4-closure-evidence.json`:

- [ ] Every required channel has accepted ownership and maintainer evidence.
- [ ] 2FA, recovery ownership, and least-privilege access are reviewed.
- [ ] The token plan and each channel publication approval are recorded without
      secrets.
- [ ] Every approved channel passes a clean-environment install and localhost
      check with retained logs.
- [ ] The published container digest is verified and the Compose example passes
      in a clean environment.
- [ ] Every evidence record has an identifier, date, reviewer, and decision.
- [ ] P4-2 status is changed to `closed` only after formal approval.
- [ ] Explicit authorization to start P4-3 is recorded.

## Current status

| Gate | State |
|---|---|
| Registry ownership | Not provided |
| 2FA and recovery evidence | Not provided |
| Token approval | Not approved |
| Clean-install verification | Not executed |
| Container digest | Not verified |
| P4-2 | `blocked` |
| P4-3 | Not started |

This packet contains planning fields only. It is not evidence of any external
control, install, publication, or approval.
