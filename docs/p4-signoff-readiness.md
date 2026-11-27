# P4 formal sign-off readiness report

Status: **NOT READY FOR FORMAL P4 SIGN-OFF.** P4 remains **NOT CLOSED**. Final
`1.0.0` publication proceeds only under the recorded risk acceptance, not P4
closure.

This report separates completed local validation from the external evidence
that is still required. It does not approve P4 and contains no invented names,
dates, signatures, or external records.

Release candidate context: `1.0.0-rc.1` at commit
`b543303da8923d0ba259a919c038a6bb2880380b` is prepared for validation only. It
is not tagged, published, production-signed, or attested. The
[RC attestation record](releases/1.0.0-rc.1-attestation.md) records that status.

Final `1.0.0` context: local artifacts and the final SBOM were prepared on
2026-11-27. The [risk acceptance](releases/1.0.0-risk-acceptance.md) is approved
within its recorded scope and expiry; the
[1.0.0 attestation record](releases/1.0.0-attestation.md) records the local and
publication status. P4 formal sign-off remains outstanding.

## Local readiness

| Check | Result | Evidence |
|---|---|---|
| P4 evidence audit | Pass: 0 errors, 0 warnings | `make p4-evidence-check` |
| Local signing and SBOM check | Historical 0.7.0 tooling pass with ephemeral keys; RC local-check not rerun in this environment | `bench/p4/p4-local-check.txt` |
| SBOM | Final CycloneDX 1.5, 280 components; RC and historical 0.7.0 tooling SBOMs retained | `dist/portensor-1.0.0.cdx.json`, `dist/portensor-1.0.0-rc.1.cdx.json`, `bench/p4/rayscan-0.7.0.cdx.json` |
| Checksum coverage | Both final archives and final SBOM | `dist/SHA256SUMS`, `dist/portensor-1.0.0.cdx.json` |
| Final attestation record | Present; records risk-accepted publication and `v1.0.0-rc.3` signed-workflow verification; final release evidence pending | `docs/releases/1.0.0-attestation.md` |
| Risk acceptance | Approved within recorded scope and expiry; not P4 closure | `docs/releases/1.0.0-risk-acceptance.md` |
| Workflow lint | Pass | `actionlint` |
| Rust formatting | Pass | `cargo fmt --all -- --check` |
| Rust lint | Pass | `cargo clippy --all-targets --all-features -- -D warnings` |
| Rust tests | Pass: 444 lib, 43 CLI, 3 official | `cargo test --all-targets --all-features` |
| Python tests | Pass: 63 | `python3 -m unittest discover -s bench/tests -t . -v` |
| Package metadata checks | Pass: static checks and 10 packaging tests; installs not executed | `make package-check` |
| External evidence validator | Pass: structural checks and 7 validator tests; template reports incomplete | `make p4-external-evidence-status` |
| Evidence references | Automated link and status checks pass; human review not performed | `make p4-evidence-check` |
| Documentation/security review | Not performed | P4-6 approval outstanding |
| Whitespace validation | Pass | `git diff --check` |
| Release preflight | Pass from clean `180b93d` for final `1.0.0`; historical RC pass from `b543303` | `make release-check` |

Local results do not establish production custody, registry ownership,
clean-runner isolation, published provenance, independent assessment, or formal
approval. The local SBOM and signatures are evidence of tooling behavior only.
The RC and final artifacts are local build outputs; their presence is not a
release, publication, signature, or attestation.

## External readiness

| ID | Requirement | External evidence present | Ready for closure |
|---|---|---|---|
| P4-1 | Production signing and custody | No; on hold | No |
| P4-2 | Package registry ownership | No; local preparation complete | No |
| P4-3 | Clean CI runner attestation | No; not started | No |
| P4-4 | SBOM and build provenance | No | No |
| P4-5 | OT/ICS external assessment | No | No |
| P4-6 | Final documentation and security sign-off | No; local documentation prepared | No |

## Formal sign-off prerequisites

- [ ] P4-1 evidence is independently reviewed and accepted.
- [ ] P4-2 evidence is independently reviewed and accepted.
- [ ] P4-3 evidence is independently reviewed and accepted.
- [ ] P4-4 evidence is independently reviewed and accepted.
- [ ] P4-5 evidence is independently reviewed and accepted.
- [ ] P4-6 documentation and security review findings are resolved.
- [ ] The Windows Npcap raw runtime is verified or explicitly waived with
      limitations recorded.
- [ ] `docs/p4-closure-checklist.md` and `docs/p4-closure-evidence.json` agree
      and all evidence references resolve.
- [ ] The final P4 reviewer, security reviewer, and release owner are named and
      have no unresolved conflicts.
- [ ] Formal approval fields are completed from reviewable evidence.

## Review procedure

1. Use `docs/p4-external-evidence-owners.md` to obtain a named owner and
   reviewer for each open requirement.
2. Collect evidence under the intake rules in
   `docs/p4-external-blockers.md`; use the
   [P4-2 external evidence intake packet](distribution/p4-2-external-evidence-intake.md)
   and its [machine-readable template](distribution/p4-2-external-evidence.template.json)
   for channel records. Run `make p4-external-evidence-check` before acceptance.
   Never submit private keys, tokens, recovery codes, or credentials.
3. Verify provenance, scope, date, version, and acceptance criteria before
   changing any status.
4. Update the checklist and JSON inventory together. Do not change a status on
   one record only.
5. Rerun `make p4-evidence-check`, `make p4-local-check`, and all release checks.
   Run `make release-check` only from a clean worktree.
6. Record the formal decision only after all six requirements and the platform
   waiver are resolved.

## Approval record

No approval is recorded. The fields below remain intentionally incomplete.

| Role | Name | Decision | Date | Evidence reviewed |
|---|---|---|---|---|
| P4 reviewer |  |  |  |  |
| Security reviewer |  |  |  |  |
| Release owner |  |  |  |  |

## Decision

**Do not close P4.** The local pipeline is auditable and passes, but external
trust evidence is absent. The `1.0.0-rc.1` commit and local record are
validation artifacts only. No tag, push, publication, production signature,
attestation, final release, or final `1.0.0` promotion is authorized by this
report.
