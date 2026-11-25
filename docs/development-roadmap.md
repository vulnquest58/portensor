# Development roadmap

This roadmap separates prerequisites from deliverable milestones. Prerequisites
are readiness gates; a milestone does not start until its prerequisites are
met. Each phase must pass its exit criteria before the next phase begins.
Changes are not pushed or published until the active phase is complete.

Status legend: `complete`, `in progress`, `pending`, `blocked`.

## Prerequisites

| ID | Prerequisite | Exit evidence | Status |
|---|---|---|---|
| P0 | Release and CI integrity: lint every workflow, enforce a pre-tag gate, and prevent releases from invalid workflow state. | Malformed workflows fail CI and release preflight; all valid workflows pass; version/artifact checks pass from a clean tree; published tags are never rewritten. | complete |
| P1 | Script capability model: approve an ADR for WASM active capabilities, sidecar policy, scope/rate/byte/timeout limits, manifest versioning, lockfile format, and sidecar isolation. | ADR approved; threat model documented; limit-enforcement tests defined; residual sidecar risk accepted or sandboxed. See [ADR 0001](decisions/0001-script-capability-model.md) and the [script threat model](security/script-threat-model.md). | complete |
| P2 | Validation and fault lab: reproducible baselines for 20%/30% loss, full-range scans, coordinator crash points, and worker-load imbalance. | Bench artifacts and reference-host results are documented; pass/fail thresholds are frozen before optimization work. See [validation-baseline.md](validation-baseline.md). | complete |
| P3 | Durable coordinator design: state store, checkpoint boundaries, idempotency rules, restart recovery, and metrics. | Design review complete; failure-injection matrix covers before-claim, after-claim, mid-report, and restart scenarios. See [ADR 0002](decisions/0002-durable-coordinator.md). | complete |
| P4 | Packaging and release credentials: signing keys, registries, clean runners, SBOM/provenance tooling, and external OT assessment scope/budget. | Keys and runners verified; registry ownership confirmed; OT assessment partner and legal scope approved. | in progress; external evidence pending. Local signing/SBOM checks and authorized HTB Garfield/RedEye/Unclaimed/Scaffold validation are recorded in [p4-release-readiness.md](p4-release-readiness.md). Requirement status and sign-off are tracked in [p4-closure-checklist.md](p4-closure-checklist.md); local evidence findings are recorded in [p4-evidence-audit.md](p4-evidence-audit.md). Production key custody, registry ownership, clean-runner attestations, and OT approval are still blocked. |

## Immediate maintenance (P0)

P0 is a prerequisite, not a versioned feature milestone.

Exit criteria:

- `actionlint` runs on all `.github/workflows/*.yml` in CI and release preflight.
- The release workflow's build jobs depend on workflow lint.
- `make release-check` verifies workflow syntax, version consistency, clean
  tree, and release artifact checksums.
- The `v0.7.0` workflow failure is documented and the tag is not rewritten.
- P0 evidence is recorded in [release-process.md](release-process.md).

## v0.8 - Scripting platform

Entry prerequisites: P0, P1, P2.

Exit criteria:

- At least 20 official passive scripts in `packs/official-baseline`, each with
  at least one positive and one negative fixture; fixture suite passes 100%.
- `scripts list` validates every manifest; malformed manifests and findings are
  rejected without panics.
- Active scripts are WASM-only and use host capabilities that enforce:
  - target/port allowlist derived from scope;
  - maximum requests per second;
  - maximum bytes sent and received;
  - wall-clock timeout.
- Tests prove all four limits are enforced; out-of-scope or cross-target access
  produces zero successful requests and an audit event.
- Sidecars receive no active-network capability. On Linux CI, a sidecar
  network-connect fixture is denied by the OS sandbox; on platforms without
  verified isolation, active scripting is disabled and documented.
- `scripts update` is atomic and digest-pinned: an interrupted update leaves the
  prior installed version usable; rollback and offline update tests pass.
- Python and WASM SDK templates execute in CI. Documentation covers manifest
  schema, capability ABI, safety policy, testing, signing, and publishing.
- The official pack remains included in release archives; install and update
  tests pass.
- No new critical/high dependency or security findings; existing accuracy gates
  remain unchanged.

Status: complete. The official pack now contains 24 fixture-backed passive
checks; active capabilities, sidecar isolation, atomic digest-pinned updates,
SDK templates, and the authoring/signing documentation are covered by the test
suite and [script-sdk.md](script-sdk.md).

## v0.9 - Explainable workflows

Entry prerequisites: v0.8 exit; output and script schemas frozen.

Exit criteria:

- `portensor smart` supports single host, CIDR, target file, IPv6,
  scope-guarded target, and no-raw-privilege host.
- It emits human and machine-readable plans with profile, mode, ports,
  estimated probes, required privileges, fallback rationale, and risk notes.
- `--dry-run` performs zero probes; identical inputs produce identical plans
  apart from timestamps.
- Every automatic fallback or default is reported explicitly.
- Interactive mode can produce and save the same plan model; plan-builder tests
  cover all six scenarios.
- HTML reports are self-contained, use no remote assets, escape all
  user/scan-controlled fields, and pass XSS fixtures with zero unescaped
  findings.
- HTML includes services, evidence, advisories, script findings, TLS, OS
  fingerprints, and diffs; parser validation and large-report tests pass.
- At least three pipeline presets or golden outputs are tested, including
  host-port to httpx-style and JSONL to nuclei-style workflows.
- No regression in existing formats or accuracy gates.

Status: complete. The shared plan model lives in `src/plan.rs`; `smart`
dry-run/JSON/save paths and the six required scenarios are tested, and the
interactive wizard emits and can save the same model. `--format html` is
self-contained with escaped fields, XSS and large-report tests, and all scan
sections. Pipeline presets are documented in `docs/pipelines.md` and covered by
three binary-level tests in `tests/cli.rs`.

## v0.10 - Accuracy and scale

Entry prerequisites: P2, P3; performance thresholds frozen.

Exit criteria:

- At 20% loss, verified-mode exactness remains 100% across five runs; median
  duration is at most 7.5 s and p95 at most 9.5 s, versus v0.7.0's
  8.302 s / 10.134 s.
- At 30% loss, exactness remains 100% across three runs with zero false
  positives.
- Baseline and 5% loss results do not regress beyond documented measurement
  noise.
- Full-range scenario (65,535 ports across 16 hosts) completes with peak RSS at
  most 128 MiB, median wall/CPU time at most 0.9x the v0.7.0 baseline, and no
  OOM.
- The coordinator survives restarts at all P3 injection points; 100% of shards
  complete exactly once, and the merged report matches an uninterrupted run.
- A four-worker uneven-load test completes within 1.2x the theoretical lower
  bound; no worker is idle longer than 5 seconds while work remains.
- `/metrics` and `/readyz` expose queue depth, in-flight work, completions,
  failures, and leases. Logs correlate job IDs end-to-end and contain no tokens
  or report contents.
- All prior accuracy, OT, script, and security gates pass.

Status: complete on 2026-11-21. Final evidence: 20% loss 5/5 exact at 5.289 s
median / 6.573 s p95; 30% loss 3/3 exact across repeated sessions; 5% and
baseline exact; full-range 8.511 s median wall, 43.820 s median CPU, 102.1 MiB
median peak RSS; all seven coordinator crash, restart, observability, and
uneven-load scenarios pass. See
[validation-baseline.md](validation-baseline.md) and
[ADR 0002](decisions/0002-durable-coordinator.md).

## v1.0 - Platform and trust

Entry prerequisites: P4 and v0.10 exit.

Exit criteria:

- Homebrew, Scoop, Chocolatey, AUR, GHCR, and Docker Compose packages or images
  install on clean environments and pass `--version` plus the localhost gate.
- Release assets are signed where supported, with SBOM and provenance;
  checksums verify.
- A supported-platform matrix is published. Windows Npcap raw SYN/ACK runtime
  passes; active OS fingerprinting is either tested or explicitly unsupported
  with a reason. macOS raw capability status is tested and documented.
- All major architectural decisions have accepted ADRs; SemVer policy and
  compatibility fixtures pass.
- A `SECURITY.md` policy provides private reporting and defined response
  targets; no unresolved critical/high findings.
- External OT/ICS assessment is complete with no unresolved critical/high
  findings; exceptions are documented.
- If launched, a bug-bounty or vulnerability-disclosure program has approved
  scope, safe harbor, budget, and triage process.

Status: pending.

## Cross-cutting release gates

Every release must satisfy all of the following:

- `actionlint`, `cargo fmt`, clippy with `-D warnings`, Rust tests, Python
  tests, `cargo audit`, and `cargo deny` pass.
- Localhost exactness, matched-mode baseline, 5% loss, and current OT/script
  fixtures pass.
- No regression against frozen accuracy thresholds.
- Release notes, compatibility notes, and artifact checksums are present.
- No active-script scope bypass, secret leakage, or unresolved critical/high
  security finding.

Evasion features remain unscheduled until scope enforcement, capability
gating, and legal/security safeguards pass a dedicated review.
