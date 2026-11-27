# Release process and pre-tag gate

This document defines the mandatory release preflight introduced by roadmap
phase P0. It is permanent process documentation: update it whenever the
release workflow, versioning rules, or validation gates change.

## Non-negotiable rules

1. Every GitHub Actions workflow under `.github/workflows/` must pass
   `actionlint` before a release tag is created.
2. A release tag must be created from a green `main` commit. The release
   workflow re-runs workflow lint before building any artifact.
3. Version markers in `Cargo.toml`, `Cargo.lock`, `Makefile`, `README.md`,
   `CHANGELOG.md`, and `man/portensor.1` must agree.
4. Release archives and `dist/portensor-<version>.cdx.json` must match the version
   and pass `sha256sum -c dist/SHA256SUMS`.
5. Every remote GitHub Action reference must use a verified full commit SHA with
   a comment naming the corresponding version or branch date.
6. `make release-check` must pass from a clean worktree before tagging.
7. Published tags are immutable. Never rewrite a tag to fix CI or release
   metadata; ship a follow-up commit and, when necessary, a new patch release.

## Workflow validation

`.github/actionlint.yaml` declares the custom `portensor-lab` self-hosted runner
label used by `lab.yml`. Workflow lint runs in two places:

- `.github/workflows/ci.yml` job `workflows` on every push and pull request.
- `.github/workflows/release.yml` job `workflows`; Linux, Windows, and publish
  jobs depend on it.

Both jobs use the pinned image `rhysd/actionlint:1.7.12`. Local contributors
must install `actionlint` (the repository was validated with 1.7.12) before
running `make release-check`; CI does not depend on a locally installed binary.

Actions in `.github/workflows/` are pinned to full commit SHAs. The version
comments and runner-image limitations are recorded in
[release-runners.md](release-runners.md). `make p4-evidence-check` rejects
floating action tags and missing runner documentation.

## Version bump checklist

1. Confirm `main` is green, including the `workflows` job.
2. Update the version in:
   - `Cargo.toml` (`[package] version`)
   - `Cargo.lock` (the local `portensor` package entry)
   - `Makefile` (`VERSION`)
   - `README.md` version badge
   - `man/portensor.1` (regenerate with `make man`)
3. Move the release notes from `## [Unreleased]` to
   `## [X.Y.Z] - YYYY-MM-DD` in `CHANGELOG.md`.
4. Update validation/benchmark evidence required for that release.
5. Generate the SBOM with `make sbom`. See [sbom.md](sbom.md) for the format and
   verification procedure.
6. Build the archives with `make dist`. The checksum manifest includes the SBOM
   when `dist/portensor-<version>.cdx.json` is present. Do not tag with stale
   archives or an SBOM for a different version.
7. Run `make release-check`. It requires the current SBOM and fails on a missing
   SBOM, missing checksum entry, invalid CycloneDX document, or digest mismatch.
8. Commit the release changes. The worktree must be clean before tagging.
9. For every release, create or update
   `docs/releases/<version>-attestation.md` with the commit, artifact hashes,
   and explicit tag/signature/attestation status. For a release candidate or a
   final release that is not yet published, record the local finalization and
   the publication blocker; do not tag or publish it. A final release may
   continue to the next step only after the P4 gate is closed or a risk
   acceptance is signed and approved.
10. Create an annotated tag: `git tag -a vX.Y.Z -m "portensor vX.Y.Z"`.
11. Push the commit and tag only after the release gate and any phase-specific
    checks have passed. Pushing a tag triggers the release workflow.

## `make release-check`

The target runs:

- `make workflow-lint` (`actionlint`)
- `scripts/release-check.sh`
- `make ci` (`fmt`, clippy, tests, Python benchmark tests, release build)
- `cargo audit`
- `cargo deny check`

`scripts/release-check.sh` enforces a clean worktree, version consistency, the
presence of the workflow lint config, the current CycloneDX SBOM, SBOM coverage
in `dist/SHA256SUMS`, and checksum verification for current release artifacts.
Set `PORTENSOR_RELEASE_CHECK_ALLOW_DIRTY=1` only for local development checks;
release work must use the default clean-tree mode.

Required local tools: `actionlint`, `cargo-audit`, `cargo-deny`, and Python 3.

## Signed artifacts, SBOM, and provenance

P4 adds release controls that are enforced by `.github/workflows/release.yml`.
The signing and provenance decision is recorded in
[ADR 0005](decisions/0005-release-signing-and-provenance.md); production signing
requirements are drafted in the
[production signing policy](security/production-signing-policy.md); custody,
rotation, and revocation requirements are drafted in the
[key custody procedure](security/key-custody-procedure.md); independent
verification is defined in
[release signature verification](security/release-signature-verification.md);
and the v1.0 compatibility and release commitments are in
[compatibility-policy.md](compatibility-policy.md).

- `make p4-local-check` verifies the local GPG/cosign signing workflow,
  regenerates the CycloneDX SBOM, includes it in `dist/SHA256SUMS`, and checks
  the checksum manifest; see [p4-release-readiness.md](p4-release-readiness.md)
  and [sbom.md](sbom.md).
- `make p4-evidence-check` validates the closure checklist, evidence JSON,
  links, local artifacts, action pins, runner documentation, and CI controls;
  see [p4-evidence-audit.md](p4-evidence-audit.md).
- A release fails unless `GPG_PRIVATE_KEY` or `COSIGN_PRIVATE_KEY` is
  configured. The workflow verifies the signature it created and publishes the
  corresponding public key.
- `SHA256SUMS` covers both platform archives and the CycloneDX SBOM. The release
  job validates the CycloneDX document, checks for the SBOM, asserts its checksum
  entry, and runs `sha256sum -c`.
- GitHub OIDC attestations cover build provenance and the SBOM. These are
  generated only during a tag-triggered release and do not prove production key
  custody by themselves.
- The SBOM is generated for all Cargo targets with `cargo-cyclonedx 0.5.10`;
  cosign is installed at pinned version `v3.1.4`. Actions are pinned to commit
  SHAs and runners are documented in [release-runners.md](release-runners.md).

Do not use the throwaway key created by `p4-local-check` for a release. The
production key fingerprint and verification instructions must be recorded before
P4 can complete.

## Release candidate records

Local release records live under `docs/releases/`. The
[`1.0.0-rc.1` record](releases/1.0.0-rc.1-attestation.md) documents the source
commit `b543303da8923d0ba259a919c038a6bb2880380b`, local artifact digests, and
the absence of a tag, publication, production signature, or GitHub OIDC
attestation. The [`1.0.0` record](releases/1.0.0-attestation.md) documents the
local finalization artifacts and the publication status. The
[`1.0.0` risk acceptance](releases/1.0.0-risk-acceptance.md) is approved within
its recorded scope and expiry and authorizes risk-accepted publication. These
records do not close P4, replace independent custody approval, or satisfy the
P4-1/P4-3/P4-4 external evidence requirements.

## v0.7.0 workflow incident

The `v0.7.0` tag commit contained an unquoted YAML scalar in
`.github/workflows/ci.yml` (`syn::`), so GitHub Actions could not parse the
workflow and the checks for that tag started in a failed state without jobs.
The release workflow itself completed successfully. Commit `69d88b5` fixed the
quoted filter on `main` after publication.

The tag was not rewritten. The permanent fix is the workflow lint gate above:
a malformed workflow now fails CI, and the release workflow refuses to build
artifacts if any workflow is invalid.

## v0.7.2 publish incident

The `v0.7.2` build jobs succeeded, but the `publish` job failed at `Checksums`.
The shellcheck-safe `./` globs changed the `SHA256SUMS` entries to `./...`, so
the subsequent `grep` for `portensor-0.7.2.cdx.json` failed. The SBOM artifact
also included the committed `dist/rayscan-0.7.0.cdx.json` because the upload
path matched every CycloneDX file.

The tag was not rewritten. The CI-built archives and new SBOM were checksummed,
GPG-signed, verified, and published manually. No GitHub OIDC attestations were
created for this release. Commit `37d5474` fixes the checksum globs and restricts
the SBOM upload on `main` for future tags.

## P0 completion evidence

- `.github/actionlint.yaml` added for the `portensor-lab` label.
- `actionlint 1.7.12` passes for all repository workflows.
- The pre-fix `v0.7.0` `ci.yml` is rejected by `actionlint`, proving the gate
  catches the original failure mode.
- `make workflow-lint` and `make release-check` added.
- CI and release workflows both lint all workflows; release jobs depend on
  lint success.
- Version and artifact checks are automated in `scripts/release-check.sh`.
- No tag or release is created as part of P0.
