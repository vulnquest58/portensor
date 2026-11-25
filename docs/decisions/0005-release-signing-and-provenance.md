# ADR 0005: Release signing, SBOM, and provenance

- Status: Accepted for P4; production signing identity pending
- Date: 2026-11-21
- Related: [P4 release readiness](../p4-release-readiness.md), [Release process](../release-process.md), [Security policy](../../SECURITY.md)

## Context

Release integrity cannot depend on a checksum file that is published by the
same unauthenticated channel as the artifacts. P4 requires a signed release,
a machine-readable SBOM, and independently verifiable build provenance. The
project also needs a clear boundary between the production signing identity,
ephemeral local test keys, and the GitHub OIDC identity used for attestations.

The existing workflow already has the mechanics, but production key custody and
a published verification identity do not exist yet. Local checks use throwaway
keys and must never be represented as production attestations.

## Decision

1. Sign `dist/SHA256SUMS` rather than signing every artifact individually.
   `SHA256SUMS` covers all platform archives and the CycloneDX SBOM.
2. Support GPG and cosign signatures. A release is rejected unless at least one
   signing secret is configured, and the workflow verifies each signature it
   creates before publication.
3. Publish the public verification key alongside the signatures. The production
   public fingerprint and verification commands are release metadata, not
   repository secrets.
4. Generate a CycloneDX 1.5 SBOM for all Cargo targets with a pinned
   `cargo-cyclonedx` version and include it in `SHA256SUMS`.
5. Use GitHub OIDC build-provenance and SBOM attestations for the release
   artifacts. The attestation signer identity is the release workflow's GitHub
   repository/ref identity, not the production GPG/cosign key.
6. Keep the production signing key outside the repository and CI logs. Generate
   it in an approved offline, HSM, or otherwise controlled environment; grant
   signing use only to the release process; document custody, backup, rotation,
   revocation, and emergency replacement before first production use.
7. A clean release run must publish a signed checksum file, public key,
   signature, SBOM, and attestations, and a separate verification host must
   verify them. Local ephemeral-key checks are tooling tests only.

## Consequences

- Consumers can verify one checksum manifest and then verify every artifact
  from it, without trusting the GitHub release page alone.
- GPG and cosign provide independent verification paths; a single compromised
  tool does not silently remove all signature evidence.
- OIDC attestations link artifacts to the workflow run, while GPG/cosign link
  them to the project's production signing identity. Neither replaces the other.
- Key loss or compromise requires a documented revocation and re-release
  process; tags remain immutable.
- Until a production key is generated and its public fingerprint is published,
  P4 requirement 1 and the release-signing portion of requirement 4 remain
  open.

## Validation

- `scripts/p4-local-check.sh` creates ephemeral GPG and cosign keys, signs and
  verifies a copy of `dist/SHA256SUMS`, derives the public keys, generates a
  CycloneDX SBOM, and checks the release workflow controls.
- `bench/p4/p4-local-check.txt` records only fingerprints and pass/fail results;
  private keys are deleted when the check exits.
- `.github/workflows/release.yml` enforces signing, signature verification,
  SBOM checksum coverage, and OIDC provenance/SBOM attestations.
- Production validation must be a clean-run release dry run followed by
  verification on a separate host using only published materials.
