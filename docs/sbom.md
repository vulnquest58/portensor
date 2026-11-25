# Software bill of materials

Portensor ships a CycloneDX JSON SBOM with each release. The SBOM is covered by
the release checksum manifest and, when attestations are published, by GitHub
OIDC attestations. It is not a substitute for production key custody or
independent verification.

## Format

- CycloneDX JSON, specification version 1.5.
- Filename: `portensor-<version>.cdx.json`.
- The document includes all Cargo targets and must contain at least 100
  components; the current 0.7.0 SBOM contains 280.
- The local evidence copy is `bench/p4/portensor-<version>.cdx.json`.

## Generation

Generate the local artifact with:

```sh
make sbom
```

This runs `cargo cyclonedx --format json --spec-version 1.5` with
`cargo-cyclonedx 0.5.10` and writes `dist/portensor-<version>.cdx.json`.

`make p4-local-check` performs the complete local workflow:

1. Regenerates the SBOM into `dist/`.
2. Copies the same bytes to `bench/p4/` for the evidence audit.
3. Regenerates `dist/SHA256SUMS` over the Linux archive, Windows archive, and
   SBOM.
4. Runs `sha256sum -c dist/SHA256SUMS`.
5. Signs the checksum manifest with ephemeral GPG and cosign test keys and
   verifies the signatures.

The ephemeral keys are local test material only. They do not establish
production signer identity or key custody.

During a tag-triggered release, the `sbom` job generates the SBOM, validates the
CycloneDX format and component count, and uploads it as an artifact. The
`publish` job refuses to continue when the SBOM is missing, includes it in
`SHA256SUMS`, verifies the checksum manifest, signs the manifest, and creates
build-provenance and SBOM attestations.

## Verification

From a checkout with release artifacts:

```sh
sha256sum -c dist/SHA256SUMS
python3 -m json.tool dist/portensor-<version>.cdx.json
```

After a published release with a production key:

```sh
gpg --import dist/SHA256SUMS.gpg.pub
gpg --verify dist/SHA256SUMS.asc dist/SHA256SUMS
cosign verify-blob --key dist/SHA256SUMS.cosign.pub \
  --bundle dist/SHA256SUMS.cosign.bundle dist/SHA256SUMS
```

GitHub attestations require the published release and repository identity:

```sh
gh attestation verify dist/portensor-<version>.cdx.json --repo vulnquest58/portensor
gh attestation verify dist/portensor-<version>-linux-x86_64.tar.gz --repo vulnquest58/portensor
```

Missing SBOM files, missing SBOM checksum entries, digest mismatches, or
invalid CycloneDX documents fail `make p4-local-check`,
`scripts/release-check.sh`, and the release workflow. Local checks passing do
not close P4-4; published attestations and independent verification remain
external evidence.
