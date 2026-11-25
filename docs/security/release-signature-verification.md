# Release signature verification

Status: **verification procedure defined; production verification evidence not
obtained.** P4-1 remains `external-pending`.

This procedure lets a user verify an official Portensor release from published
material without trusting the build host. It does not publish a production
fingerprint; the authoritative public key and fingerprint must be recorded in
the approved release metadata before P4-1 can close.

## Trust anchor

The trusted signer is identified by the production public key and fingerprint
published through the approved release channel. Do not trust a key merely
because it is attached to the same release page as the artifact.

Never use a private key, recovery material, access token, or credential for
verification.

## Verification order

1. Download the release artifacts, `SHA256SUMS`, public key, signatures, and
   SBOM from the official release.
2. Confirm the public key fingerprint against the approved identity record.
3. Verify the `SHA256SUMS` signature.
4. Verify every artifact and the SBOM against `SHA256SUMS`.
5. Confirm the SBOM entry exists and matches the published SBOM.
6. Verify build-provenance and SBOM attestations, where published.
7. Record the commands, tool versions, results, and verification host.

## GPG verification

```sh
gpg --import <PUBLIC_KEY_FILE>
gpg --fingerprint <SIGNER_ID>
gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum -c SHA256SUMS
```

The fingerprint must match the approved production identity. A good signature
from an unknown or unapproved key is not sufficient.

## cosign verification

```sh
cosign verify-blob --key <PUBLIC_KEY_FILE> \
  --bundle SHA256SUMS.cosign.bundle SHA256SUMS
sha256sum -c SHA256SUMS
```

The public key must match the approved production identity. The signature must
cover the same `SHA256SUMS` digest that is used for artifact verification.

## SBOM association

```sh
python3 -m json.tool portensor-<version>.cdx.json
test -f portensor-<version>.cdx.json
grep -F "  portensor-<version>.cdx.json" SHA256SUMS
```

The SBOM must be the one covered by the signed manifest and must identify the
same release version. Verify that the SBOM describes the artifacts in the
release; a checksum-valid but unrelated SBOM is not sufficient.

## GitHub attestations

```sh
gh attestation verify portensor-<version>-linux-x86_64.tar.gz \
  --repo vulnquest58/portensor
gh attestation verify portensor-<version>-windows-x86_64.zip \
  --repo vulnquest58/portensor
gh attestation verify portensor-<version>.cdx.json \
  --repo vulnquest58/portensor
```

Attestations identify the source repository, workflow, commit, and artifact
digests. They complement, but do not replace, the production signature.

## Failure handling

Stop and do not install the release when:

- The public key fingerprint is not approved.
- A signature does not verify.
- `sha256sum -c` reports a mismatch or missing file.
- The SBOM is absent from `SHA256SUMS`.
- The artifact or SBOM version differs from the release.
- An attestation cannot be verified or identifies an unexpected source.
- A key is revoked or expired.

Report a suspected release compromise through the private security channel in
`SECURITY.md`. Do not publish unverified incident details.

## Local validation boundary

`make p4-local-check` creates ephemeral GPG and cosign keys, signs a temporary
copy of `dist/SHA256SUMS`, and verifies it. This proves the local mechanics only.
It is not production custody, identity, or independent verification.

## Evidence to retain

For P4-1 closure, the independent verifier must record:

- Release tag and artifact versions.
- Approved public fingerprint.
- Commands and tool versions.
- Verification host and date.
- Signature, checksum, SBOM, and attestation results.
- Storage reference for any retained transcript.
- Reviewer identity and approval status.

The current evidence register is [P4-1 evidence register](p4-1-evidence-register.md).
Clean-host execution requirements are in the
[clean-host verification procedure](p4-1-clean-host-verification.md), and the
current blocked decision is in the
[P4-1 acceptance report](p4-1-acceptance-report.md).
