# P4-1 clean-host verification procedure

Status: **procedure ready; not executed.** No production-signed release or
approved public fingerprint has been supplied. P4-1 remains `external-pending`.

This procedure defines the independent verification required to close P4-1. The
verifier must use a clean host that was not used to build, sign, or publish the
release. Local ephemeral signatures are not acceptable evidence.

## Preconditions

Do not start verification until all of the following exist:

- Written project-owner authorization for the verification.
- Approved production signer identity and public key fingerprint.
- Production-signed release artifacts and `SHA256SUMS`.
- GPG detached signature and/or cosign bundle.
- Published CycloneDX SBOM.
- Optional GitHub attestation references.
- Named independent verifier with no release-signing role.
- Access to an isolated clean host with trusted tool installations.

If any precondition is absent, record the verification as **not executed** and
stop. Do not substitute local or ephemeral evidence.

## Host isolation requirements

- Use a fresh VM, dedicated physical host, or equivalent isolated environment.
- Confirm the host was not used for the release build, signing, or publication.
- Do not install or import production private keys, recovery material, tokens,
  or repository credentials.
- Use a dedicated verifier account and a temporary GPG home directory.
- Record the OS name, version, image identifier or digest, architecture, and
  verification date.
- Record `gpg`, `cosign`, `gh`, Python, and `sha256sum` versions from trusted
  installations.
- Verify downloaded evidence over an authenticated channel where available.
- Do not trust a key merely because it is hosted beside the artifact.

## Verification steps

### 1. Record the verification environment

```sh
date -u
uname -a
gpg --version
cosign version
gh --version
python3 --version
sha256sum --version
```

Record the clean-host image identifier, verifier identity, and isolation
evidence.

### 2. Download and inventory evidence

Download from the approved official release:

- Linux and Windows archives.
- `SHA256SUMS`.
- GPG signature and/or cosign bundle.
- Production public key.
- CycloneDX SBOM.
- Attestation references, if published.

Record each source URL, retrieval date, and SHA-256 digest. Do not use an
artifact mirror unless the owner approved it.

### 3. Validate the public identity out of band

Compare the public key fingerprint with the owner-approved identity record
through an independent channel. Record the approved fingerprint, observed
fingerprint, channel, and confirmation date.

```sh
export GNUPGHOME="$(mktemp -d)"
chmod 700 "$GNUPGHOME"
gpg --import /path/to/public-key.asc
gpg --fingerprint --with-colons
gpg --check-sigs
```

The fingerprint must match exactly. Stop on any mismatch. Never import an
unapproved production key into a permanent keyring.

### 4. Verify the checksum signature

For GPG:

```sh
gpg --verify SHA256SUMS.asc SHA256SUMS
```

For cosign:

```sh
cosign verify-blob --key /path/to/public-key.pub \
  --bundle SHA256SUMS.cosign.bundle SHA256SUMS
```

Record the full verification output and exit status. A good signature from an
unapproved key is a failure.

### 5. Verify artifacts and SBOM

```sh
sha256sum -c SHA256SUMS
grep -F "  portensor-<version>.cdx.json" SHA256SUMS
python3 -m json.tool portensor-<version>.cdx.json >/dev/null
```

Confirm every expected archive and the SBOM are present, checksum-valid, and
associated with the same release version. A checksum-valid but unrelated SBOM
is a failure.

### 6. Verify attestations

When published:

```sh
gh attestation verify portensor-<version>-linux-x86_64.tar.gz \
  --repo vulnquest58/portensor
gh attestation verify portensor-<version>-windows-x86_64.zip \
  --repo vulnquest58/portensor
gh attestation verify portensor-<version>.cdx.json \
  --repo vulnquest58/portensor
```

Record whether each attestation identifies the expected repository, workflow,
source commit, and artifact digest. Attestations do not replace the production
signature.

### 7. Record the result

The transcript must include:

- Requirement ID: P4-1.
- Evidence identifier: P4-1-E6.
- Release tag, version, and source commit.
- Approved and observed public fingerprint.
- Public identity verification channel and date.
- Clean-host identity, OS image, isolation evidence, and verifier.
- Tool versions.
- Every command, output, and exit status.
- Signature, checksum, SBOM, and attestation results.
- Any limitation or anomaly.
- Evidence storage reference and SHA-256 digest.
- Reviewer identity and approval status.

Store the transcript in the owner-approved access-controlled evidence location.
Do not fabricate a transcript or record commands that were not executed.

## Pass criteria

All must be true:

- The host was isolated from build and signing.
- The public fingerprint matches the approved identity through an independent
  channel.
- The signature verifies against the approved key.
- Every archive and the SBOM verify against `SHA256SUMS`.
- The SBOM is associated with the release.
- Published attestations verify against the expected source, where applicable.
- No unexpected artifact is required to complete verification.
- The independent verifier and required approvers accept the transcript.

## Failure handling

Stop and do not install or approve the release when:

- The host isolation cannot be established.
- The fingerprint differs or cannot be independently confirmed.
- The key is expired, revoked, or unapproved.
- A signature or checksum fails.
- The SBOM is missing, unrelated, or not covered by the signed manifest.
- An attestation identifies an unexpected source.
- The transcript is incomplete or cannot be reproduced.

Report a suspected compromise through the private channel in `SECURITY.md`.

## Execution record

| Item | Current state |
|---|---|
| Production-signed release supplied | No |
| Approved public fingerprint supplied | No |
| Clean host authorized | No |
| Verification executed | No |
| Transcript reference | Not available |
| Verifier and reviewer approval | Not recorded |

This procedure remains unexecuted until the exact inputs in the
[P4-1 acceptance report](p4-1-acceptance-report.md) are supplied.
