# Package maintenance policy

Status: **draft; no registry publication approved.** P4-2 remains `blocked`.

This policy defines how approved package channels are updated after P4 is
formally cleared. It does not authorize publishing now.

## Source of truth

The immutable GitHub release tag and its signed checksums are the source of
truth. Package metadata must use the exact release archives and checksums; it
must not rebuild, patch, or replace those artifacts during package publication.

Local metadata generation is performed by:

```sh
make package-metadata
make package-check
```

Generated files are drafts until an authorized release owner reviews them
against the final release assets.

## Release sequence

1. Complete the release gate and obtain explicit release authorization.
2. Verify the published archives, checksums, SBOM, signatures, and attestations.
3. Generate package metadata from the verified release assets.
4. Review the generated Homebrew, Scoop, Chocolatey, AUR, and Docker Compose
   definitions.
5. Run the clean-environment install checks in
   [clean-install verification](clean-install-verification.md).
6. Obtain channel-owner approval for each publication.
7. Publish only the approved channel artifacts.
8. Record package URLs, versions, checksums, reviewer, and date.

No package manager publication may occur before the release announcement and
verification material are available.

## Access and secrets

Record ownership, account-control evidence, and token decisions in the
[P4-2 external evidence intake and approval packet](p4-2-external-evidence-intake.md).
The packet records approvals only; never store a token or recovery secret in it.

- Registry accounts must use individual named access, not shared credentials.
- Require 2FA and a documented recovery owner for every channel.
- Grant least-privilege publishing access; do not reuse account passwords in CI.
- Store tokens only in the approved organization or repository secret store.
- Never commit tokens, recovery codes, private keys, cookies, or session data.
- Rotate publishing credentials after a role change or suspected exposure.
- Revoke access promptly when a maintainer leaves the release role.

## Package-specific responsibilities

### Homebrew

- Keep the tap formula and bottle/source URL aligned with the supported Linux
  x86_64 release.
- Verify checksums after any metadata edit.
- Run `brew audit` and `brew test` on a clean Linux environment when the tap
  owner authorizes publication.
- Do not represent macOS support unless a tested artifact exists.

### Scoop

- Keep the 64-bit Windows URL and SHA-256 aligned with the release archive.
- Validate the manifest on a clean Windows environment with Scoop installed.
- Do not enable unattended autoupdate until checksum resolution and review are
  proven.

### Chocolatey

- Keep the package version, download URL, checksum, and install script aligned.
- Validate with `choco pack` and install on a clean Windows environment.
- Do not publish with a package version that differs from the release.
- Keep package ownership and maintainer contact current.

### AUR

- Keep `pkgver`, source URL, and checksum aligned with the release.
- Build in a clean Arch environment with the approved `makepkg` configuration.
- Verify the installed binary and man pages.
- Do not silently replace a published package with a different upstream build.

### GHCR and Docker Compose

- Publish the image from the approved immutable source revision.
- Pin the image tag used in the Compose example to an approved release.
- Verify the image digest and run the Compose localhost check on a clean host.
- Do not mount the Docker socket or add privileged mode to the example.
- Host networking is a Linux requirement for scanning the host loopback; do not
  claim equivalent behavior on unsupported Docker Desktop configurations.

## Rollback and security response

- Do not rewrite an immutable release tag.
- If an artifact is wrong, publish a new patch release and update package
  metadata to the new version.
- If a package is compromised, remove or yank it through the channel's approved
  mechanism, publish a security notice, and preserve the original release
  evidence for review.
- If a registry token is exposed, revoke it, rotate it, review publication
  history, and record the incident.
- Record every rollback and security action with an evidence identifier.

## Clean-install gate

A package channel is not P4-2 complete until a clean environment install passes:

```sh
portensor --version
python3 bench/localhost_gate.py --binary "$(command -v portensor)"
```

The exact per-channel commands and evidence fields are in
[clean-install verification](clean-install-verification.md). A successful local
metadata render is not an install test.
