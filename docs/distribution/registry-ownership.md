# Package registry ownership and maintainer evidence

Status: **no external ownership confirmed.** P4-2 remains `blocked`.

This document defines the proof required before any package is published. It
does not assert account control, create credentials, or contact a registry. The
GitHub remote identifies the intended project namespace only; it is not proof of
control over any distribution account.

## Required channels

| Channel | Namespace or package | Owner evidence required | Account-control evidence | Current state |
|---|---|---|---|---|
| Homebrew | Tap owner and `portensor` formula namespace | Tap owner authorization; formula review approval | Tap push permission; 2FA; recovery owner | Not provided |
| Scoop | Bucket owner and `portensor` manifest namespace | Bucket owner authorization; manifest review approval | Bucket push permission; 2FA; recovery owner | Not provided |
| Chocolatey | Community package `portensor` | Maintainer/package-owner confirmation | Package ownership; 2FA; recovery owner | Not provided |
| AUR | `portensor` package | Maintainer account confirmation | AUR account control; SSH key ownership; recovery process | Not provided |
| GHCR | `ghcr.io/vulnquest58/portensor` | Organization/package owner authorization | Package write permission; organization 2FA policy | Not provided |
| Docker Hub / Compose | Docker Hub namespace and image repository | Namespace owner authorization | Repository write permission; 2FA; recovery owner | Not provided |

Docker Compose is a distribution example around the published container image;
its acceptance depends on the GHCR or Docker Hub ownership evidence.

Use the [P4-2 external evidence intake and approval packet](p4-2-external-evidence-intake.md)
to record ownership, account control, token decisions, clean installs, and the
published image digest. The packet starts blank and does not satisfy any
requirement by itself.

## Required owner submission

For each approved channel, the project owner must provide:

1. Channel and exact namespace, package name, or tap/bucket URL.
2. Named accountable owner and maintainer.
3. Written confirmation that the owner can publish and review the package.
4. Account-control evidence: 2FA enabled, recovery owner or mechanism, and
   least-privilege publishing access.
5. Publishing-token plan: token scope, storage location, rotation owner, and
   revocation method. Do not submit the token or secret.
6. Maintainer responsibility acceptance, including security response and
   release-update duties.
7. Evidence identifier, date, reviewer, and storage reference.

Private account details must be redacted. Do not commit 2FA seeds, recovery
codes, API tokens, SSH private keys, cookies, or session data.

## Maintainer responsibilities

Each channel owner must:

- Publish only artifacts from an approved immutable release tag.
- Verify the release archive checksum before updating package metadata.
- Keep package definitions aligned with the supported platform matrix.
- Respond to package-specific security or integrity reports.
- Remove or yank a compromised package without rewriting the immutable release.
- Record ownership changes and credential rotations.
- Avoid automation that publishes without a reviewed release decision.

The full process is in
[package maintenance policy](package-maintenance-policy.md).

## External evidence still missing

- Homebrew tap and formula ownership confirmation.
- Scoop bucket and manifest ownership confirmation.
- Chocolatey package ownership and maintainer confirmation.
- AUR account, SSH key, and recovery confirmation.
- GHCR package write and organization-policy confirmation.
- Docker Hub namespace and image-repository control confirmation.
- Account 2FA, recovery, and least-privilege evidence for every approved
  channel.
- Clean-environment install results from
  [clean-install verification](clean-install-verification.md).

No channel is approved until all its evidence is reviewed and recorded in
`docs/p4-closure-checklist.md`. Local package metadata generation does not
satisfy this gate.
