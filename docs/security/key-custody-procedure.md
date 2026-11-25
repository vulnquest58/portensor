# Production key custody procedure

Status: **draft; not approved for production use.** No production signing
identity, custodian, backup, or key material is recorded here. P4-1 remains
`external-pending`.

This procedure implements the controls required by the
[production signing policy](production-signing-policy.md). It must be approved
by the project owner and security lead before a production key is used.

## Roles

| Role | Responsibility |
|---|---|
| Project owner | Approves the signing identity, release authorization, and policy |
| Security lead | Approves custody, access, backup, rotation, revocation, and emergency controls |
| Key custodian | Holds or can authorize use of the private key in the approved environment |
| Backup custodian | Holds the approved recovery material or recovery procedure |
| Release engineer | Runs the approved release workflow and publishes signatures |
| Independent verifier | Verifies published artifacts from a separate clean host |

No individual may approve a release, perform the production signature, and be
the sole independent verifier. Conflicts of interest must be recorded and
resolved.

## Custody requirements

- Generate production keys in an approved offline, HSM, or controlled
  environment. Never generate production keys on a public CI runner.
- Keep private key material out of the repository, logs, release notes, issue
  trackers, and ordinary project files.
- Publish only public keys, fingerprints, key identifiers, and verification
  commands.
- Restrict signing access to named custodians and the approved release process.
- Record every access grant, change, and removal in the custody record.
- Use dual control for backup restoration and emergency replacement when
  required by the approved policy.
- Encrypt backups and store them in an approved location separate from the
  production key.
- Test signing access and backup restoration before the first production
  release.
- Retain custody records for the life of the key and the supported release
  window.

## Access control

1. The project owner and security lead approve the custodians in writing.
2. Each custodian receives the minimum access needed for the assigned role.
3. Access is reviewed at least when a custodian changes roles or leaves.
4. Shared credentials are prohibited; use individually attributable access to
   the approved signing service.
5. Failed or unauthorized signing attempts are reviewed by the security lead.
6. Emergency access requires the documented dual-control or break-glass
   procedure and post-event review.

## Backup and recovery

- Back up the private key or recovery material using the approved encrypted
  mechanism.
- Store the backup separately from the primary signing environment.
- Record who can restore the backup and what approvals are required.
- Test recovery in a safe environment before production use.
- Never test recovery by exposing private material to the repository or an
  unapproved host.
- Record the recovery test result, verifier, and date in the evidence register.

## Rotation procedure

1. Open a rotation record identifying the current key, replacement key, reason,
   owner, and planned cutover release.
2. Generate the replacement key under the approved custody controls.
3. Publish the replacement public key and fingerprint through an approved
   channel before the first release that uses it.
4. Verify a signed test artifact from a separate clean host.
5. Keep the previous public key available for historical verification.
6. Sign the first release with the new key and publish the new signature and a
   key transition notice.
7. Retire the previous key after the approved overlap period. Do not rewrite
   existing tags or signatures.
8. Record the rotation result and reviewer approval.

Rotation must also be considered after a custodian change, a security incident,
a suspected exposure, or a change in the approved signing environment.

## Revocation and emergency replacement

1. Declare the affected key compromised or unusable and stop new releases.
2. Revoke the key through the approved registry, keyserver, or custody
   mechanism when applicable.
3. Publish a security notice identifying the affected key fingerprint, releases,
   and verification impact. Never include private material.
4. Invalidate or supersede affected signatures in release metadata where the
   publication channel permits it. Preserve the original immutable tag and
   artifacts for forensic review.
5. Activate the approved backup or emergency replacement key under dual control.
6. Build and publish a new release under a new immutable tag after all release
   checks pass.
7. Record the incident, revocation, replacement, notification, and reviewer
   approval.

Emergency replacement does not authorize reusing a compromised key or rewriting
a published tag.

## Required evidence

Every evidence record must include the requirement ID, evidence identifier,
description, responsible owner, date obtained, verification method, result,
storage reference, and reviewer/approval status. The current register is
[P4-1 evidence register](p4-1-evidence-register.md).

Required production records:

- Approved custody and access-control record.
- Production public fingerprint and verification commands.
- Backup/recovery test result.
- Rotation or revocation drill record, redacted for sensitive details.
- Named owner, security approval, and date.
- Clean-host verification transcript for a signed release.

Local signatures from `make p4-local-check` use ephemeral test keys and are
tooling evidence only. They cannot satisfy these production records.
