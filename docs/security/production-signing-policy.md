# Production signing policy

Status: **draft; not approved for production use.** P4-1 remains
`external-pending`. No production signing identity, key, fingerprint, custodian,
or approval is recorded here.

This policy defines the production trust architecture for official Portensor
release artifacts. It does not claim that the architecture is deployed.

## Scope

This policy applies to artifacts published as official Portensor releases:

- Linux and Windows platform archives.
- `SHA256SUMS`.
- CycloneDX SBOM.
- Public verification keys and signature bundles.
- GitHub build-provenance and SBOM attestations.

Local development builds, ephemeral test keys, forks, and unreleased tags are
out of scope and must never be represented as production releases.

## Signing architecture

The release manifest is the signing boundary:

1. Build the platform archives and CycloneDX SBOM.
2. Generate `SHA256SUMS` covering every archive and the SBOM.
3. Verify the checksum manifest before signing.
4. Sign `SHA256SUMS`, not each artifact independently.
5. Publish the public verification key, signature, SBOM, and checksums together.
6. Create GitHub OIDC build-provenance and SBOM attestations for the release
   artifacts.

GPG detached signatures and cosign blob signatures are both supported by the
release workflow. At least one approved production signing identity is required.
The project owner must decide whether both are mandatory before the first
production release; that decision is not recorded yet.

The GitHub OIDC identity attests the build workflow and source revision. It is
not a substitute for the production signing identity and does not establish key
custody.

## Identity and ownership

| Item | Required value | Current state |
|---|---|---|
| Production signing technology | GPG and/or cosign, approved by project owner | Tooling present; policy decision pending |
| Signing identity | Organization or accountable maintainer identity | Not selected |
| Key owner | Named accountable owner | Not assigned |
| Custodian | Authorized holder or signing service operator | Not assigned |
| Backup custodian | Authorized recovery holder | Not assigned |
| Public identity reference | Key fingerprint and published verification location | Not published |
| Approval authority | Project owner and security lead | Not recorded |

Role assignments and evidence are tracked in
[the P4 external evidence ownership matrix](../p4-external-evidence-owners.md).
Names must be recorded through the approved governance process, not invented in
this repository.

## Trust boundaries

- Production private material is never committed, logged, or stored in ordinary
  project files.
- Local test keys created by `make p4-local-check` are ephemeral and are not
  production identities.
- GitHub Actions secrets hold only the production signing material in the
  approved secret store; documentation records references, not secret values.
- The verification host trusts the published public key/fingerprint and the
  published release metadata, not the build host.
- A checksum without a valid signature is not sufficient production evidence.
- A signature without checksum coverage of the SBOM and archives is incomplete.

## Custody and access

The detailed operational procedure is in
[key custody procedure](key-custody-procedure.md). At minimum:

- Generate production keys in an approved offline, HSM, or controlled
  environment.
- Restrict signing use to the named release process and authorized custodians.
- Require separation between release approval, signing, and independent
  verification.
- Maintain an approved encrypted backup or recovery mechanism.
- Audit access grants and removals.
- Never share private keys, recovery material, or credentials through the
  repository, issues, chat, or documentation.

## Rotation and revocation

The rotation and revocation steps are defined in
[key custody procedure](key-custody-procedure.md). Rotation and revocation must
be approved before first production use. Published tags and existing signatures
are immutable; a compromised key requires revocation, notification, and a new
release under a new tag, not history rewriting.

## Verification

Users and release reviewers must follow
[release signature verification](release-signature-verification.md). A
production release is not P4-1 complete until an independent clean host verifies:

- The checksum manifest.
- The GPG and/or cosign signature.
- The SBOM checksum entry.
- The artifact-to-SBOM association.
- The GitHub attestations, where applicable.

## Evidence required for closure

P4-1 closure requires reviewable records for:

1. Approved signing architecture and identity.
2. Production key custody and access-control attestation.
3. Public key/fingerprint and verification instructions.
4. Backup/recovery test.
5. Rotation and revocation approval or exercised drill.
6. Clean-host signature verification transcript.
7. Reviewer acceptance and formal approval.

Evidence fields and current status are tracked in the
[P4-1 evidence register](p4-1-evidence-register.md). The authorized intake
process is the
[secure evidence submission procedure](p4-1-evidence-submission.md); independent
verification follows the
[clean-host procedure](p4-1-clean-host-verification.md). The current blocked
decision is in the [P4-1 acceptance report](p4-1-acceptance-report.md). Local
tooling results are marked separately and do not satisfy production custody.

## Approval

No approval is recorded. The following fields must be completed only from
reviewable evidence:

| Role | Name | Decision | Date | Evidence reviewed |
|---|---|---|---|---|
| Project owner |  |  |  |  |
| Security lead |  |  |  |  |
| Release owner |  |  |  |  |
