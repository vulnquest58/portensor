# P4-1 secure evidence submission procedure

Status: **intake procedure ready; no production evidence received.** P4-1
remains `external-pending`.

This procedure defines how the authorized project owner or delegated security
lead submits production signing evidence for review. It does not create a
production identity and must not be used to generate, transfer, or store
private key material in this repository.

## Authorization boundary

Only the project owner, or a delegate named in a written project-owner
authorization, may initiate a P4-1 evidence submission. Do not contact key
custodians, registries, assessors, or other external parties until the project
owner authorizes that contact.

The submission must not contain:

- GPG or cosign private keys, key backups, recovery shares, or HSM export data.
- Passwords, access tokens, recovery codes, 2FA seeds, or cloud credentials.
- Unredacted custodian personal data that is not required for review.
- Claims that cannot be tied to a verifiable record.

Public keys, fingerprints, signatures, checksums, SBOMs, attestation references,
and redacted procedural evidence are acceptable.

## Secure intake channels

- Submit private or restricted custody material only through the project
  owner's approved out-of-band secure channel. Do not use public issues, pull
  requests, chat, or committed files.
- Public evidence may be referenced by URL or submitted as a public artifact.
  Record the URL, retrieval date, and SHA-256 digest of each downloaded evidence
  file.
- The reviewer must confirm the submission channel and submitter identity
  independently. A message signed with the same key being introduced is not
  sufficient identity proof.
- Store submitted evidence in the owner-approved access-controlled location.
  Repository documentation records only evidence identifiers and references,
  never secrets.

## Required submission package

### A. Authorization and identity (P4-1-E1)

- Written project-owner authorization naming the submitter, signer, and
  accountable owner.
- Selected production signing technology: GPG, cosign, or both, with the
  owner's explicit decision.
- Approval of the
  [production signing policy](production-signing-policy.md) and
  [key custody procedure](key-custody-procedure.md), including approver name,
  role, date, and evidence reference.
- Public signer identity and ownership statement.
- Named key custodian, backup custodian, and security lead.

### B. Public signing identity (P4-1-E3)

- ASCII-armored GPG public key and/or cosign public key.
- Full fingerprint, key identifier, algorithm, creation date, and expiry.
- Approved publication location for the public key and fingerprint.
- Out-of-band fingerprint confirmation record.
- Revocation certificate status, without submitting private recovery material.
- Signed challenge or equivalent proof that the submitter controls the public
  key, if required by the reviewer.

The reviewer validates the key with an isolated temporary keyring:

```sh
export GNUPGHOME="$(mktemp -d)"
chmod 700 "$GNUPGHOME"
gpg --import /path/to/public-key.asc
gpg --fingerprint --with-colons
gpg --check-sigs
gpg --export-ownertrust
```

The fingerprint must match the owner-approved record through an independent
channel. Never import an unapproved production key into a permanent reviewer
keyring.

### C. Custody evidence (P4-1-E2, P4-1-E4, P4-1-E5)

- Custody attestation signed by the accountable owner and security lead.
- Key-generation environment description: offline, HSM, or controlled service.
- Access-control record: named roles, least privilege, dual control, and
  separation of duties.
- Backup/recovery design and a successful restoration test record, redacted.
- Rotation and revocation procedure approval, plus a drill or rehearsal record.
- Emergency contact and break-glass procedure, redacted.
- Confirmation that private material is absent from repositories, logs, chat,
  issue trackers, and CI output.

A custody attestation is evidence of process, not proof of private-key secrecy.
The reviewer evaluates the controls and records limitations.

### D. Production-signed release (P4-1-E3, P4-1-E6)

- Immutable release tag and source commit.
- Platform archives and CycloneDX SBOM.
- `SHA256SUMS` covering every archive and the SBOM.
- GPG detached signature and/or cosign bundle over `SHA256SUMS`.
- Public key used for the signature.
- GitHub build-provenance and SBOM attestation references.
- Publication URLs and retrieval dates.

### E. Clean-host verification (P4-1-E6)

- Completed transcript from the
  [clean-host verification procedure](p4-1-clean-host-verification.md).
- Verifier identity, host isolation description, OS image, tool versions, date,
  commands, outputs, and artifact digests.
- Confirmation that the verification host was not used to build or sign the
  release.
- Evidence storage reference and reviewer approval.

### F. Formal acceptance (P4-1-E7)

- Independent reviewer recommendation.
- Project-owner acceptance of residual risk.
- Security-lead approval.
- Date and evidence version reviewed.

## Evidence record fields

For every submitted item, the reviewer records:

| Field | Requirement |
|---|---|
| Requirement ID | P4-1 |
| Evidence identifier | Stable ID from the [evidence register](p4-1-evidence-register.md) |
| Description | What the evidence proves |
| Issuing organization or responsible owner | Accountable submitter |
| Date obtained | Date the reviewer received the evidence |
| Verification method | Command, independent comparison, or document review |
| Verification result | Pass, fail, or limitation |
| Storage reference | Access-controlled location or public URL plus SHA-256 |
| Reviewer and approval status | Named reviewer and approval state |

## Review sequence

1. Record receipt without changing any P4 status.
2. Confirm submitter authorization and independent identity.
3. Scan the package for prohibited private material or credentials without
   reproducing any secret.
4. Verify the public key fingerprint out of band.
5. Review custody, backup, rotation, and revocation evidence against the policy.
6. Verify the production-signed release and clean-host transcript.
7. Record results and limitations in the evidence register.
8. Obtain independent reviewer, project-owner, and security-lead decisions.
9. Change P4-1 status only after every acceptance criterion is satisfied and
   formally approved.

## Rejection and stop conditions

Stop the submission and do not update P4-1 when:

- Authorization or submitter identity cannot be verified.
- Private key material, recovery shares, credentials, or unredacted secrets are
  included.
- The fingerprint does not match the approved public identity.
- The key is expired, revoked, or not approved for production use.
- Custody evidence is missing, internally inconsistent, or lacks separation of
  duties.
- The signed release is incomplete, uses ephemeral keys, or lacks SBOM coverage.
- Clean-host verification was performed on the build/signing host or is absent.
- Required approvals are absent.

Report prohibited material without copying it into the repository. Follow the
private reporting channel in `SECURITY.md` for a suspected key compromise.
