# Release and attestation records

Status: **records only; no record closes P4 or authorizes a final release.**

These records document what was built and committed, and whether it was signed,
attested, or published. They must not claim production signatures, registry
ownership, clean-runner evidence, independent assessment, or formal approval
that does not exist.

| Version | Commit | Status | Record |
|---|---|---|---|
| `1.0.0` | `180b93dc9b9052e3e4d2643eaac37fc7a75316a7` | Local finalization; not tagged, published, production-signed, or attested; P4 open; risk acceptance draft not approved | [1.0.0 record](1.0.0-attestation.md), [risk acceptance draft](1.0.0-risk-acceptance.md) |
| `1.0.0-rc.1` | `b543303da8923d0ba259a919c038a6bb2880380b` | Release candidate; not tagged, published, production-signed, or attested; P4 open | [1.0.0-rc.1 record](1.0.0-rc.1-attestation.md) |

## Recording rules

1. Record the exact version, source commit, artifact digests, and release date.
2. State whether a tag, publication, production signature, and GitHub OIDC
   attestation exist. Absence must be explicit.
3. Link the authoritative P4 status. A release record is not a P4 closure or
   risk acceptance.
4. Final `1.0.0` promotion requires P4 closure with formal approval or a signed
   risk acceptance naming the owner, scope, affected artifacts, and expiry.
5. Never record private keys, registry credentials, recovery codes, or other
   secrets in a release record.
