# P4 release readiness

Status: **in progress; not complete**. This phase is an external-evidence gate,
not a code milestone. The local controls are implemented and reproducible, but
production key custody, registry ownership, clean-runner execution, and the
external OT/ICS assessment cannot be verified from this development host.

Release candidate context: `1.0.0-rc.1` at commit
`b543303da8923d0ba259a919c038a6bb2880380b` is prepared for validation only. It
is not tagged, published, production-signed, or attested. The
[RC attestation record](releases/1.0.0-rc.1-attestation.md) records that status.
P4-1 through P4-6 remain open; final `1.0.0` promotion is conditional on closure
or formal risk acceptance.

Final `1.0.0` local artifacts and the final CycloneDX SBOM were prepared on
2026-11-27. They are not tagged, published, production-signed, or attested. The
[1.0.0 attestation record](releases/1.0.0-attestation.md) records that state, and
the [risk acceptance](releases/1.0.0-risk-acceptance.md) is an unapproved draft.
This finalization does not change any P4 status.

No private keys, registry tokens, VPN credentials, or account secrets are stored
in the repository.

## Closure checklist

The authoritative requirement-by-requirement record is
[`p4-closure-checklist.md`](p4-closure-checklist.md), with a machine-readable
counterpart in
[`p4-closure-evidence.json`](p4-closure-evidence.json). The local evidence audit
is in [`p4-evidence-audit.md`](p4-evidence-audit.md). The checklist separates
local evidence from the external records still required for P4 sign-off. This
document provides the supporting implementation detail.

## Exit criteria

| Requirement | Local implementation | Verified evidence | Remaining external evidence | Status |
|---|---|---|---|---|
| Release signing keys | GPG and cosign signing/verification workflows; unsigned releases now fail | Historical 0.7.0 local tooling: ephemeral GPG and cosign test keys signed and verified a copy of `dist/SHA256SUMS`; public key derivation checked | Production key generation, custody, public fingerprint, rotation/revocation, and signing from controlled environments | blocked |
| Registry ownership | Ownership checklist below; local Homebrew/Scoop/Chocolatey/AUR/Compose templates, `make package-check`, blank machine-readable evidence packet, and `make p4-external-evidence-check` | Metadata is generated only from checksum-verified local archives; JSON/XML/YAML parsing and PKGBUILD bash syntax pass; Chocolatey pack and archive extraction pass; external evidence validator and tests pass locally; no account control is asserted | Owner confirmation and 2FA/account control for every distribution channel, channel approvals, and clean-environment install results | blocked |
| Clean runners | GitHub-hosted `ubuntu-24.04` and `windows-2022` release jobs; actions pinned to commit SHAs; runner limits in [`release-runners.md`](release-runners.md) | Workflow lint passes; release jobs log `ImageOS` and `ImageVersion` | A clean release run recording resolved `ImageVersion` values and producing and verifying signed assets, SBOM, and attestations | blocked |
| SBOM and provenance | CycloneDX generation, checksum coverage, artifact attestations, and SBOM attestation in the release workflow; procedure in [`sbom.md`](sbom.md) | RC CycloneDX 1.5 SBOM with 280 components in `dist/portensor-1.0.0-rc.1.cdx.json`; historical 0.7.0 local tooling SBOM retained; `SHA256SUMS` covers both archives and the RC SBOM | Actual GitHub OIDC attestation and external verification from a clean environment | in progress |
| OT/ICS assessment | Assessment inputs documented; no local substitute for the external review | Not applicable | Approved partner, legal scope, budget, schedule, and final report | blocked |
| v1.0 security and documentation | Private reporting/disclosure policy, ADRs, security model, compatibility policy, and release policy | `SECURITY.md`, ADRs 0001–0005, [`compatibility-policy.md`](compatibility-policy.md), and [`release-process.md`](release-process.md) are present | Documentation/security review sign-off and resolution of findings | in progress |
| Authorized live validation | Scope-guarded HTB Garfield, RedEye, Unclaimed, and Scaffold runs | Garfield: 22/22 confirmed TCP ports via two-pass connect discovery. RedEye v2: 4/4 exact nmap/rayscan match with explicit SNI and endpoint-aware mixed OS. Unclaimed: 13/13 via two-pass recovery with HTTP/WinRM/SMB evidence. Scaffold: 30/30 discovered ports confirmed on a Windows domain controller with anonymous LDAP rootDSE, SMB signing, and certificate evidence; high-rate nmap yielded an invalid all-filtered result and a slower pass timed out. See [`bench/htb/README.md`](../bench/htb/README.md), [`redeye.md`](../bench/htb/redeye.md), [`unclaimed.md`](../bench/htb/unclaimed.md), and [`scaffold.md`](../bench/htb/scaffold.md) | Additional machines if required; native Windows Npcap raw runtime | in progress |
| PingPong RC validation | Raw IPv4 SYN over OpenVPN `tun0`, RST cleanup, and cooldown-safe validation script | 15/15 cooldown inventory; latest scripted run 6 open + 9 silent; latest nmap full run 18 open; full-range raw SYN still 1/15 known-open. See [PingPong evidence](../bench/v1.0-rc/pingpong-evidence/README.md) | Native Windows Npcap raw-SYN verification or explicit waiver; further target-state validation if required | local-ready |
| Windows Npcap raw runtime | Native raw path not installable here | WSL host-NAT raw SYN failed and produced a false tarpit classification | Install Npcap on a controlled Windows runner and repeat raw SYN/OS checks | blocked |

## Registry ownership

These channels are required by v1.0. P4 needs confirmed ownership before any
publishing account or token is used. The Git remote is
`github.com/vulnquest58/rayscan`; that proves the intended namespace, not control
of the account or each registry.

| Channel | Namespace to confirm | Required proof | Status |
|---|---|---|---|
| Homebrew | Tap owner and formula namespace | Owner can push the tap and approve the formula | pending |
| Scoop | Bucket owner and manifest namespace | Owner can push the bucket and approve the manifest | pending |
| Chocolatey | Community package maintainer | Maintainer account controls the package and 2FA | pending |
| AUR | AUR account and SSH key | Account controls the package and recovery key | pending |
| GitHub Container Registry | `ghcr.io/vulnquest58` | Organization/repository package permissions | pending |
| Docker Hub / Compose | Docker Hub namespace | Account controls the repository and 2FA | pending |

Do not create tokens for these channels until ownership and the release key
custody plan are approved. Store CI credentials only in the repository or
organization secret store.

## Local package metadata verification

`make package-check` renders draft metadata for Homebrew, Scoop, Chocolatey,
AUR, and Docker Compose from the archives listed in `dist/SHA256SUMS`. It
verifies archive checksums and required file layout, parses JSON, XML, and YAML,
and runs `bash -n`, Ruby, or PowerShell syntax checks when those tools are
available. Missing validators are reported as skipped.

This local output is not registry ownership, publication, or a clean install.
The required external evidence and commands are in
[registry ownership](distribution/registry-ownership.md),
[package maintenance policy](distribution/package-maintenance-policy.md), and
[clean-install verification](distribution/clean-install-verification.md). Use
the [external evidence intake packet](distribution/p4-2-external-evidence-intake.md)
to record completed owner and approval decisions. P4-2 remains `blocked` until
that external evidence is reviewed.

## Release workflow safeguards

The release workflow now:

1. Generates a CycloneDX 1.5 SBOM for all targets with `cargo-cyclonedx` pinned
   to `0.5.10`, then validates the JSON format and component count.
2. Fails if the SBOM is missing or absent from `SHA256SUMS`, then runs
   `sha256sum -c SHA256SUMS`.
3. Fails if neither `GPG_PRIVATE_KEY` nor `COSIGN_PRIVATE_KEY` is configured.
4. Verifies the signature it just created and exports the public key.
5. Creates GitHub build-provenance and SBOM attestations using OIDC.
6. Publishes the signatures, public keys, SBOM, checksums, and archives
   together.

The cosign installer is pinned to `v3.1.4`. The GPG and cosign private keys are
written only in the runner's temporary/ephemeral environment. The cosign private
key directory uses `umask 077` and is removed by a trap. All GitHub Actions are
pinned to full commit SHAs; runner-image limits are documented in
[`release-runners.md`](release-runners.md).

## Reproduce local evidence

```bash
make p4-local-check
make package-check
python3 bench/htb/analyze.py
python3 bench/htb/analyze_redeye.py
```

`make p4-local-check` creates an ephemeral GPG key and an ephemeral cosign key
pair, regenerates the CycloneDX SBOM, rebuilds `dist/SHA256SUMS` over both
archives and the SBOM, verifies the manifest, then signs a copy of the manifest
and verifies both signatures. It writes:

- `bench/p4/p4-local-check.txt` — fingerprints, checksum coverage, and
  verification results only.
- `bench/p4/portensor-<version>.cdx.json` — generated SBOM when
  `make p4-local-check` is run.

The historical `bench/p4/rayscan-0.7.0.cdx.json` is retained as local tooling
evidence. The current RC release SBOM is
`dist/portensor-1.0.0-rc.1.cdx.json`. The ephemeral private keys are deleted
before the check exits. The recorded GPG fingerprint belongs to a throwaway key
and must not be used for a release. See [`sbom.md`](sbom.md) for SBOM generation
and verification details.

`make package-check` writes local package definitions under `dist/packages/`
and records static validation in `bench/p4/p4-package-check.txt`. Chocolatey
pack and archive extraction evidence are stored separately. None of this
substitutes for registry ownership or clean-install acceptance.

## Required approvals before P4 can complete

1. **Signing custody:** approve the
   [production signing policy](security/production-signing-policy.md) and
   [key custody procedure](security/key-custody-procedure.md), generate the
   production key in an approved offline/HSM/controlled environment, publish
   its fingerprint and
   [verification instructions](security/release-signature-verification.md),
   configure the CI secret, and verify a signed test artifact from a clean
   machine. Never share the private key.
2. **Registry control:** confirm ownership, 2FA, recovery, and least-privilege
   publishing access for each row in the registry table.
3. **Clean-runner proof:** with explicit authorization to run a release dry run,
   verify the archives, SBOM, GPG/cosign signature, build provenance, and SBOM
   attestation on a fresh runner and a separate verification host.
4. **OT/ICS assessment:** approve the assessor, legal scope, rules of engagement,
   budget, schedule, and remediation owner; then complete the report with no
   unresolved critical/high findings.
5. **Additional live validation:** RedEye v2 exercises explicit SNI and
   endpoint-aware OS handling on a mixed Linux-edge/Windows-ADFS target with an
   exact four-port match. A further HTB account/API session is required if more
   machines are needed. Install Npcap on a controlled Windows host for the
   raw-SYN runtime check, or record an explicit v1.0 waiver.
6. **Documentation and security review:** review `SECURITY.md`, the ADRs, the
   compatibility/release policies, and this checklist; resolve findings and
   record the approvals in [`p4-closure-checklist.md`](p4-closure-checklist.md).

External evidence ownership and required review steps are tracked in
[`p4-external-evidence-owners.md`](p4-external-evidence-owners.md), with current
gaps in [`p4-external-blockers.md`](p4-external-blockers.md) and the decision
state in [`p4-signoff-readiness.md`](p4-signoff-readiness.md). These are
coordination records only; no external evidence has been obtained and no status
has changed.

Until all six are evidenced, P4 remains open and final `1.0.0` promotion is
blocked. The `1.0.0-rc.1` candidate is validation-only. Local tooling tests must
not be represented as production key custody or registry ownership.
