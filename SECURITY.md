# Security Policy

Portensor is an authorized-use network scanner. Reports and probes can be
misused; only scan systems you own or have explicit written permission to test.

## Supported versions

| Version | Supported |
|---:|---|
| 0.7.x | Yes |
| 0.6.x and older | No |

Security fixes are issued on the latest supported minor release. Pre-release,
forked, or locally modified builds are not supported. Versioning, deprecation,
platform support, and release verification commitments are defined in the
[compatibility and release policy](docs/compatibility-policy.md).

## Reporting a vulnerability

Use GitHub's private vulnerability reporting for this repository:

https://github.com/vulnquest58/portensor/security/advisories/new

Do not open a public issue, discussion, or pull request for a suspected
vulnerability. Include:

- affected version or commit;
- the smallest reproducible command or test case;
- impact, including whether the issue crosses the `--scope` boundary, exposes
  credentials or local files, or corrupts scan output;
- whether you intend to publish, and any requested coordinated-disclosure date.

Do not include live credentials, private keys, customer scan data, or
third-party target details. Redact them before sending. Maintainers will
acknowledge a complete report, investigate, and coordinate disclosure through
the advisory. No bug bounty or payment is promised.

Response targets:

- acknowledge a complete report within 3 business days;
- complete initial triage within 10 business days;
- target a fix or mitigation within 30 days for critical issues and 60 days for
  high-severity issues, with progress updates through the advisory.

These are targets rather than warranties. Complex issues or issues requiring an
upstream fix may take longer; maintainers will document the revised timeline in
the private advisory.

## Scope

Security reports are in scope when they affect:

- scope-guard enforcement or unauthorized probe transmission;
- TLS/SNI, certificate validation, or Host-header handling claims;
- credential, token, key, or report leakage;
- script/WASM/sidecar sandbox escape or capability abuse;
- malicious probe-pack, registry, or lockfile handling;
- release signing, SBOM, provenance, or update verification;
- memory safety or denial of service in the scanner, coordinator, or merge path.

Out of scope:

- third-party service vulnerabilities found during an authorized scan;
- findings produced by the scanner itself (report them to the affected owner);
- a user deliberately running an untrusted native binary or disabling safety
  controls;
- a compromised operating system, kernel, hypervisor, or network path;
- missing hardening that does not cross a documented security boundary;
- social engineering or physical access.

## Security model and limitations

- `--scope` is an authorization boundary, not a discovery boundary. Keep
  targets and scope files accurate; use `--force-out-of-scope` only for
  deliberate, authorized exceptions.
- TLS inspection intentionally accepts self-signed and expired certificates so
  services remain identifiable. `hostname_matches`, `self_signed`, `expired`,
  and `not_yet_valid` are evidence fields, not trust guarantees. `--sni`
  selects a virtual host; it does not add certificate trust.
- Active scripts and sidecars are opt-in. Intrusive scripts require
  `--allow-intrusive`. Review third-party packs before use; a digest verifies
  integrity, not safety.
- The coordinator control plane is unauthenticated unless a token is configured.
  Bind it to loopback or a trusted network, or enable HTTPS with
  `--tls-cert`/`--tls-key`. Tokens are read from the environment or CLI and are
  never written to reports.
- Scan reports can contain target addresses, banners, certificate identities,
  and vulnerability findings. Treat them as sensitive; the scanner does not
  encrypt report files.
- Root/CAP_NET_RAW is required for raw SYN, ACK, and OS probes. Run with the
  least privilege that supports the requested mode.

## Release verification

Release artifacts are signed with GPG and/or cosign, and the release workflow
publishes checksums, an SBOM, and provenance/SBOM attestations. Verify
`dist/SHA256SUMS`, its signature, and the recorded signing identity before use.
The production signing-key fingerprint and custody details are not yet
published; until they are, do not treat a local test signature as a production
release attestation. See [release-process.md](docs/release-process.md),
[ADR 0005](docs/decisions/0005-release-signing-and-provenance.md),
[p4-release-readiness.md](docs/p4-release-readiness.md), and the
[P4 closure checklist](docs/p4-closure-checklist.md) for the current status.

## Disclosure policy

Please allow maintainers reasonable time to investigate and release a fix
before public disclosure. Maintainers will credit reporters who request it and
will not publish private report contents without consent.
