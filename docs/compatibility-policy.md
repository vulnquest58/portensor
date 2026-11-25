# Compatibility and release policy

Status: **v1.0 policy; P4 review pending**. This document defines the compatibility
contract that v1.0 will ship with. It does not itself authorize a release.

## Versioning

Portensor uses semantic versioning for the project release:

- **Major** versions may make incompatible changes to documented CLI behavior,
  configuration keys, JSON fields, probe/script pack schemas, or the script API.
- **Minor** versions add backward-compatible features, commands, flags, fields,
  and supported platforms.
- **Patch** versions contain backward-compatible fixes, security fixes, and
  documentation corrections.

Before v1.0, these rules are aspirational but not guaranteed. At v1.0 they become
the compatibility baseline.

## CLI

- Existing documented flags and subcommands remain valid for the major version.
- A flag or subcommand may be deprecated only with a warning and release-note
  entry, and must remain functional for at least one minor release before
  removal.
- Exit-code meanings are part of the contract. Adding a new nonzero code for a
  previously successful case is a breaking change.
- Machine-readable output is subject to the JSON and pipeline contracts below;
  human-readable table layout is not byte-stable.

## Configuration

- TOML keys documented in the user guide are part of the contract.
- New optional keys may be added in minor releases. Removed or renamed keys
  require a major release and a migration note.
- Unknown keys are rejected rather than silently ignored, so configuration
  mistakes fail closed.
- CLI values continue to override TOML, and TOML continues to override profile
  or built-in defaults unless a release note explicitly changes precedence.

## JSON and pipeline formats

- Consumers must ignore unknown object fields; additive fields are minor
  changes.
- Removing, renaming, or changing the type of an existing documented field is a
  major change.
- `--json`, `--format json`, JSONL streaming, port-list, host-port, Nmap XML,
  Markdown, HTML, and diff outputs are tested formats. Human-readable terminal
  tables are excluded from byte-level compatibility guarantees.
- Pipeline presets document their own compatibility expectations in
  [pipelines.md](pipelines.md); the same additive-field rule applies.

## Probe, script, and pack formats

- Existing documented probe-pack keys and script manifests remain readable for
  the major version.
- Schema changes that require author action must be introduced with a new
  schema or capability version, not by silently reinterpreting existing data.
- The script capability model and sidecar policy are defined in
  [ADR 0001](decisions/0001-script-capability-model.md) and the
  [script threat model](security/script-threat-model.md).
- Digest verification protects integrity, not safety; pack compatibility does
  not imply trust.

## Platforms and capabilities

| Platform | Status | Raw capability |
|---|---|---|
| Linux x86_64 (glibc) | Supported | IPv4/IPv6 raw SYN, ACK, and OS fingerprinting with `CAP_NET_RAW` |
| Linux x86_64 (musl static) | Supported | Same raw capability as the host kernel and privileges allow |
| Windows x86_64 | Supported | Connect and UDP engines; IPv4 raw SYN/ACK with Npcap and elevation |
| WSL2 | Supported as Linux | Raw behavior follows the WSL kernel and host network path |
| macOS | Not a v1.0 supported target | Raw capability and packaging are not certified |

Unsupported platforms may build from source but are not covered by the release
compatibility guarantee. Platform-specific limitations are documented at the
feature boundary and must fail visibly rather than silently changing scan
semantics.

## Security support

- The latest minor release receives security fixes; older minors are unsupported
  unless a release note states otherwise.
- Critical and high-severity vulnerabilities are handled through private
  reporting and coordinated disclosure as described in [SECURITY.md](../SECURITY.md).
- Security fixes may be backported at maintainer discretion when the affected
  release is still supported.
- A security fix must not be represented as complete until the advisory,
  release notes, and verification instructions are published together.

## Release policy

- Release tags are immutable. A broken artifact is fixed by a follow-up patch
  release, never by rewriting a published tag.
- A release requires a clean worktree, version consistency, workflow lint,
  formatting, clippy, Rust and Python tests, dependency audit, and the release
  preflight in [release-process.md](release-process.md).
- Release assets must have checksums, an SBOM, signatures, and provenance
  attestations as defined in
  [ADR 0005](decisions/0005-release-signing-and-provenance.md).
- The production signing fingerprint and verification commands must be
  published before a release can be treated as a production release.
- No package is published to Homebrew, Scoop, Chocolatey, AUR, Docker, or any
  other registry until P4 is formally cleared and explicit approval is given.
- Release notes identify incompatible changes, deprecations, security fixes, and
  any accepted platform limitations.

## Compatibility evidence

The compatibility gate is not a promise based on inspection alone. Before v1.0:

1. Existing CLI, configuration, JSON, pipeline, and pack fixtures pass in CI.
2. A clean-environment install from every approved package channel passes
   `--version` and the localhost gate.
3. The published supported-platform matrix matches the tested artifacts.
4. The P4 closure checklist records the review and any approved exceptions.
