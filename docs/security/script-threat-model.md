# Script execution threat model

This document supports [ADR 0001](../decisions/0001-script-capability-model.md).
It is the security baseline for the v0.8 scripting platform. Update it when the
capability ABI, sandbox, marketplace, or lockfile changes.

## Scope and assets

In scope:

- the scanner process, its script runner, and child sidecars;
- WASM modules and active host capabilities;
- local pack installation, lockfiles, and remote marketplace updates;
- scan metadata, findings, scope rules, coordinator tokens, and reports.

Protected assets:

- authorization boundaries defined by `--scope`;
- target hosts and the local network;
- scanner and coordinator credentials;
- local files, environment variables, and configuration;
- report and finding integrity;
- availability of the scanning host (CPU, memory, file descriptors, network).

Out of scope:

- a user deliberately running an untrusted native binary outside portensor;
- compromised operating-system or kernel;
- malicious registry infrastructure with a valid user-supplied digest that the
  user explicitly trusts;
- third-party service vulnerabilities discovered by an authorized scan.

## Trust boundaries

1. **Scanner to WASM**: WASM has no WASI; only the versioned host ABI crosses
   the boundary. The host validates every call.
2. **Scanner to sidecar**: stdin JSON and environment variables are inputs.
   The sidecar is untrusted code and must run under the network-deny sandbox.
3. **Scanner to registry**: remote pack downloads cross an untrusted network.
   Digests are mandatory; manifests are validated before installation.
4. **Scanner to target**: active script connections cross the authorization
   boundary and must pass scope and port checks.
5. **Scanner to logs**: logs are a potential exfiltration or secret-leak path.

## Threats and controls

| Threat | Impact | Control |
|---|---|---|
| Script scans a host outside scope | Unauthorized traffic, legal/reputational damage | Host broker accepts only the scanned host:port; `--scope` is checked before `connect`; no hostname or arbitrary address arguments. |
| Script scans another port on the same host | Scope bypass or unexpected service interaction | Host rejects a port different from the input result port. |
| Script opens many connections or floods a target | DoS, detection, rate-limit exhaustion | One connection at a time, 10 attempts per invocation, 5 connections/second, existing global scan rate, and hard timeouts. |
| Script sends or receives unbounded data | Memory exhaustion or data exfiltration | 1 MiB each direction per invocation; host truncates/rejects; no unbounded read API. |
| Script runs forever | Resource exhaustion | WASM fuel, memory/table limits, existing 30-second script timeout, 5-second per-operation timeout. |
| Sidecar opens arbitrary network connections | Scope bypass or data exfiltration | Linux seccomp network-deny sandbox; macOS and Windows sidecars disabled until equivalent isolation exists. Sidecars never receive the active host ABI. |
| Malicious manifest path traversal | Local file overwrite | Existing archive/path validation; install into a temporary directory; reject absolute paths, `..`, links, and device nodes. |
| Lockfile substitution or rollback | Execution of unexpected pack | Lockfile pins name, version, source, digest, and path; updates verify before atomic replacement. |
| Registry compromise | Malicious code execution | Mandatory SHA-256 digest, manifest validation, explicit install/update; signatures are a future layer, not a v0.8 claim. |
| Token or report leakage in logs | Credential exposure | Audit events contain only script/capability/target/port/action/outcome/error code; payloads, banners, tokens, and reports are never logged. |
| Finding injection into terminal/report | Terminal escape or report corruption | Existing sanitization and schema validation; active findings use the same validated finding path. |
| Pack consumes excessive disk or entries | Local denial of service | Existing archive/expanded size and entry caps; lockfile and temporary directory cleanup. |
| Sidecar inherits sensitive environment | Secret exposure | Pass only documented variables; do not forward the ambient environment; continue validating `PORTENSOR_SCRIPT_API`. |
| Sandbox unavailable or fails open | False assurance | Fail closed for sidecars: refuse to execute when the platform sandbox is unavailable; report a clear error. WASM remains available. |
| Active script output is trusted as a service identity | False attribution/advisory poisoning | Validate and confidence-gate service attribution; preserve existing evidence merge rules. |

## Sidecar isolation status

The required behavior is fail-closed:

- Linux: seccomp filter denies network socket creation/connection before
  `exec`; a fixture must prove denial.
- macOS: no verified network-deny sandbox in v0.8; sidecars are refused and the
  error points to WASM.
- Windows: no verified AppContainer sandbox in v0.8; sidecars are refused and
  the error points to WASM.

## Residual risks

- Seccomp and sandbox policies may be incomplete on unusual kernels or
  platforms. Tests cover the documented Linux runner; unsupported systems fail
  closed rather than silently weakening isolation.
- A pack can still consume CPU within its WASM fuel budget and script timeout.
- Digest pinning proves integrity, not publisher identity; signing and
  provenance are future work.
- The scanner cannot prevent a user from manually executing a downloaded
  sidecar outside portensor.
- A sidecar that is permitted by the sandbox can still inspect the metadata it
  receives. Packs should be installed only from trusted sources.

## Validation checklist

- [ ] Out-of-scope target is denied and no packet is sent.
- [ ] Different-port connection is denied.
- [ ] Connection count, rate, byte, and timeout limits are enforced.
- [ ] WASM cannot import filesystem, environment, clock, or WASI networking.
- [ ] Linux sidecar connect fixture fails under the sandbox.
- [ ] Unsupported-platform sidecar execution fails closed.
- [ ] Interrupted `scripts update` leaves the previous pack and lockfile usable.
- [ ] Logs contain no tokens, payloads, banners, or report contents.
- [ ] Malformed findings and manifests are rejected without panic.
- [ ] Existing scope, merge, and accuracy gates remain green.

## Review triggers

Review this model when any of the following changes:

- adding a new host capability or protocol;
- relaxing a byte, connection, rate, or timeout limit;
- adding pack signing or a new registry;
- supporting a new sidecar platform or sandbox mechanism;
- changing scope resolution or target representation.
