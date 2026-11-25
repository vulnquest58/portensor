# ADR 0001: Script capability model and sidecar policy

- Status: Accepted for v0.8
- Date: 2026-11-19
- Related: [script threat model](../security/script-threat-model.md)

## Context

Portensor supports sidecar scripts and in-process WASM scripts. Sidecars are
arbitrary local programs; WASM modules run without WASI in a bounded wasmtime
sandbox. The current manifest has a single `danger` field, and the scanner
provides scan metadata on stdin. This is adequate for passive checks but not
for scripts that need to establish additional connections.

The v0.8 scripting platform must add active checks without allowing a pack to
scan arbitrary hosts, bypass scope, exhaust the host, or read scanner secrets.
The existing official pack is a Python sidecar pack, so backward compatibility
and clear migration guidance matter.

## Decision

### 1. Capability classes

Every script declares exactly one capability class:

| Capability | Default | Allowed transport | Behavior |
|---|---|---|---|
| `metadata` | yes | none | Consumes the scan result JSON on stdin and returns findings. It must not open network connections. |
| `target-tcp` | no | WASM only | May open TCP connections only to the scanned host and scanned port that produced the result. |

There is no `network-any` capability in v0.8. A script cannot choose a different
host, resolve a hostname, or access a different port.

### 2. WASM active capability ABI

Active scripts are WASM modules. They import a small, versioned host API from
the `portensor.script.v1` namespace:

- `tcp_connect(port, timeout_ms) -> handle`
- `tcp_read(handle, buffer_ptr, buffer_len, timeout_ms) -> bytes_read`
- `tcp_write(handle, buffer_ptr, buffer_len) -> bytes_written`
- `tcp_close(handle)`

The host fixes the destination from the scan result. There is no hostname or
address argument. The host rejects a port that differs from the input port.
TLS and UDP are out of scope for v1; scripts inspect TLS metadata passively.

Hard limits are enforced by the host, not the module:

- one open connection per script invocation;
- at most 10 connection attempts per invocation;
- at most 5 new connections per second across the script runner;
- 1 MiB written and 1 MiB read per invocation;
- 5 seconds per connection operation, bounded by the existing 30-second script
  timeout;
- no filesystem, environment, clock, or WASI access.

Every connection attempt checks scope before connecting. A scope failure,
rate-limit failure, byte-limit failure, or timeout returns a typed error to the
module and emits a structured audit event. Findings produced after a blocked
operation are discarded.

### 3. Sidecar policy

Sidecars remain metadata-only. They do not receive the host active API and the
scanner never passes credentials or report contents beyond the documented
input object.

Because a sidecar is an arbitrary process, manifest metadata alone cannot
prevent a malicious sidecar from opening sockets. The runtime therefore applies
a network-deny sandbox:

- Linux: install a seccomp filter before `exec` that denies network socket
  creation and connection syscalls; a sidecar-connect fixture must fail with a
  permission error.
- macOS: use a sandbox profile that denies network operations when the
  platform sandbox is available.
- Windows: sidecar execution is disabled in v0.8 unless an AppContainer-based
  network-deny sandbox is implemented and verified. WASM remains available.

A sidecar that cannot be sandboxed is not silently treated as trusted. The
scanner returns an actionable error explaining that the platform lacks verified
sidecar isolation. The official Python pack therefore runs only on platforms
where the sidecar sandbox is verified; WASM packs remain cross-platform.

### 4. Manifest and lockfile

The manifest schema remains backward compatible:

```toml
[[script]]
name = "example"
description = "Checks one exposed service"
category = "compliance"
capabilities = ["metadata"]   # new; defaults to metadata
danger = "safe"
command = ["python3", "check.py", "example"]
services = ["example"]
timeout_ms = 3000
```

Active scripts use `wasm`, not `command`, and must declare
`capabilities = ["target-tcp"]`. A manifest fails to load if it requests
`target-tcp` with a sidecar command or an unknown capability.

`scripts update` is atomic and uses a digest-pinned lockfile at
`<scripts-library>/packs.lock`. The lockfile records pack name, version,
source, SHA-256 digest, and installed relative path. Updates download and
validate into a temporary directory, then replace the installed pack and lock
entry under a lock. An interruption leaves the previous pack and lockfile
usable. Removing a pack removes its lock entry.

### 5. Audit and diagnostics

Active script activity emits structured events at `info` level:
`script`, `capability`, `target`, `port`, `action`, `outcome`, and a bounded
error code. It never logs payloads, banners, credentials, reports, or tokens.
The existing `--log-level`/`PORTENSOR_LOG` controls visibility.

## Consequences

- Active scripts are portable only through WASM; Python sidecars stay passive
  and may be unavailable on platforms without a verified network sandbox.
- Packs that need arbitrary internet access are intentionally unsupported.
- The host API is small enough to test exhaustively and to evolve with a
  version suffix.
- The official pack must gain fixtures and capability declarations before
  release.
- Windows users may need WASM equivalents for checks currently implemented in
  Python; this is documented as a known limitation rather than hidden.

## Validation plan

The v0.8 implementation must include:

- positive and negative fixtures for every official script;
- a WASM active-script fixture that connects only to the scanned port;
- denied tests for a different host, different port, out-of-scope target,
  rate limit, byte limit, and timeout;
- a Linux sidecar-connect fixture that fails under the network-deny sandbox;
- a Windows/macOS capability check asserting sidecars are refused when the
  sandbox is unavailable;
- manifest tests for missing/unknown capabilities and command-plus-active
  combinations;
- atomic-update tests that interrupt download, validation, and replacement;
- a log-capture test asserting no secrets or payload contents appear in audit
  events.

## Alternatives considered

1. **Allow sidecars to open target connections under `danger = "intrusive"`.**
   Rejected: cannot enforce scope or resource limits against an arbitrary
   process, and platform isolation is not portable.
2. **Add WASI networking to WASM.** Rejected: WASI networking is not uniformly
   available and would expose a broader capability surface than the scanner
   needs.
3. **Allow arbitrary hostnames in active scripts.** Rejected: makes scope
   enforcement and SSRF prevention ambiguous. Scripts receive the already
   resolved scan target only.
