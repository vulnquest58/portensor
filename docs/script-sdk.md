# Script SDK and pack authoring

Portensor executes read-only script checks against ports that the scanner has
already identified. A script receives scan metadata and returns findings (and
optionally a service identification). Scripts never receive sockets from the
scanner; active TCP access is a separate, WASM-only capability.

The working templates are:

- [`sdk/python-metadata`](../sdk/python-metadata) - Python sidecar, metadata
  capability.
- [`sdk/wasm-metadata`](../sdk/wasm-metadata) - WASM module, metadata
  capability, committed as readable WAT and compiled by wasmtime at load time.

## Pack layout

A pack is a directory containing `pack.toml` and its scripts:

```text
my-pack/
  pack.toml
  check.py
  active.wat
```

`pack.toml` contains one or more `[[script]]` entries:

```toml
name = "my-pack"
description = "Example checks"

[[script]]
name = "http-metadata"
description = "Reports interesting HTTP metadata"
category = "discovery"          # discovery | vulnerability | auth | brute | compliance
danger = "safe"                 # safe | intrusive
capabilities = ["metadata"]     # exactly one: metadata | target-tcp
command = ["python3", "check.py"]  # sidecar form
services = ["http", "https"]
ports = [80, 443]               # optional additional filter
timeout_ms = 3000               # 100..30000
```

Use `wasm = "active.wat"` or `wasm = "active.wasm"` instead of `command` for a
WASM script. A script may not set both. `capabilities` defaults to
`["metadata"]`; omit it only when metadata is what you want.

Names must match `[A-Za-z0-9._-]` and be at most 64 characters. Script names
must be unique within a pack; service filters are lowercased, sorted, and
deduplicated.

## Metadata contract

The scanner sends one JSON object on stdin (sidecar) or through the `alloc` and
`run` exports (WASM):

```json
{
  "api": 1,
  "target": "192.0.2.10",
  "port": 443,
  "state": "open",
  "confidence": 0.97,
  "banner": "HTTP/1.1 200 OK",
  "detail": "handshake:ok",
  "evidence": "handshake:ok | banner:nginx",
  "service": {
    "name": "http",
    "product": "nginx",
    "version": "1.25.4",
    "cpe": "cpe:2.3:a:nginx:nginx:1.25.4:*:*:*:*:*:*:*",
    "info": {"server": "nginx"},
    "confidence": 0.95
  },
  "tls": {
    "version": "TLSv1.3",
    "cipher": "TLS13_AES_256_GCM_SHA384",
    "subject": "CN=example.test",
    "issuer": "CN=Example CA",
    "not_before": 1700000000,
    "not_after": 1800000000,
    "days_remaining": 120,
    "expired": false,
    "not_yet_valid": false,
    "self_signed": false,
    "hostname_matches": true,
    "chain_len": 2,
    "signature_algorithm": "sha256WithRSA"
  }
}
```

Fields may be absent. Scripts must validate `api == 1` and must tolerate
missing or unexpected fields. Treat all metadata as untrusted text: cap sizes,
avoid terminal escape sequences, and never execute it.

Sidecars also receive `PORTENSOR_SCRIPT_API=1`, `PORTENSOR_SCRIPT_NAME`,
`PORTENSOR_SCRIPT_PLUGIN`, `PORTENSOR_SCRIPT_CAPABILITY=metadata`,
`PORTENSOR_TARGET`, `PORTENSOR_PORT`, `PATH`, `PYTHONDONTWRITEBYTECODE=1`, and
`PYTHONNOUSERSITE=1`. The ambient environment is cleared.

The script writes one JSON object:

```json
{
  "findings": [
    {
      "id": "example-finding",
      "title": "Short finding title",
      "severity": "medium",
      "confidence": 0.9,
      "description": "Why this matters.",
      "evidence": "service=http port=80",
      "cve": ["CVE-2025-0001"],
      "references": ["https://example.test/advisory"]
    }
  ],
  "service": {
    "name": "http",
    "product": "Example",
    "version": "1.0",
    "info": {"key": "value"},
    "confidence": 0.9
  }
}
```

`findings` and `service` are optional but at least one useful output is
required in practice. IDs must be `[A-Za-z0-9._-]`; severities are `info`,
`low`, `medium`, `high`, and `critical`; confidence must be finite and within
`0.0..=1.0`. At most 16 findings are accepted. Output is rejected, not trusted,
when it violates these limits.

## WASM ABI

A WASM module must export:

- `memory`;
- `alloc(len: i32) -> i32` - return a writable input pointer;
- `run(input_ptr: i32, input_len: i32) -> i64` - return
  `(output_ptr << 32) | output_len`.

The host writes the JSON input into `alloc`'s buffer, calls `run`, reads the
output from `memory`, and validates it as the same JSON output document. A
returned output larger than 64 KiB is rejected. The module has no WASI,
filesystem, environment, clock, or network imports unless it declares the
`target-tcp` capability.

Metadata-only WASM modules may import nothing. They are limited by the standard
fuel and memory ceilings and the script timeout.

## Active capability (`target-tcp`)

Active scripts must be WASM. A sidecar that declares `target-tcp` is rejected
with `active capabilities require wasm`. Active modules may import only:

```text
portensor.script.v1.tcp_connect(port: i32, timeout_ms: i32) -> i32
portensor.script.v1.tcp_read(handle: i32, ptr: i32, len: i32, timeout_ms: i32) -> i32
portensor.script.v1.tcp_write(handle: i32, ptr: i32, len: i32) -> i32
portensor.script.v1.tcp_close(handle: i32) -> i32
```

The host fixes the destination to the scanned target and port. A different port
returns `-2`; a handle other than `0` returns `-8`. Only one connection may be
open at a time. Limits are 10 connection attempts, 5 connections per second,
1 MiB sent and 1 MiB received per invocation, and 5 seconds per operation,
within the script's 30-second maximum timeout. A scope check runs before every
connection.

Return codes: `0` success, `-1` scope denied, `-2` wrong port, `-3` attempt
limit, `-4` rate limit, `-5` no open connection, `-6` I/O error, `-7` byte
limit, `-8` bad request. Active calls emit structured audit events containing
only script, capability, target, port, action, outcome, and error code.

## Safety rules

- Metadata scripts are read-only and must not perform network access. Sidecars
  run under a Linux seccomp network-deny sandbox, have a cleared environment,
  and cannot execute on platforms without verified isolation.
- Do not emit credentials, full banners, payloads, or report contents as
  evidence. Keep evidence short and factual.
- Do not claim a vulnerability from a version alone without stating the
  uncertainty in `confidence` and `description`.
- Keep findings deterministic and bounded. Truncate attacker-controlled text.
- Official packs require at least one positive and one negative fixture per
  script. Run `portensor scripts list <pack> --json` during development.

## Testing

```bash
cargo test --test official_scripts --all-features --locked
cargo test --lib script::tests::sdk_templates_execute --all-features --locked
python3 sdk/python-metadata/check.py <<'JSON'
{"api":1,"target":"192.0.2.10","port":80,"service":{"name":"http"}}
JSON
portensor scripts list sdk/wasm-metadata --json
```

The SDK template test loads both packs and executes their scripts in CI.

## Signing and publishing

v0.8 does not claim publisher signatures. Remote installation is
digest-pinned: the registry index supplies a SHA-256 digest, the archive is
downloaded and verified before extraction, and the installed pack is tracked in
`packs.lock` with name, version, source, digest, path, and kind. `scripts
update` re-resolves the registry entry, verifies the new digest, and atomically
replaces the installed directory; an interrupted update restores the previous
pack on the next operation.

Before publishing a pack:

1. Validate the manifest with `portensor scripts list`.
2. Run every positive and negative fixture.
3. Build a deterministic archive whose single top-level directory is the pack
   name.
4. Generate a SHA-256 digest and publish it in the registry index.
5. Publish the archive and the index over HTTPS; never publish an unverified
   digest.
6. Test install, reinstall with `--force`, update, and offline failure behavior.

Signing, provenance attestations, and publisher identity are future work; do
not describe digest pinning as a signature.
