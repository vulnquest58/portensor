# Probe Engine

rayscan identifies services with a declarative probe engine. Packs are TOML
files; probes are data, not code. This keeps probe execution deterministic,
auditable, and safe to embed in the binary, unlike service-detection systems
that execute embedded scripts.

The engine supersedes the v1 single-step pack format while remaining backward
compatible: a pack written for the old `send`/`expect` fields still loads.

## Execution model

1. A scan finishes discovery and verification, producing open TCP results.
2. For each open result, probes are considered in load order (user packs
   first, built-in packs after). A probe with `ports` only runs on those
   ports; an empty list means any port.
3. The first probe that matches a port wins. Remaining probes are not tried
   for that result.
4. Afterwards the match is merged into the result and exposed through
   `service`, `service.cpe`, `service.info`, `banner`, `detail`, and
   `evidence`.

A probe runs in one of two modes:

- **Passive** — no step carries a payload. The probe matches against the
  banner already captured by the scanner. No new connection is opened.
- **Active** — at least one step carries a payload. The probe reconnects and
  runs every step sequentially over that one TCP connection.

Active probes also declare their transport: plaintext by default, or TLS with
`tls = true`. TLS probes perform their own handshake (certificate verification
is intentionally disabled, matching the scanner's inspection policy) and
advertise `http/1.1` via ALPN. When TLS inspection succeeded on a port, active
plaintext probes on that port are skipped so HTTPS endpoints never receive
plaintext payloads; TLS probes still run.

Only open TCP results are probed. UDP results (`udp:*`) and closed/filtered
ports are skipped.

## Step semantics

Steps execute in order. For each step:

1. If it has a payload, send it.
2. Read until one of: `read_until` matches, EOF, the idle window (250 ms)
   passes, the step timeout expires, or the 16 KiB response cap is reached.
3. If the step declares an expectation and the response does not satisfy it,
   the probe fails immediately. Earlier responses are discarded.

A step without a payload reads whatever the server sends first, which handles
protocols with a server greeting (VNC, some industrial protocols). A step
without an expectation is accepted as-is and contributes nothing to
corroboration.

Responses from all steps are appended to one transcript (separated by
newlines). Extraction patterns always run over the whole transcript.

## Pack schema

Top level:

| Key | Type | Required | Notes |
| :--- | :--- | :--- | :--- |
| `name` | string | yes | Pack name; shown by `probes list` |
| `description` | string | no | Informational only |
| `[[probe]]` | table array | yes | At least one probe |

Probe keys:

| Key | Type | Notes |
| :--- | :--- | :--- |
| `name` | string | Required; ASCII alphanumerics plus ` ._-:/()` |
| `service` | string | Service name assigned on match; required in practice |
| `ports` | integer array | Restrict candidate ports; empty means any |
| `product` | string | Static product fallback |
| `version` | string | Static version fallback |
| `cpe` | string | CPE 2.3 identifier copied to `service.cpe` |
| `product_regex` | string | Product extraction; capture group 1 |
| `version_regex` | string | Probe-level version extraction |
| `confidence` | float | Explicit base confidence, overrides the ladder |
| `ignore_case` | bool | Case-insensitive literal `expect` matching |
| `tls` | bool | Run steps over a TLS session (ALPN `http/1.1`, self-signed accepted) |
| `timeout_ms` | integer | Probe timeout; clamped to 100–10000 ms |
| `[probe.info]` | table | `key = "regex"` facts copied into `service.info` |
| `[[probe.step]]` | table array | Multi-step session (up to 8 steps) |

Legacy single-step probes may also place `send`, `send_hex`, `expect`,
`expect_regex`, and `expect_hex` directly on the probe. Mixing those keys with
`[[probe.step]]` is rejected.

Step keys:

| Key | Type | Notes |
| :--- | :--- | :--- |
| `name` | string | Shown in `--explain` evidence when the step agrees |
| `send` | string | UTF-8 payload |
| `send_hex` | string | Binary payload; whitespace, `:`, and `-` ignored |
| `expect` | string | Literal substring match |
| `expect_regex` | string | Regex match (use `(?i)` for case-insensitivity) |
| `expect_hex` | string | Binary substring match |
| `version_regex` | string | Fallback version extraction for this probe |
| `read_until` | string | Stop reading once this regex matches |
| `timeout_ms` | integer | Per-step timeout override |

Set `send` or `send_hex`, never both, and at most one expectation per step.

### Extraction rules

- `version_regex` order: probe-level pattern, then per-step patterns in step
  order, then the static `version`.
- `product_regex`, then the static `product`.
- `[probe.info]` entries each apply their regex to the transcript. Capture
  group 1 is used when present, otherwise the whole match. Empty values and
  values longer than 200 characters are truncated/dropped.
- Every extracted value is trimmed.

### Confidence

When `confidence` is not set explicitly:

| Match quality | Base |
| :--- | :--- |
| Service name only | 0.70 |
| Product identified | 0.85 |
| Version extracted | 0.98 |

Each additional step with a satisfied expectation adds 0.01, capped at 0.99.
The previous confidence for the same service is never lowered when a probe
refines an existing identification.

### Merge behavior

On a match, rayscan replaces the service name with the probe's `service`,
keeps any product/version/CPE from an earlier assessment of the same service
when the probe does not provide one, merges `info` maps (probe keys win), and
keeps the higher confidence. A `plugin:<pack>/<name>` tag is appended to the
port's `detail` field (shown in tables and JSON); the agreeing step names and
tag are appended to `evidence`, which is preserved when the accuracy stage
prepends its four-pillar breakdown. The banner becomes the first non-empty
transcript line (160 characters).

## Limits and safety

| Limit | Value |
| :--- | :--- |
| Pack file size | 256 KiB |
| Packs per run (built-ins included) | 64 |
| Probes per run | 512 |
| Steps per probe | 8 |
| Payload size | 8 KiB |
| Response per step | 16 KiB |
| Regex length | 512 characters |
| Probe/step timeout | 100 ms–10 s |
| Extracted value | 200 characters |

Unknown keys are rejected (`deny_unknown_fields`) so typos fail loudly rather
than silently weakening a probe. Only probes explicitly declared in a pack
run; nothing is auto-discovered from the working directory.

## Built-in library

The following packs are compiled into the binary (52 probes, 12 TLS-aware).
TLS-aware probes are named after their transport (for example `-tls` or
`-https`):

| Pack | Probes | Notable facts extracted |
| :--- | :--- | :--- |
| `databases` | `redis-info`, `elasticsearch-root`, `elasticsearch-root-tls`, `opensearch-root`, `opensearch-root-tls`, `couchdb-root`, `memcached-stats`, `cassandra-options`, `postgresql-startup`, `mysql-greeting`, `mongodb-hello`, `mongodb-hello-tls` | Redis mode/OS/uptime/config file; Elasticsearch cluster/build; OpenSearch distribution; CouchDB vendor/features; memcached connections/uptime; CQL version; PostgreSQL auth method/database; MySQL/MariaDB/Percona/TiDB version; MongoDB identity |
| `containers` | `docker-version`, `docker-ping`, `docker-ping-tls`, `docker-registry`, `kubernetes-version`, `kubernetes-api-tls`, `kubernetes-kubelet`, `kubernetes-kubelet-tls`, `kubelet-pods`, `etcd-version`, `etcd-version-tls`, `consul-agent-self`, `vault-health`, `vault-health-tls` | Docker API/Go/OS/kernel; registry API version; Kubernetes platform/Go/build date; etcd cluster version; Consul datacenter/node/server role; Vault initialization/seal state |
| `industrial` | `modbus-device-id`, `s7-comm`, `dnp3-link-status`, `ethernet-ip-list-services`, `opcua-hello`, `iec-104-startdt`, `niagara-fox`, `omron-fins`, `hart-ip-session`, `ge-srtp-info`, `melsec-q-cpuinfo` | Protocol identity and liveness via standard identification PDUs; OPC UA HEL/ACK, IEC 60870-5-104 STARTDT, Niagara Fox, OMRON FINS/TCP, HART-IP session, GE SRTP initialization/system-register, and MELSEC-Q CPU information handshakes |
| `remote` | `vnc-handshake`, `winrm-wsman`, `winrm-wsman-tls` | RFB version; WinRM WSMan challenge response |
| `appliances` | `jenkins-root`, `grafana-health`, `prometheus-buildinfo`, `kibana-status`, `rabbitmq-overview`, `portainer-status`, `portainer-https`, `sonarqube-status` | Product version plus server/database/commit/branch/Erlang/node/status details |
| `messaging` | `mqtt-connect`, `mqtt-connect-tls`, `kafka-apiversions`, `kafka-apiversions-tls` | MQTT broker CONNACK; Kafka ApiVersions negotiation |

List the current set with:

```bash
rayscan probes list
rayscan probes list --json
rayscan probes list --plugins ./my-probes/
```

## Writing a pack

1. Start from a banner the service emits without input, or from a safe,
   read-only request (`GET /version`, `INFO`, `OPTIONS`, identification
   sub-functions).
2. Prefer an expectation that uniquely identifies the product; generic
   strings such as `{"status":` match unrelated JSON APIs.
3. Add `version_regex` around the product-specific version field.
4. Put optional facts into `[probe.info]`; keep names snake_case.
5. For HTTPS-only endpoints, set `tls = true` and target the API path with a
   read-only `GET`; the engine performs the handshake and advertises
   `http/1.1` via ALPN.
6. Test without scanning the world:

```bash
rayscan scan -t 10.0.0.5 -p 9000 --plugins probes.toml --explain 9000
```

7. Validate a whole directory listing first:

```bash
rayscan probes list --plugins probes.toml --json
```

Because user packs load before built-ins, a custom probe for a built-in port
takes precedence. Keep probes non-destructive: no writes, no authentication
attempts, no configuration changes. Cases that need conditional logic belong in
script plugins (`--scripts`: sandboxed WASM or sidecar programs sharing one
JSON contract); this engine intentionally stays declarative.

## Differences from nmap-service-probes

- No embedded scripting language; probes cannot execute code (use `--scripts`
  script plugins for compute-heavy checks).
- TOML instead of the nmap text format, with multi-step sessions first-class.
- Hex payloads and hex expectations are native, so binary protocols do not
  need escapes.
- Confidence is explicit and corroboration-aware, feeding the accuracy score
  and `--min-confidence` filters.
- No `rarity`/`softmatch` semantics yet; ordering plus port lists control
  cost.
