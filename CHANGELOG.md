# Changelog

All notable changes to portensor are documented here.

## [Unreleased]

### Fixed

- Detect WASM fuel exhaustion through `wasmtime::Trap::OutOfFuel` instead of
  matching the rendered backtrace text, so runaway scripts reliably report the
  fuel budget error across Wasmtime builds.

## [0.7.2] - 2026-11-25

### Portensor 0.7.2

- First published release under the `portensor` name after the repository,
  crate, CLI, configuration, paths, packaging, and release assets were renamed
  from `rayscan`.
- The Linux static-musl archive includes the binary, regenerated man pages,
  official pack, README, changelog, and license. The Windows GNU archive
  includes the binary, official pack, README, changelog, and license. The
  release also publishes a CycloneDX SBOM, signed `SHA256SUMS`, and the public
  signing key. GitHub OIDC build-provenance and SBOM attestations were not
  created because the automated publish step failed before attestation; the
  workflow fix on `main` applies to future tags.
- P4 packaging, registry, key-custody, and independent OT review remain open
  external requirements; this release does not claim P4 closure.

### Release workflow fix

- Fixed the release checksum step to use `--`-prefixed globs so actionlint's
  shellcheck pass accepts the pinned release workflow without breaking the
  SBOM checksum lookup.
- Restricted the SBOM artifact upload to `portensor-*.cdx.json` so historical
  `rayscan` evidence cannot enter a new release.
- The v0.7.2 tag predates the workflow fix; its successful CI-built assets were
  checksummed, GPG-signed, verified, and published manually.
- No scanner behavior changed from 0.7.1. The 0.7.1 tag remains immutable, but
  no 0.7.1 GitHub release was published.

## [0.7.1] - 2026-11-25

### Portensor rebrand

- Renamed the project, crate, CLI binary, configuration, data paths, Docker
  image, release assets, package metadata, documentation, tests, and scripts
  from `rayscan` to `portensor`.
- Renamed the GitHub repository to `vulnquest58/portensor` and updated the
  repository, homepage, badges, and release links.
- Regenerated the man pages under the `portensor` name and removed the old
  `rayscan` binaries and man pages from the working tree.
- Added the `portensor` Linux and Windows release asset names while leaving
  historical v0.7.0 release artifacts and P4 evidence unchanged.

### Release readiness and authorized live validation

- Added P4 local evidence tooling: `make p4-local-check` exercises ephemeral GPG
  and cosign signing/verification, regenerates a CycloneDX SBOM, covers both
  archives and the SBOM in `dist/SHA256SUMS`, and checks the release workflow
  controls. Production key custody, registry ownership, and OT approval remain
  external blockers.
- Added the P4 closure checklist, machine-readable evidence manifest, ADR 0005
  for release signing/provenance, and the v1.0 compatibility and release policy.
  The checklist keeps all six requirements open until external evidence and
  reviewer sign-off exist.
- Added `make p4-evidence-check` and the P4 evidence audit. The audit validates
  paths, statuses, links, local artifacts, SBOM checksum coverage, action pins,
  runner documentation, and CI controls; it passes with zero errors and zero
  warnings and does not close any requirement.
- Pinned every workflow action to a full commit SHA, replaced floating runner
  labels with `ubuntu-24.04`/`windows-2022`, added runner-image logging, and
  documented reproducibility limits in `docs/release-runners.md`.
- Added P4 external evidence ownership, blocker, and sign-off readiness reports,
  plus the P4-1 production signing policy, key custody procedure, independent
  signature verification procedure, and evidence register. They record required
  external evidence only; no status was promoted, no approval was recorded, and
  P4 remains not closed.
- Added the secure P4-1 evidence submission procedure, clean-host verification
  procedure, and blocked acceptance report. They define the exact owner inputs
  and verification transcript required; no production identity or approval was
  created and P4-1 remains `external-pending`.
- Added local P4-2 package metadata generation for Homebrew, Scoop, Chocolatey,
  AUR, and Docker Compose, plus archive-layout, checksum, JSON/XML/YAML, shell
  syntax, PowerShell parse, and Chocolatey pack checks. Added registry
  ownership, maintenance, and clean-install procedures. No registry was
  contacted, no package was published, no clean install was claimed, and P4-2
  remains `blocked`.
- Added a blank P4-2 external evidence intake and approval packet for channel
  ownership, 2FA/recovery, token decisions, clean installs, and container
  digest records. It records no external evidence and does not change any
  status.
- Added a machine-readable P4-2 evidence template, `make
  p4-external-evidence-status`, `make p4-external-evidence-check`, and a
  validator with regression tests. The validator rejects incomplete channel
  records, invalid container digests, version mismatches, and embedded secrets.
  The template is intentionally incomplete and records no evidence.
- Hardened the release workflow: unsigned releases now fail, missing, invalid,
  or unchecksummed SBOMs fail, signatures and checksums are verified before
  publication, public keys and the SBOM are published with the archives, and
  GitHub OIDC build-provenance and SBOM attestations are enabled. SBOM usage is
  documented in `docs/sbom.md`.
- Recorded an authorized, scope-guarded HTB Garfield validation: 22/22 confirmed
  TCP ports via two-pass connect-only discovery, 100% precision, SMB/RDP/WinRM
  fingerprints, Windows OS family classification, and documented limitations for
  no-banner verification, UDP, and raw SYN through WSL NAT. See
  `bench/htb/README.md`.
- Added explicit TLS SNI override support (`--sni` / config `sni`), including
  FQDN normalization and validation, SNI-aware certificate matching, and HTTP
  `Host` propagation. SNI conflicts with `--no-tls` and `--ack`.
- Added endpoint-aware OS fingerprinting: `mixed` family summaries, per-port
  `OsEndpointGuess` records with raw stack evidence plus service-derived hints,
  and terminal, JSON, Markdown, HTML, Nmap XML, and accuracy integration.
- Reran the authorized RedEye validation in v2 mode: nmap and portensor both
  found the same four TCP ports (22, 80, 443, 3000); explicit SNI identified
  ADFS on 443 and nginx on 3000; endpoint OS reported Linux on 22/80/3000 and
  Windows on 443 while retaining the Windows-like raw stack evidence. See
  `bench/htb/redeye.md`.
- Recorded an authorized Unclaimed validation: 13/13 confirmed TCP ports via
  two-pass connect-only discovery, a Windows member-server OS fingerprint,
  Microsoft HTTPAPI/WinRM/SMB services, a host-header-dependent baggage chatbot
  page, and a rate-limiting limitation. No exploitation was performed. See
  `bench/htb/unclaimed.md`.
- Recorded an authorized Scaffold validation: 30/30 confirmed TCP ports on a
  Windows domain controller, domain/LDAP rootDSE evidence, SMB signing, IIS and
  LDAPS certificates, plus high-rate nmap all-filtered and slow-scan timeout
  failures from target rate limiting. No authentication or exploitation was
  attempted. See `bench/htb/scaffold.md`.
- Fixed a coordinator merge-workspace race: concurrent merges in one process
  could derive the same timestamp-based temporary directory and mix shard
  reports. Workspaces are now created atomically with a random nonce and retry
  on collision.

### Accuracy, scale, and durable coordinator

- Replaced the v0.7.0 in-memory distributed state with a versioned, durable
  coordinator store: atomic state snapshots, per-shard result objects,
  deterministic merge recovery, restart counters, run/completion identity,
  state ownership locks, output/state mismatch rejection, and private file
  permissions on Unix. A restarted coordinator requeues expired leases,
  reattaches orphan results, repairs interrupted merges, and keeps a completed
  report fetchable without re-running shards.
- Added coordinator observability and scheduling controls: `/readyz` and
  `/metrics` behind the control-plane token, queue/in-flight/completion/failure
  and lease gauges, correlated `run=<id>` logs, duplicate/conflicting result
  rejection, and one-level straggler splitting. A parent running longer than
  2 seconds with no pending work is superseded; children inherit the job
  arguments with hidden work-part flags, and the split is deterministic.
- Reworked loss recovery. A silent handshake now fans out up to eight
  concurrent verification reconnects (two per retry, capped at eight) instead
  of paying one full probe window per retry, so a tarpit costs one window and a
  real service answers on any fresh connection. `--retries 0` still disables
  post-handshake recovery. Rechecks use safe local source ports, run
  concurrently, and no longer inflate the cached connect ceiling.
- Optimized connect-only discovery with a blocking OS-thread worker pool,
  cached RTT timeouts, and a 512 KiB worker stack; rechecking open candidates
  is parallel, and the minimum connect timeout is 1.1 seconds. The balanced
  profile now defaults to four retries.
- Added final v0.10 evidence: 20% loss passed 5/5 exact at 5.289 s median and
  6.573 s p95 (median <=7.5 s, p95 <=9.5 s); 30% loss passed 3/3 exact at
  9.108 s median; 5% loss and the no-loss baseline stayed exact. Full-range
  (65,535 ports x 16 hosts) passed at 8.511 s median wall, 43.820 s median CPU,
  and 102.1 MiB median peak RSS (limits 12.321 s, 75.375 s, 128 MiB). All seven
  coordinator crash, restart, observability, and uneven-load lab scenarios
  pass.
- Added verification, recheck, split-partition, coordinator recovery, and lab
  regression tests. The full suite passes: 440 library tests, 43 CLI tests, and
  3 official-script tests, with `cargo fmt` and clippy `-D warnings` clean.

### Explainable workflows

- Added `portensor smart`, a deterministic scan-plan model covering profile,
  mode, targets, ports, estimated probes, required privileges, scope,
  explicit defaults, automatic fallbacks, and risk notes. `--dry-run` sends no
  probes, `--plan-json` emits a machine-readable plan, and
  `--plan-output FILE` saves the model. The interactive wizard now prints and
  can save the same model.
- Added a self-contained HTML report format with inline CSS only, escaped
  scan-controlled fields, no remote assets, and coverage for services,
  evidence, advisories, script findings, TLS, OS fingerprints, and diffs.
- Added tested pipeline presets and documentation for `host-port` to
  httpx-style URLs, JSONL to nuclei-style targets, and `port-list` to a
  second-stage scan.

### Scripting platform

- Added explicit script capabilities (`metadata` or WASM-only `target-tcp`),
  a versioned active TCP host ABI with scope/target/port enforcement, rate,
  attempt, byte, and timeout limits, structured audit events, and a Linux
  seccomp network-deny sandbox for sidecars. Sidecars fail closed on platforms
  without verified isolation.
- Added digest-pinned `packs.lock` tracking, atomic staged installs with
  crash recovery, and `portensor scripts update` for registry-installed packs.
- Expanded `packs/official-baseline` to 24 passive checks with positive and
  negative fixtures, plus executable Python and WASM SDK templates and the
  script authoring/ABI/signing guide in `docs/script-sdk.md`.

### Tooling

- Added workflow linting for every GitHub Actions file in CI and release
  preflight, with a permanent release process and cross-phase development
  roadmap. Added `make release-check` for version consistency, clean-tree, and
  checksum gates. The published `v0.7.0` tag remains immutable; its workflow
  parse failure is documented and guarded against going forward.
- Added the scripting capability ADR and threat model, the durable coordinator
  design, plus full-range and coordinator fault-lab baselines for the v0.10
  accuracy and scale gates. Added `make scale-baseline` and
  `make distributed-lab`.

## [0.7.0] - 2026-11-19

### Added

- **Loss-aware connect recovery**: a timed-out connect is retried only while
  the target is producing healthy responses, except for one retry of an
  isolated first timeout. The timeout budget is capped at three. A minimum
  1.5 s timeout floor now survives a smaller configured ceiling. When packet loss drops a banner after a successful handshake,
  verified connect scans reconnect and retry an ambiguous `closed`/`silent`/
  no-service result up to two times instead of reporting a live service as
  silent. Retries retain the strongest evidence seen, honor rate/host
  concurrency limits, and are visible with `--log-level debug`.
- **Soak and saturation harness**: `bench/soak.py` and `make soak` repeatedly
  scan a configurable high-concurrency loopback scenario, require the exact
  open set, and report wall/CPU/peak RSS over time. It supports a fixed round
  count or a long `--duration` soak and JSON output for trend analysis.
- **Structured diagnostics**: opt-in JSON-lines stderr logging via global
  `--log-level` or `PORTENSOR_LOG` (`error`, `warn`, `info`, `debug`, `trace`;
  default off). Events cover scan start/finish, timeout and verification retries,
  distributed claims, heartbeat/result failures, and coordinator completion.
  Tokens, banners, payloads, and report contents are never logged.
- **Distributed resilience**: coordinator requests now have a 300 s lifetime
  and a 128-request in-flight cap; workers classify 401/403/409/422 errors as
  terminal instead of retrying them, while transport/429/5xx failures back off
  and retry. Push-mode failures apply backoff before requeueing. Ctrl-C and
  SIGTERM share the same graceful path for coordinator, worker, and agent, and
  a worker's heartbeat sleep is cancelled as soon as its job finishes instead
  of delaying `--max-jobs` exit by up to 30 seconds.
- **Standardized benchmark validation**: `bench/validate.py` (and
  `make bench-validate`) creates a reproducible loopback scenario with banner
  services, silent tarpits, and closed ports, then runs interleaved warmup and
  measured rounds. It validates verified-mode exactness against nmap on all
  ports and compares handshake-only portensor with nmap on the same non-tarpit
  ports for matched speed, CPU, and peak-RSS measurements. It writes
  `bench/results/validation.json` plus a Markdown summary, enforces accuracy
  and resource ceilings, and exits non-zero on regression. The shared harness
  now measures per-run CPU and peak RSS with GNU `time -v` instead of the
  non-per-process `ru_maxrss` value, with a CPU-only `getrusage` fallback.
  `--netem-loss` reruns the suite in an unprivileged network namespace with
  `tc netem`; both 5% and 20% loss profiles now pass exactness for connect and
  verified modes, and the suite still exits non-zero on any regression.
  Measured results and limits are recorded in
  `docs/benchmark-validation.md`.
- **Vendor-aware advisory confidence**: NVD correlation now stores exact CPE
  vendor/product identities (database schema 2) and prefers a plugin-supplied
  `service.cpe` over the product alias table, preventing cross-vendor false
  positives such as Apache HTTP Server matches against Oracle HTTP Server.
  Version matching preserves patch and distro suffixes (`4.7p1`, `1.0.2u`,
  `5.0.51a-3ubuntu5`), compares numeric components numerically, and orders
  prerelease markers before the final release. Malformed NVD bounds are
  rejected instead of widening a range, and wildcard CPEs cannot override
  explicit bounds. Advisory matches now expose `confidence` and `evidence`
  fields; low-confidence all-version matches are suppressed (`confidence <
  0.55`) while exact-version, range, and curated evidence remain ranked.
  Existing databases must be rebuilt with `portensor db update`.
- **Adaptive target politeness**: `--rate-auto` now distinguishes timeout,
  ICMP-unreachable, and tarpit/handshake-silent feedback in 500-probe windows;
  it halves on adverse bursts and recovers by 25% when responses are healthy,
  always within the configured `--rate` ceiling. Raw SYN AIMD now accepts
  explicit ICMP-error and high-density SYN-open pressure, so it backs off even
  when ICMP replies make the raw response ratio look healthy or when the
  silent-path ratio floor would otherwise freeze it. The anomaly threshold is
  wired into the raw engine, and adaptive floors are clamped to low rate caps.
  Added deterministic tests for connect ICMP/tarpit feedback, AIMD pressure,
  floor clamping, and per-host SYN-open detection.
- **Windows raw SYN/ACK scanning**: `--syn` and `--ack` now work on Windows
  (IPv4 only) through a dynamically loaded Npcap `wpcap.dll`, with no new crate
  dependency. The backend uses `GetBestRoute`/`GetAdaptersInfo` for interface
  and source-address selection, `SendARP` for next-hop MAC discovery, and the
  shared pacing, AIMD, jitter, decoy, fragmentation, and retry logic. It
  reports multiple adapters independently, requires an elevated terminal, and
  fails with an install hint when Npcap is absent. Windows active OS
  fingerprinting and raw IPv6 remain unsupported. `portensor doctor` now checks
  Npcap readiness and the selected route; CI compiles every Windows target and
  runs the shared raw-networking unit tests.
- **Official baseline script pack**: release archives now include
  `packs/official-baseline/`, a read-only Python sidecar pack (Python 3.8+
  on `PATH`) that reports
  expired, not-yet-valid, expiring-soon, self-signed, and SHA-1/MD5-signed TLS
  certificates; SMB signing that is not required and accepted SMBv1
  negotiation; Redis `INFO` without authentication; and Docker Engine API
  version/ping responses without authentication. The checks consume only
  metadata already gathered by the scan and open no additional connections.
  Install with `portensor scripts install ./packs/official-baseline` and run with
  `--scripts-library`.
- **Nmap XML baselines**: `--diff`, `--compare-to`/`--compare`, and
  `portensor diff` now accept Nmap XML reports (`nmap -oX`) as either the
  baseline or current snapshot. TCP port state and service name/product/version
  are imported for IPv4 and IPv6 hosts, including XML entities; UDP ports and
  aggregate `<extraports>` counts are ignored because the differential model is
  TCP-only. `--save-baseline` continues to write portensor JSON.
- **Broker, database, and infrastructure probes**: the built-in library now
  includes RabbitMQ AMQP Connection.Start (5672 and AMQPS 5671), NATS INFO
  (4222), ZooKeeper `srvr` (2181), rsync daemon greeting (873), ClickHouse
  `version()` (8123), and InfluxDB `/ping` (8086). The library ships 60 probes
  (13 TLS-aware), with version extraction and focused mock-server tests for
  every new protocol.
- **Distributed HTTPS**: the coordinator and push agents can terminate TLS
  directly with `--tls-cert`/`--tls-key`; workers and push coordinators verify
  private CAs with `--ca-cert`, or opt into `--insecure-tls` for isolated
  testing. This protects bearer tokens, job assignments, and shard reports on
  untrusted networks without requiring a reverse proxy. Plaintext HTTP remains
  the default and warns on non-loopback binds.
- **OT/ICS coverage**: `--preset ot` (aliases `ics`, `scada`) scans a curated
  control-plane port set covering Modbus, S7, DNP3, IEC 60870-5-104,
  EtherNet/IP, OPC UA, BACnet/IP, HART-IP, Niagara Fox, MELSEC, Omron FINS,
  GE SRTP, PCWorx, ProConOS, Red Lion, HMI HTTP(S), and SNMP. The built-in
  industrial pack now identifies OPC UA servers with a binary HEL/ACK
  handshake on 4840, IEC 60870-5-104 stations with STARTDT activation on 2404,
  Tridium Niagara
  Fox stations on 1911/4911 (extracting the application version), OMRON
  FINS/TCP PLCs with a node-address exchange on 9600, HART-IP servers
  with a session-initiate handshake on 5094, GE SRTP PLCs with a zero-filled
  initialization followed by a system-register read on 18245, Mitsubishi
  MELSEC-Q PLCs with a CPU-information request on 5007, and Phoenix Contact
  PCWorx PLCs with a three-step session-ID exchange on 1962. `--udp`
  recognizes BACnet/IP I-Am replies on 47808 (device instance and vendor ID)
  alongside the existing UDP inspectors.
- **Stateful probe sessions and binary matching**: probe steps can capture
  values from their own response with `capture` (regex) or `capture_hex`
  (`offset:length` raw bytes), and later `send`/`send_hex` payloads interpolate
  them as `${name}`. Captures must be declared before use, duplicate names and
  forward references fail at pack load, and binary captures preserve `0x00`
  and high-bit bytes. `expect_hex` now accepts `??` wildcards, and
  `expect_hex_offset` anchors a binary expectation at a zero-based response
  offset. The PCWorx probe uses these features to echo the PLC-generated
  session ID across its second and third requests.
- **Evidence-preserving report merge**: duplicate `host:port` results now union
  evidence strings, detail tags, script findings, advisories, banners, TLS/RDP
  metadata, and non-conflicting service fields. Conflicting service identities
  or `info` values are recorded in `evidence` instead of being silently
  discarded, so distributed and sharded reports retain the observations that
  led to the retained result.
- **Raw TCP ACK firewall mapping**: `--ack` sends stateless ACK probes over
  IPv4 and IPv6 and reports firewall behavior as `unfiltered` when a RST echoes
  the probe cookie (the packet reached a host or stateless device) and
  `filtered` when no response arrives. ACK mode defaults `--show` to
  `unfiltered`, honors `--retries`, `--timeout`, `--rate`, `--ttl`, and
  `--source-port-range`, and   automatically disables handshake verification,
  service/OS/UDP detection, advisories, plugins, scripts, decoys,
  fragmentation, and AIMD rate control (intentional drops are not congestion).
  `--format port-list`/`host-port` are rejected because they only render
  open/closed results. The new state flows through table, JSON,
  JSONL, CSV, Markdown, SARIF, and Nmap XML output, merge/state totals,
  resume files, and diffs; XML reports the ACK RST reason as `reset`.
- **Probe shaping controls**: `--ttl N` (config key `ttl`) sets the IPv4 TTL
  or IPv6 hop limit on raw SYN, ACK, decoy, fragment, and OS fingerprint probes.
  `--source-port-range MIN-MAX` (config key `source_port_range`) selects the
  raw SYN/ACK source-port range; the BPF filter follows the chosen range and
  retransmissions continue to advance to fresh source ports. Both flags use
  the same defaults as before (TTL 64, ports 61000-61999), and invalid values
  fail with a usage error before any raw socket is opened.
- **Multi-probe OS consensus**: `--os-probes N` (config key `os_probes`,
  default 3, range 1-8) samples up to N distinct open ports per host and
  combines the SYN-ACK fingerprints with a family majority vote. Confidence is
  reduced when ports disagree, Unknown samples are ignored for the vote, and
  human/JSON output now carries `samples`, port `agreement`, and estimated
  `hops` alongside the existing family and evidence fields.
- **RTT-driven SYN retransmission**: raw SYN probes now carry per-host
  retransmission deadlines derived from the RFC 6298 estimator (`MIN_RTO` 200
  ms, capped by `--connect-timeout-ms`). Retries are interleaved with the
  initial sweep instead of waiting for a whole pass, use a separate
  `--retry-rate` pacer, and advance to a fresh source port with a recomputed
  cookie. Fresh ports are required: reusing the original 4-tuple lets the
  target coalesce duplicate SYNs and rely on its delayed SYN-ACK retransmit.
  Hosts that never answer are not retried during the initial sweep, and the
  1% silent-path rule still ends unproductive retries. IPv4 and IPv6 share the
  scheduler. Loss-lab recall is unchanged (19-20/20 at 20% bidirectional loss
  with two retries); single-pass recall is 12/20.
- **Per-host concurrency cap**: `--host-concurrency N` (config key
  `host_concurrency`, default `0` = unlimited) bounds simultaneous connect
  attempts per target host. The cap applies to the connect scanner and to
  SYN-open verification, without changing global worker or rate limits.
- **Distributed orchestration**: `portensor distributed plan` emits a Bash or
  PowerShell script that runs every deterministic shard and merges the reports;
  `distributed serve` runs a token-authenticated HTTP/JSON coordinator in pull
  mode for polling `distributed worker` clients or in push mode for
  `distributed agent` endpoints. Jobs carry forced JSON output, stable
  `--shard-index`/`--shard-count`, per-job timeouts, heartbeats, lease-based
  requeueing, and bounded attempts. The coordinator merges finished shards with
  the normal open-wins/advisory-union rules, writes `--out`, and exits nonzero
  on failed shards. Shared bearer tokens come from `--token` or
  `PORTENSOR_DISTRIBUTED_TOKEN` (minimum 16 characters); plaintext binds outside
  loopback warn and optional HTTPS is supported. Raw jobs are reserved for
  workers with raw-scan capability.
- **Empty shard reports**: sharded scans whose target hash selects no targets
  now emit a valid empty JSON report instead of failing, so distributed plans
  and coordinators can merge them normally.

### Security

- Updated Wasmtime to 50.0.2, resolving RUSTSEC-2026-0566 through
  RUSTSEC-2026-0573. `cargo audit` and `cargo deny check` now pass; the only
  remaining audit warning is the explicitly allowed unmaintained `fxhash`
  transitive dependency.

### Validation

- Linux x86_64 glibc, static-musl, and Windows x86_64 GNU release builds.
- `cargo fmt --check`, clippy with `-D warnings`, the full Rust test suite,
  `cargo audit`, `cargo deny`, and the Python benchmark-harness tests.
- Exact localhost gate, matched-mode baseline validation, 5%/20% loss
  validation, the 30-second soak, and the 256-host-concurrency soak.
- Distributed pull, push, rejected-token, and graceful-shutdown smoke tests.
- Windows connect-mode smoke test; Npcap raw mode remains covered by the
  Windows CI compile/unit checks and requires Npcap plus elevation at runtime.

### Known limitations

- The privileged raw-SYN/SYN-proxy lab gate and the self-hosted namespace lab
  were not available on the release host (no passwordless sudo). The
  unprivileged netem loss gate, localhost gate, and Windows raw-unavailable
  failure path still ran.
- Npcap is not installed on the release host, so Windows raw SYN/ACK runtime
  behavior was not exercised locally.
- External OT/ICS and live-target certification was not performed for this
  release; results in this repository are loopback, namespace, or previously
  documented live-lab measurements.
- Locally built archives are unsigned; signing is performed by the release
  workflow when GPG or cosign secrets are configured.

## [0.6.0] - 2026-11-17

### Added

- **Remote script marketplace**: `portensor scripts search [QUERY] --registry
  URL` lists packs from a JSON registry index, and `portensor scripts install
  NAME --registry URL` resolves the highest version, verifies the entry's
  mandatory SHA-256 digest, and safely extracts the gzip tarball (single
  top-level directory; absolute paths, `..` traversal, links, and device
  nodes rejected; 64 MiB archive / 512 MiB expanded / 4096-entry caps) before
  the normal manifest validation and library install (`--force` to replace).
  Direct archive URLs install with `install URL --sha256 HEX`.
  `PORTENSOR_SCRIPT_REGISTRY` supplies the registry URL, relative archive URLs
  resolve against the index location, versions sort with numeric-aware
  ordering (`1.10` > `1.9`), and index entries are validated up front
  (schema 1, identifier/version/tag/description/digest/URL shape, 256-pack
  cap). Plain HTTP registries print a warning; the digest still pins
  integrity.
- **Script pack library**: install packs once and reuse them across scans.
  `portensor scripts install DIR` validates (compiles) every manifest before
  copying a pack directory into the library, `portensor scripts uninstall NAME`
  removes it, `portensor scripts library [--json]` prints the location, and
  `portensor scripts list` defaults to the installed packs when no PATH is
  given. Scans load stowed packs with `--scripts-library`. The library lives
  at `<data>/portensor/scripts` (sibling of the NVD database) and honors the new
  global `--scripts-dir DIR` plus `PORTENSOR_SCRIPTS_DIR`. Script directories
  now also load manifests from one level of pack subdirectories, and `--scripts`
  is repeatable — all paths feed one registry with duplicate plugin detection.
  Installs are capped at 4096 entries / 512 MiB per pack and refuse
  symlinks; replacing an installed pack requires `--force`.
- **WASM script plugins**: manifests can now reference a sandboxed WebAssembly
  module (`wasm = "check.wasm"`, mutually exclusive with `command`). Modules
  run in-process on wasmtime without WASI — no file system, network, clock, or
  environment access — and share the sidecar JSON contract (context in,
  `findings`/`service` out). Modules export `memory`, `alloc(i32) -> i32`, and
  `run(i32, i32) -> i64` (packed `(ptr << 32) | len`). Execution is bounded by
  a fuel budget, a 16 MiB memory/10k table-element limiter, and the manifest
  timeout; source is capped at 4 MiB and compiled at manifest load, so invalid
  modules fail fast in `portensor scripts list` (which now reports `kind` and
  `wasm_path` in JSON and a `wasm:` line in table output). Sidecar `command`
  manifests are unchanged.
- **Sidecar script plugin engine (Q2 start)**: cross-language script plugins
  described by TOML manifests (`--scripts FILE_OR_DIR`). Portensor sends one
  JSON context document on stdin (target, port, state, confidence, banner,
  detail, evidence, full `service` object, TLS metadata) and reads one JSON
  result from stdout; the script runs with the manifest directory as its
  working directory and honors optional `ports`/`services` filters and a
  100 ms-30 s per-run timeout (`timeout_ms`, default 5000). Findings are
  validated (16 per run, length caps, CVE and URL shape checks, control
  characters stripped) and attached per port as a `findings` array without
  altering the accuracy confidence. They surface in JSON/JSONL, a
  `Script Plugin Findings:` table section, the Markdown `## Script Findings`
  table, SARIF rules/results, and `--explain`. Manifests declare a category
  (`discovery`, `vulnerability`, `auth`, `brute`, `compliance`) and a danger
  level; `danger = "intrusive"` scripts only run with `--allow-intrusive`.
  Runtime script failures print a warning and never abort the scan.
- **Script-declared service identification**: script plugins can return an
  optional `service` object (`name`, `product`, `version`, `cpe`, `info`,
  `confidence`) that merges into the port's service record when the port is
  not yet identified or already carries the same service name. It feeds
  accuracy scoring and CVE advisory correlation and tags `detail` with
  `script:<pack>/<name>`. Confidence defaults to the probe ladder (0.98 with
  a version, 0.85 with a product, 0.70 name-only).
- **`--min-severity`**: drops script findings below a threshold
  (`info|low|medium|high|critical`) before rendering, across every output
  format.
- **`portensor scripts list [PATH]`** validates script manifests and prints
  pack, name, category, danger, command, filters, and timeout; `--json` emits
  machine-readable output.
- **Multi-step service/version probe engine (v2)**: the embedded probe library
  now ships 45 probes (12 TLS-aware) across six packs — `databases` (PostgreSQL
  startup, Redis `INFO`, Cassandra `OPTIONS`, Elasticsearch/OpenSearch HTTP and
  HTTPS, memcached, CouchDB, MySQL/MariaDB greeting, MongoDB `isMaster` OP_QUERY
  over TCP and TLS), `containers` (Docker Engine and registry,
  Kubernetes API server and kubelet, etcd, Consul, Vault, each HTTP/HTTPS where
  applicable), `industrial` (Modbus, S7 COTP, DNP3, EtherNet/IP), `remote` (VNC
  handshake, WinRM WSMan HTTP/HTTPS), `appliances` (Jenkins, Grafana,
  Prometheus, Kibana, RabbitMQ management, Portainer HTTP/HTTPS, SonarQube),
  and `messaging` (MQTT CONNECT/CONNACK and Kafka ApiVersions over TCP and
  TLS).
  Packs support sequential steps over one connection, UTF-8 and hex payloads,
  literal/regex/binary expectations, `read_until` early stops, CPE tagging,
  capture-group extraction into `service.info`, and corroboration-aware
  confidence (base ladder plus 0.01 per extra satisfying step, capped at
  0.99). The v1 single-step format still loads, and `--plugins` accepts a file
  or directory.
- **TLS-aware probe steps** (`tls = true`): probes can run over a TLS session
  with self-signed certificates accepted and `http/1.1` advertised via ALPN,
  enabling deep HTTPS probing of Kubernetes, Docker, etcd, Elasticsearch,
  Vault, WinRM, and Portainer endpoints. Active plaintext probes are skipped on
  ports where TLS inspection succeeded, so HTTPS endpoints never receive
  plaintext payloads.
- **`portensor probes list`**: prints every compiled probe with pack, service,
  ports, and step count; `--json` emits machine-readable output and
  `--plugins PATH` includes custom packs.
- **Deep SMB negotiation** (`src/smb.rs`): SMB2 NEGOTIATE now records dialect
  (2.0.2–3.1.1), signing requirement, capabilities, and server GUID; SMB1
  fallback extracts Native OS, LAN Manager, and domain strings. Results are
  exposed as `smb_*` fields in `service.info`.
- **Richer TLS metadata**: handshakes advertise `h2` and `http/1.1` via ALPN
  and report the negotiated protocol, public-key and signature algorithms
  (including Ed25519/ECDSA/RSA-PSS), and certificate-chain subjects in the
  `tls` output object.
- **`service.cpe` and `service.info`** fields on detected services, populated
  by built-in and custom probes. `--explain` now prints the identification
  detail tag, CPE, and up to eight protocol facts per port.
- **Faster single-host SYN scans**: the SYN engine now shards the port space
  across TX workers when a scan covers fewer targets than workers, so one
  host can saturate every TX core instead of pacing 65k ports through a
  single thread. Responses are routed per `(destination, port group)`;
  `sendmmsg` syscall arrays are preallocated per flush. UDP detection and
  OS fingerprinting phases now probe concurrently in bounded chunks instead
  of walking hosts/ports sequentially.
- **Decoupled banner verification**: connect workers no longer occupy a slot
  for the whole connect + verify sequence. Connected streams are handed to a
  dedicated verification pool (4× the connect workers) that performs banner
  waits and active probes, so bursts of silent or slow-banner ports cannot
  throttle the connect pipeline. A 6-worker scan against 2 banner ports plus
  16 silent tarpits completes ~3× faster than before with identical results.

### Changed

- User probe packs load before built-in packs, so a custom probe for the same
  port takes precedence (first match per port still wins).
- Probe assessments that refine an existing service preserve its
  product/version/CPE when the probe does not supply them, merge `info` maps,
  and never lower the previously reported confidence.
- `gen_man` now emits one man page per subcommand (`portensor-scan(1)`,
  `portensor-db-update(1)`, `portensor-scripts-list(1)`, ...) with full option
  documentation, resolving the previously dangling cross-references in
  `portensor(1)`. `make install` installs every generated page and release
  archives bundle them.

### Fixed

- SYN verification no longer loses live ports on lossy links. Retries of an
  ambiguous verification (a handshake that ends in an immediate close) could
  replace an earlier successful handshake with the last attempt's timeout, so
  a dropped SYN on the final retry demoted an open port to filtered. Outcomes
  are now ranked `Open > Silent > Closed > Filtered` and the strongest
  evidence wins (`prefer_best_evidence` in `src/scanner.rs`). Verification
  also honors the same 1500 ms `MIN_CONNECT_TIMEOUT` floor as connect scans,
  since a shorter ceiling cannot outlast the kernel's first SYN retransmit.
  On a 20% bidirectional-loss veth lab, `--syn --retries 2` went from 9-15/20
  recovered open ports to 18-20/20; see `docs/syn-loss-gate.md` and
  `scripts/syn-loss-lab.sh`.
- SYN-proxy ports are no longer reported open. A reset that arrives after the
  handshake but **before** any probe payload was sent is now classified
  `closed` (and feeds the SYN-proxy defense assessment) instead of `open`;
  the RSC-BUG-001 rule still applies to resets after a delivered payload.
  This restores the Phase 3 accuracy gate (`bench/accuracy_suite.py`, zero
  false positives) on the lab target at 0%, 5%, and 20% loss.

## [0.5.0] - 2026-11-13

### Added

- **Port presets** (`--preset <PRESET>`): curated engagement port sets with
  `dc|ad`, `win|ws`, `web|http`, `linux|lx`, `full|all`, and `q|top` (nmap
  top-1000 frequency table) presets. `--preset` conflicts with `--ports` and
  `--top-ports`. Presets expand to explicit port lists for save/resume state
  compatibility.
- **Independent connect timeout** (`--connect-timeout-ms`): per-connect
  timeout ceiling in milliseconds that overrides `--timeout` seconds.
- **Adaptive rate control** (`--rate-auto`): connect-scan rate controller
  halves the rate when >25% of probes time out in a 500-probe window and
  increases by 25% when <5% time out, clamped by a floor and ceiling.
- **Windows OS role refinement**: inferred `OsRole` from open service ports
  (Domain Controller / Member Server / Workstation) and emitted in table/JSON
  outputs and `OsGuess`.
- **`--compare` alias** for `--diff` (visible alias `compare-to` retained).
- **ARP host-discovery sweep** (`src/discovery.rs`): IPv4 targets in
  `--ping-sweep` are now probed with an ARP who-has liveness check before
  ICMP/TCP. Linux sends raw `AF_PACKET` ARP requests for **directly connected
  routes only** (reusing the SYN engine's route/ARP machinery; the gateway is
  never probed, so its replies cannot count as liveness). Windows uses the
  `SendARP` helper API from iphlpapi. This closes the largest platform gap in
  host discovery: hosts that drop ICMP and filter every TCP-ping port
  (embedded devices, TVs, IoT appliances) were previously undiscoverable on
  Windows, where raw ICMP is unavailable. Live-verified: a webOS smart TV that
  answers no ping port is now found via `--ping-sweep` on Windows.
- **UDP probes for SSDP (1900) and mDNS (5353)** (`src/udp.rs`): an M-SEARCH
  `ssdp:all` request and a `_services._dns-sd._udp.local` PTR enumeration
  query, with response classifiers (SSDP `ST:`/`Server:`/`Location:` header
  extraction; mDNS responses are classified as `mdns` instead of `dns`).
  These surface UPnP routers and IoT/Bonjour devices on LAN sweeps.
- **ICMP echo id hardening** (`src/discovery.rs`): each raw ICMP/ICMPv6 sweep
  now derives a per-target echo identifier from `(pid ^ target)`, so
  concurrent probes can never collide on `(id, sequence)` if the kernel
  multiplexes replies across raw sockets.
- **`--format port-list`** (aliases `ports`/`portlist`): comma-separated open
  port numbers only, ready to paste into `-p` of any tool. Entries are sorted
  and de-duplicated (audit RSC-BUG-003). When no `--ports`/`--top-ports` is
  given, this discovery format sweeps the full TCP range (1-65535) and includes
  handshake-completed silent listeners by default, so a fresh target can be
  enumerated in one command and the resulting list used for a deeper
  second-stage scan; other formats keep the 1-1024 / open-only defaults.

### Fixed

- **Post-handshake resets no longer classify open ports as closed** (audit
  RSC-BUG-001): verification only runs after a successful TCP connect, so a
  reset/abort/broken-pipe reported there proves the port accepted the
  connection. SYN-proxy-protected hosts previously produced ~32% false
  negatives on live HTB targets.
- **Machine-readable formats auto-quiet** (audit RSC-BUG-002 / PROPOSAL-001):
  `[tls]`, `[rdp]`, `[os]` and plugin progress lines are suppressed
  automatically for every non-human format (`port-list`, `json`, `jsonl`,
  `csv`, `nmap-xml`, `greppable`, `sarif`, `host-port`) — `--quiet` is no
  longer required for clean pipeline output. All progress writes remain on
  stderr.
- **Defense intelligence never contaminates machine formats** (audit
  RSC-BUG-004): defense blocks render only for table output; `port-list` and
  other machine formats emit results only, even with `--defense` set.

### Tests

- Regression coverage for the v0.4.0 audit: reset-after-handshake and
  accept-then-close classified `Open` (RSC-BUG-001), port-list dedup
  (RSC-BUG-003), pure `--format port-list` stdout with `--tls --os --defense`
  and no progress on stderr (RSC-BUG-002/004, PROPOSAL-001), and
  machine-format classification.

### Deferred (roadmap)

- ACK scan (`--ack`) with an `unfiltered` port state in the SYN engine to
  distinguish stateful-DROP filtering from reachable-but-unfiltered hosts.
- Raw SYN scanning on Windows via an Npcap packet path.

## [0.4.0] - 2026-11-11

### Added

- **Pipeline-ready output and exit codes**: `--format host-port` (alias
  `hostport`/`plain`) emits one `host:port` per open port for direct chaining
  into httpx/nuclei-style tools (IPv6 bracketed). `--exclude-ports` accepts the
  same list/range syntax as `--ports` and applies to resumed scans too.
  `--fail-on-change` on `scan --diff` and on the standalone `diff` subcommand
  exits `1` when new/gone/modified ports or posture shifts are detected, while
  a clean run exits `0` (no diagnostic printed on the status path). Exit codes
  remain `0`/`1`/`2` for success/runtime failure/usage otherwise.
- **Baseline and alert workflow**: `--save-baseline FILE` writes the current
  run as a JSON baseline in the exact format `--diff` consumes.
  `--alert-file FILE` (scan and `diff`) writes a compact, timestamp-free alert
  on every run — `status: no changes` or `status: changes detected` with one
  line per change — suitable for log shipping or a future webhook bridge.
- **Expanded service and version detection**:
  - HTTP now sends `GET` instead of `HEAD`, identifies products from
    `Server`, `X-Powered-By`, `X-Jenkins`, `kbn-name`/`kbn-version`,
    `X-Elastic-Product`, and `Docker-Distribution-Api-Version`, and fingerprints
    common Bug Bounty web surfaces from login/dashboard pages (Jenkins, Kibana,
    Elasticsearch/OpenSearch, Grafana, Apache Tomcat, phpMyAdmin, Adminer,
    Webmin, Zabbix, Prometheus, Portainer, SonarQube, Kubernetes Dashboard,
    Argo CD, RabbitMQ Management, Nexus, GitLab, MinIO, Rancher, Proxmox VE,
    pfSense, OpenWrt LuCI, WebLogic, WebSphere, Jira, Confluence).
  - Native probes now run before the HTTP probe on their ports: SMB2 NEGOTIATE
    with SMB1 fallback (dialect reported, e.g. `SMB 3.0.2`), MongoDB legacy
    `buildInfo` (server version), Redis `INFO server` (`redis_version`), and
    memcached `stats` (version). The previous MongoDB probe used an invalid
    opcode and is replaced by a correctly framed OP_QUERY.
  - SSH parsing recognizes OpenSSH, Dropbear, libssh, Win32-OpenSSH, Cisco,
    Paramiko, AsyncSSH, PuTTY, and SunSSH.
  - RDP identity: X.224 connection negotiation followed by a TLS CredSSP NTLM
    probe recovers the negotiated security protocol (`HYBRID_EX`, `HYBRID`,
    `SSL`, …), NLA computer/domain names, and the Windows build, mapped to a
    product such as `Windows 10 / Server 2019`. Silent RDP ports are retained
    and promoted to `open`, and JSON results gain an `rdp` object.
  - `service` objects now include an identification `confidence` (`0.98` with
    version, `0.85` with product, `0.70` with protocol name only) for JSON/JSONL
    pipelines and `jq` filtering.
- **TLS auto-inspection on non-standard ports**: in the default `Auto` mode,
  an open port whose banner already looks like TLS — or whose service could not
  be identified at all — is now inspected for certificate/version/cipher
  metadata instead of being limited to the well-known TLS port list. HTTP and
  other identified services are skipped as before.
- **HTTPS application fingerprints**: after a direct TLS handshake, a bounded
  decrypted `GET` reuses the HTTP fingerprint database, so Jenkins, Kibana,
  Grafana, Elasticsearch, and other products are reported as
  `service.name = "https"` with product/version on arbitrary ports. Ports that
  complete a TCP handshake but reset the plaintext probe are retained for TLS
  inspection and promoted from `closed` to `open` when the handshake succeeds.

- **Multi-target resume**: `--resume`/`--save-state` no longer require a single
  target. Per-host progress is tracked in the state file (`hosts` entries with
  each target's probed ports and state counts), so an interrupted multi-target
  scan resumes by scanning only each host's remaining ports. Merged reports add
  prior results/counts without duplication, and resuming a complete state
  finishes instantly with no probes. Single-target states saved by earlier
  versions resume unchanged; resuming them against a different host set keeps
  prior results only for hosts outside the new scan. Raw SYN mode
  (`--syn`) remains single-target for resumable scans.

- **Scope Guard Engine** (`--scope FILE`, `--force-out-of-scope`, `src/scope.rs`):
  Enforces legal and operational engagement boundaries for bug bounty hunters
  (e.g., HackerOne, Bugcrowd) and offensive security teams. Supports structured
  `scope.toml` or line-based target lists with CIDRs, IPv4 ranges, and wildcard
  domains (`*.example.com`). Explicit deny rules override allowlists, and
  unauthorized targets are rejected before packets are sent unless overridden
  with `--force-out-of-scope`. Target-file contents are expanded before
  validation, domain allow rules authorize the addresses they resolve to, and
  explicit IP/CIDR targets are checked against IP allowlists independently.
- **CISA KEV & EPSS Threat Prioritization** (`--kev-only`, `--min-epss SCORE`,
  `portensor db intel`, `src/advisory.rs`, `src/intel.rs`, `data/cisa_kev.json`):
  Correlates open services against the CISA Known Exploited Vulnerabilities
  catalog and FIRST.org Exploit Prediction Scoring System (EPSS). Services with
  active weaponized exploitation in the wild are highlighted with bold `[KEV]`
  badges and probability metrics in table, markdown, JSON, and SARIF outputs.
  Hunters can filter directly for exploitable targets via `--kev-only` and `--min-epss`.
  `portensor db intel [--force] [--json]` downloads the complete CISA KEV catalog
  and current EPSS CSV, merges them with the bundled fallback set, and atomically
  caches a gzip index under `<db>/intel/threat_intel.json.gz` with a 24-hour
  freshness window. Cached indicators are overlaid automatically for advisory
  scans.
- **Real-Time Streaming Output** (`--stream`, `src/lib.rs`, `src/output.rs`):
  Streams verified port findings line-by-line as unbuffered JSONL directly to
  `stdout`. Allows downstream pipeline tools (H1Hunter, ParamOracle, Shadow Octopus)
  to consume findings asynchronously without waiting for the full scan to finish.
  Post-scan TLS, plugin, and advisory enrichment is not backfilled into streamed
  records; use the final report when those fields are required.
- **IPv6 Neighbor Discovery Protocol (NDP) & ICMPv6 Sweep** (`--ndp`,
  `--ndp-timeout-ms`, `src/discovery.rs`, `src/targets.rs`):
  Expands broad IPv6 CIDRs such as `/64` through link-local all-nodes multicast
  probing (`ff02::1`), the Linux neighbor table (`ip -6 neigh` /
  `/proc/net/ndisc_cache`), and verified host routes instead of enumerating
  every address. Replies are merged and deduplicated, and link-local results are
  automatically attached to the correct interface scope ID for connect, TLS,
  UDP, plugin, and verification probes. Discovery is Linux-only, requires raw
  ICMPv6 privileges, and honors `--ndp-timeout-ms` (default 750 ms). Native raw
  ICMPv6 Echo (Type 128/129) remains available to `--ping-sweep`.

### Changed

- Version bumped to `0.4.0` across `Cargo.toml`, README, and man pages.
- `--advisories` is automatically activated when passing `--kev-only` or `--min-epss`.
- Table and markdown advisory summaries now prominently display `[KEV]` and EPSS percentages.
- JSON results now include `cisa_kev: bool` and `epss: Option<f32>` fields for every advisory.
- **Raw SYN engine throughput rework** (`src/syn/engine.rs`, `src/syn/v6.rs`,
  `src/syn/packet.rs`): IPv4 SYN frames are now written directly into
  preallocated batch slots reused across every probe and retransmission pass,
  eliminating the per-frame heap allocation and `to_vec()` copy on the hot
  transmit path. IPv6 probes switched from one `sendto(2)` syscall per packet to
  batched `sendmmsg(2)` over the same reused-buffer pool. The default batch size
  rose from 64 to 4096 frames per syscall, response draining/progress/AIMD
  updates now run once per batch flush instead of once per probe, and pacing is
  enforced exactly once per flush.
- **Parallel SYN transmit sharding** (`src/syn/engine.rs`): target list is split
  into contiguous shards, one dedicated AF_PACKET TX thread per shard (up to
  half the CPU cores, capped at 8), each with its own rate budget, AIMD
  controller, pacer, tx-time map, and retransmission pass. The single RX thread
  fan-outs decoded responses to the owning shard via a target map, and shard
  reports are merged into the final `ScanReport` (`workers` reports TX shards
  plus the RX thread). Retransmission passes remain per-shard and skip probes
  already answered within their own shard.
- **Batched SYN receive** (`src/syn/engine.rs`, `src/syn/v6.rs`): both RX loops
  replaced per-packet `recvfrom(2)` with `recvmmsg(2)` over prebuilt iovec/
  `mmsghdr` arrays of 64 reusable 2 KiB slots, cutting one syscall per response
  frame on the hot receive path.
- **AIMD rate control hardened for silent paths** (`src/syn/aimd.rs`,
  `src/syn/engine.rs`, `src/syn/v6.rs`): discovered through live benchmarking
  against a NAT'd reachability-real target. Three defects fixed:
  (1) the AIMD update ran once per batch flush with cumulative counters read
  before the just-flushed batch's responses could arrive, so every update read
  the ratio low and multiplicative decrease collapsed the rate toward `min_pps`
  (a 65535-port capped scan would run roughly 50x slower than the requested
  rate); updates now happen on a fixed 1-second window with per-window
  counters; (2) sub-1-percent response ratios carry no congestion signal when
  the path or target silently drops RST responses (common behind firewalls and
  NATs), so the controller now freezes the configured rate instead of
  collapsing it; partial response ratios still feed the regular AIMD logic;
  (3) the additive-increase step doubled from `rate/20` to `rate/4` so the
  controller can recover the configured rate within a few seconds after a
  real decrease. Additionally, when the first pass observes responses on under
  1 percent of probes, retransmission passes are skipped: a path that answers
  nothing does not begin answering after a resend, and the retry passes would
  only re-pay the full wall clock. Rate caps are now honored exactly
  (65535 ports at 10000/2000/500 pps complete in 8.2/33.6/132 s respectively
  in the benchmark environment).
- **Live permitted-range benchmark documentation** (`README.md`,
  `docs/bench-results.md`, `bench-artifacts/`): same-day live measurements on
  explicitly permitted ranges - the loopback sweep, the WSL2 NAT gateway
  (`172.22.64.1`, full cross-tool matrix against masscan/rustscan/nmap), and
  scanme.nmap.org (held to ≤3,000 pps, one full-range pass per tool, traffic
  stopped when the target rate-limited the test IP). Raw per-run logs, runner
  scripts, and parsed JSON results are archived verbatim under
  `bench-artifacts/` (including `bench-artifacts/live/`).

### Fixed

- An empty JSON baseline (target with no open ports) is now accepted by
  `--diff`/`portensor diff` instead of being rejected as an invalid file.

## [0.3.0] - 2026-11-08

### Added

- **TLS inspection** (`--tls`, `--no-tls`, `src/tls.rs`): Direct and STARTTLS
  handshakes on known ports capture protocol version, cipher, certificate
  subject/issuer/SANs/serial/validity, days remaining, self-signed and hostname
  status, chain length, and STARTTLS protocol. Certificates are captured even
  when untrusted; metadata appears in JSON, CSV, and Markdown output.
- **SARIF 2.1.0 and Markdown output** (`--format sarif`, `--format markdown`):
  Advisory rules and findings with CVSS/severity properties and host:port
  locations, plus human-readable summary, services, vulnerabilities, TLS, OS,
  defense, and differential sections.
- **Advisory-aware diffs** (`src/diff.rs`): Baselines retain
  `{id, severity, cvss}` advisories. Diffs report added/resolved/re-scored
  findings, advisory counts in change summaries, and new critical advisories.
- **Declarative probe packs** (`--plugins FILE`, `src/plugin.rs`): TOML packs
  with passive or active payloads, literal/regex expectations, version capture,
  bounded resource limits, and first-match-wins semantics.
- **ICMP/TCP ping sweep** (`--ping-sweep`, `--ping-count`, `--ping-timeout-ms`,
  `src/discovery.rs`): Linux IPv4 raw ICMP with TCP fallback; IPv6 TCP fallback.
  Connection refusals count as alive, target order is preserved, and work is
  chunked across hosts.
- **Raw IPv6 SYN scanning and IPv6 OS fingerprinting** (`src/syn/v6.rs`): Linux
  `AF_INET6` raw sockets, full 128-bit SYN cookies, retries, rate limiting, and
  SYN-ACK option classification. Mixed IPv4/IPv6 target sets are scanned and
  merged transparently.
- **Distributed target sharding** (`--shard-index`, `--shard-count`,
  `src/shard.rs`): Stable FNV-1a placement with family-aware hashing and
  validation up to 1,024 shards.
- **Report merge command** (`portensor merge`, `src/merge.rs`): Merge JSON or JSONL
  reports, deduplicate host:port results with open-wins precedence, union
  advisories, merge OS/defense maps, and adjust summaries.
- **Stealth traffic shaping** (`--jitter-ms`, `--decoys`, `--fragment-size`):
  Random delay before scanner probes and SYN batches, up to eight IPv4 decoy
  source addresses, and 8-byte-aligned IPv4 SYN fragmentation. The stealth
  profile now defaults to 50 ms jitter.
- **Supply-chain tooling**: `deny.toml`, `cargo-fuzz` targets for service, UDP,
  and packet parsers, `make deny`/`make fuzz`/`make sign`, optional GPG/cosign
  signing in `make dist`, a CI deny job, and a tag-triggered release workflow for
  musl Linux and Windows GNU archives.

### Changed

- Version bumped to `0.3.0` across `Cargo.toml`, archives, README, and man page.
- Phase 9 feature gate documented in `docs/phase9-features.md`, including live
  STARTTLS and Metasploitable 2 validations.
- JSON port objects now include an optional `tls` object; CSV gains
  `tls_version`, `tls_subject`, and `tls_days_remaining` columns.
- Raw SYN target handling now accepts IPv4 and IPv6 in the same invocation.
- UDP probing binds `[::]:0` for IPv6 targets instead of an IPv4 wildcard.
- `--ping-count` and `--ping-timeout-ms` require `--ping-sweep`; `--decoys` and
  `--fragment-size` require `--syn`.
- Output format enum now includes `sarif` and `markdown`.

### Fixed

- `portensor merge` no longer duplicates open-only JSON entries into a redundant
  `results` array; `results` is emitted only when an input supplied one or the
  inputs are JSONL.
- UDP service probing against IPv6 targets no longer fails on an IPv4-only bind.
- SMTP STARTTLS negotiation now handles a bare `250` response terminator.
- Clippy warnings in checksum, plugin hex parsing, and packet tests.

## [0.2.0] - 2026-11-07

### Added

- **Unified Accuracy Scoring Engine (0–100%)** (`src/accuracy.rs`): Every responsive port is scored across 4 empirical pillars:
  - TCP Handshake (20%): verified 3-way handshake completion.
  - Application Protocol (40%): bounded protocol parsing and banner validation, with dedicated recognition for silent/binary client-first listeners (rpcbind 111, PostgreSQL 5432, X11 6000, AJP 8009, NFS 2049).
  - Stack / OS Conformance (20%): TCP/IP options and TTL fingerprint alignment.
  - Behavioral Latency Stability (20%): RTT consistency and absence of drop retries.
- **Explain Mode & Confidence Filter** (`--explain [PORT]`, `--min-confidence <N>`): Detailed diagnostic breakdown of scoring criteria and evidence strings; ability to filter out low-confidence or ambiguous candidates.
- **Defense Awareness & Middlebox Classifier** (`src/defense.rs`): Evaluates target defensive perimeters into a 6-tier posture hierarchy:
  - `[CLEAN] Direct Host`
  - `[NOTICE] Rate-Limiting Active`
  - `[WARNING] TCP Tarpit Active`
  - `[WARNING] SYN-Proxy Middlebox Detected`
  - `[WARNING] Layer-7 WAF / DPI Detected`
  - `[CRITICAL] Heavy Middlebox / Deception Detected`
- **Defense Observations Tracking** (`src/model.rs`, `src/verify.rs`): `ScanReport` retains reclassified verification drops so middlebox discrepancies are detected even when `--show closed` is omitted.
- **Network State Change Detection & Differential Auditing** (`src/diff.rs`):
  - Live scan comparison via `--diff <FILE>` / `--compare-to <FILE>`.
  - Standalone offline CLI subcommand `portensor diff <BASELINE> <CURRENT> [--json]`.
  - Colorful visual indicators: `[+] NEW`, `[-] GONE`, `[*] CHANGED`, `[~] POSTURE`.
- **Smart Resume with Pre-Scan Gap Analysis Audit** (`src/resume.rs`): Visual audit table displaying completed vs remaining ports, completion percentage, prior findings, and host anomaly flags before resumed probing begins.
- **Speed & Discovery Optimizations** (`--discover-only`, `--top-ports-first`):
  - `--discover-only` mode disables banner waits for ultra-fast perimeter mapping (~1.52 s / 1k ports).
  - `--top-ports-first` prioritized ordering enabled by default in `fast` and `balanced` profiles (first results < 50 ms).
- **Live Results Table & In-Memory Deduplication** (`src/lib.rs`): Streams responsive ports cleanly above the progress bar with `HashSet<(IpAddr, u16)>` deduplication during retries.
- **Cyber High-Contrast Theme** (`--theme cyber`): Enhanced terminal visibility palette for modern terminals.
- **Standalone Native Windows Subcommand Execution**: `portensor.exe diff` supported natively alongside connect scanning.
- **Offline CVE Advisory Correlation** (`--advisories`, `src/advisory.rs`, `data/advisories.json`): Detected service product/version/banner tuples are matched against a bundled curated CVE database (vsftpd 2.3.4 backdoor, Samba 3.0.x, UnrealIRCd 3.2.8.1, Debian OpenSSH PRNG, Apache 2.2.x DoS and 2.4.49/2.4.50 path traversal, Exim 4.87-4.91, distccd). Findings attach to port results and render as an `ADVISORIES` table column, a severity-sorted correlation section, `--explain` breakdowns, and `advisories` arrays in JSON/JSONL output. Correlation is fully offline and advisory only; no additional target traffic is generated.
- **Local NVD CVE Advisory Database** (`portensor db update`, `portensor db status`, `src/db/`): A user-maintained mirror built from the official NVD CVE 2.0 feeds covering 1999 through 2026 (over 400k CVEs and 325k product mappings at release). Feed processing is streamed and digest-verified, and the mirror is stored as compact yearly records plus 256-way product shards with atomic manifest updates and a concurrency lock. Manual refreshes support `--years SPEC` subsets and `--force`; `db status [--json]` reports coverage, age, and staleness. Every scan checks the rolling `recent` feed and applies changes automatically unless `--no-db-update` is passed, and update failures never fail a scan. NVD matches merge with curated findings and are tagged with `source: "nvd"`; curated findings rank first and each source is severity-sorted, while human-readable advisory sections cap at 10 rows per service and JSON keeps the full list. Database location follows `--db-dir`, `PORTENSOR_DB_DIR`, or the platform data directory.

### Changed

- Scans now perform an automatic lightweight NVD `recent`-feed check by default; use `--no-db-update` to disable it.
- Updated version to `v0.2.0` across `Cargo.toml`, `Makefile`, `README.md`, man pages, and distribution archives.
- Streamlined `render_table` with `TableOptions` parameter struct.
- Hardened test assertions against package version macros.

### Fixed

- **Defense Awareness false positives on client-first services** (`src/defense.rs`): known binary-protocol ports (rpcbind 111, distccd 3632, PostgreSQL 5432, X11 6000, AJP 8009, ...) that hold connections mute are no longer counted as TCP-tarpit evidence, verification failures on those ports no longer imply a SYN proxy, and their low accuracy scores no longer suggest rate-limiting. Expected client-first listeners are reported as a neutral indicator instead.
- Anomaly annotations (`anomaly:`) are now detected on any result for a host instead of only the first result, so tarpit/honeypot farms cannot be missed by result ordering.

## [0.1.0] - 2026-11-03

### Added

- **`Profile::Stealth` and `--stealth` flag** (`src/config.rs`, `src/cli.rs`):
  new stealth profile (rate 20 pps, probe timeout 1000ms, workers 8, retries 3) with
  automatic probe randomization to evade basic network IDS thresholds and rate-limiting middleboxes.
- **Expanded UDP detection** (`src/udp.rs`): added active probes and response decoders
  for NetBIOS Name Service (NBNS port 137, extracting computer/workgroup names) and
  SIP VoIP/PBX (port 5060, parsing SIP status line and Server product/version).
- **Expanded OS fingerprinting database** (`src/fingerprint.rs`): added signatures for
  pfSense / OPNsense firewalls (FreeBSD kernel), MikroTik RouterOS (Linux router kernel
  with timestamps disabled), and Windows Server 2019/2022.
- **Technical whitepaper** (`docs/why-accuracy-first-matters.md`): deep-dive analysis on
  why high-speed scanners fail against TCP tarpits and SYN proxies, and how portensor't two-phase
  verification solves it with 100% precision.
- **Public release README overhaul** (`README.md`): added status badges (CI, Version, Rust, Platforms, License),
  tarpit comparison benchmark matrix, and profile selection guide.
- **Graceful Ctrl-C signal handling** (`src/lib.rs`): `tokio::signal::ctrl_c()`
  spawned at scan start sets a `shutdown: Arc<AtomicBool>` on `ScanOptions`.
  Workers check the flag before each job; when set they stop picking new work and
  the scan returns a **partial report** instead of an error.
- **`partial: bool` field on `ScanReport`** (`src/model.rs`): `true` when the
  scan was interrupted before all probes completed.  Callers can distinguish a
  complete result from an interrupted one.
- **Resumable scans** (`src/resume.rs`): new `--save-state FILE` and `--resume FILE`
  CLI flags.  `save_state()` serialises the current scan results, counts, elapsed
  time, and list of probed ports to a versioned JSON file.  `--resume` loads the
  saved state, computes remaining ports, runs only those ports, and merges results.
- **Optional ports specification & `--top-ports` flag** (`src/cli.rs`, `src/ports.rs`):
  `--ports` is now optional; when omitted, `portensor` automatically defaults to the
  standard well-known ports `1-1024`. Added `--top-ports N` to probe the top N most
  frequently used services (e.g. `--top-ports 100`).
- **Native Windows release binary** (`portensor.exe`): cross-compiled for
  `x86_64-pc-windows-gnu` via MinGW toolchain; runs natively on Windows CMD and PowerShell.
- **Nmap-compatible XML output** (`src/output.rs`, `--format nmap-xml`): full
  `<nmaprun>` / `<host>` / `<ports>` / `<runstats>` tree compatible with
  Metasploit, nmap-parse-output, and other nmap-XML consumers.  OS fingerprints
  appear as `<os><osmatch>` elements.
- **Greppable output** (`src/output.rs`, `--format greppable`): Nmap `-oG`-style
  one-line-per-host format: `Host: <ip>  Ports: <port>/<state>/<proto>//<svc>/…`
- **Static musl binary** (`make musl`): cross-compiles portensor for
  `x86_64-unknown-linux-musl` producing a fully-static binary with no libc
  dependency; install `musl-tools` and run `make musl` once.
- **Man page** (`man/portensor.1`, `make man`): full `roff` manual page generated
  from the clap command definition via `clap_mangen`; covers all flags, formats,
  output modes, and exit codes.
- **`src/bin/gen_man.rs`**: build-time helper binary that regenerates `man/portensor.1`.
- **Dockerfile** (multi-stage): `rust:1.99.1-alpine` builder compiles the musl
  binary; `scratch` final layer holds only the binary.  Build with `make docker`.
- **Makefile targets**: `make musl`, `make install`, `make docker`, `make man`.
  `make install` copies the release binary to `$(PREFIX)/bin/portensor` and the man
  page to `$(PREFIX)/share/man/man1/portensor.1`.
- **`shutdown: Arc<AtomicBool>`** field on `ScanOptions`: workers consult the flag
  at the top of each job loop iteration.
- **6 unit tests** in `src/resume.rs`: port subtraction, empty / full / partial
  scanned sets, save/load round-trip, restored-counts verification, and
  structured service-metadata restoration.
- **1 unit test** in `src/ports.rs` for saved `top-N` and list specifications.
- **4 unit tests** in `src/output.rs`: NmapXml host/port/service elements,
  empty-version omission, greppable one-line-per-host, and XML closure.
- `docs/phase6-gate.md`: gate report with musl binary evidence, nmap XML sample,
  greppable sample, resume demo, man page, and Dockerfile notes (image build
  still requires a Docker host).

### Changed

- `src/model.rs`: `ScanReport` gains `partial: bool` and `probed_ports: Vec<u16>`.
  All existing constructors (scanner, syn/engine, anomaly, verify, output tests)
  updated.
- `src/scanner.rs`: `ScanOptions` gains `shutdown: Arc<AtomicBool>`.  `scan()`
  returns a partial `ScanReport` (instead of `Err`) when interrupted and records
  every port that was actually probed.  `run_worker()` checks the shutdown flag
  before each probe.
- `src/lib.rs`: when `--save-state` is used, all outcomes are retained for the
  state file while display filtering remains unchanged; a resumed run reuses the
  saved port specification and rejects multiple targets.
- `src/cli.rs`: `ScanArgs` gains `--resume` and `--save-state` flags;
  `ResolvedConfig` gains `resume_file: Option<PathBuf>` and
  `save_state_file: Option<PathBuf>`.
- `src/output.rs`: `OutputFormat` gains `NmapXml` and `Greppable` variants;
  `emit()` dispatches to the new renderers.
- `src/lib.rs`: `pub mod resume` registered; `run_scan()` wires signal handling,
  resume loading, state saving, and partial-report warning.
- `Cargo.toml`: `[[bin]] gen_man` section added; `clap_mangen = "0.2"` and tokio
  `signal` feature were already added in Phase 6 prep.
- `make ci` test count: **106 Rust unit tests + 9 CLI integration + 13 Python = 128 total**.
- **Live Metasploitable 2 validation** (`docs/live-test-metasploitable.md`):
  18/18 open ports with service/version metadata and Linux 2.6.x OS fingerprint
  in 1.77 s; UDP DNS/rpcbind/NetBIOS detection in 1.5 s.

### Fixed

- **OS classifier false positive** (`src/fingerprint.rs`): Ubuntu/Metasploitable
  fingerprints without TCP timestamps were classified as MikroTik RouterOS.
  The Linux 2.6.x signature now accepts absent timestamps and the MikroTik
  window range was narrowed; regression test added.
- **Service/version parsing** (`src/service.rs`): extract FTP product/version
  from `220 (vsFTPd 2.3.4)`, identify Postfix SMTP, IRC 6667/6697, shell
  prompts, Ruby DRb, and rexec (`Where are you?`).
- **UDP detection** (`src/udp.rs`, `src/lib.rs`): added NTP, SNMP, and RPC
  portmapper probes; port-aware response inspection; independent probing of
  requested UDP ports even when TCP is closed; UDP service metadata is now
  attached to the structured result.
- **Resume correctness** (`src/lib.rs`, `src/resume.rs`, `src/model.rs`):
  resume reuses the saved port specification when `--ports` is omitted, records
  the exact ports probed by an interrupted randomized scan, preserves all
  outcomes and structured service metadata, and rejects multi-target resume
  rather than producing incomplete state.
- **Nmap XML** (`src/output.rs`): omit `product`/`version` attributes when the
  value is unknown instead of emitting empty strings.

---

## [Unreleased - Phase 5]

### Added

- **OS fingerprinting** (`src/fingerprint.rs`): opt-in via `--os` flag.
  Sends one raw SYN probe (AF_PACKET) per discovered host, extracts features
  from the SYN-ACK (TTL, window, MSS, WScale, SACK, timestamps, DF bit,
  options order), and classifies the host's OS family using weighted additive
  scoring against an 11-entry signature database.
- **`OsFamily`** enum: `Linux`, `Windows`, `MacOS`, `Bsd`, `Cisco`, `Unknown`.
- **`TcpFingerprint`** struct: raw TCP/IP features parsed from a SYN-ACK frame.
- **`OsGuess`** struct (serde-serialisable): family, detail string, confidence
  score, and inferred initial TTL.
- **`WinMatch`** matcher: `Any`, `Exact`, `Range`, `Set` — used in signatures.
- **`infer_initial_ttl()`**: snaps observed TTL + hops to nearest of 64/128/255.
- **`classify()`**: weighted additive scoring returning the best-matching `OsGuess`.
- **`parse_tcp_options()`**: extracts MSS, WScale, SACK-OK, timestamps from raw
  option bytes; records option order.
- **`fingerprint_from_frame()`**: parse Ethernet/IPv4/TCP frame → `TcpFingerprint`.
- **`probe_fingerprint()`** / **`probe_fingerprint_async()`**: Linux-only raw SYN
  probe; runs in `spawn_blocking`; returns `None` gracefully without root.
- **`build_fingerprint_syn()`**: 74-byte SYN frame with full TCP options section
  (MSS, NOP, WScale, NOP, NOP, SACK-OK, Timestamps) to elicit a rich SYN-ACK.
- **9 unit tests** in `src/fingerprint.rs`: TTL inference, Linux/Windows/Cisco/
  BSD/macOS classification, options parsing, frame rejection, hop estimation.
- **`report.os_fingerprints`**: `HashMap<IpAddr, OsGuess>` added to `ScanReport`.
- **JSON `os_fingerprints` field**: emitted in `--json` output when `--os` is used.
- **OS column in table output**: visible when `--os` returns at least one result.
- `docs/phase5-gate.md`: lab gate report with signature DB, scoring rationale,
  unit test evidence, and live Metasploitable 2 results.

### Changed

- `src/model.rs`: `ScanReport` gains `os_fingerprints: HashMap<IpAddr, OsGuess>`.
  All existing `ScanReport` constructors (scanner, syn/engine, anomaly, verify,
  output tests) updated with `os_fingerprints: HashMap::new()`.
- `src/cli.rs`: `ScanArgs` gains `--os` flag; `ResolvedConfig` gains
  `os_detection: bool`.
- `src/lib.rs`: Phase 5 OS probing stage wired after Phase 4 UDP detection;
  progress messages printed to stderr when `--os` is active.
- `src/output.rs`: `JsonReport` gains `os_fingerprints` (skipped when empty);
  `render_table` shows an OS column when fingerprints are present.

---

## [Unreleased - Phase 4]

### Added

- **UDP detection** (`src/udp.rs`): opt-in UDP fingerprinting via `--udp` flag.
  Sends a DNS probe to each open TCP port; identifies DNS, SNMP, and NTP from
  the response bytes; falls back to preserving printable ASCII banners.
- **UDP wired into `run_scan()`** (`src/lib.rs`): when `--udp` is set, every
  open TCP port is probed with `probe_udp()` after TCP scan completes; detected
  UDP service info is attached to the port's banner field.
- **`UdpServiceInfo` / `UdpDetection`** structs in `src/udp.rs`: serde-serialisable
  UDP result types with optional product and version fields.
- **5 unit tests** in `src/udp.rs` covering DNS, SNMP, NTP, text banner, and
  empty-data edge cases.
- `docs/phase4-gate.md`: lab gate report with live Metasploitable 2 evidence.

### Changed

- `src/lib.rs`: `report` binding made `mut` so UDP probing can mutate results
  in-place after the TCP scan completes.
- `src/cli.rs` `ResolvedConfig` now includes `udp_detection: bool` (wired from
  the `--udp` CLI flag).

---

## [Unreleased - Phase 3]

### Added

- **AIMD rate control** (`src/syn/aimd.rs`): additive-increase/multiplicative-decrease
  congestion avoidance for the SYN TX loop; enabled by default, disable with `--no-aimd`.
- **Retry rate reduction** (`--retry-rate N`): retransmission passes run at a reduced
  packet rate (default: rate/4) to avoid flooding the network.
- **Anomaly detection** (`src/anomaly.rs`, `--anomaly-threshold N`): flags hosts that
  respond with an anomalously large number of SYN-ACKs for extra scrutiny before they
  are added to the verified open set.
- **Confidence field** on `PortResult` (`confidence: Option<f32>`): carried through the
  verification pipeline and emitted in JSON and CSV output when present.
- `verify_syn_open_candidates()` in `src/verify.rs`: accepts a pre-filtered candidate
  list from the anomaly detection stage, keeping the verification path composable.
- New CLI flags: `--no-aimd`, `--aimd-min-rate N`, `--retry-rate N`, `--anomaly-threshold N`.
- `bench/accuracy_suite.py`: multi-profile accuracy runner that cycles through
  `LAB_LOSS=0%/5%/20%`, asserts recall ≥ 0.99 and FP = 0, and prints a results table.
- 31 new unit tests (77 Rust + 13 Python total):
  - 6 in `src/syn/aimd.rs` covering AIMD additive/multiplicative steps and clamps.
  - 3 in `src/anomaly.rs` covering threshold logic and partition results.
  - 2 more in `src/verify.rs` covering candidate-list reclassification and count merging.

### Changed

- Default `--syn` now performs discovery plus verification. Use `--syn --connect-only`
  for raw layer-3/4 semantics (deliberately reports tarpits and SYN proxies as open).
- `--connect-only` consistently disables both banner verification and SYN candidate
  verification.
- `SynScanOptions` gains `retry_rate_pps`, `aimd`, and `aimd_min_pps` fields.

### Fixed

- Low `--rate` values could stall forever when a transmit batch exceeded the
  token-bucket burst; batches now acquire tokens in burst-sized steps.
- SYN latency no longer includes time spent waiting in the transmit pacer.

## [Unreleased - Phase 2]

### Added

- Raw SYN engine (`--syn` flag) using `AF_PACKET + SOCK_RAW` on Linux.
- SipHash-1-3 SYN cookies encoded in the TCP ISN — stateless, zero per-probe heap allocation.
- BlackRock stateless bijection (masscan-style Feistel cipher) for full port-range coverage
  with no repeats and O(1) memory regardless of target count.
- Dedicated RX thread with kernel-side BPF filter accepting only SYN-ACK, RST, and
  ICMP port-unreachable replies to our source-port range (61000–61999).
- ARP resolution over `AF_PACKET` to discover the gateway MAC address.
- `/proc/net/route` parser to select the correct outgoing interface and source IP per target.
- Clear error and exit code 1 when `CAP_NET_RAW` or root is absent; the caller
  can re-run without `--syn` to use the Phase 1 connect scan.
- `siphasher`, `crossbeam-channel`, and `core_affinity` dependencies (87 crates total,
  `cargo audit` clean).
- 10 new unit tests: cookie encode/decode, BPF filter shape, raw-frame build/parse
  (SYN-ACK, RST, ICMP unreachable), BlackRock bijectivity, and route/MAC parsing.
- `docs/phase2-gate.md` with terminal evidence for all gate criteria.

### Changed

- `src/lib.rs` now exposes `pub mod syn` gated on `#[cfg(target_os = "linux")]`.
- `ScanArgs` gains `--syn` flag; `run_scan` dispatches to `syn::engine::syn_scan`
  when the flag is set.

## [Unreleased]

### Added

- Async TCP connect scanner with a fixed worker pool and lazy target/port job
  production.
- Target parsing for IPs, CIDRs, ranges, files, `@file`, hostnames, exclusions,
  and IPv4/IPv6 family selection, with a 65,536-address cap.
- Port list/range parsing and validation.
- Built-in `fast`, `balanced`, and `careful` profiles plus optional
  `portensor.toml` configuration.
- Table, JSON, JSONL, and CSV output; `--json` benchmark alias; file output.
- Banner verification so tarpits and SYN proxies are not reported as open;
  `--connect-only` restores handshake-only behavior.
- RFC 6298 per-host RTT estimator, 1.5s minimum timeout, global token bucket,
  `RLIMIT_NOFILE`-aware workers, and local-resource retries.
- JSON error taxonomy for open, closed, filtered, silent, unreachable, and
  error states.
- 30 unit tests, 6 binary-level CLI tests, and an exact `1-65535` localhost gate.
- Phase 1 architecture and gate documentation.

### Changed

- The CLI now exposes `portensor scan`; the Phase 0 shell is gone.
- Default scans verify a service after the handshake instead of treating every
  successful handshake as open.
- `make ci` now includes the release build.

## [0.1.0 - Phase 0] - 2026-11-03

### Added

- Phase 0 Rust CLI shell with `--version` and `--help`.
- Pinned Rust 1.99.1 toolchain with `rustfmt` and `clippy`.
- GitHub Actions CI for formatting, clippy, tests, release build, benchmark
  tests, and `cargo audit`.
- WSL2/Linux network-namespace lab with open, closed, DROP-filtered, tarpit,
  rate-limited, and SYN-proxy targets, plus `netem` delay/jitter/loss profiles.
- Ground-truth checker and benchmark harness for portensor, nmap, masscan, and
  rustscan.
- Offline parser and metric tests for the benchmark harness.

### Notes

- The connect scanner is Phase 1 and is not implemented in this release.
- Raw-packet lab tests require root and are isolated from shared CI.
