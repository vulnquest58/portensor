# Architecture

## Phase boundaries

**Phase 0** built the measurement apparatus: pinned toolchain, CI, lab namespace,
and benchmark harness.

**Phase 1** added the async TCP connect engine. It is the accuracy baseline, the
fallback on systems without raw-socket capability, and the benchmark reference.

**Phase 2** added a raw SYN engine (`--syn`): Linux uses `CAP_NET_RAW` and
`AF_PACKET`, while Windows loads Npcap's `wpcap.dll` at runtime and supports
IPv4. It shares the same CLI, output schema, and lab ground truth as Phase 1.
Without raw-socket capability it fails with a clear error and exit code 1; the
caller can re-run without `--syn` to use the connect engine.

**Phase 3** made raw SYN results trustworthy and introduced congestion control.
Unanswered probes are retransmitted up to the configured retry count at a reduced
rate controlled by an AIMD controller (`syn::aimd`). Every SYN-open candidate is
rechecked with a connect plus banner verification. Hosts with anomalously large
open-port counts are flagged by `anomaly::partition_candidates()` before
verification. Tarpits and SYN proxies are therefore reclassified instead of being
reported as open.

```text
CLI / config
     |
     v
targets + ports
     |
     +--[default]--> bounded worker pool --> result collector --> output
     |                    |        |
     |                    |        +-- classify
     |                    |        +-- RTT estimator
     |                    |        +-- token bucket
     |                    +----------- service verification (banner)
     |
     +--[--syn / Linux + CAP_NET_RAW]-->  syn::engine
                                              |
                                    +---------+---------+
                                    |                   |
                                 TX thread           RX thread
                             (BlackRock permute)  (BPF filter)
                             (SYN cookies)        (SYN-ACK / RST / ICMP)
                             (raw AF_PACKET)      (validate cookie)
     ^
     |
bench/bench.py  --->  lab/ground_truth.json
     ^                         |
     |                         v
nmap / masscan / rustscan   lab/lab.sh (network namespace)
```

The default `--syn` path feeds SYN-open candidates through `verify` before
output. `--connect-only` bypasses that recheck and exposes raw SYN semantics.

## Modules

| Module | Responsibility |
| :--- | :--- |
| `cli` | Clap surface, resolved settings, profile precedence, exit codes |
| `config` | TOML schema, built-in profiles, state filters |
| `targets` | IP, CIDR, range, file, `@file`, hostname, family filtering, exclusions |
| `ports` | Port lists, ranges, validation, deduplication |
| `scanner` | Worker pool, per-probe logic, service verification, result collection |
| `classify` | Mapping OS errors to closed/filtered/unreachable/resource failures |
| `rtt` | RFC 6298 SRTT/RTTVAR estimator with Karn backoff |
| `rate` | Shared token bucket |
| `limits` | Target cap, worker cap, `RLIMIT_NOFILE` sizing |
| `output` | Table, JSON, JSONL, and CSV rendering |
| `syn::cookie` | SipHash-1-3 SYN cookie encode / decode / validate |
| `syn::permute` | BlackRock stateless bijection (Feistel cipher), no repeats |
| `syn::route` | `/proc/net/route` LPM parser, ARP resolution, `iface_ip/mac/index` |
| `syn::packet` | Raw Ethernet/IP/TCP SYN and ACK frame builders; SYN-ACK / RST / ICMP parser |
| `syn::filter` | Classic BPF bytecode generator and `attach_filter()` |
| `syn::retry` | Per-probe RTT retransmission queue and fresh-source-port progression |
| `syn::engine` | TX/RX thread orchestrator, SYN/ACK probe policy, per-probe retransmission scheduling, and result aggregation |
| `syn::aimd` | AIMD rate controller for the TX loop — additive increase on success, multiplicative decrease on loss |
| `verify` | Connect-plus-banner verification of SYN-open candidates and state/count merging |
| `anomaly` | Flags hosts with anomalously large open-port counts for pre-verification scrutiny |
| `diag` | Opt-in structured JSON diagnostics on stderr |
| `shutdown` | Shared SIGINT/SIGTERM graceful-shutdown signal handling |

## Job model

Targets and ports are materialized as two small vectors. The cross product is
never materialized: a shared atomic index hands out `(target_index, port_index)`
jobs to a fixed worker pool. Memory is O(targets + ports), not O(jobs).

Each worker accumulates completed results and ships them in batches (64
results or a 50 ms flush) through a bounded channel sized from the worker
count. The collector unwinds each batch, updates full state counts, and
retains only states selected for output. This keeps a default open-only
scan from storing every closed port and removes a channel round-trip per
probe.

Targets are capped at 65,536 addresses (a `/16`). Automatic worker sizing
targets `cores × 32`, clamped to 64–512 and bounded at roughly 75% of
`RLIMIT_NOFILE`; beyond about 512 workers the connect engine loses
wall-clock time to scheduler contention (4,096 workers run roughly 2×
slower than 384 on a 12-core host). `--workers` still accepts up to 4,096
for explicit tuning. The soft limit is raised to a safe working value when
the hard limit allows it.

## Connect engine

For each job:

1. Acquire a token from the global rate limiter, if a rate is configured.
2. Acquire the target host's connect permit when `--host-concurrency N` is set.
3. Read the per-host timeout from the RTT estimator.
4. Run `TcpStream::connect` under that timeout.
5. Classify a failure using the raw OS error first, then `ErrorKind`.
6. On handshake success, wait briefly for a banner unless `--connect-only` is set.
7. Emit `open`, `closed`, `filtered`, `silent`, `unreachable`, or `error`.

Banner waits and active probes (step 6) run on a dedicated verification pool
sized 4× the connect worker count, so bursts of silent or slow-banner ports
cannot occupy connect-worker slots and throttle the connect pipeline.

`--host-concurrency N` is an opt-in per-target semaphore shared by the connect
scanner and SYN-open verification; `0` keeps the default unlimited behavior.
It bounds how many simultaneous connections one host sees without changing the
global worker or rate limits. Adaptive target politeness is available for
connect scans with `--rate-auto`: a 500-probe window halves the rate on timeout,
ICMP-unreachable, or tarpit/handshake-silent bursts and recovers by 25% when
responses are healthy, always within the configured `--rate` ceiling. The raw
SYN loop feeds ICMP errors and high-density SYN-open anomalies into AIMD using
the same politeness intent.

Remaining SYN-engine speed idea (not yet implemented): exploiting AIMD headroom
above the configured rate on healthy paths.

Timeouts do not provide RTT samples (Karn's rule); they increase a bounded
per-host backoff. Successful connects and RTT-bearing refusals update SRTT and
RTTVAR. The minimum connect timeout is 1.1 seconds so a dropped SYN has room for
the kernel's normal retransmission even under lab loss. A timed-out connect is
retried only while per-target healthy responses show the host is reachable
(one retry is allowed for an isolated first timeout), with the timeout budget
capped by `min(--retries, 3)`; a host whose timeouts dominate is treated as
filtering. Local resource failures (`EMFILE`, `ENFILE`,
`ENOBUFS`, `ENOMEM`) are retried separately and never reported as a port state.
When banner verification is ambiguous (`closed`, `silent`, or open with no
banner data), verified scans fan out up to eight concurrent reconnects (two per
retry, capped at eight) after the initial attempt, retaining the strongest
evidence seen. A tarpit therefore costs one extra probe window rather than one
window per retry, while independent banner losses are recovered in parallel.
`--retries 0` disables this post-handshake recovery.

## SYN engine (`--syn`, Linux + CAP_NET_RAW)

The SYN engine uses one RX thread plus one TX thread per probe shard, each
dedicated to a core. Shards split the target list contiguously first; when
there are fewer targets than TX workers (the common single-host scan), the
port list is additionally split into contiguous groups so one host can still
saturate every TX core. The RX thread routes each response to the owning
shard by destination address and port.

**TX thread:**
1. Permute logical probe indices with the BlackRock bijection (Feistel cipher on
   `Z_n`), so every `(target, port)` probe is visited exactly once without
   materializing the full job list.
2. Derive a source port from the permuted index in `[61000, 61999]` and encode
   the target `(dst_ip, dst_port, src_port)` into a SipHash-1-3 SYN cookie
   placed in the TCP ISN. Source ports are reused across different probes; the
   cookie binds the full tuple.
3. Build raw Ethernet/IPv4/TCP frames (source MAC from `iface_mac`, destination
   MAC from ARP, headers by hand) and send them in batches with `sendmmsg(2)`.
4. Give each probe its own retransmission deadline. When the deadline expires
   and no response was recorded, resend it with a fresh source port and cookie,
   up to `--retries`, while new probes keep flowing. Retries use the separate
   `--retry-rate` pacer; AIMD applies only to the initial sweep.
5. Retry entries stay queued through their final deadline even when no further
   attempt is allowed, which bounds the end-of-scan wait. Hosts that have never
   answered are not retried during the initial sweep, and a path that answered
   under 1% of probes stops retrying after the initial timeout.
6. `--ttl` overrides the IPv4 TTL and IPv6 hop limit on real, decoy, fragmented,
   and OS fingerprint probes. `--source-port-range MIN-MAX` replaces the
   default 61000-61999 SYN source-port range; initial probes and retries stay
   inside it, and the BPF filter is generated from the same range.

**RX thread:**
1. Receives frames on the `AF_PACKET` socket filtered by a classic BPF program
   that accepts SYN-ACK, RST, and ICMP unreachable packets for the scanner's
   source-port range.
2. Validates the SYN cookie in each SYN-ACK (`ack_no - 1 == stored ISN`).
3. Records `open` (SYN-ACK), `closed` (RST), or `filtered` (ICMP unreachable
   or no response after the retry window).

Per-probe transmit timestamps and terminal states are kept in bounded hash maps
for the duration of the scan. The source-port and destination-port vectors are
small; the full target/port Cartesian product is never materialized.

**Fallback:** when `CAP_NET_RAW` is absent, the engine prints one line to stderr
and exits with code 1. The caller can then re-invoke without `--syn` to use the
connect scanner.

**IPv6:** IPv4 uses `AF_PACKET` with a classic BPF filter. IPv6 uses an
`AF_INET6` raw socket for RX and `IPPROTO_RAW` for TX with a complete IPv6/TCP
header, letting the kernel handle routing and neighbour discovery. SYN cookies
bind the full 128-bit address. IPv4 decoys and fragmentation are not available
for IPv6, and mixed-family target sets are partitioned and merged into a single
report.

## TCP ACK engine (`--ack`, Linux + CAP_NET_RAW)

ACK mode reuses the SYN engine's sharding, pacing, retransmission, and RX
infrastructure but sends a probe with TCP flag `ACK` (0x10) only. The probe
carries the tuple cookie in both the sequence and acknowledgment fields. ACK
does not establish a handshake, so it answers a firewall question, not a
service question: it cannot distinguish open from closed ports.

- A RST is accepted as `unfiltered` only when its sequence number equals the
  cookie for `(target IP, target port, source port)`. RSTs that fail the check
  are ignored as unrelated or spoofed traffic.
- No response or an ICMP unreachable after the retry window is `filtered`.
- `unfiltered` is sticky, like `open`: later filtered timeouts do not downgrade
  it.
- ACK probes honor `--retries`, `--timeout`, `--rate`, `--ttl`, and
  `--source-port-range`; decoys and fragmentation are SYN-only.
- Verification, service/OS/UDP detection, advisories, plugins, and scripts are
  skipped. `--show` defaults to `unfiltered`, and `--format port-list` /
  `host-port` are rejected because those renderers print open/closed results
  only.
- IPv4 uses the same `AF_PACKET` frame builder; IPv6 uses the `AF_INET6` path
  with a full-address cookie.

## TLS, SNI, and OS post-stages

TLS inspection runs after discovery/verification and before plugin matching and
accuracy scoring. It probes known direct-TLS and STARTTLS ports, TLS-looking
banners, and unidentified services. The scanner intentionally accepts
self-signed certificates and records identity/trust properties instead of
failing the handshake.

`--sni HOST` (or `sni` in TOML) overrides the TLS server name independently of
the target IP. The same validated DNS name is used for the rustls handshake,
certificate SAN/CN matching, and the HTTP `Host` header. This is required when
one IP fronts multiple TLS virtual hosts, and prevents a target-IP `Host` header
from selecting a default vhost. The resolved value is exported as `tls.sni`.

OS fingerprinting samples up to `--os-probes` open ports per host and keeps
every SYN-ACK as an `OsEndpointGuess` under `os_fingerprints[host].endpoints`.
Each endpoint records port, family, detail, confidence, inferred TTL, hops,
TCP/IP evidence, and the detected service. The host-level `OsGuess` remains a
convenience summary: it reports the dominant family when evidence agrees, or
`mixed` when two or more families have endpoint confidence of at least 35%.
Per-port tables and accuracy scoring prefer the endpoint result; JSON,
Markdown, HTML, and Nmap XML expose the endpoint rows. Raw OS samples are
collected before the service post-stages; service-derived endpoint corrections
are applied after TLS, plugins, and scripts and before scoring, so a service
identified by SNI or a plugin can still refine its endpoint family. This avoids
assigning one OS to a host whose TLS edge and backend services run on different
stacks.

## Result semantics

The JSON schema (`host`, `port`, `state`) is identical across engines.

| State | Connect engine meaning | Verified `--syn` meaning | Raw `--syn --connect-only` meaning | Raw `--ack` meaning |
| :--- | :--- | :--- | :--- | :--- |
| `open` | Handshake + banner, or immediate peer close | SYN-ACK candidate passes connect + banner verification | SYN-ACK received and cookie validates | *(not emitted)* |
| `silent` | Handshake succeeded; no banner in window | Candidate handshake succeeded; no banner in window | *(not emitted)* | *(not emitted)* |
| `closed` | ECONNREFUSED / RST | Candidate connect refused or reset | RST received | *(not emitted)* |
| `filtered` | Connect timed out | Candidate connect timed out | ICMP unreachable or no response after retries | ICMP unreachable or no response after retries |
| `unfiltered` | *(not emitted)* | *(not emitted)* | *(not emitted)* | RST received with the probe cookie in its sequence field |
| `unreachable` | EHOSTUNREACH / ENETUNREACH | Candidate connect unreachable | *(not emitted)* | *(not emitted)* |
| `error` | Local or unexpected failure | Local verification failure | *(not emitted)* | *(not emitted)* |

> **Note:** At the raw SYN layer, tarpits and SYN proxies respond with a
> SYN-ACK and look open. The default `--syn` path therefore rechecks every
> SYN-open candidate through the connect engine and reclassifies it. Raw-layer
> behavior is available with `--syn --connect-only` for diagnostics.

## Configuration

TOML values are loaded from `--config FILE`, or from `portensor.toml` in the
working directory when present. Precedence is:

```text
CLI argument > TOML value > selected profile default > built-in fallback
```

The `fast`, `balanced`, and `careful` profiles adjust the timeout ceiling, banner
wait, rate, worker count, and retry count. Input validation rejects
non-positive timeouts, probe windows outside 10-60,000ms, rates above 1,000,000/s,
and worker or per-host concurrency counts above 4,096. `sni` must be a
normalized DNS hostname: IP literals, wildcards, underscores, malformed labels,
and non-FQDNs are rejected. CLI `--sni` overrides the TOML value and is
incompatible with `--no-tls`/`--ack`.

## Lab and benchmark

`lab/lab.sh` creates one network namespace, a veth pair, host/target addresses,
a DROP rule, a 5/s conntrack limit, a netfilter SYN proxy, and a `netem` qdisc.
It has no default route and never touches public interfaces.

The benchmark harness compares predicted open ports with
`lab/ground_truth.json`. Any predicted open port outside the ground-truth open
set is a false positive, including tarpits and SYN proxies. The harness does not
pin CPUs or control background load; that belongs in the dedicated performance
phase.

## Rules for later phases

1. Every new module must be reachable from the CLI and covered by a test.
2. The lab and benchmark must remain runnable without external scanners.
3. A speed change that lowers recall or precision is a regression, not a win.
4. Raw-packet code stays Linux-first; unsupported platforms fail visibly.
5. Never report a local resource error (`EMFILE`, `ENOBUFS`) as a port state.
6. Preserve the benchmark JSON contract unless the harness and tests change in
   the same commit.
