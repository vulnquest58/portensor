# Portensor

[![CI](https://img.shields.io/badge/CI-passing-brightgreen.svg)](https://github.com/vulnquest58/portensor)
[![Version](https://img.shields.io/badge/version-v1.0.0--rc.1-blue.svg)](Cargo.toml)
[![Rust](https://img.shields.io/badge/rust-1.99.1%20pinned-orange.svg)](rust-toolchain.toml)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20Windows%20%7C%20Static%20musl-informational.svg)](#cross-platform-binaries)
[![Author](https://img.shields.io/badge/author-vulnquest58-blueviolet.svg)](https://github.com/vulnquest58)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

An accuracy-first TCP/UDP port scanner with passive OS fingerprinting, written in Rust.  
Maintained by **vulnquest58** ([@vulnquest58](https://github.com/vulnquest58)).

**Status: Release Candidate (v1.0.0-rc.1).** High-speed scanners without evidence-based verification produce thousands of false positives when encountering real-world enterprise defenses (TCP tarpits, SYN-proxies, and middlebox drop rules). `portensor` solves this with a two-phase architecture: high-speed raw SYN discovery combined with rigorous semantic handshake verification, banner grabbing, passive TCP/IP stack fingerprinting, and offensive operations features for bug bounty hunters (Scope Guard boundary enforcement, CISA KEV and EPSS prioritization, real-time unbuffered JSONL streaming, IPv6 Neighbor Discovery, and the v0.6.0 cross-language script plugin engine — sidecar and sandboxed WASM plugins, a local pack library, and a digest-verified remote marketplace).

Includes guided interactive setup, diagnostic `doctor`, multiple UI themes (including high-contrast `cyber`), real-time streaming results table, and speed-optimized discovery modes (`--discover-only`, `--top-ports-first`).

---

## What Makes Portensor Different

Most port scanners fall into one of two extremes: raw packet blasters that drown operators in false positives (masscan, rustscan), or classic deep probes that crawl when scanning large subnets (nmap). `portensor` introduces three architectural differentiators:

### 1. Empirical Accuracy Scoring (0–100%)
Instead of reducing open ports to an opaque binary `open` state, `portensor` computes an empirical **Accuracy Score** derived from 4 foundational pillars:
- **TCP Handshake (20%)**: Validated 3-way handshake completion.
- **Application Protocol Verification (40%)**: Bounded banner capture and protocol validation (with dedicated recognition for client-first binary listeners like RPC, PostgreSQL, X11).
- **Stack & OS Conformance (20%)**: Passive TCP/IP fingerprint alignment (TTL, Window, MSS, SACK, TS).
- **Behavioral Latency Stability (20%)**: Response latency consistency and absence of drop retransmissions.
Every finding includes an inspectable evidence string (e.g. `handshake:ok(20%) banner:OpenSSH/8.9(40%) stack:linux(20%) latency:2.1ms(19%)`).

### 2. Defense Awareness & Middlebox Classification
`portensor` acts as a network intelligence classifier. When scanning modern infrastructure, it detects and categorizes middleboxes, firewalls, and deception defenses:
- `[CLEAN] Direct Host`
- `[NOTICE] Rate-Limiting Active`
- `[WARNING] TCP Tarpit Active`
- `[WARNING] SYN-Proxy Middlebox Detected`
- `[WARNING] Layer-7 WAF / DPI Detected`
- `[CRITICAL] Heavy Middlebox / Deception Detected`

### 3. Built-In Network Differential Auditing (`--diff`)
Tracks perimeter drift natively in $O(N)$ time. Compare live scans against historical baselines or evaluate two saved reports offline to immediately identify new ports, retired services, version upgrades, and posture shifts without external diff scripts or database dependencies.

---

## Why Accuracy-First Matters

Traditional high-speed scanners (masscan, rustscan, zmap) prioritize raw packets per second over semantic correctness. When facing TCP tarpits (`xt_TARPIT`), SYN proxies (`iptables -j SYNPROXY`), or port knocker defenses, they blindly classify every `SYN-ACK` as an open service.

In our controlled benchmark lab simulating an enterprise perimeter with tarpits and SYN-proxies across 1,000 ports:

| Scanner | Scan Time | Real Open Ports (16) | False Positives | Precision | Recall |
|---|---|---|---|---|---|
| **masscan** | 0.42s | 16 / 16 | **984** | **1.6%** | 100% |
| **rustscan** | 3.12s | 16 / 16 | **128** | **11.1%** | 100% |
| **nmap** (`-sS -T4`) | 48.6s | 16 / 16 | 0 | 100% | 100% |
| **portensor** (v0.6.0) | **0.86s** | **16 / 16** | **0** | **100%** | **100%** |

*The portensor row records the v0.6.0 controlled-lab measurement; matched-mode
v0.7.0 validation is recorded in
[Benchmark Validation](docs/benchmark-validation.md). For full engineering
details and lab reproduction, see
[Why Accuracy-First Matters](docs/why-accuracy-first-matters.md).*

---

## Cross-Platform Binaries

`portensor` is available as pre-compiled standalone native binaries with zero external runtime dependencies:

| Binary | Target Platform | Description |
|---|---|---|
| `portensor-linux` | Linux (x86_64 glibc) | Dynamic release binary for standard Linux distributions |
| `portensor-static-musl` | Linux (x86_64 musl) | Fully static standalone binary, runs anywhere (including Alpine / scratch) |
| `portensor.exe` | Windows (x86_64) | Native Windows executable (connect/UDP engine plus Npcap-backed IPv4 raw SYN/ACK) |

Raw IPv4 SYN and ACK discovery works on Linux/WSL2 with `CAP_NET_RAW` and on
Windows with [Npcap](https://npcap.com/) installed and the scanner run as
administrator. Linux IPv6 uses kernel-routed `AF_INET6` raw sockets; Windows
raw scanning is IPv4-only, and active OS fingerprinting remains Linux-only.
Without Npcap, the Windows binary still uses the verified connect engine and
UDP probes.

## What exists today

| Area | Current capability |
| :--- | :--- |
| Toolchain | `rust-toolchain.toml`, pinned Rust 1.99.1, `rustfmt`, `clippy` |
| CLI | `portensor scan`, `portensor smart`, `portensor diff`, `portensor merge`, `portensor distributed plan/serve/worker/agent`, `portensor doctor`, `portensor db update/status`, `portensor probes list`, `portensor scripts list/search/install/update`, guided `portensor interactive`, global `--theme` |
| Discovery | Async TCP connect scanner plus raw SYN on Linux (IPv4/IPv6) and Windows with Npcap (IPv4) (`--syn`); raw TCP ACK firewall mapping (`--ack`, RST = `unfiltered`, timeout = `filtered`) on both raw backends; optional ICMP/TCP ping sweep (`--ping-sweep`) with ARP liveness probing on IPv4 (Linux raw `AF_PACKET`, Windows `SendARP`) |
| Accuracy | 4-pillar empirical accuracy scoring (`0-100%`), `--explain`, `--min-confidence` |
| Defense awareness | Middlebox, TCP tarpit, SYN proxy, and rate-limiting detection (`--defense`) |
| Advisory correlation | Offline CVE matching against detected product/version/banner using a bundled curated database and an auto-updating local NVD mirror (`--advisories`, `portensor db update`); vendor-aware CPE identity, version suffix/prerelease normalization, and confidence-gated findings |
| Change detection | Advisory-aware baseline differential auditing (`--diff`, `--compare-to`, `portensor diff`); accepts portensor JSON, state files, and Nmap XML |
| Service detection | TCP banner grab + signature matching (SSH, HTTP, FTP, MySQL, Redis, SMB, MongoDB, memcached, …), HTTP admin-panel fingerprinting, version extraction, per-service confidence (`0.70`–`0.99`), protocol-native probes, deep SMB2/SMB1 negotiation, and multi-step declarative TOML probe packs (`--plugins`) with 60 embedded probes (13 TLS-aware) covering databases, containers/orchestration, industrial control, remote access, appliances, and message brokers (`portensor probes list`) |
| Plugin engine (Q2) | Cross-language script plugins over one JSON in/out contract (`--scripts`): sandboxed in-process WASM modules (wasmtime, no WASI, fuel/timeout bounded) or sidecar processes, manifest categories and `danger = "intrusive"` gating (`--allow-intrusive`), optional script-declared service identification that feeds scoring and advisories, `--min-severity` finding filtering, validated findings attached per port and surfaced in JSON/JSONL, table, Markdown, SARIF, and `--explain` (`portensor scripts list`), a read-only official baseline pack (`packs/official-baseline`), plus a digest-verified remote pack marketplace (`scripts search/install --registry`) |
| TLS inspection | Certificate, version, cipher, negotiated ALPN, key/signature algorithms, certificate chain, SAN, expiry, self-signed and hostname checks on direct/STARTTLS ports and on TLS plus unidentified services found on non-standard ports; direct sessions also fingerprint the HTTPS application (`--tls`, `--no-tls`) |
| UDP detection | DNS, rpcbind, SNMP, NTP, NetBIOS (137), SIP (5060), SSDP M-SEARCH (1900), mDNS service-type enumeration (5353), and BACnet/IP Who-Is (47808) via `--udp` flag, including IPv6 (`src/udp.rs`) |
| OS fingerprinting | Active TCP/IP stack analysis over IPv4 and IPv6 (TTL, Window, MSS, WScale, SACK, TS) via `--os` on Linux raw sockets (`src/fingerprint.rs`); samples up to `--os-probes N` open ports per host (default 3, max 8), records an independent family/confidence/evidence result for every sampled endpoint, and summarizes single-OS hosts or reports `mixed` when strong endpoint evidence conflicts (for example a Linux TLS edge in front of Windows ADFS); per-endpoint results appear in JSON, tables, Markdown, HTML, and Nmap XML; Windows host roles are refined to Domain Controller / Member Server / Workstation from open service ports |
| Port presets | Curated engagement port sets via `--preset dc|ad`, `win|ws`, `web|http`, `linux|lx`, `ot|ics|scada`, `full|all`, and `q|top` (nmap top-1000 fidelity) with `--preset` conflict rules |
| Connect timeout | Independent per-connect timeout ceiling via `--connect-timeout-ms` that overrides the `--timeout` seconds default |
| Rate auto | Adaptive target politeness for connect scans: backs off on timeout, ICMP-unreachable, and tarpit/handshake-silent bursts (`--rate-auto`); raw SYN AIMD also reacts to ICMP errors and high-density SYN-open anomalies |
| Per-host concurrency | Optional cap on simultaneous connect attempts per target host (`--host-concurrency N`, 0 = unlimited); also applied to SYN-open verification |
| Distributed scans | Stable FNV-1a target sharding (`--shard-index`/`--shard-count`), `portensor merge` for JSON/JSONL reports, and a token-authenticated coordinator with local-plan, polling-worker, and push-agent modes plus optional HTTPS (`--tls-cert`/`--tls-key`, `--ca-cert`) (`portensor distributed`) |
| Evasion | Random delay jitter, configurable TTL/hop limit, custom SYN source-port range, IPv4 SYN decoys, and IP fragmentation (`--jitter-ms`, `--ttl`, `--source-port-range`, `--decoys`, `--fragment-size`) |
| Resumable scans | Smart `--resume FILE` with pre-scan gap analysis audit + `--save-state FILE` (`src/resume.rs`) |
| Signal handling | Graceful Ctrl-C/SIGTERM: workers stop, partial results printed, state saved |
| Diagnostics | Opt-in structured JSON stderr logs (`--log-level`, `PORTENSOR_LOG`) for scan retries, distributed job lifecycle, and delivery failures; secrets and payloads are omitted |
| Output formats | `table`, `json`, `jsonl`, `csv`, `host-port`, `nmap-xml`, `greppable`, `sarif`, `markdown`; dark/light/hacker/minimal themes |
| Supply chain | `cargo audit`/`cargo deny`, fuzz targets, checksums, optional GPG/cosign signing (`make deny`, `make fuzz`, `make sign`) |
| Packaging | Static musl binary (`make musl`), Dockerfile (scratch), man page (`make man`), local Homebrew/Scoop/Chocolatey/AUR/Compose metadata (`make package-check`) |
| Safety | Global token-bucket rate limit, file-descriptor-aware workers, target caps |
| Lab | WSL2/Linux network namespace with open/closed/DROP/tarpit/rate-limited/SYN-proxy targets |
| Benchmarks | Dependency-free lab harness plus matched-mode localhost validation for portensor, nmap, masscan, and rustscan |
| Docs | Architecture, benchmark contract, Phase 0-6 gates, Phase 8-9 gates, live validation |

## Live Validation — Metasploitable 2

Validated end-to-end across Windows 11 (`portensor.exe`) and Linux WSL2 (`portensor-static-musl` and `portensor-linux`) against a Metasploitable 2 target at `192.168.100.37`.

All 19 vulnerable services were discovered with zero false positives. See the full 10-scenario test report in [Comprehensive Live Test Suite](docs/live-metasploitable-full-suite.md).

```bash
# Linux / WSL2 Raw SYN + OS + Service Discovery:
sudo portensor scan --syn --os --target 192.168.100.37 --top-ports 100

# Windows Native Fast Top-Ports Discovery:
.\portensor.exe scan --target 192.168.100.37 --top-ports 100
```

**18/18 open ports in 1.77 s**, zero false positives:

| Ports | Detected service | Evidence |
| :--- | :--- | :--- |
| 21 | `ftp` vsFTPd 2.3.4 | `220 (vsFTPd 2.3.4)` |
| 22 | `ssh` OpenSSH 4.7p1 | SSH identification string |
| 23 | `telnet` | Telnet negotiation |
| 25 | `smtp` Postfix | `220 ... ESMTP Postfix (Ubuntu)` |
| 80 | `http` Apache 2.2.8 | HTTP response |
| 111 | rpcbind | TCP open + UDP rpcbind reply |
| 512 | `exec` | `Where are you?` |
| 1524 | `shell` | `root@metasploitable:/#` |
| 3306 | `mysql` MySQL 5.0.51a-3ubuntu5 | MySQL handshake |
| 3632 | distccd | TCP open |
| 5432 | PostgreSQL | TCP open |
| 5900 | `vnc` 3.3 | `RFB 003.003` |
| 6000 | X11 | TCP open |
| 6667, 6697 | `irc` | UnrealIRCd welcome/notice |
| 8009 | Tomcat AJP | TCP open |
| 8180 | `http` Apache-Coyote 1.1 | HTTP response |
| 8787 | `ruby-drb` | DRb error banner |

Passive OS fingerprint: **Linux 2.6.x**, confidence 100%, initial TTL 64,
window 5840, no timestamps. UDP `--udp` found DNS (53), rpcbind (111), and
NetBIOS-NS (137, host `METASPLOITABLE`) in 1.5 s.

Resume was validated with a randomized 17-port scan interrupted after one
second: the state file recorded the 9 ports actually probed, and
`--resume` without repeating `--ports` read the saved port spec, scanned only
the remaining 8, and merged all 17 planned outcomes. State files now retain
every outcome (open/closed/filtered/silent) so resuming cannot silently lose
ambiguous probes.

**Timing note:** Metasploitable's Postfix takes about 2 s to emit its banner.
The default `balanced` window is 300 ms and can mark SMTP `silent` on a loaded
VM; use `--probe-timeout-ms 2500` (or a longer timeout) for this target.
Full commands and raw results are in
[docs/live-test-metasploitable.md](docs/live-test-metasploitable.md).

### Authorized HTB validation

Scope-guarded lab runs are documented in
[bench/htb/README.md](bench/htb/README.md) (Garfield: 22/22 AD ports via
two-pass discovery) and [bench/htb/redeye.md](bench/htb/redeye.md) (RedEye v2:
4/4 exact match, explicit SNI, and endpoint-aware mixed Linux-edge/Windows-ADFS
OS reporting). These are authorized, user-provided targets; no exploitation was
performed.

### IPv4 vs. IPv6 Comparative Live Validation (Phase 9)

In Phase 9 (v0.3.0), comprehensive dual-stack validations were conducted comparing local lab targets and external educational systems across IPv4 and IPv6:

| Target | Protocol | Address | Findings | Elapsed | Accuracy & Evidence |
| :--- | :---: | :--- | :--- | :---: | :--- |
| **Metasploitable 2** | IPv4 | `192.168.100.37` | **16 open ports** (FTP, SSH, Telnet, SMTP, HTTP, MySQL, PostgreSQL, VNC...) | 9.55s | 85%–100% confidence, OS: Linux 2.6.x (100%), Defense: Direct/SYN-Proxy (92%), CVE Advisories matched |
| **Metasploitable 2** | IPv6 | `fd24:91bb:6122:1600::37` | **2 open ports** (22/SSH OpenSSH 4.7p1, 5432/PostgreSQL) | 1.52s | 95% (SSH), 65% (PostgreSQL); IPv4-only services cleanly isolated |
| **scanme.nmap.org** | IPv4 | `45.33.32.156` | **Port 22/SSH** (`OpenSSH 6.6.1p1`) | 1.51s | 95% confidence, 215ms WAN latency verification |
| **scanme.nmap.org** | IPv6 | `2600:3c01::f03c:91ff:fe18:bb2f` | **0 open** (All 5 ports filtered) | 1.50s | Cleanly detected missing WAN IPv6 routing with 0% false positives |

#### Differential Network Drift Analysis (`portensor diff`)
Comparing the IPv4 baseline against the IPv6 scan using `portensor diff`:
```text
Network State Differential Analysis (vs reports/metasploitable2-phase9-live.json):
────────────────────────────────────────────────────────────────────────────────
[-] GONE    192.168.100.37:21     ftp vsFTPd/2.3.4           (advisories +0 -1)
[-] GONE    192.168.100.37:22     ssh OpenSSH/4.7p1          (advisories +0 -1)
[-] GONE    192.168.100.37:80     http Apache/2.2.8          (advisories +0 -2)
... [16 ports shifted]
[+] NEW     fd24:91bb:6122:1600::37:22 ssh OpenSSH/4.7p1    (Confidence: 95%)
[+] NEW     fd24:91bb:6122:1600::37:5432                     (Confidence: 65%)

Diff Summary: 2 new | 16 closed/gone | 0 modified | 0 posture shifted (0 unchanged)
```
For the full technical breakdown, see [Empirical Comparative Analysis: IPv4 vs. IPv6 Network Scanning](reports/live-testing-metasploitable-and-scanme-ipv6.md).

## Live Permitted-Range Benchmark (v0.4.0)

Fresh same-day live measurements (2026-11-09) on ranges where scanning is
explicitly permitted, documented with raw outputs and per-run wall clocks in
[docs/bench-results.md](docs/bench-results.md) and verbatim artifacts in
[`bench-artifacts/`](bench-artifacts/). Nothing here is estimated.

### Ranges and permissions

| Range | Permission basis | Measured traffic |
| :--- | :--- | :--- |
| `127.0.0.0/24` loopback sweep | Own machine | 3 × portensor full-range sweeps + 1 × nmap `-sT` reference |
| `172.22.64.1` (WSL2 NAT gateway, Windows host) | Own machine | Full cross-tool matrix: portensor ×12, masscan ×4, rustscan ×3, nmap `-sS` ×1 |
| `45.33.32.156` (scanme.nmap.org) | Nmap's published permission banner ("authorized to scan this machine with Nmap or other port scanners") | Held to ≤3,000 pps, one full-range pass per tool |

### Results — own-machine NAT gateway (`172.22.64.1`, 65535 ports)

The Windows host answers SYN-ACK on exactly 6 of 65,535 ports
(80, 135, 139, 445, 2179, 49668; nmap `-sS -T4` ground truth at 87.4 s).

| Tool / mode | Wall (s) | 6-port accuracy |
| :--- | :--- | :--- |
| portensor `--syn --connect-only`, unlimited | 1.58–1.61 | 6/6 ×3 |
| portensor `--syn --connect-only`, 10k pps | 7.17–7.19 | 6/6 ×3 |
| portensor `--syn` verified, unlimited | 2.58–2.93 | 2/6 (deliberately conservative: banner-less Windows services demoted) |
| masscan 100k pps | 5.44 | 6/6 |
| masscan 10k pps | 42.7–120+ (non-deterministic exit artifact) | 6/6 |
| rustscan TCP connect | 18.6–19.4 | 6/6 ×3 |
| nmap `-sS -T4` | 87.39 | 6/6 |

Rate caps are honored exactly after the AIMD hardening shipped in v0.4.0
(65,535 ports at 10k/2k/500 pps complete in 8.2/33.6/132 s — within 1.5% of
the ideal `ports/rate` curve).

### Results — loopback sweep (`127.0.0.0/24`, 65535 probes)

| Tool | Wall (s) | Result |
| :--- | :--- | :--- |
| portensor `--syn --connect-only` /24 sweep | 35.3–40.5 ×3 | finds the real `127.0.0.53:53` (systemd-resolved) listener ×3 |
| nmap `-sT -T4` /24 sweep | >300 (timed out) | same listener, much slower |

### Results — scanme.nmap.org (authorized live target)

Measured sequence, all ≤3,000 pps (masscan/portensor/nmap `-sS` raw legs and
TCP-connect legs):

1. Pre-test baseline HTTP fetch of `scanme.nmap.org` succeeded (the target was
   reachable).
2. Every raw-SYN leg (portensor raw, masscan, nmap `-sS`) returned **zero
   responses from the internet through the WSL2 NAT** — the Hyper-V vSwitch
   does not map raw-crafted SYN/SYN-ACK flows; curl-style TCP connects work
   where raw SYN does not. This is the same environment property that made
   the `192.168.100.37` lab the right place for raw-SYN validation.
3. After the first parallel-capacity burst (nmap `-sS -T4` full range,
   rustscan `-b 3000`), the target's firewall rate-limited the test IP:
   subsequent curl/connect legs to `45.33.32.156:80` timed out from both the
   WSL guest **and** the Windows host, while general egress (example.com HTTP,
   8.8.8.8 ping) stayed healthy. All further scanme legs therefore measured
   empty, and all scanme traffic was stopped at that point.
4. After the rate-limit cleared (baseline HTTP fetch OK again), a single
   gentle re-verification leg was run: top-1000, ≤1,000 pps, one pass,
   TCP-connect engine (`--syn --connect-only`). portensor completed with full
   classification in 3.9 s cold / 1.7 s warm — 22 and 80 open (2/2),
   998 correctly classified `closed`, **0 filtered/misclassified**, and the
   defense layer tagged the target `direct_host` with listener-verified
   evidence on both ports. The nmap `-sT -T3` reference needed 24.5 s for the
   same 2 opens (raw logs: `bench-artifacts/live/scanme_gentle_*.txt`).

### Comparison — LAN lab vs out-of-network authorized target

Against the documented Metasploitable 2 LAN suite (same engine), the
out-of-network authorized target behaves like this:

| Dimension | Metasploitable 2 (LAN lab, historical suite) | scanme.nmap.org (internet, gentle leg) |
| :--- | :--- | :--- |
| Open TCP surface | ~18 textbook services (FTP/SMTP/VNC/…) all banner-identified | exactly 2 (SSH :22, HTTP :80), no service banners grabbed in connect-only mode |
| Classification quality | full `open/closed` split over the whole range | full `open/closed` split over the whole range (998 closed, 0 errors) |
| Target behavior | everything answered, never varied | only observed ports answered; ~425–611 ms measured port latency vs ~1–3 ms in the lab |
| Defense layer | direct host | `direct_host` with standard semantics on every open port |
| Scan load the target survived | sustained full-rate bursts | rate-limited a high-parallelism burst (≈3k pps), then accepted a 2× gentle ≤1k-pps pass |
| Engine advantage | raw-SYN mode possible (unlimited rate) | connect engine only (WSL2 NAT raw-egress limitation), still `6-14×` faster than nmap `-sT` |

The engine gives the same accuracy class in both environments; what changes
off-LAN is transport (raw SYN unavailable through WSL2 NAT), latency
(~2 orders of magnitude), and the loading behavior of the far end — full
cycle results, environment caveats, and repro instructions live in
[docs/bench-results.md](docs/bench-results.md).

### Analysis

- **Where the SYN engine is intended to run, it wins on both axes tested:**
  full-range completed answers in 1.6 s with the same accuracy as masscan's
  SYN layer, and the verified mode trades runtime (2.6 s) for service
  classification instead of completeness; use `--connect-only` when the
  open/closed question is the goal.
- **Parallel-capacity engines can trip target rate limits even at 3k pps.**
  The scanme rate-limit event demonstrates the correct operational response:
  cap rates (`--rate`), limit full-range passes, and stop immediately when the
  target starts dropping everything. Adaptive target politeness now covers the
  common mid-scan signals: connect scans under `--rate-auto` back off on
  timeout, ICMP-unreachable, and tarpit/handshake-silent bursts, while raw SYN
  AIMD treats ICMP Destination Unreachable and high-density SYN-open anomalies
  (`--anomaly-threshold`) as explicit pressure even when the ordinary response
  ratio is high or below the silent-path floor. The configured `--rate` remains
  the hard ceiling.
- **Raw SYN egress through WSL2 NAT is fundamentally unavailable.** Internet
  raw SYN testing from this setup requires a Linux host/VM with a bridged
  NIC — the engine is correct (lab + NAT-gateway results), the transport
  environment is the limitation; this is documented rather than papered over.
- **masscan's capped-mode WSL2 exit artifact** (progress readout never exits)
  makes its 10k-pps wall here a lower-bound artifact; uncapped masscan
  (5.44 s) remains the fair reference, and portensor is 3.4× faster at that
  effective rate in `--connect-only` mode.

## Requirements

- Linux, WSL2 with Ubuntu 22.04+, or Windows 10/11.
- Rust 1.99.1 (the pinned toolchain is installed automatically by `rustup`).
- Python 3.10+ for the lab and benchmark harness.
- Linux root only for `make lab`, `--syn`, and `--ack`; the other CLI paths and tests do not need root.
- Windows raw scanning requires Npcap plus an elevated terminal; no extra Rust dependency is needed.
- Optional: `musl-tools` (`sudo apt-get install -y musl-tools`) for `make musl`.
- Optional comparison tools: `nmap`, `masscan`, `rustscan`.
- Optional release checks: `actionlint`, `cargo-audit`, and `cargo-deny` for
  `make release-check`.

On this machine Rust lives in WSL2, not Windows:

```bash
wsl -e bash -lc 'source "$HOME/.cargo/env"; rustc --version'
```

## Build and test

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
cargo build --release --locked
python3 -m unittest discover -s bench/tests -t . -v
```

Or:

```bash
make ci
```

Before creating a release tag, run the full preflight from a clean worktree:

```bash
make release-check
```

It validates every GitHub Actions workflow, checks version consistency, SBOM
coverage, and release checksums, then runs the Rust and Python suites plus audit
and deny. See [Release process](docs/release-process.md) for the complete
checklist.

## Usage

```bash
# Scan target directly (defaults to 1-1024 standard ports):
portensor scan --target 127.0.0.1

# Scan top N most common ports:
portensor scan --target 10.77.0.2 --top-ports 100

# Specify specific ports or ranges:
portensor scan --target 10.77.0.2 --ports 80,443,3306,8080,8081 --json
portensor scan --target 10.0.0.0/24 --ports 22,80,443 --profile careful
sudo portensor scan --syn --target 10.77.0.2 --ports 1-65535 --json
```

### Interactive setup and diagnostics

```bash
# Guided setup; requires a terminal and offers raw SYN only when available
portensor interactive

# Check platform, terminal, workers, config, UDP, raw-SYN, and route readiness
portensor doctor
portensor doctor --json

# Choose a palette for tables, progress, and diagnostics
portensor scan --target 127.0.0.1 --theme cyber
```

Themes are `dark` (default), `light`, `hacker`, `cyber` (vibrant magenta & cyan high-contrast palette), and `minimal`. `minimal`
disables color, and `NO_COLOR` or a non-TTY stdout also disables ANSI styling.
The interactive wizard covers target, port strategy, profile, scan mode, UDP,
output format, and output file; it never invokes a raw mode it cannot support.
It prints the shared scan-plan model before starting and can save that model as
JSON.

### Explainable smart plans

`portensor smart` reuses the normal scan flags and prints a deterministic plan
before running: profile, mode, targets, ports, estimated probes, required
privileges, explicit defaults, fallbacks, scope, and risk notes. `--dry-run`
performs no probes and is the safe way to review or machine-parse a plan:

```bash
# Review the plan without sending any probe:
portensor smart -t 10.0.0.0/24 --top-ports 1000 --scope scope.toml --dry-run

# Machine-readable plan:
portensor smart -t 10.0.0.5 -p 22,80,443 --dry-run --plan-json

# Execute the same plan (printed to stderr), or save the model:
portensor smart -t 10.0.0.5 -p 22,80,443
portensor smart -t 10.0.0.5 -p 22,80,443 --dry-run --plan-output plan.json
```

When raw privileges are available, automatic mode selects raw SYN; when they
are not, it reports the connect fallback instead of failing. See
[Pipeline presets](docs/pipelines.md) for chaining formats and report examples.

### Discovery vs. Verification Modes & Port Prioritization

Portensor decouples rapid network discovery from in-depth verification:

| Mode | Command Flag | Time (1,024 ports) | Service Banners | OS Evidence | Best For |
|---|---|---|---|---|---|
| **Verified Scan** (Default) | *(standard scan)* | **~6.2 s** | Yes (full probe) | Yes (with `--os`) | Auditing, elimination of tarpits/proxies |
| **Fast Discovery** | `--discover-only` | **~1.52 s** (4× faster) | Skipped (0 ms wait) | SYN handshake only | Perimeter mapping, massive sweeps |

```bash
# Ultra-fast discovery mode (disables banner read timeouts):
portensor scan --target 192.168.100.37 --discover-only

# Top-ports-first prioritization (default in 'fast' and 'balanced' profiles):
# Scans prevalence-ranked ports (HTTP, SSH, MySQL...) first; first open ports show up < 50ms:
portensor scan --target 192.168.100.37

# Disable top-ports prioritization to preserve numeric sequence:
portensor scan --target 192.168.100.37 --no-top-ports-first
```

### TCP ACK Firewall Mapping (`--ack`)

`--ack` sends stateless TCP ACK probes to map firewall behavior without
completing a handshake. A RST whose sequence number echoes the cookie placed in
the probe's acknowledgment field means the packet reached a host or a stateless
device that answered (`unfiltered`); no response within the timeout means the
probe was dropped (`filtered`). ACK scanning cannot distinguish open from closed
ports, so services, OS fingerprinting, UDP, advisories, plugins, and scripts are
disabled automatically, and only `unfiltered` results are shown by default.

```bash
# Map unfiltered TCP ports through a firewall (Linux root/CAP_NET_RAW):
sudo portensor scan --ack --target 192.168.100.37 --ports 1-1024 --json

# ACK probes honor probe shaping shared with SYN scans:
sudo portensor scan --ack --target 192.168.100.37 --top-ports 100 \
    --ttl 64 --source-port-range 40000-40100
```

On Windows, run the same commands from an elevated PowerShell with Npcap
installed (IPv4 only):

```powershell
.\portensor.exe scan --syn --target 10.77.0.2 --ports 1-65535 --json
.\portensor.exe scan --ack --target 10.77.0.2 --ports 1-1024 --json
```

ACK mode is available for IPv4 everywhere raw scanning is available and for
IPv6 on Linux only. It accepts `--retries`, `--timeout`,
`--rate`, `--ttl`, and `--source-port-range`, and rejects `--decoys`,
`--fragment-size`, `--format port-list`, and `--format host-port` (those
renderers expose only open/closed results). Loopback validation in a Linux
network namespace returns `unfiltered` for both open and closed ports on
`127.0.0.1` and `::1`, and an `iptables`/`ip6tables` INPUT `DROP` rule turns the
result into `filtered`. Adaptive AIMD rate control is disabled in ACK mode so
intentional firewall drops do not throttle the sweep.

### Real-Time Live Results Table & Deduplication

During scans, `portensor` dynamically streams open and responsive ports to a live table directly above the progress bar without interfering with progress updates. Retried or ambiguous candidates are deduplicated in memory so each port is displayed cleanly once.
To disable the live table stream and display only the final summary table, pass `--no-live`.

### Unified Accuracy Scoring Engine (`--explain` & `--min-confidence`)

Rather than treating every responsive port as an opaque `open` state, `portensor` computes an objective **Accuracy Score (0–100%)** grounded in 4 empirical criteria:

1. **TCP Handshake (20%)**: Valid 3-way handshake established without truncation.
2. **Application Banner / Payload (40%)**: Verified protocol handshake (SSH, HTTP, MySQL, Redis, SMB, etc.) or responsive application data.
3. **Stack & OS Conformance (20%)**: TCP/IP options, TTL, and window scale match operating system fingerprinting norms.
4. **Behavioral Stability (20%)**: Predictable RTT latency without packet loss retries or anomalous RST teardowns.

```bash
# Print comprehensive diagnostic evidence breakdown for port 22:
sudo portensor scan --syn --os --target 192.168.100.37 -p 22 --explain 22

# Explain all open ports on target:
sudo portensor scan --syn --os --target 192.168.100.37 --explain

# Filter out low-confidence/ambiguous candidates (require >= 90% confidence):
portensor scan --target 192.168.100.37 --min-confidence 90
```

`--explain` also prints the identification detail tag (`plugin:<pack>/<probe>`
for probe matches), extracted CPE, and protocol facts collected in
`service.info`.

### Defense Awareness & Middlebox Classifier (`--defense`)

Enterprise and cloud environments frequently mask service availability using middleboxes, firewalls, and deception defenses. Rather than mistaking these behaviors for real open services or silent drops, `portensor` actively analyzes handshake discrepancies, silent response ratios, and latency patterns to classify host defense posture:

- `[CLEAN] Direct Host`: Genuine end-host behavior without middlebox interference.
- `[NOTICE] Rate-Limiting Active`: Probe drops detected under burst rates (suggests reducing `--rate` or using `--profile careful`).
- `[WARNING] TCP Tarpit Active`: `xt_TARPIT` or honeypots holding TCP handshakes indefinitely without delivering application data.
- `[WARNING] SYN-Proxy Middlebox Detected`: `iptables SYNPROXY` or hardware proxies answering SYN probes but failing backend TCP completion.
- `[WARNING] Layer-7 WAF / DPI Detected`: Deep-packet inspection RSTs triggered by application payloads.
- `[CRITICAL] Heavy Middlebox / Deception Detected`: Multi-layer deception combining proxies, tarpits, and filtering.

```bash
# Force display of defense intelligence even for clean direct hosts:
portensor scan --target 192.168.100.37 --defense

# Defense intelligence is automatically embedded in all --json reports:
portensor scan --target 192.168.100.37 --json
```

### Offline CVE Advisory Correlation (`--advisories` & `portensor db`)

`portensor` correlates detected service identity (product, version, and banner context) against two offline sources:

1. A small bundled curated database (`data/advisories.json`) with hand-verified version and banner gates.
2. A local NVD mirror built from the official CVE 2.0 feeds, covering CVEs from 1999 through the current year (401,682 CVEs / 325,837 product mappings as of November 2026).

Correlation is advisory only: it never sends extra probes, and findings must be confirmed against current vendor advisories.

- Severity is derived from CVSS (Critical >= 9.0, High >= 7.0, Medium >= 4.0).
- Version rules support exact, upper-bound, range, and all-version matches, so patched releases are not flagged.
- Curated banner gates prevent ambiguous matches (for example the Debian OpenSSL PRNG issue only matches Debian/Ubuntu SSH banners).
- NVD matches use exact CPE vendor/product identities when a plugin supplies a `service.cpe`, otherwise a conservative built-in product alias table; CPE identities are never broadened across vendors.
- Explicit NVD version bounds are strict: malformed bounds reject the record instead of widening it, and a wildcard CPE in the same product mapping cannot override a narrower range.
- Versions preserve patch and distro suffixes such as `4.7p1`, `1.0.2u`, and `5.0.51a-3ubuntu5`, compare numeric components numerically, and order prerelease markers before the final release.
- New CVEs that only have CNA-supplied data are indexed but not correlated until NVD publishes CPE configurations.
- Low-confidence NVD matches are discarded (`confidence < 0.55`). Exact-version evidence starts at `0.90`, ranges at `0.80`, and all-version records at `0.60`, scaled by service identification confidence; records marked as affecting all versions are therefore suppressed unless the service was identified with a version.

```bash
# One-time full sync (all yearly feeds, 2002-2026) plus the rolling recent feed:
portensor db update

# Faster initial subsets, forced re-downloads, and coverage/status inspection:
portensor db update --years 2024-2026
portensor db update --years 2024,2025 --force
portensor db status
portensor db status --json

# Correlate detected service versions against curated + local NVD data:
portensor scan --target 192.168.100.37 --advisories

# Disable the automatic recent-feed check for isolated or offline scans:
portensor scan --target 192.168.100.37 --advisories --no-db-update

# Download and index the full CISA KEV and EPSS feeds (24-hour cache):
portensor db intel
portensor db intel --force --json
```

`portensor db intel` downloads the complete CISA Known Exploited Vulnerabilities
catalog and the current EPSS CSV, merges them with the bundled fallback set, and
writes an atomic gzip index to `<db>/intel/threat_intel.json.gz`. Advisory scans
overlay that cache automatically. Use `--force` to bypass the 24-hour freshness
window, for example in a scheduled intelligence refresh. A live refresh on
2026-11-09 indexed 1,775 KEV CVEs and 402,199 EPSS-scored CVEs.

Once initialized, every scan performs a lightweight check of the NVD `recent` feed and applies new or changed CVEs automatically (a few seconds when nothing changed). A full sync must be run manually once to bootstrap the database; without it, scans use only the bundled curated database and print a hint when `--advisories` is requested. Update failures never fail the scan. Schema 2 stores CPE vendor identities; databases created by older releases are ignored and rebuilt by rerunning `portensor db update`.

The database lives in a user-writable data directory, resolved in this order: `--db-dir <DIR>`, `PORTENSOR_DB_DIR`, then `%APPDATA%\portensor\db` on Windows or `$XDG_DATA_HOME/portensor/db` (`~/.local/share/portensor/db`) elsewhere. A full mirror is roughly 275 MB and grows over time; yearly feeds and 256-way product shards keep lookups fast, and a lock file prevents concurrent updates.

```text
Vulnerability Advisory Correlation:
──────────────────────────────────────────────────────────────────────
  192.168.100.37:21/tcp (ftp vsFTPd/2.3.4)
    [CRITICAL] CVE-2011-2523  CVSS 10.0  vsftpd 2.3.4 backdoor command execution
    [HIGH] CVE-2021-3618  CVSS 7.4  ALPACA is an application layer protocol content confusion attack...
  192.168.100.37:22/tcp (ssh OpenSSH/4.7p1)
    [HIGH] CVE-2008-0166  CVSS 7.8  Debian OpenSSL PRNG flaw enables weak SSH keys
    [CRITICAL] CVE-2023-38408  CVSS 9.8  The PKCS#11 feature in ssh-agent...
    ...
    ... and 61 more (see JSON output for the full list)
  192.168.100.37:80/tcp (http Apache/2.2.8)
    [HIGH] CVE-2011-3192  CVSS 7.8  Apache Range header memory-exhaustion denial of service
    [MEDIUM] CVE-2007-6750  CVSS 5.0  Apache Slowloris partial-request denial of service
    [CRITICAL] CVE-2009-3555  CVSS 9.8  The TLS protocol...
    ...
    ... and 91 more (see JSON output for the full list)

  175 advisory match(es) across 3 open service(s); offline CVE correlation (curated + local NVD database) — verify against vendor advisories.
```

The table renderer adds an `ADVISORIES` column summarizing the highest-ranked match per port, `--explain` includes an `Advisory Matches:` breakdown, and JSON/JSONL results include an `advisories` array on each port object. Each match carries a `source` of `curated` or `nvd`, a `confidence` score, and an `evidence` label (`curated`, `exact_version`, `version_range`, or `all_versions`). Human-readable sections show at most 10 matches per service; JSON/JSONL always contains the full list. Curated matches are listed first (they carry hand-verified version and banner gates), followed by NVD matches; each group is sorted by severity. When both sources report the same CVE, the curated entry is kept.

### CISA KEV & EPSS Threat Prioritization (`--kev-only` & `--min-epss`)

In fast-paced penetration tests and bug bounty engagements on platforms like HackerOne or Bugcrowd, CVSS score alone is insufficient for triage: an informational or medium vulnerability with an active weaponized exploit in the wild often poses greater immediate risk than an unexploited critical flaw.

`portensor` enriches advisory correlation with two operational threat intelligence feeds:
1. **CISA Known Exploited Vulnerabilities (KEV)**: Actively weaponized vulnerabilities confirmed by CISA to be exploited in the wild. Flagged with a prominent `[KEV]` badge in terminal tables, explain output, markdown, and JSON.
2. **FIRST.org Exploit Prediction Scoring System (EPSS)**: Probability score ($0.0$ to $1.0$, rendered as $0.0\%$ to $100.0\%$) estimating the likelihood of exploitation activity within 30 days.

```bash
# Filter advisory findings to only services with confirmed CISA KEV exploits:
portensor scan --target 192.168.100.37 --kev-only

# Filter for vulnerabilities with high exploitation probability (EPSS >= 50%):
portensor scan --target 192.168.100.37 --min-epss 0.50

# Combine KEV filter with Markdown executive reporting:
portensor scan --target 192.168.100.37 --kev-only --format markdown -o report.md
```

### Scope Guard Boundary Protection (`--scope` & `--force-out-of-scope`)

The primary legal and operational hazard in authorized penetration testing and bug bounty engagements is scanning outside the agreed perimeter. `portensor` includes a dedicated **Scope Guard Engine** (`src/scope.rs`) that enforces target boundaries before any probe packet leaves the host.

A scope file (`scope.toml` or line-based target list) defines allowed and denied CIDRs, IP ranges, and wildcard domains:

```toml
[scope]
program = "HackerOne - Target Engagement"
allow = [
    "*.example.com",
    "10.0.0.0/8",
    "172.16.1.1-172.16.1.50",
    "2001:db8::/32",
]
deny = [
    "admin.example.com",
    "10.0.5.1",
]
```

```bash
# Safe scan guarded by engagement scope:
portensor scan --target api.example.com --scope scope.toml

# Scanning an out-of-scope target fails immediately with a legal violation error:
portensor scan --target out-of-scope.net --scope scope.toml
# Error: SCOPE VIOLATION: Target 'out-of-scope.net' is NOT in the authorized scope for program 'HackerOne - Target Engagement'. Scan aborted for legal safety.

# Explicitly override scope enforcement with auditable warnings:
portensor scan --target out-of-scope.net --scope scope.toml --force-out-of-scope
```

`--target-file` and `@file` contents are expanded before scope validation, so a
denied domain cannot bypass the guard by being placed in a file. Domain allow
rules authorize the addresses that the domain resolves to, while explicit IP,
CIDR, and range targets must independently match an IP allow rule. Deny rules
always win, including when a domain resolves to a denied address.

### Real-Time Streaming Output for Offensive Pipelines (`--stream`)

When orchestrating toolchains in bug bounty reconnaissance (such as piping portensor outputs directly into downstream fuzzers, directory bruteforcers, or parameter analyzers like `H1Hunter`, `ParamOracle`, or `Shadow Octopus`), waiting for a full 65,535-port scan to terminate creates unnecessary pipeline latency.

Passing `--stream` writes verified open port findings line-by-line as unbuffered JSONL directly to `stdout`:

```bash
# Stream verified open ports in real-time to jq or Unix pipelines:
portensor scan --target 192.168.100.37 -p 1-65535 --stream | jq -c '{port: .port, service: .service.name}'

# Pipe discovered web endpoints into curl or HTTP fuzzing tools immediately:
portensor scan --target 192.168.100.37 --stream | while read -r line; do
    PORT=$(echo "$line" | jq -r '.port')
    echo "[+] Pipeline triggered for port $PORT immediately"
done
```

Streamed records are emitted as soon as the scan stage verifies a port and
include the banner/service metadata collected at that point. TLS inspection,
plugin matches, advisory correlation, KEV/EPSS filters, and diff data run after
the scan and are not backfilled into streamed lines; use the final JSON/report
output when those fields are required.

### Network State Change Detection & Differential Auditing (`--diff` & `portensor diff`)

`portensor` provides built-in differential change detection to track perimeter drift, newly opened ports, vanished services, version upgrades, and defense posture shifts without requiring external diff scripts. Baselines can be portensor JSON reports, `--save-state` files, or Nmap XML reports (`nmap -oX`):

```bash
# 1. Compare live scan against an existing baseline scan or state file:
portensor scan --target 192.168.100.37 --diff /tmp/baseline.json

# 2. Standalone offline diff between any two saved JSON, state, or Nmap XML reports:
portensor diff /tmp/yesterday.json /tmp/today.json

# 3. Migrate a Nmap baseline without converting it first:
portensor diff /tmp/nmap-baseline.xml /tmp/today.json

# 4. Machine-readable JSON diff output for CI/CD and security monitoring:
portensor diff /tmp/yesterday.json /tmp/today.json --json
```

Nmap XML import reads TCP `<port>`, `<state>`, and `<service>` elements
(including IPv6 hosts and XML entities). UDP ports and aggregate
`<extraports>` counts are ignored because the diff model is TCP-only and
cannot expand Nmap's aggregated closed-port ranges.

**Differential Output Format:**
```text
Network State Differential Analysis (vs /tmp/baseline.json):
──────────────────────────────────────────────────────────────────────
[*] CHANGED 192.168.100.37:22     ssh OpenSSH/7.4 → ssh OpenSSH/8.9
[-] GONE    192.168.100.37:80     http nginx/1.14.0          (http nginx/1.14.0 (Was: open))
[+] NEW     192.168.100.37:443    https nginx/1.24.0         (https nginx/1.24.0 (Confidence: 98%))
[~] POSTURE 192.168.100.37        [CLEAN] Direct Host → [NOTICE] Rate-Limiting Active

Diff Summary: 1 new | 1 closed/gone | 1 modified | 1 posture shifted (12 unchanged)
```

#### Practical Daily Workflow: Baseline → Scan → Diff

Here is how security teams integrate `portensor` into automated daily perimeter monitoring:

```bash
# Day 1 (Monday): Establish clean baseline snapshot of target infrastructure:
sudo portensor scan --syn --os --target 192.168.100.0/24 --top-ports 100 \
    --save-baseline /var/log/portensor/baseline.json --json -o monday.json

# Day 2 (Tuesday): Run daily audit, write a change alert, and fail CI on any drift:
sudo portensor scan --syn --os --target 192.168.100.0/24 --top-ports 100 \
    --diff /var/log/portensor/baseline.json \
    --alert-file /var/log/portensor/alert.txt --fail-on-change \
    --json -o /var/log/portensor/tuesday.json

# Offline Investigation: Perform offline differential comparison between any historical scans:
portensor diff /var/log/portensor/baseline.json /var/log/portensor/tuesday.json

# CI/CD: the same check in one command, no jq required (exit 0 = no change, 1 = drift):
portensor diff /var/log/portensor/baseline.json /var/log/portensor/tuesday.json \
    --alert-file /var/log/portensor/alert.txt --fail-on-change
```

`--alert-file` writes a compact, timestamp-free alert on every run
(`status: no changes` or `status: changes detected` plus one line per change),
so it can be tailed, shipped to a SIEM, or sent as a webhook payload. Update
the baseline only after accepting the drift: `--save-baseline` writes the JSON
report of the current run in the same format `--diff` consumes. Existing Nmap
deployments can seed the same workflow with `nmap -oX`: pass the XML report to
`--diff` or `portensor diff` directly; subsequent `--save-baseline` files are
portensor JSON.

### Feeding Other Tools (`--format host-port`, `--exclude-ports`)

```bash
# Pipe open ports straight into httpx for probing/title/tech detection:
sudo portensor scan -t 10.0.0.0/24 -p 1-65535 --syn --connect-only --quiet \
    --format host-port | httpx -silent -td -title -tech-detect -json -o web.json

# Full chain: portensor discovery → httpx live URLs → nuclei templates:
sudo portensor scan -t 10.0.0.0/24 -p 1-65535 --syn --connect-only --quiet \
    --format host-port | httpx -silent \
    | nuclei -silent -severity critical,high -o findings.txt

# Service-aware filtering with jq before handing off to web tooling:
sudo portensor scan -t 10.0.0.0/24 -p 1-65535 --syn --format json --quiet \
    | jq -r '.open[] | select(.service.product == "Jenkins" or .service.name == "http")
             | "\(.host):\(.port)"' | httpx -silent

# Keep noisy corporate ports out of a large engagement scan:
sudo portensor scan -t 10.0.0.0/24 -p 1-65535 --exclude-ports 445,3389,5985-5986

# Machine-consumable JSON lines for custom ingest scripts:
portensor scan -t 10.0.0.0/24 --top-ports 1000 --format jsonl --quiet

# Streaming variant: verify so service metadata is attached, stream as JSONL:
portensor scan -t 10.0.0.0/24 --top-ports 1000 --stream \
    | jq -c 'select(.service.product) | {host, port, product: .service.product,
              version: .service.version, confidence: .service.confidence}'
```

Existing target-list input (`--target-file`), exclusion (`--exclude`),
sharding (`--shard-index`/`--shard-count`), and resume (`--save-state` /
`--resume`) work unchanged in these pipelines; `--exclude-ports` accepts the
same list/range syntax as `--ports`.

### Smart Resume with Gap Analysis Audit

When resuming an interrupted or large-scale scan with `--resume <FILE>`, `portensor` executes an immediate pre-scan diagnostic audit to inspect remaining scope and verify host anomaly thresholds:

```bash
# Resume an interrupted scan with comprehensive gap analysis audit:
portensor scan --target 192.168.100.37 --resume /tmp/scan-state.json
```

```text
Resume Gap Analysis Audit:
──────────────────────────────────────────────────────────────────────
Target Scope:        192.168.100.37
Port Specification:  1-65535
Progress:            1024/65535 ports completed (1.6%)
Remaining Gaps:      64511 ports to scan
Prior Findings:      19 open, 1005 closed, 0 filtered, 0 silent
Host Anomaly Check:  Clean (No host anomaly threshold triggered)
──────────────────────────────────────────────────────────────────────
```

Targets may be repeated and may be an IP, CIDR, range, hostname, file path, or
`@file`:

```bash
portensor scan \
  --target 10.0.0.0/24 \
  --target 10.0.1.10-10.0.1.20 \
  --exclude 10.0.0.128/25 \
  --ports 22,80,443
```

Port expressions accept lists and ranges: `80,443,8000-8100` or `1:1024`.
If `--ports` is omitted, `portensor` automatically defaults to the standard
well-known ports `1-1024`. Use `--top-ports N` to probe the top N most frequent
services. Target expansion is capped at 65,536 addresses. Worker auto-sizing
targets `cores × 32`, clamped to 64–512 and bounded by `RLIMIT_NOFILE`;
`--workers` accepts up to 4,096 for explicit tuning (larger pools lose
wall-clock time to scheduler contention).

### Distributed Sharding & Merge

Large target sets can be split deterministically across workers or machines with
stable FNV-1a placement. Every target lands in exactly one shard; shuffled input
order still produces the same partition.

```bash
# Four parallel shards, each writing a JSON report:
for i in 0 1 2 3; do
  portensor scan -t 10.0.0.0/16 -p 1-65535 --shard-index "$i" --shard-count 4 \
    --json -o "shard-$i.json"
done

# Merge reports (JSON or JSONL); open results win and evidence is preserved:
portensor merge shard-0.json shard-1.json shard-2.json shard-3.json -o merged.json

# Merge JSONL shards into JSONL:
portensor merge --jsonl shard-0.jsonl shard-1.jsonl -o merged.jsonl
```

Duplicate `host:port` entries keep the stronger state and confidence, but union
evidence, detail tags, script findings, advisories, and compatible service
metadata. Conflicting service identities are recorded in `evidence` instead of
being silently discarded.

`--shard-index` and `--shard-count` must be supplied together; the count ranges
from 1 to 1024. Resume/progress state is per shard, so each parallel invocation
must use its own `--save-state` file. A shard that owns no targets (when there
are fewer resolved targets than shards) emits a valid empty JSON report, so
merging does not fail.

### Distributed Orchestration (`distributed plan|serve|worker|agent`)

Three orchestration shapes share the same deterministic shards and merge path:

```bash
# 1. Local plan: print (or write) a script that runs every shard and merges.
portensor distributed plan --shards 16 --shell bash --output run.sh -- \
  scan -t 10.0.0.0/16 -p 22,80,443 --no-db-update

# 2. Pull mode: coordinator plus any number of polling workers.
export PORTENSOR_DISTRIBUTED_TOKEN="$(openssl rand -hex 24)"
portensor distributed serve --listen 0.0.0.0:9090 --shards 16 \
  --out merged.json -- scan -t 10.0.0.0/16 -p 22,80,443
# On each worker host (same binary and target-file paths):
portensor distributed worker --coordinator http://10.0.0.5:9090 --max-jobs 0

# 3. Push mode: coordinator dispatches to inbound agents.
portensor distributed agent --listen 0.0.0.0:9091 --concurrency 2
portensor distributed serve --listen 0.0.0.0:9090 --shards 16 \
  --agents http://10.0.0.11:9091,http://10.0.0.12:9091 \
  --out merged.json -- scan -t 10.0.0.0/16 -p 22,80,443
```

The coordinator forces `--format json`, owns `--output`/`--shard-*`, and
rejects job-local side effects (`--resume`, `--save-state`, `--diff`,
`--stream`, alert flags). Workers heartbeat while scanning; expired leases are
requeued up to `--max-attempts` (default 3), and finished shards merge with the
same evidence-preserving rules as `portensor merge`. The coordinator writes
`--out` and exits nonzero if any shard ultimately failed. Empty shards are
reported as empty merges rather than errors.

Coordinator state is durable by default at `<out>.state.json` (override with
`--state FILE`). Versioned snapshots, per-shard result objects under
`<state>.d/`, and an ownership lock survive restarts: expired leases are
requeued, accepted results are reattached, interrupted merges are repaired, and
a completed report stays fetchable without re-running shards. State and result
files are owner-only on Unix. `GET /readyz` and `GET /metrics` expose readiness,
queue depth, in-flight and completed jobs, failures, leases, splits, and
restart counters behind the bearer token. Logs carry a `run=<id>` field.

When no pending work remains but a worker is still running a shard after two
seconds, the coordinator supersedes the parent and splits the remaining work
into up to eight child jobs. Child jobs inherit the original arguments with
hidden work-part flags, and the split level is limited to one.

Control-plane requests have a 300-second lifetime and a 128-request in-flight
cap, so a stalled client cannot pin the coordinator indefinitely. Transient
transport, 408/425/429, and 5xx failures are retried with backoff; terminal
401/403/409/422 responses fail fast instead of burning the retry budget.
Ctrl-C and SIGTERM take the same graceful shutdown path on the coordinator,
workers, and agents. Use `--log-level info` (or `PORTENSOR_LOG=info`) for
structured job and delivery diagnostics on stderr.

Authentication is a shared bearer token (`--token` or
`PORTENSOR_DISTRIBUTED_TOKEN`, minimum 16 characters). The control plane speaks
HTTP/JSON by default. Enable HTTPS directly on the coordinator and push agents
with `--tls-cert`/`--tls-key`; workers and push coordinators verify private CAs
with `--ca-cert` (or opt into `--insecure-tls` only for testing). Without TLS,
bind to loopback or a trusted network. Raw jobs (`--syn`, `--os`, `--ndp`) are
claimed only by workers that report raw capability (Linux with
`CAP_NET_RAW`/root); with no capable worker those jobs remain queued. Workers
and agents execute the current binary, so install the same build on every node
and keep `--target-file` paths available locally.

```bash
# HTTPS coordinator plus a polling worker that trusts a private CA.
portensor distributed serve --listen 0.0.0.0:9090 \
  --tls-cert coordinator.pem --tls-key coordinator.key \
  --out merged.json -- scan -t 10.0.0.0/16 -p 22,80,443
portensor distributed worker --coordinator https://10.0.0.5:9090 \
  --ca-cert ca.pem

# HTTPS push agent and a coordinator that verifies the agent certificate.
portensor distributed agent --listen 0.0.0.0:9091 \
  --tls-cert agent.pem --tls-key agent.key
portensor distributed serve --listen 0.0.0.0:9090 \
  --tls-cert coordinator.pem --tls-key coordinator.key --ca-cert ca.pem \
  --agents https://10.0.0.11:9091 -- scan -t 10.0.0.0/16 -p 22,80,443
```

### Ping Sweep, ARP, and IPv6 Discovery (ARP & ICMP & NDP)

Reachability can be checked before the port scan. On Linux, IPv4 uses raw ICMP
echo where permitted and falls back to TCP connects. For IPv6, `portensor` supports
native raw ICMPv6 echo probes (RFC 4443 Type 128/129) and **Neighbor Discovery
Protocol (NDP)** multicast probing (`ff02::1` all-nodes) combined with the Linux
neighbor table (`ip -6 neigh` / `/proc/net/ndisc_cache`) and verified host routes.
With `--ndp`, broad CIDRs such as `fe80::/64` are expanded to the active
neighbors instead of 18 quintillion addresses. Link-local results automatically
carry the interface scope ID through connect, TLS, UDP, plugin, and verification
probes. Discovery is Linux-only, requires raw ICMPv6 privileges, and waits up to
`--ndp-timeout-ms` (default 750 ms). Connection refusals still prove the host is
alive.

IPv4 targets in `--ping-sweep` are additionally checked with an **ARP who-has
liveness probe** before ICMP/TCP: on Linux, raw `AF_PACKET` ARP requests are
sent for **directly connected routes only** (the gateway is never asked for, so
its replies cannot count as liveness); on Windows, the `SendARP` helper API is
used. This closes the largest platform gap: hosts that drop ICMP and filter all
TCP-ping ports (embedded devices, TVs, IoT appliances with stateful DROP
firewalls) are now discovered on Windows, where raw ICMP is unavailable. Each
raw ICMP sweep also derives a unique per-host echo identifier so concurrent
probes never collide on `(id, sequence)`.

```bash
# Three echo attempts, 750 ms each, then scan only responsive hosts:
sudo portensor scan -t 10.0.0.0/24 -p 22,80,443 --ping-sweep \
  --ping-count 3 --ping-timeout-ms 750

# Discover active hosts in a /64 with NDP, then scan their services:
sudo portensor scan -6 -t fe80::/64 --ndp --ndp-timeout-ms 750 -p 22,80,443

# Native ICMPv6 / TCP ping sweep for an explicit IPv6 target:
portensor scan -6 -t fd24:91bb:6122:1600::37 -p 22,80,443 --ping-sweep
```

NDP does not create a route to the public internet: a network without IPv6
upstream connectivity can resolve AAAA records but cannot scan public IPv6
targets.

`--discover-only` remains a separate mode that reports open ports without
waiting for service banners.

### Service & Version Detection (HTTP panels, native probes, confidence)

Detection combines the passive banner with one light, protocol-shaped probe on
ports that never speak first. Probes are bounded, sent only after the initial
grace read, and never retried beyond the scan timeout:

| Port | Probe | Extracted identity |
| :--- | :--- | :--- |
| any | `GET / HTTP/1.0` (only if no banner) | HTTP status + headers + first ~1 KB of body |
| 445 | SMB2 NEGOTIATE (dialects 2.0.2–3.1.1), SMB1 fallback | dialect, signing mode, capabilities, server GUID, Native OS / LAN Manager / domain (SMBv1) |
| 27017 | MongoDB legacy `buildInfo` | `MongoDB` + server version |
| 6379 | Redis `INFO server` | `Redis` + `redis_version` |
| 11211 | memcached `stats` | `memcached` + version |
| 3389 | X.224 negotiation + TLS CredSSP NTLM probe | `RDP`, negotiated protocol, NLA computer/domain, Windows build |

Deep coverage for services that never speak first comes from the built-in
probe library below: PostgreSQL startup, Elasticsearch/OpenSearch root,
Cassandra OPTIONS, ClickHouse `version()`, InfluxDB `/ping`, Docker Engine and
registry, Kubernetes API server and kubelet, etcd, Consul, Vault, Modbus, S7,
DNP3, EtherNet/IP, OPC UA, IEC 60870-5-104, Tridium Niagara Fox, OMRON FINS,
HART-IP, GE SRTP, Mitsubishi MELSEC-Q, Phoenix Contact PCWorx, VNC, WinRM,
rsync, ZooKeeper `srvr`, Jenkins, Grafana, Prometheus, Kibana, RabbitMQ
management and AMQP, NATS, Portainer, and SonarQube. TLS-fronted endpoints are
covered by TLS-aware probes for the Kubernetes API server and kubelet, Docker
API, etcd, Elasticsearch/OpenSearch, AMQPS, Vault, WinRM, and Portainer.

RDP never sends an unsolicited banner. Silent results on 3389 are retained and
promoted to `open` when the NLA identity succeeds, and JSON output gains an
`rdp` object (`protocol`, `computer_name`, `domain`, `os_version`, `product`).

HTTP identification prefers explicit application headers and login-page
fingerprints over the generic `Server` token:

- Headers: `Server`, `X-Powered-By`, `X-Jenkins`, `kbn-name`/`kbn-version`,
  `X-Elastic-Product`, `Docker-Distribution-Api-Version`.
- Panels: Jenkins, Kibana, Elasticsearch, OpenSearch, Grafana, Apache Tomcat,
  phpMyAdmin, Adminer, Webmin, Zabbix, Prometheus, Portainer, SonarQube,
  Kubernetes Dashboard, Argo CD, RabbitMQ Management, Nexus, GitLab, MinIO,
  Rancher, Proxmox VE, pfSense, OpenWrt LuCI, WebLogic, WebSphere, Jira,
  Confluence.
- Protocols: SSH implementation/version (OpenSSH, Dropbear, libssh, Win32-OpenSSH,
  Cisco, …), MySQL/MariaDB, PostgreSQL, Redis, memcached, MongoDB, FTP, SMTP,
  VNC, SMB, RDP, and TLS.

Each `service` object in JSON/JSONL carries an identification `confidence`
from the probe ladder: `0.98` when a version was parsed, `0.85` when only a
product was identified, and `0.70` for a bare protocol name (plus `0.01` per
extra corroborating step, capped at `0.99`). Probes may also populate
`service.cpe` and a `service.info` map of protocol facts.

```json
{
  "host": "10.0.0.5",
  "port": 8080,
  "state": "open",
  "banner": "HTTP/1.1 200 OK",
  "service": {
    "name": "http",
    "product": "Jenkins",
    "version": "2.426.1",
    "confidence": 0.98,
    "cpe": "cpe:2.3:a:jenkins:jenkins",
    "info": { "server": "Jetty(10.0.19)" }
  }
}
```

### Probe Engine: Built-ins and Declarative Packs (`--plugins`)

Service identification is driven by a declarative probe engine. Six packs
(60 probes, 13 TLS-aware) are compiled into the binary and always available:

| Pack | Coverage |
| :--- | :--- |
| `databases` | PostgreSQL startup, Redis `INFO`, Cassandra `OPTIONS`, Elasticsearch/OpenSearch root (HTTP and HTTPS), ClickHouse `version()`, InfluxDB `/ping`, memcached stats, CouchDB root, MySQL/MariaDB greeting (passive), MongoDB `isMaster` OP_QUERY (TCP and TLS) |
| `containers` | Docker Engine `/version`/`_ping` (HTTP and TLS), Docker registry v2, Kubernetes API server and kubelet (HTTP and TLS), etcd (HTTP and TLS), Consul agent, Vault health (HTTP and TLS) |
| `industrial` | Modbus device identification, S7 COTP, DNP3 link status, EtherNet/IP ListServices, OPC UA HEL/ACK, IEC 60870-5-104 STARTDT, Tridium Niagara Fox hello, OMRON FINS/TCP node address, HART-IP session initiation, GE SRTP initialization and system-register read, Mitsubishi MELSEC-Q CPU information, Phoenix Contact PCWorx session-ID handshake |
| `remote` | VNC handshake + version, WinRM WSMan (HTTP and HTTPS), ZooKeeper `srvr`, rsync daemon greeting |
| `appliances` | Jenkins, Grafana, Prometheus, Kibana, RabbitMQ management, Portainer (HTTP and HTTPS), SonarQube |
| `messaging` | MQTT CONNECT/CONNACK (TCP and TLS), Kafka ApiVersions (TCP and TLS), RabbitMQ AMQP Connection.Start (TCP and TLS), NATS INFO |

```bash
portensor probes list
portensor probes list --json
portensor probes list --plugins ./my-probes/
```

Probes are TOML. The v2 schema supports multi-step sessions over one TCP
connection, TLS sessions, binary payloads, binary expectations with `??`
wildcards and fixed offsets, response captures reused as `${name}` in later
requests, early-stop reads, CPE tagging, and capture-group extraction into
`service.info`:

```toml
# probes.toml - one pack per file
name = "example"
description = "Example appliance probes"

[[probe]]
name = "acme-console"
service = "acme-admin"
ports = [9000]
product = "Acme Appliance"
cpe = "cpe:2.3:a:acme:appliance"
version_regex = 'Acme Console v([0-9.]+)'
timeout_ms = 1500
# tls = true          # run steps over TLS (self-signed accepted,
#                     # ALPN advertises http/1.1)

[probe.info]
node = 'node-id: ([a-f0-9-]+)'
region = 'region: ([a-z0-9-]+)'

[[probe.step]]
name = "greeting"
expect_regex = 'ACME Console'
read_until = '\r\n'

[[probe.step]]
name = "status"
send = "GET /status HTTP/1.1\r\nHost: target\r\nConnection: close\r\n\r\n"
expect = "HTTP/1.1 200"
read_until = '\r\n\r\n'
```

Each step may send text (`send`) or binary (`send_hex`) and match one of
`expect` (literal), `expect_regex`, or `expect_hex` (binary substring). A
failing step aborts the probe; all other steps run sequentially on the same
socket, so challenge-response protocols work without reconnecting. Steps with
no payload read the initial banner. `read_until` stops reading as soon as the
regex matches, keeping HTTP-style multi-step probes fast. With `tls = true` the
probe runs its own handshake (the scanner accepts self-signed certificates by
design) and the same step/extraction rules apply. Active plaintext probes are
skipped on ports where TLS inspection already succeeded, so HTTPS endpoints are
never sent plaintext payloads.

Extraction runs over the whole transcript. Capture group 1 wins when present,
so `[probe.info] name = 'node-id: ([a-f0-9-]+)'` emits `"node": "<id>"` in the
`service.info` object alongside `service.cpe`. A probe-level `version_regex`
takes precedence over per-step patterns.

Confidence follows the corroboration ladder: `0.70` for a bare service name,
`0.85` when a product matched, `0.98` when a version was extracted, plus
`0.01` per extra independently satisfiable step (capped at `0.99`). An explicit
`confidence` in the pack overrides the ladder. The first matching probe per
port wins, user packs load before built-ins, and every hit appends
`plugin:<pack>/<name>` to the port's `detail` tag plus the agreeing step names
to JSON `evidence`.

Limits: 16 KiB response, 8 KiB payload, 8 steps and 32 captures per probe,
512 probes and 64 packs per run, 256 KiB per pack file, 512-character
regexes, and timeouts clamped to 100 ms–10 s. Only open TCP results are
probed. See [docs/probe-engine.md](docs/probe-engine.md) for the full schema
reference and authoring guide.

```bash
portensor scan -t 10.0.0.5 -p 9000 --plugins probes.toml --explain 9000
```

### Script Plugins (`--scripts`, `--allow-intrusive`, `portensor scripts list`)

The declarative probe engine never executes code. When a check needs real
logic — parsing a JSON API, scripting a TLS negotiation, computing risk — it
runs as a **script plugin**: either a WASM module or a sidecar process,
described by a TOML manifest. Portensor speaks the same one-JSON-in/one-JSON-out
contract with both, so Python, Go, Rust, any shell script, or a compiled
`wasm32` module can participate without linking to the scanner.

Manifest (one `[[script]]` per check; a directory may hold several `*.toml`
manifests):

```toml
name = "container-audit"

[[script]]
name = "container-check"
description = "Flags unauthenticated Docker engine API endpoints"
category = "vulnerability"      # discovery | vulnerability | auth | brute | compliance
danger = "safe"                 # "intrusive" requires --allow-intrusive
capabilities = ["metadata"]     # exactly one: metadata | target-tcp
command = ["python3", "check.py"]  # sidecar: runs with the manifest dir as cwd
# wasm = "check.wasm"           # or: sandboxed in-process WASM module
services = ["docker"]           # optional service filter; ports = [] also optional
timeout_ms = 5000               # 100-30000
```

Each run receives the port context as JSON — `target`, `port`, `state`,
`confidence`, `banner`, `detail`, `evidence`, the full `service` object, and
`tls` metadata. Sidecar scripts get it on stdin plus a cleared environment with
only documented `PORTENSOR_SCRIPT_*`, `PORTENSOR_TARGET`, `PORTENSOR_PORT`, `PATH`, and
Python isolation variables; WASM modules receive it through their `alloc`/`run`
exports (see below). The script answers
with `{"findings": [{"id", "title", "severity", "confidence", "description",
"evidence", "cve", "references"}]}`. Findings are validated (length caps,
control-character stripping, CVE/reference shape) and attached to the port as
a separate `findings` array — they never inflate or deflate the port's
accuracy confidence. `--min-severity high` drops findings below the threshold
before rendering; values are `info`, `low`, `medium`, `high`, and `critical`.

**WASM modules** (`wasm = "module.wasm"`, mutually exclusive with `command`)
run in-process on wasmtime with no WASI: no file system, network, clock, or
environment access. Execution is bounded by a fuel budget, a 16 MiB memory
limit, and the manifest timeout. Modules export `memory`,
`alloc(len: i32) -> i32`, and `run(input_ptr: i32, input_len: i32) -> i64`,
where the return value packs the output JSON location as
`(ptr << 32) | len`. The module is compiled at manifest load, so syntax errors
fail fast in `portensor scripts list`. Need a WASI-capable or heavier runtime?
Use a sidecar `command` instead.

WASM modules may declare `capabilities = ["target-tcp"]` to opt into the
versioned active host ABI. The host fixes the destination to the scanned
target and port, rechecks `--scope` before every connection, allows one open
connection, caps attempts, connections per second, bytes in each direction,
and per-operation time, and emits audit events. Sidecars cannot receive
`target-tcp`; on platforms without a verified network-deny sandbox, sidecar
execution is refused and WASM is the supported option. See
[docs/script-sdk.md](docs/script-sdk.md) for the ABI and pack-authoring guide.

Discovery scripts can also identify the port: an optional `service` object
(`name` required; `product`, `version`, `cpe`, `info`, `confidence` optional)
merges into `service.*` when the port is not yet identified or already carries
the same service name, feeds accuracy scoring and advisory correlation, and
tags `detail` with `script:<pack>/<name>`. Without an explicit `confidence`
the probe ladder applies (0.98 with a version, 0.85 with a product, 0.70
name-only).

Findings appear in JSON/JSONL, a `Script Plugin Findings:` table section, the
Markdown `## Script Findings` table, SARIF rules, and `--explain` output.
Runtime script failures are reported on stderr and never abort a scan.

```bash
portensor scripts list ./scripts --json     # validate manifests before a run
portensor scan -t 10.0.0.5 --scripts ./scripts --json
portensor scan -t 10.0.0.5 --scripts ./scripts --allow-intrusive
```

#### Script library

Packs can be installed once and reused from every scan. The library lives
under the platform data directory (`%APPDATA%\portensor\scripts` on Windows,
`$XDG_DATA_HOME/portensor/scripts` or `~/.local/share/portensor/scripts`
elsewhere), one subdirectory per pack; override the location with the global
`--scripts-dir DIR` or `PORTENSOR_SCRIPTS_DIR`.

```bash
portensor scripts install ./my-pack          # validate + copy into the library
portensor scripts list                       # list installed packs (PATH optional)
portensor scripts library --json             # print the library location
portensor scan -t 10.0.0.5 --scripts-library # run every installed pack
portensor scripts update                     # update registry-installed packs
portensor scripts update my-pack --json      # update one pack
portensor scripts uninstall my-pack
```

`install` compiles every manifest first, so a broken pack never lands on disk,
and re-installing an existing name requires `--force`. `--scripts` stays
available for ad-hoc paths and is repeatable; every path (plus the library
when `--scripts-library` is set) contributes packs to one registry and
duplicate plugin names are rejected. Registry installs are recorded in
`packs.lock` with name, version, source, digest, path, and kind. `scripts
update` re-resolves the registry, verifies the new SHA-256 digest, and
atomically replaces the pack; an interrupted update restores the previous
version on the next operation. Direct-URL installs are pinned by the digest
supplied with `--sha256` and are not updated automatically.

#### Official baseline pack

Release archives include `packs/official-baseline/`, a read-only pack for
baseline hygiene checks. It requires Python 3.8+ on `PATH` and consumes only
metadata already collected by the scan - it opens no additional connections.
The manifest invokes `python3`; on Windows installations that only provide
`python.exe`, edit the installed manifest's `command` entries accordingly.
The pack contains 24 `danger = "safe"` metadata-only scripts, each with a
positive and negative fixture. Representative checks:

| Script family | Findings |
| :--- | :--- |
| `tls-certificate`, `tls-weak-protocol`, `tls-weak-cipher`, `tls-hostname-mismatch` | Certificate hygiene, deprecated TLS versions/ciphers, and hostname mismatches |
| `cleartext-ftp/telnet/http/smtp/pop3/imap` | Services reachable without TLS |
| `ssh/http/mysql/postgresql/redis/mongodb/memcached-version-disclosure` | Passive product/version disclosure |
| `smb-hardening` | SMB signing not required, and SMBv1 negotiation accepted |
| `redis-unauthenticated` | Redis answered `INFO` without authentication |
| `docker-unauthenticated` | Docker Engine API answered a version/ping request without authentication |
| `vnc-exposed`, `rdp-exposed`, `mongodb-exposed`, `elasticsearch-exposed` | Management or data services reachable from the scanned network |

```bash
portensor scripts install ./packs/official-baseline
portensor scripts list
portensor scan -t 10.0.0.5 -p 443,445,6379,2375 --scripts-library --json
```

The pack is not installed automatically, so the scanner itself remains a
single dependency-free binary. Install only packs you trust. Sidecars are
network-denied and receive a cleared environment on Linux; on other platforms
they are refused, so prefer WASM for portable checks.

#### Remote marketplace

A registry is a JSON index (schema 1) published over HTTP(S), so any static
host, object store, or internal mirror can serve packs without a service:

```json
{
  "schema": 1,
  "packs": [
    {
      "name": "web-audit",
      "version": "1.2.0",
      "description": "Checks for exposed admin surfaces",
      "tags": ["http", "discovery"],
      "url": "packs/web-audit-1.2.0.tar.gz",
      "sha256": "…64 hex characters…"
    }
  ]
}
```

```bash
portensor scripts search http --registry https://mirror.example/registry/index.json
portensor scripts search --json --registry https://mirror.example/registry/index.json
portensor scripts install web-audit --registry https://mirror.example/registry/index.json
portensor scripts install https://mirror.example/web-audit-1.2.0.tar.gz --sha256 HEX
```

`search` filters case-insensitively on name, description, and tags; `--json`
returns resolved URLs and digests. `install NAME` picks the highest version
(numeric-aware, so `1.10` > `1.9`), downloads the archive, verifies the index
digest, extracts it, re-validates every manifest, and only then copies it into
the library — a corrupt or mismatched archive never lands on disk. Archives
are gzip tarballs with one top-level directory named after the pack;
extraction refuses absolute paths, `..` traversal, links, device nodes, more
than 4096 entries, archives over 64 MiB, and expanded trees over 512 MiB.
Direct URLs require `--sha256`; `PORTENSOR_SCRIPT_REGISTRY` supplies the
registry URL for both commands. Prefer HTTPS: plain HTTP works but prints a
warning, with integrity guaranteed only by the digest.

Limits: 128 scripts and 32 packs per run, 64 KiB manifest and stdout caps,
4 MiB WASM module source, 16 findings per script run, 100 ms-30 s per-script
timeouts, 4096 entries / 512 MiB per installed pack. Sidecar scripts execute
with your privileges and only target open TCP ports you already scanned —
treat every script directory like you would any binary you run. WASM modules
add a sandbox, but a `command` manifest is equivalent to running the binary
yourself.

### TLS Certificate Inspection (`--tls` / `--no-tls`)

Open TCP endpoints are inspected automatically on known direct-TLS and
STARTTLS ports, on non-standard ports whose banner already looks like TLS, and
on services that could not be identified at all. `--tls` forces a direct TLS
handshake on every open TCP port; `--no-tls` disables the stage entirely. TLS
runs before plugin matching, accuracy scoring, and advisory correlation.

Direct ports: `443`, `8443`, `9443`, `993`, `995`, `465`, `636`, `990`, `5986`,
`2376`, `8883`, `5061`. STARTTLS ports: FTP `21`, SMTP `25`/`587`, POP3 `110`,
IMAP `143`.

Direct TLS sessions also issue a bounded `GET` over the encrypted channel, so
HTTPS application fingerprints (Jenkins, Kibana, Grafana, Elasticsearch, …)
surface on arbitrary ports as `service.name = "https"`. Endpoints that reset
the plaintext HTTP probe but complete a TLS handshake are promoted from
`closed` to `open` instead of being lost.

```bash
portensor scan -t 10.0.0.5 -p 443,8443 --tls --json
portensor scan -t 10.0.0.5 -p 443 --no-tls

# Virtual hosts sharing one IP: override SNI independently of the target.
portensor scan -t 10.0.0.5 -p 443 --tls --sni sts.example.test --json
portensor scan -t 10.0.0.5 -p 3000 --tls --sni chat.example.test --json
```

`--sni HOST` sets the DNS name used in the TLS handshake, the HTTP `Host`
header, and certificate name validation. It is independent of the target IP and
lets one scan select a specific virtual host. Names are normalized to lowercase
DNS form; IP literals, wildcards, underscores, and non-FQDNs are rejected.
Without `--sni`, certificate matching remains IP-based against the scan target.
`--sni` conflicts with `--no-tls` and `--ack`.

The JSON port object gains a `tls` object containing `version`, `cipher`,
`alpn`, `key_algorithm`, `signature_algorithm`, `chain` (certificate subject
lines), `subject`, `issuer`, `san`, `serial`, `not_before`, `not_after`,
`days_remaining`, `expired`, `not_yet_valid`, `self_signed`,
`hostname_matches`, `chain_len`, optional `starttls`, and the explicit `sni`
name when configured. Sessions advertise `h2`/`http/1.1` via ALPN and report
the negotiated protocol. The certificate is captured even when it is
self-signed, expired, or does not match the target; these conditions are
reported as fields rather than treated as handshake failures.

### IPv6 Raw SYN and OS Fingerprinting

`--syn --os` now covers both address families when run as root on Linux. IPv4
continues to use `AF_PACKET` with BPF filtering; IPv6 uses `AF_INET6` raw
sockets so the kernel handles routing and neighbour discovery. SYN cookies bind
the full 128-bit address. `--os-probes` applies to both families, sampling up to
N distinct open ports and reporting family agreement plus hop count. IPv6 OS
fingerprints use the SYN-ACK hop limit,
window, and TCP options. IPv6 ACK probes (`--ack`) validate the echoed cookie
against the full address and both ports.

```bash
sudo portensor scan -6 -t 2001:db8::10 -p 1-1024 --syn --os
sudo portensor scan -6 -t ::1 -p 80,443 --syn --format json
sudo portensor scan -6 -t 2001:db8::10 -p 1-1024 --ack
```

Decoys and IPv4 fragmentation remain IPv4-only. Mixed IPv4/IPv6 target sets are
partitioned automatically and merged into one report. `--ttl` sets the IPv4 TTL
or IPv6 hop limit for raw SYN, ACK, and OS fingerprint probes.

OS results are endpoint-aware. Every SYN-ACK sample is retained as an
`os_fingerprints[host].endpoints[]` entry with its port, detected service,
family, confidence, TTL/hop metadata, and TCP/IP evidence. The host-level
family is the normal consensus when one stack dominates. When two or more
families each have strong endpoint evidence (confidence at least 35%), the host
family is `mixed` and the endpoint rows identify which ports belong to which
stack. This avoids claiming a single OS for a Linux TLS front end that proxies
to Windows ADFS, or for a host exposing multiple container or appliance
stacks. Per-port accuracy scoring and the terminal/Markdown/HTML/Nmap XML
reports use the endpoint result when one exists.

### Stealth, Jitter, TTL, Decoys, and Fragmentation

```bash
# 0-250 ms random delay before probes:
sudo portensor scan -t 10.0.0.5 -p 1-1024 --syn --jitter-ms 250

# Set a custom IPv4 TTL / IPv6 hop limit for SYN and OS probes:
sudo portensor scan -t 10.0.0.5 -p 1-1024 --syn --os --ttl 128

# Restrict raw SYN/ACK source ports (retries advance within this range):
sudo portensor scan -t 10.0.0.5 -p 1-1024 --syn --source-port-range 40000-40100
sudo portensor scan -t 10.0.0.5 -p 1-1024 --ack --source-port-range 40000-40100

# Add up to eight IPv4 decoy source addresses:
sudo portensor scan -t 10.0.0.5 -p 1-1024 --syn --decoys 10.0.0.101,10.0.0.102

# Split IPv4 SYN probes into 8-byte-aligned fragments:
sudo portensor scan -t 10.0.0.5 -p 80,443 --syn --fragment-size 8
```

The `stealth` profile defaults to 50 ms jitter in addition to its 20 pps rate
limit, eight workers, and three retries. Decoys and fragmentation require
`--syn`; the custom source-port range applies to `--syn` and `--ack`. Decoy
source ports are chosen outside the configured range. Use a range with at least
two ports if retransmissions need fresh source ports. OS fingerprint probes keep
their dedicated source ports (62000 for IPv4, 62001 for IPv6).

### Output formats

| Format | Flag | Description |
| :--- | :--- | :--- |
| `table` | (default) | Human-readable aligned table with optional OS column |
| `json` | `--json` / `--format json` | Structured JSON (benchmark-compatible) |
| `jsonl` | `--format jsonl` | One JSON object per line (NDJSON) |
| `csv` | `--format csv` | Comma-separated values |
| `host-port` | `--format host-port` | Plain `host:port` list, one open port per line, for pipeline chaining |
| `nmap-xml` | `--format nmap-xml` | Nmap-compatible XML (Metasploit, nmap-parse-output) |
| `greppable` | `--format greppable` | Nmap `-oG` style, one line per host |
| `sarif` | `--format sarif` | SARIF 2.1.0 rules/results for code-scanning and vulnerability dashboards |
| `markdown` | `--format markdown` | Summary, services, advisories, TLS, OS, defense, and diff tables |
| `html` | `--format html` | Self-contained report with inline CSS, escaped fields, no remote assets |

SARIF output creates one rule per advisory ID and one result per affected
host/port, with CVSS/severity properties and a `tcp://host:port` artifact URI.
Markdown output is designed for tickets and pull requests. Both formats include
the full advisory list regardless of the table truncation limit.

HTML output inlines its CSS and escapes every scan-controlled field. It includes
services and evidence, advisories, script findings, TLS details, OS
fingerprints, and change tables when a diff is active; no remote assets are
loaded.

```bash
portensor scan -t 10.0.0.5 -p 1-1024 --advisories --format sarif -o portensor.sarif
portensor scan -t 10.0.0.5 -p 1-1024 --advisories --format markdown -o report.md
portensor scan -t 10.0.0.5 -p 1-1024 --advisories --tls --os --format html -o report.html
```

### Resumable scans

Save state on completion or Ctrl-C, then resume later:

```bash
# Start scan, save state if interrupted
portensor scan -t 192.168.100.37 -p 1-65535 --save-state /tmp/scan.json

# Resume from where it stopped; the saved port spec is reused automatically
portensor scan -t 192.168.100.37 --resume /tmp/scan.json
```

The state file records the original port specification, the ports actually
probed, every recorded outcome, and structured service metadata. Resuming does
not retry already-probed ports and works for multiple targets: per-host
progress is tracked (`hosts` entries in the state file), so each target keeps
its own completed-port set and counts. Single-target scans saved by older
versions resume unchanged; when resumed against the same host set, results for
hosts no longer being scanned are preserved in the merged report. Raw SYN and
ACK modes (`--syn`, `--ack`) still require a single target for resumable scans.

### Packaging

```bash
make musl     # static binary → target/x86_64-unknown-linux-musl/release/portensor
make install  # install to /usr/local/bin and /usr/local/share/man/man1
make docker   # docker build -t portensor:latest .
make man      # regenerate man/portensor.1 from CLI definition
make dist     # package the prebuilt Linux/Windows binaries and SHA256SUMS
make package-metadata  # render local Homebrew/Scoop/Chocolatey/AUR/Compose metadata
make package-check     # render and run available static package syntax checks
make p4-external-evidence-status  # report P4-2 external packet completeness
make p4-external-evidence-check   # enforce accepted P4-2 external evidence
```

These targets do not contact a registry, publish a package, or perform a clean
install. Those remain external P4-2 evidence. The evidence commands operate only
on a local JSON packet and never contact a registry or store secrets.

### Profiles

| Profile | Timeout ceiling | Banner wait | Rate | Workers | Retries | Use case |
| :--- | ---: | ---: | ---: | ---: | ---: | :--- |
| `fast` | 1s | 150ms | 5,000/s | auto | 1 | Local Gigabit LANs / non-rate-limited hosts |
| `balanced` | 2s | 300ms | 1,000/s | auto | 4 | **Default** — optimal speed and accuracy balance |
| `careful` | 5s | 750ms | 200/s | 128 | 3 | Sensitive networks / high-latency WAN links |
| `stealth` | 5s | 1,000ms | 20/s | 8 | 3 | IDS evasion, low-profile scanning, randomized |

The default profile is `balanced`. Pass `--profile NAME` or use the `--stealth` flag (activates the stealth profile with randomized probe order). CLI options override config values, and config values override profile defaults.

### Configuration

Create `portensor.toml` in the working directory, or pass `--config FILE`:

```toml
profile = "balanced"
timeout = 2.0
probe_timeout_ms = 300
rate = 1000
workers = 0
host_concurrency = 0
os_probes = 3
retries = 4
randomize = false
connect_only = false
format = "table"
show = ["open"]
theme = "dark"
plugins = "probes.toml"  # optional declarative probe pack
scripts = "scripts/"     # optional script pack manifest or directory
jitter_ms = 50           # optional random delay before each probe
ttl = 64                 # optional raw SYN / OS probe TTL or hop limit
source_port_range = "40000-40100"  # optional raw SYN source ports
```

### Result semantics

A successful TCP handshake is not automatically reported as open:

- `open`: handshake succeeded and the service sent a banner, or closed immediately.
- `silent`: handshake succeeded but no banner arrived within the probe window.
- `closed`: connection refused or reset.
- `filtered`: connect attempt timed out.
- `unreachable`: host or network unreachable.
- `error`: local or unexpected failure; never reported as open.

The default output shows open ports only. `--show closed,filtered` selects other
states; `--all-states` shows everything. `--connect-only` disables banner
verification and reports every successful handshake as open, which is the
classic port-scanner behaviour and will report tarpits and SYN proxies as open.
Banner verification is the default because the benchmark and lab treat a bare
handshake as insufficient proof of a service.

With `--syn`, a SYN-ACK is only a discovery result. Unanswered probes are
retransmitted up to `--retries` times, then every SYN-open candidate is checked
with a connect and banner read before it is reported as `open`. Tarpits become
`silent`; SYN proxies usually become `silent` or `closed`. `--syn --connect-only
--retries 0` exposes the raw layer for diagnostics and deliberately reports
tarpits and SYN proxies as open.

Output formats are `table` (default), `json`, `jsonl`, `csv`, `host-port`,
`nmap-xml`, `greppable`, `sarif`, `markdown`, and `html`. Use `--json` as the
benchmark-compatible alias for `--format json`.
Progress is written to stderr; JSON on stdout stays clean. Use `--output FILE`
to write to a file instead of stdout, and `--quiet` to suppress progress and
status messages.

### Diagnostic logging

Structured diagnostics are opt-in and always go to stderr, so `--json` and
`--stream` output stays clean:

```bash
PORTENSOR_LOG=info portensor scan -t 10.0.0.0/24 -p 22,80,443 --no-db-update
portensor --log-level debug scan -t 10.0.0.1 -p 1-1024 --timeout 2
```

Each line is a JSON object with `ts_ms`, `level`, `event`, and event-specific
fields. Levels are `off` (default), `error`, `warn`, `info`, `debug`, and
`trace`;
`--log-level` overrides `PORTENSOR_LOG`. Scan events record target/port counts,
mode, retry decisions, and final state counts. Distributed events record worker
start/stop, claimed jobs, heartbeat and result-delivery failures, and
coordinator completion. Tokens, banners, payloads, and report contents are never
logged.

The benchmark JSON contract is in
[`docs/benchmark-contract.md`](docs/benchmark-contract.md). Exit status is `0`
for a completed scan, `1` for a runtime failure, and `2` for invalid arguments
or configuration. With `--fail-on-change`/`diff --fail-on-change`, a completed
run that detected changes exits `1` as a deliberate status (no diagnostic is
printed); a clean run exits `0`.

## Lab

The lab is one network namespace plus a veth pair. It creates no default route
and never touches public interfaces.

```bash
sudo make lab          # start
sudo make lab-check    # start, verify ground truth, stop
sudo make lab-down     # stop
```

Inside this WSL2 environment, use the root WSL user to avoid a sudo prompt:

```bash
wsl -u root -e bash -lc 'cd /mnt/e/VulnQuest_Pro/portensor && make lab-check'
```

Topology:

| Target | State | Notes |
| :--- | :--- | :--- |
| `10.77.0.2:80`, `:443`, `:8080` | open | HTTP-like banners |
| `10.77.0.2:3306` | open | MySQL-like banner |
| `10.77.0.2:8081` | open, rate-limited | HTTP banner; new connections above 5/s are dropped |
| `10.77.0.2:81`, `:9999` | closed | kernel RST |
| `10.77.0.2:9001` | filtered | DROP in the namespace INPUT chain |
| `10.77.0.2:9000` | tarpit | handshake succeeds, no data |
| `10.77.0.2:9003` | SYN proxy | netfilter completes the handshake with no backend |

Loss and latency profiles:

```bash
LAB_LOSS=5%  sudo -E make lab
LAB_LOSS=20% sudo -E make lab
LAB_LOSS=5% LAB_DELAY=20ms LAB_JITTER=5ms sudo -E make lab
```

The default is `0%` loss and `1ms` delay. `make lab-check` should be run at 0%
loss; lossy profiles are for scanner accuracy experiments. The SYN-proxy target
requires the kernel's `ipt_SYNPROXY` module; the current WSL2 kernel provides it.

## Benchmark harness

The harness scores scanner output against `lab/ground_truth.json`. It computes
recall, precision, and F1, and records wall time, CPU time, and peak RSS. CPU and
RSS come from GNU time when it is available; the fallback uses `getrusage` for
CPU only, because `ru_maxrss` is not per-process.

```bash
sudo make lab
python3 bench/bench.py --lab --tools portensor,nmap
make bench-test
```

Portensor reports all five ground-truth open ports and no false positives:

```text
tool       status       seconds   recall  precision      f1  open
-----------------------------------------------------------------
portensor    ok             1.530    1.000      1.000   1.000     5
nmap       ok             1.364    1.000      0.714   0.833     7
```

Nmap is faster here but reports the tarpit and SYN proxy as open. The harness
counts those as false positives by design: a completed TCP handshake is not
proof of a useful service or a real backend.

The JSON report is written to `bench/results/latest.json` unless `--no-save` is
used. Missing tools are reported as skipped, not treated as failures, unless
`--require-all` is supplied.

The standardized localhost validation suite compares verified portensor against
nmap on a scenario with banner services, silent tarpits, and closed ports. It
also compares a handshake-only portensor mode against nmap on the same non-tarpit
ports, so speed is measured with matched discovery semantics. Every tool runs
in interleaved warmup and measured rounds; the report includes median/p95 wall
time, CPU, peak RSS, exactness, and the portensor-to-nmap handshake ratio.

```bash
make bench-validate
```

Measured on the documented WSL2 machine (5 runs, release build of this tree):

```text
tool             mode       ports exact    runs  median_s    p95_s    cpu_s   rss_mib
portensor          verified      20 yes    5/5        0.722    0.765    0.050      12.9
portensor-connect  handshake     18 yes    5/5        0.114    0.128    0.040      12.4
nmap             handshake     20 no     5/5        0.038    0.039    0.030      14.4
nmap-speed       handshake     18 yes    5/5        0.038    0.040    0.030      14.6
```

Verified portensor found all eight banner services with no false positives;
nmap's handshake scan reported both tarpits as open. On the matched 18-port
handshake scenario both tools were exact, and nmap was about 3.0x faster.
Verified mode fans out up to eight concurrent verification reconnects when a
handshake is silent (two per retry, capped at eight), so a banner lost after the
handshake is recovered without spending one full window per tarpit. A tarpit
costs one additional probe window; `--retries 0` disables the recheck when
speed matters more than loss recovery.
The suite writes `bench/results/validation.json` and
`bench/results/validation.md` and exits non-zero on accuracy or resource
regressions. `--netem-loss` reruns it inside an unprivileged network namespace
with `tc netem`; the measured 5% and 20% runs are exact for both portensor modes.
The no-loss nmap handshake runs remain faster, but nmap was not part of the loss matrix. The 20% case now completes at about 5.3 s median and
6.6 s p95 because concurrent verification reconnects recover lost banners
without serial retry windows. See
[`docs/benchmark-validation.md`](docs/benchmark-validation.md) for the full
table. The privileged lab suite below remains the multi-target loss gate.

The v0.10 gate evidence adds full-range and coordinator-fault labs:

```bash
make scale-baseline     # 65,535 ports x 16 loopback hosts, 3 runs
make distributed-lab    # fake-worker crash, restart, and uneven-load lab
```

Full-range completed at 8.511 s median wall, 43.820 s median CPU, and 102.1 MiB
median peak RSS (limits 12.321 s, 75.375 s, and 128 MiB). All seven coordinator
crash, restart, observability, and uneven-load scenarios pass. Measurements,
commands, and frozen thresholds are recorded in
[`docs/validation-baseline.md`](docs/validation-baseline.md).

For saturation and leak-style repeatability, the soak harness scans a
configurable open/closed loopback scenario with high worker and per-host
concurrency and checks the exact open set every round:

```bash
make soak                     # 30-second high-concurrency soak
python3 bench/soak.py --rounds 20 --open-ports 64 --closed-ports 960 \
  --workers 512 --host-concurrency 256
python3 bench/soak.py --duration 3600 --output bench/results/soak-hour.json
```

The default checks 1,024 ports per round with 512 workers, records wall/CPU/peak
RSS, and exits nonzero on any missing or extra open port or RSS above
`--max-rss-mb` (default 512 MiB). Use `--discover-only` to stress handshake
concurrency without service verification. A 30-second run on the documented
WSL2 machine completed 102/102 exact rounds over 1,024 ports at 0.293 s median,
0.326 s p95, and 25.0 MiB peak RSS; a 512-worker/256-host-concurrency run
finished 5/5 exact at 0.273 s median.

The full localhost gate checks all 65,535 ports against an exact expected open
set:

```bash
make localhost-gate
```

With the lab running, the SYN accuracy gate performs ten full raw-SYN-plus-
verification scans and requires the exact open set with no tarpit or SYN-proxy
false positives:

```bash
sudo make lab
sudo make syn-gate
```

The gate passes 10/10 exact at 0% loss and 10/10 at 5% loss. A full 65,535-port
verified SYN scan takes about 7.6 seconds in this lab because the one DROP port
and the retry windows dominate; raw discovery itself is much faster.

## CI

`.github/workflows/ci.yml` runs the unprivileged gate on GitHub-hosted Ubuntu:
formatting, clippy, tests, release build, the exact localhost gate, and
benchmark-harness tests, plus separate `cargo audit` and `cargo deny`
jobs. Release archives are built by `.github/workflows/release.yml`, which can
optionally GPG- or cosign-sign `SHA256SUMS` through repository secrets.

Raw packet tests and the namespace lab need root and are therefore **not** run
on shared runners. `.github/workflows/lab.yml` is a manual workflow for a
self-hosted runner labelled `portensor-lab`:

```bash
sudo -E make lab-check
```

This split is intentional: a green unprivileged CI must not pretend it tested
packet capture. The v0.7.0 release was validated with the unprivileged
localhost, loss, soak, and distributed gates; the privileged raw-SYN lab,
Npcap-backed Windows raw mode, and external live-target certification remain
environment-specific gates and are called out in the release notes.

## Phase gates

- [Phase 0](docs/phase0-gate.md): toolchain, CI, lab, benchmark harness, and
  ground-truth verification. Complete.
- [Phase 1](docs/phase1-gate.md): connect scanner, exact local port set,
  dump/behavioral accuracy, profiles, and lab proof. Complete.
- [Phase 2](docs/phase2-gate.md): raw SYN engine (`AF_PACKET`), SYN cookies,
  BlackRock permutation, BPF filter, and ARP. Complete.
- [Phase 3](docs/phase3-gate.md): SYN retransmission, connect verification of
  SYN-open candidates, tarpit/SYN-proxy reclassification, and the exact SYN
  lab gate. Complete; loss resilience re-verified in
  [SYN Loss-Resilience Gate](docs/syn-loss-gate.md).
- [Phase 4](docs/phase4-gate.md): service and version detection (TCP + UDP). Complete.
- [Phase 5](docs/phase5-gate.md): OS fingerprinting via TCP/IP stack analysis. Complete.
- [Phase 6](docs/phase6-gate.md): graceful Ctrl-C, resumable scans, nmap-xml/greppable
  output, static musl binary, man page, Dockerfile. Complete.
- Phase 8: interactive wizard, `doctor` diagnostics, themed tables/progress, and
  themed output. UX foundation complete; speed and accuracy tracks follow.
- Beyond Phase 8: empirical accuracy scoring, defense-aware middlebox
  classification, advisory correlation with an offline NVD mirror, differential
  auditing (`--diff`), smart resume audit, ping sweep, declarative probe packs,
  TLS/STARTTLS certificate inspection, IPv6 raw SYN and OS fingerprinting,
  target sharding and report merging, lightweight stealth shaping, SARIF and
  Markdown reporting, and supply-chain tooling. Complete in `0.3.0`; see
  [Phase 9 feature gate](docs/phase9-features.md).
- Current development plan: [Development roadmap](docs/development-roadmap.md);
  release gates are documented in [Release process](docs/release-process.md).

## Layout

```text
src/cli.rs                  command-line surface and resolved settings
src/config.rs               TOML loading, profiles, state filters
src/theme.rs                dark/light/hacker/minimal palettes and table presets
src/doctor.rs               environment and capability diagnostics
src/interactive.rs          guarded guided scan setup
src/plan.rs                 explainable smart plans and interactive plan model
src/targets.rs              IP/CIDR/range/file/hostname expansion
src/ports.rs                port list and range parsing
src/scanner.rs              worker pool, connect engine, banner verification
src/resume.rs               save/load scan state for resumable scans
src/syn/cookie.rs           SYN cookie encode/decode (SipHash-1-3)
src/syn/permute.rs          BlackRock stateless bijection
src/syn/route.rs            routing table, ARP resolution, interface MAC
src/syn/packet.rs           raw frame builder and response parser
src/syn/filter.rs           classic BPF bytecode generator
src/syn/engine.rs           TX/RX orchestrator, retransmission, result aggregation
src/syn/v6.rs               AF_INET6 raw IPv6 SYN engine
src/syn/aimd.rs             AIMD rate controller for the TX loop
src/tls.rs                  direct/STARTTLS certificate inspection
src/smb.rs                  SMB2/SMB1 negotiation, signing, and OS metadata
src/plugin.rs               multi-step TOML probe engine and built-in library
src/script.rs               script plugin runner (sidecar + sandboxed WASM, JSON protocol)
src/discovery.rs            ICMP/TCP ping sweep
src/shard.rs                stable FNV-1a target sharding
src/merge.rs                JSON/JSONL shard report merger
src/distributed/mod.rs      distributed protocol, shard planning, job execution
src/distributed/coordinator.rs  token-authenticated coordinator (pull/push)
src/distributed/worker.rs   polling worker client
src/distributed/agent.rs    inbound push agent
src/distributed/tls.rs      HTTPS listener and client certificate trust
src/verify.rs               connect verification and reclassification of SYN opens
src/anomaly.rs              anomaly detection for hosts with large SYN-open counts
src/classify.rs             error taxonomy
src/rtt.rs                  RFC 6298 per-host estimator
src/rate.rs                 global token bucket
src/limits.rs               target/worker bounds and RLIMIT handling
src/output.rs               table/JSON/JSONL/CSV/NmapXml/Greppable/SARIF/Markdown/HTML rendering
src/fingerprint.rs          OS fingerprinting via TCP/IP stack analysis
src/bin/gen_man.rs          man page generator (cargo run --bin gen_man)
man/portensor.1               generated man page (plus one page per subcommand)
Dockerfile                  multi-stage musl build → scratch image
deny.toml                   cargo-deny license/advisory/source policy
data/probes/                built-in probe packs (embedded via include_str!)
packs/official-baseline/    read-only official script pack (Python sidecar)
fuzz/                       cargo-fuzz targets for parsers and service detection
scripts/sign-release.sh     optional GPG/cosign release signing
scripts/release-check.sh    version, clean-tree, and artifact pre-tag checks
scripts/p4-local-check.sh   ephemeral signing, SBOM, and release-control validation
scripts/p4_evidence_check.py P4 evidence, status, link, and CI consistency audit
scripts/p4_external_evidence_check.py P4-2 external evidence packet schema and acceptance check
scripts/generate_package_metadata.py local package metadata generation and archive validation
.github/actionlint.yaml     custom self-hosted runner labels for workflow lint
tests/cli.rs                binary-level CLI and JSON tests
lab/lab.sh                  namespace and veth lifecycle
lab/targets.py              ground-truth TCP services
lab/verify_lab.py           ground-truth checker
bench/bench.py              runner, parsers, and metrics
bench/validate.py           matched-mode localhost validation with reports
bench/scale_baseline.py     full-range 65,535-port x 16-host scale baseline
bench/distributed_lab.py    coordinator crash and uneven-load baseline
bench/soak.py               high-concurrency and long-duration loopback soak
bench/localhost_gate.py     exact 1-65535 localhost gate
bench/syn_gate.py           exact raw-SYN lab accuracy gate
bench/accuracy_suite.py     multi-profile accuracy runner (0%/5%/20% packet loss)
bench/htb/                  authorized live target scope, evidence, and analysis
bench/tests/                offline harness tests
docs/architecture.md        boundaries and design rules
docs/development-roadmap.md prerequisites, milestones, and measurable exit gates
docs/p4-release-readiness.md P4 signing, registry, runner, SBOM, and OT evidence status
docs/p4-closure-checklist.md P4 requirement status, acceptance criteria, and sign-off
docs/p4-closure-evidence.json machine-readable P4 evidence and status
docs/p4-evidence-audit.md   local P4 evidence audit, findings, and closure decision
docs/p4-external-evidence-owners.md external evidence owners and responsibilities
docs/p4-external-blockers.md external blockers and required closure evidence
docs/p4-signoff-readiness.md formal P4 sign-off readiness and approval state
docs/compatibility-policy.md v1.0 versioning, compatibility, platform, and release policy
docs/release-process.md     workflow lint, version, artifact, and pre-tag gates
docs/security/production-signing-policy.md production signing architecture and approval requirements
docs/security/key-custody-procedure.md production key custody, rotation, and revocation procedure
docs/security/release-signature-verification.md independent release verification procedure
docs/security/p4-1-evidence-register.md P4-1 local evidence and external evidence placeholders
docs/security/p4-1-evidence-submission.md secure production evidence intake and owner inputs
docs/security/p4-1-clean-host-verification.md independent production signature verification
docs/security/p4-1-acceptance-report.md P4-1 acceptance decision and missing inputs
docs/distribution/registry-ownership.md package registry ownership evidence requirements
docs/distribution/package-maintenance-policy.md package release, access, and maintenance policy
docs/distribution/clean-install-verification.md per-channel clean-environment install procedure
docs/distribution/p4-2-external-evidence-intake.md blank P4-2 owner, token, install, and digest evidence packet
docs/distribution/p4-2-external-evidence.template.json machine-readable P4-2 external evidence packet template
packaging/README.md         local package templates, generated metadata, and validation scope
docs/release-runners.md     runner labels, action pins, and reproducibility limits
docs/sbom.md                CycloneDX generation, checksum coverage, and verification
docs/decisions/             architecture decision records
docs/security/              signing policy, custody, verification, and P4-1 evidence register
docs/probe-engine.md        probe schema, built-in library, and authoring guide
docs/pipelines.md           tested host-port, JSONL, port-list, and smart/HTML presets
docs/benchmark-contract.md  CLI/JSON contract
docs/benchmark-validation.md  measured matched-mode validation results
docs/validation-baseline.md  P2 loss, full-range, and fault-lab baselines
docs/phase0-gate.md         Phase 0 evidence
docs/phase1-gate.md         Phase 1 evidence
docs/phase2-gate.md         Phase 2 evidence
docs/phase3-gate.md         Phase 3 evidence
docs/phase4-gate.md         Phase 4 evidence
docs/phase5-gate.md         Phase 5 evidence
docs/phase6-gate.md         Phase 6 evidence
docs/syn-loss-gate.md       SYN retransmission and packet-loss evidence
docs/live-test-metasploitable.md  final live validation and safe scan parameters
docs/live-metasploitable-full-suite.md  comprehensive 10-scenario live test suite
docs/phase8-ux-gate.md      Phase 8 UX checkpoint evidence
docs/phase9-features.md     Phase 9 feature gate and live validations
```

## Author & Maintainer

- **Author & Project Lead:** vulnquest58 ([@vulnquest58](https://github.com/vulnquest58))
- **GitHub Repository:** [https://github.com/vulnquest58/portensor](https://github.com/vulnquest58/portensor)

## Legal and ethical use

Scan only systems you own or have written authorization to test. The lab is
isolated by design; keep it that way. The scanner has no default public targets,
uses a bounded worker pool and rate limit, and does not pretend that a TCP
handshake proves application exploitability.
