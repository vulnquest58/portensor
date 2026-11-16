# SYN Loss-Resilience Gate

**Date:** 2026-11-16
**Status:** Verified; retransmission passes reclaim lossy opens.
**Toolchain:** Rust 1.99.1, edition 2024. Evidence host: 12-core WSL VM,
debug binary (`target/debug/rayscan`). Reproduce with
`scripts/syn-loss-lab.sh`.

Packet loss is the failure mode raw SYN scanning is most often blamed for:
SYNs or SYN-ACKs disappear, a live port never answers, and the scan reports a
filtered port. This gate measures that end to end and pins the retransmission
behavior to numbers.

## Topology

Loopback cannot be used for this test. When the target is local, the kernel
completes the handshake for the raw probe itself, so the scanner's
`AF_PACKET` reader never sees a SYN-ACK and every port looks silent. The lab
therefore scans across a private veth pair:

```
host netns                              peer netns
10.200.0.1/30  <------ veth ------>  10.200.0.2/30
    rsyn-h                                rsyn-n
tc netem loss in                     20 listeners + tc netem loss out
```

Twenty ports (9000-9019) accept and immediately close, modeling listeners
that give the scanner nothing to fingerprint. `tc netem loss N%` is applied
to both egress queues, so each SYN and each SYN-ACK is dropped independently
with probability N. ARP is warmed with a ping before loss is attached so a
dropped ARP request cannot abort the run.

## Reproduction

```bash
cargo build                      # or cargo build --release
sudo bash scripts/syn-loss-lab.sh --matrix
sudo bash scripts/syn-loss-lab.sh --loss 20 --retries 2
```

`--matrix` runs losses 0/5/20% against `--retries 0` and `--retries 2` and
prints one line per run (`open=N/20 elapsed=... missed=...`). Requirements:
Linux, root, iproute2, python3.

## Evidence

Single matrix pass (`make loss-lab`):

| loss | retries | open | elapsed |
| ---: | ---: | ---: | ---: |
| 0% | 0 | 20/20 | 150 ms |
| 0% | 2 | 20/20 | 221 ms |
| 5% | 0 | 18/20 | 1546 ms |
| 5% | 2 | 20/20 | 3218 ms |
| 20% | 0 | 12/20 | 2042 ms |
| 20% | 2 | 20/20 | 4859 ms |

Repeated runs (retries `2` = three full passes, the default):

| case | runs | open (per run) | median |
| :--- | ---: | :--- | ---: |
| 20% loss, retries 2 | 10 | 19, 20, 20, 19, 16, 20, 20, 18, 19, 20 | 19.5/20 |
| 5% loss, retries 2 | 5 | 20, 20, 20, 20, 20 | 20/20 |
| 5% loss, retries 0 | 5 | 19, 17, 20, 20, 17 | 19/20 |

Retransmission is the difference: at 20% bidirectional loss a single-pass scan
answers for roughly a third to two thirds of the live ports depending on the
run, while the default two retries recover all but zero to four. The slowest
cases are scans where verification has to wait out its full ceiling; recall,
not wall-clock, is the point of the knob.

Residual misses match the arithmetic: a raw probe is answered only when both
its SYN and its SYN-ACK survive (0.8 x 0.8 = 64% per pass), so three passes
still miss `0.36^3 = 4.7%` of live ports, about one port in twenty. More
`--retries` closes that further at the cost of another wait per pass.

## The bugs this gate found

### Lossy retries demoted verified-open ports

Before the fix, 20% bidirectional loss with `--retries 2` recovered only
9-15/20 ports, and the count was unstable. The raw SYN engine was sending its
retransmissions correctly; verification was losing the evidence.

`verify_candidate()` (src/scanner.rs) retries ambiguous outcomes — a
handshake that ends in an immediate close (`Open` with no service) is
ambiguous and gets re-verified to look for a banner. When a later retry timed
out, that final `Filtered` result replaced the earlier successful handshake,
so a live port demoted itself whenever the last retry's SYN was dropped. At
20% loss that happens to roughly one in five verified ports.

Two changes fixed it:

- **Best-evidence retention.** Verification outcomes are ranked
  `Open > Silent > Closed > Filtered`; a timeout or refusal on a retry can no
  longer overwrite a handshake from an earlier attempt. Unit tests cover the
  ranking and a listener that accepts one connection and then stops listening
  (`best_evidence_prefers_stronger_states`,
  `verification_keeps_stronger_evidence_when_a_retry_fails`).
- **Timeout floor.** Verification now uses
  `max(--connect-timeout-ms, 1500ms)`, the same `MIN_CONNECT_TIMEOUT` floor as
  the connect-scan path. A ceiling shorter than the kernel's first SYN
  retransmit (~1s) cannot distinguish a lossy SYN from a filtered port.

Connect scans always had the floor; verification did not, which is why the
defect only showed up on lossy paths.

### SYN-proxy ports were reported open

Running the same harness surfaced a red Phase 3 gate: the lab's iptables
SYNPROXY port (9003, no backend) showed up as `open` on every run, including
0% loss, because the RSC-BUG-001 rule maps any reset after a completed
handshake to Open. Packet capture shows why that rule was too broad:

```
client -> proxy  SYN
proxy  -> client SYN-ACK (win 0)
client -> proxy  ACK
proxy  -> client RST-ACK          <- before the client sent any payload
```

A real listener that RSC-BUG-001 protects resets **after** receiving a probe
payload. A SYN proxy with no backend kills the idle connection **before** any
payload is written. `verification_failure` now takes a `probe_sent` flag:

- reset after a payload -> `Open` (RSC-BUG-001 preserved),
- reset before any payload -> `Closed`, with a detail explaining the
  middlebox refusal. That reclassification is exactly what
  `src/defense.rs` counts as SYN-proxy evidence, so the host is tagged with a
  SYN-Proxy defense assessment instead of a phantom open port.

`bench/accuracy_suite.py` (0/5/20% loss, recall >= 99%, zero false positives)
now passes against the lab target, and a regression test covers the idle-reset
case.

## Files

- `scripts/syn-loss-lab.sh` — lab runner (netns, netem, listeners, matrix).
- `bench/accuracy_suite.py` — Phase 3 gate (lab target, 0/5/20% loss).
- `src/scanner.rs` — `verify_candidate`, `prefer_best_evidence`,
  `evidence_rank`, `verification_failure`, and the regression tests.
