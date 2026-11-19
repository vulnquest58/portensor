# Matched-mode benchmark validation

Measured with `python3 bench/validate.py` on 2026-11-19 using the release binary
built from the current tree. The generated artifacts are
`bench/results/validation.json` and `bench/results/validation.md` (ignored by
git); this page records the evidence and the interpretation.

## Environment

| Item | Value |
|---|---|
| Platform | Linux 6.18.33.2-microsoft-standard-WSL2 x86_64 |
| CPU | Intel Core i7-8750H @ 2.20 GHz, 12 logical CPUs |
| Memory | 7,867 MiB |
| Python | 3.10.12 |
| rayscan | 0.6.0 |
| nmap | 7.80 |

## Scenario

The suite created 20 free loopback ports in the 20,000-29,999 range:

- 8 banner listeners that accept repeated connections and send
  `rayscan-bench/1.0`;
- 2 silent tarpits that accept the handshake and hold the connection open
  without sending a banner;
- 10 closed ports reserved for the duration of the run.

It ran one warmup and five measured rounds per tool, alternating tool order
between rounds. Verified rayscan and nmap were scored against all 20 ports. The
handshake-only rayscan mode and a second nmap scan were scored against the 18
non-tarpit ports, which gives both tools identical discovery semantics for the
speed comparison. CPU and peak RSS come from GNU `time -v`.

## Results

| Tool | Mode | Ports | Exact | Runs | Min recall | Min precision | Median s | p95 s | CPU median s | RSS median MiB |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| rayscan | verified | 20 | yes | 5/5 | 1.000 | 1.000 | 0.443 | 0.450 | 0.070 | 12.5 |
| nmap | handshake | 20 | no | 5/5 | 1.000 | 0.800 | 0.040 | 0.053 | 0.030 | 14.5 |
| rayscan-connect | handshake | 18 | yes | 5/5 | 1.000 | 1.000 | 0.093 | 0.097 | 0.040 | 12.6 |
| nmap-speed | handshake | 18 | yes | 5/5 | 1.000 | 1.000 | 0.034 | 0.045 | 0.030 | 14.5 |

Verdict: **PASS**.

## Interpretation

- Verified rayscan was exact on every run: all 8 banner services found, both
  tarpits rejected, and no closed port reported open.
- nmap's handshake scan found every real service but also reported both tarpits
  as open, so its precision was 0.800 on the full scenario.
- On the matched 18-port handshake scenario both tools were exact. rayscan
  completed in 0.093 s median versus nmap's 0.034 s median, a 2.72x wall-time
  ratio. This is the honest like-for-like speed result for the small scenario.
- rayscan's verified pass cost 0.443 s median and 70 ms CPU, while nmap's
  handshake-only pass cost 0.040 s and 30 ms CPU. The extra time buys tarpit
  rejection and service verification; it is not a like-for-like comparison.
- Peak RSS was 12.5 MiB for rayscan and 14.5 MiB for nmap in this scenario.

## Loss-profile diagnostic

`--netem-loss` re-executes the suite inside an unprivileged network namespace
with `tc netem` on loopback. This uses the same timeouts and retries as the
baseline runs; it is a diagnostic, not a tuned loss mode. On the same machine:

| Condition | Tool / mode | Runs | Exact runs | Median s | Observed misses |
|---|---|---:|---:|---:|---|
| 5% loss | rayscan verified | 5 | 4 | 2.163 | 1 service in one run |
| 5% loss | rayscan-connect | 5 | 4 | 3.140 | 2 services in one run |
| 5% loss | nmap-speed (18 ports) | 5 | 5 | 1.141 | none |
| 20% loss | rayscan verified | 3 | 2 | 6.664 | 4 services in one run |
| 20% loss | rayscan-connect | 3 | 2 | 9.208 | 2 services in one run |
| 20% loss | nmap-speed (18 ports) | 3 | 3 | 2.175 | none |

The suite correctly exits non-zero when those runs are not exact. The result is
a concrete production-readiness finding: with default connect retry settings,
rayscan can miss a live service under heavy loss while nmap's handshake scan
recovers it. Loss-resilience work belongs to the reliability track, not to a
benchmark threshold adjustment.

```bash
python3 bench/validate.py --netem-loss 5 --repeat 5
python3 bench/validate.py --netem-loss 20 --repeat 3
```

The privileged `bench/accuracy_suite.py` remains the multi-target lab loss gate
for raw SYN and verification behavior.

## Limits

- A 20-port scan is dominated by process startup and verification waits. It is
  a correctness and matched-mode resource check, not a full-range throughput
  benchmark. Full-range live numbers remain in `docs/bench-results.md`.
- CPU and background load are not pinned or controlled beyond reporting the
  environment and load average. Cross-machine comparisons require identical
  hardware and load conditions.

## Reproduce

```bash
cargo build --release --locked
python3 bench/validate.py
make bench-test
```
