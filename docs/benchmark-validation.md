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
| rayscan | 0.7.0 |
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
| rayscan | verified | 20 | yes | 5/5 | 1.000 | 1.000 | 1.117 | 1.125 | 0.070 | 12.6 |
| nmap | handshake | 20 | no | 5/5 | 1.000 | 0.800 | 0.039 | 0.065 | 0.020 | 14.5 |
| rayscan-connect | handshake | 18 | yes | 5/5 | 1.000 | 1.000 | 0.101 | 0.103 | 0.050 | 12.5 |
| nmap-speed | handshake | 18 | yes | 5/5 | 1.000 | 1.000 | 0.039 | 0.051 | 0.030 | 14.5 |

Verdict: **PASS**.

## Interpretation

- Verified rayscan was exact on every run: all 8 banner services found, both
  tarpits rejected, and no closed port reported open.
- nmap's handshake scan found every real service but also reported both tarpits
  as open, so its precision was 0.800 on the full scenario.
- On the matched 18-port handshake scenario both tools were exact. rayscan
  completed in 0.101 s median versus nmap's 0.039 s median, a 2.59x wall-time
  ratio. This is the honest like-for-like speed result for the small scenario.
- rayscan's verified pass cost 1.117 s median and 70 ms CPU, while nmap's
  handshake-only pass cost 0.039 s and 20 ms CPU. Verified mode now rechecks an
  ambiguous silent result to recover banners lost after the handshake. A tarpit
  and a lost banner are indistinguishable from one connection, so that safety
  can cost up to two extra probe windows per tarpit. Use `--retries 0` when
  tarpit cost matters more than loss recovery; the tarpits remain `silent`, not
  open.
- Peak RSS was 12.6 MiB for rayscan and 14.5 MiB for nmap in this scenario.

## Loss-profile validation

`--netem-loss` re-executes the suite inside an unprivileged network namespace
with `tc netem` on loopback. This uses the same timeouts and retries as the
baseline runs; it is a production-safety diagnostic, not a tuned loss mode. On
the same machine, with the 1.5 s timeout floor and bounded timeout/verification
retries:

| Condition | Tool / mode | Runs | Exact runs | Median s | p95 s | Observed misses |
|---|---|---:|---:|---:|---:|---|
| 5% loss | rayscan verified | 5 | 5 | 3.122 | 4.069 | none |
| 5% loss | rayscan-connect | 5 | 5 | 1.119 | 1.390 | none |
| 5% loss | nmap-speed (18 ports) | 5 | 5 | 1.142 | 2.298 | none |
| 20% loss | rayscan verified | 3 | 3 | 8.302 | 10.134 | none |
| 20% loss | rayscan-connect | 3 | 3 | 5.705 | 9.729 | none |
| 20% loss | nmap-speed (18 ports) | 3 | 3 | 2.194 | 3.681 | none |

All loss runs now pass the exactness gate. The 20% scenario costs roughly eight
seconds because lost SYNs and lost banners both consume full retry windows;
this is the price of not turning a live service into `silent`. Both connect and
verified modes completed with zero false positives. The suite still exits
nonzero on any future miss, so the diagnostic is an enforced regression gate.

```bash
python3 bench/validate.py --netem-loss 5 --repeat 5
python3 bench/validate.py --netem-loss 20 --repeat 3
```

The privileged `bench/accuracy_suite.py` remains the multi-target lab loss gate
for raw SYN and verification behavior.

## Saturation and soak

Separate from the matched comparison, `bench/soak.py` scans 1,024 loopback
ports (64 open, 960 closed) with 512 workers and checks the exact open set every
round. A 30-second run completed 102/102 exact rounds at 0.293 s median, 0.326 s
p95, and 25.0 MiB peak RSS. A run with `--host-concurrency 256` completed 5/5
exact rounds at 0.273 s median and 24.4 MiB peak RSS. This is localhost
saturation evidence, not a remote-host throughput claim.

## Limits

- A 20-port scan is dominated by process startup and verification waits. It is
  a correctness and matched-mode resource check, not a full-range throughput
  benchmark. Full-range live numbers remain in `docs/bench-results.md`.
- CPU and background load are not pinned or controlled beyond reporting the
  environment and load average. Cross-machine comparisons require identical
  hardware and load conditions.
- A tarpit and a lost banner are indistinguishable on a single connection, so
  verified mode's loss recovery rechecks ambiguous silence. This raises tarpit
  cost in exactness runs; `--retries 0` is the explicit speed-first override.

## Reproduce

```bash
cargo build --release --locked
python3 bench/validate.py
python3 bench/validate.py --netem-loss 5 --repeat 5
python3 bench/validate.py --netem-loss 20 --repeat 3
python3 bench/soak.py --duration 30
make bench-test
```
