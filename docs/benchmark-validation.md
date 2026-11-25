# Matched-mode benchmark validation

Measured with `python3 bench/validate.py` on 2026-11-21 using the release binary
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
| portensor | 0.7.0 |
| nmap | 7.80 |

## Scenario

The suite created 20 free loopback ports in the 20,000-29,999 range:

- 8 banner listeners that accept repeated connections and send
  `portensor-bench/1.0`;
- 2 silent tarpits that accept the handshake and hold the connection open
  without sending a banner;
- 10 closed ports reserved for the duration of the run.

It ran one warmup and five measured rounds per tool, alternating tool order
between rounds. Verified portensor and nmap were scored against all 20 ports. The
handshake-only portensor mode and a second nmap scan were scored against the 18
non-tarpit ports, which gives both tools identical discovery semantics for the
speed comparison. CPU and peak RSS come from GNU `time -v`.

## Results

| Tool | Mode | Ports | Exact | Runs | Min recall | Min precision | Median s | p95 s | CPU median s | RSS median MiB |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| portensor | verified | 20 | yes | 5/5 | 1.000 | 1.000 | 0.722 | 0.765 | 0.050 | 12.9 |
| portensor-connect | handshake | 18 | yes | 5/5 | 1.000 | 1.000 | 0.114 | 0.128 | 0.040 | 12.4 |
| nmap | handshake | 20 | no | 5/5 | 1.000 | 0.800 | 0.038 | 0.039 | 0.030 | 14.4 |
| nmap-speed | handshake | 18 | yes | 5/5 | 1.000 | 1.000 | 0.038 | 0.040 | 0.030 | 14.6 |

Verdict: **PASS**.

## Interpretation

- Verified portensor was exact on every run: all 8 banner services found, both
  tarpits rejected, and no closed port reported open.
- nmap's handshake scan found every real service but also reported both tarpits
  as open, so its precision was 0.800 on the full scenario.
- On the matched 18-port handshake scenario both tools were exact. portensor
  completed in 0.114 s median versus nmap's 0.038 s median, a 3.01x wall-time
  ratio. This is the honest like-for-like speed result for the small scenario.
- portensor's verified pass cost 0.722 s median and 50 ms CPU, while nmap's
  handshake-only pass cost 0.038 s and 30 ms CPU. Verified mode fans out up to
  eight concurrent reconnects when a handshake is silent, so a lost banner is
  recovered without serial retry windows. A tarpit costs one extra probe
  window; `--retries 0` disables the recheck when speed matters more than loss
  recovery, and the tarpits remain `silent`, not open.
- Peak RSS was 12.9 MiB for portensor and 14.5 MiB for nmap in this scenario.

## Loss-profile validation

`--netem-loss` re-executes the suite inside an unprivileged network namespace
with `tc netem` on loopback. This uses the same timeouts and retries as the
baseline runs; it is a production-safety diagnostic, not a tuned loss mode. On
the same machine, with the 1.1 s timeout floor, bounded connect retries, and the
concurrent verification fanout:

| Condition | Tool / mode | Runs | Exact runs | Median s | p95 s | Observed misses |
|---|---|---:|---:|---:|---:|---|
| 5% loss | portensor verified | 5 | 5 | 2.813 | 3.744 | none |
| 5% loss | portensor-connect | 5 | 5 | 2.177 | 3.173 | none |
| 20% loss | portensor verified | 5 | 5 | 5.289 | 6.573 | none |
| 20% loss | portensor-connect | 5 | 5 | 5.225 | 6.296 | none |
| 30% loss | portensor verified | 3 | 3 | 9.108 | 9.754 | none |
| 30% loss | portensor-connect | 3 | 3 | 6.255 | 7.453 | none |

All loss runs pass the exactness gate. The 20% scenario improved from a 10.075 s
baseline median to 5.289 s by fanning out verification reconnects, while the
30% profile is stable at 3/3 exact across repeated sessions. Both connect and
verified modes completed with zero false positives. The suite still exits
nonzero on any future miss, so the diagnostic is an enforced regression gate.

```bash
python3 bench/validate.py --netem-loss 5 --repeat 5
python3 bench/validate.py --netem-loss 20 --repeat 5
python3 bench/validate.py --netem-loss 30 --repeat 3
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
python3 bench/validate.py --netem-loss 20 --repeat 5
python3 bench/validate.py --netem-loss 30 --repeat 3
python3 bench/soak.py --duration 30
make bench-test
```
