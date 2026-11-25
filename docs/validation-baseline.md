# Validation and fault-lab baselines (v0.10)

This page freezes the reference measurements used by the v0.10 accuracy and
scale gates and records the final status. Pre-optimization measurements were
taken on 2026-11-19 with the v0.7.0 release binary; final measurements were
taken on 2026-11-21 with the release binary built from the current tree.
Artifacts are written to ignored `bench/results/` files; the commands below
reproduce them.

The thresholds were frozen before optimization. Gate status is based on the
current tree, not on the historical baseline.

## Environment

| Item | Value |
|---|---|
| Platform | Linux 6.18.33.2-microsoft-standard-WSL2 x86_64 |
| CPU | Intel Core i7-8750H @ 2.20 GHz, 12 logical CPUs |
| Memory | 7,867 MiB |
| Python | 3.10.12 |
| portensor | 0.7.0 build from the current tree |
| nmap | 7.80 |

## Gate status

| Gate | Limit | Current result | Status |
|---|---|---|---|
| 20% loss exactness | 100% of 5 runs | 5/5 | pass |
| 20% loss median wall | <= 7.5 s | 5.289 s | pass |
| 20% loss p95 wall | <= 9.5 s | 6.573 s | pass |
| 30% loss exactness | 100% of 3 runs, zero FP | 3/3, zero FP | pass |
| 5% loss / baseline | no regression | 2.813 s / 0.722 s verified median | pass |
| Full-range wall | <= 12.321 s median | 8.511 s | pass |
| Full-range CPU | <= 75.375 s median | 43.820 s | pass |
| Full-range peak RSS | <= 128 MiB | 102.1 MiB median, 106.9 MiB max | pass |
| Coordinator fault lab | all scenarios pass | 7/7 | pass |

## Loss profiles

The loss runs use the unprivileged loopback `tc netem` suite in
`bench/validate.py`. The 20%/30% profiles exercise production timeout and
verification behavior; the 20-port scenario has 8 banner services, 2 silent
tarpits, and 10 closed ports.

Frozen gates:

- 20% loss: exactness 100% across five runs; median at most 7.5 s and p95 at
  most 9.5 s.
- 30% loss: exactness 100% across three runs with zero false positives.
- Baseline and 5% loss must not regress beyond measurement noise.

Historical v0.7.0 pre-optimization measurements (reference only):

| Condition | Tool / mode | Runs | Exact runs | Median s | p95 s | CPU s | RSS MiB |
|---|---|---:|---:|---:|---:|---:|---:|
| 20% loss | portensor verified | 3 | 3 | 10.075 | 10.287 | 0.100 | 12.5 |
| 20% loss | portensor-connect | 3 | 3 | 8.904 | 10.755 | 0.080 | 12.3 |
| 30% loss | portensor verified | 3 | 3 | 11.768 | 13.201 | 0.070 | 12.9 |
| 30% loss | portensor-connect | 3 | 3 | 11.777 | 12.736 | 0.060 | 12.6 |

Final v0.10 measurements:

| Condition | Tool / mode | Runs | Exact runs | Median s | p95 s | CPU s | RSS MiB |
|---|---|---:|---:|---:|---:|---:|---:|
| no loss | portensor verified | 5 | 5 | 0.722 | 0.765 | 0.050 | 12.9 |
| 5% loss | portensor verified | 5 | 5 | 2.813 | 3.744 | 0.060 | 12.9 |
| 5% loss | portensor-connect | 5 | 5 | 2.177 | 3.173 | 0.060 | 12.7 |
| 20% loss | portensor verified | 5 | 5 | 5.289 | 6.573 | 0.070 | 12.8 |
| 20% loss | portensor-connect | 5 | 5 | 5.225 | 6.296 | 0.050 | 12.7 |
| 30% loss | portensor verified | 3 | 3 | 9.108 | 9.754 | 0.070 | 13.1 |
| 30% loss | portensor-connect | 3 | 3 | 6.255 | 7.453 | 0.060 | 12.7 |

The 30% profile was rerun twice more (three rounds each) after the final
changes; both sessions were 3/3 exact at 9.097 s / 9.124 s and 8.895 s / 9.107 s
median/p95. This replaces the earlier note that the gate was not yet stable.

Verification recovery now fans out up to eight concurrent reconnects after an
initial silent handshake (two per retry, capped at eight). A tarpit costs one
additional probe window instead of one full window per retry, while independent
banner losses are recovered in parallel. `--retries 0` still disables
post-handshake recovery.

The remote-target recheck no longer doubles the traffic for non-local scans.
Local open rechecks run concurrently with source ports outside the candidate
set, preserving the simultaneous-open safety property.

## Full-range scale

`bench/scale_baseline.py` scans ports 1-65535 on 16 loopback addresses
(1,048,560 probes) in connect-only mode with 512 workers, no rate limit, no
retries, and a 2-second connect timeout. Runs are sequential and include the
scanner's own process startup.

Historical v0.7.0 baseline:

| Run | Exit | Open | Wall s | CPU s | Peak RSS MiB |
|---:|---:|---:|---:|---:|---:|
| 1 | 0 | 34 | 13.690 | 83.750 | 37.9 |
| 2 | 0 | 34 | 15.360 | 100.770 | 38.2 |
| 3 | 0 | 34 | 13.610 | 81.270 | 36.9 |

Final v0.10 result:

| Run | Exit | Open | Wall s | CPU s | Peak RSS MiB |
|---:|---:|---:|---:|---:|---:|
| 1 | 0 | 34 | 8.694 | 45.570 | 101.2 |
| 2 | 0 | 34 | 8.511 | 43.480 | 106.9 |
| 3 | 0 | 34 | 8.503 | 43.820 | 102.1 |

Frozen v0.10 gate: peak RSS at most 128 MiB, median wall and CPU at most 0.9x
the baseline (wall <= 12.321 s, CPU <= 75.375 s), no OOM. The 34 open loopback
ports are host services and are not part of the scale gate.

The blocking connect-only worker pool, cached RTT timeouts, and parallel
recheck account for the improvement. The narrower RSS margin (about 107 MiB
against a 128 MiB ceiling) is accepted and monitored; no OOM occurred.

## Coordinator crash and uneven-load lab

`bench/distributed_lab.py` uses fake workers against the public coordinator
HTTP API. It does not execute scans, so the measurements isolate control-plane
state and scheduling.

Historical pre-P3 baseline:

| Scenario | Baseline result | Observed |
|---|---|---|
| Crash after claim | fail | Restart shows 4 pending, 0 running; the active claim is lost. |
| Crash after result | fail | Completed shard count resets from 1 to 0; report is unavailable (409). |
| Crash after completion | fail | Completed shard count resets from 4 to 0; restarted coordinator has no report (409), although the old report file exists. |
| Uneven load | fail | 10.082 s wall vs 10.0 s lower bound (1.008x), but max idle 9.062 s exceeds 5 s while the long shard runs. |

Final v0.10 result: all seven scenarios pass:

| Scenario | Check |
|---|---|
| `crash-before-claim` | Restart preserves pending work and the run identity. |
| `crash-after-claim` | Expired lease is requeued; the shard completes exactly once. |
| `crash-after-result` | Accepted result and completed count survive restart; merged report matches. |
| `crash-completed-restart` | Completed report remains fetchable after restart; no shards rerun. |
| `mid-result-body` | Truncated result body is rejected; a valid retry is accepted. |
| `metrics-and-readiness` | `/readyz`, `/metrics` fields, run ID, and `run=<id>` logs correlate. |
| `uneven-load` | Four workers stay within 1.2x the lower bound and no idle stretch exceeds 5 s. |

Frozen v0.10 gate: coordinator survives restarts at every P3 injection point,
100% of shards complete exactly once, merged report matches an uninterrupted
run, four-worker uneven load completes within 1.2x the theoretical lower bound,
and no worker is idle longer than 5 seconds while work remains.

## Reproduce

Run from the repository root in WSL:

```bash
export PATH="/home/vuln/.cargo/bin:/usr/local/bin:/usr/bin:/bin"
python3 bench/validate.py --repeat 5 \
  --tools portensor,portensor-connect,nmap,nmap-speed \
  --require-tools portensor \
  --output bench/results/loss0-current.json \
  --markdown bench/results/loss0-current.md
python3 bench/validate.py --netem-loss 5 --repeat 3 \
  --tools portensor,portensor-connect --require-tools portensor \
  --output bench/results/loss5-current.json \
  --markdown bench/results/loss5-current.md
python3 bench/validate.py --netem-loss 20 --repeat 5 \
  --tools portensor,portensor-connect --require-tools portensor \
  --output bench/results/loss20-current.json \
  --markdown bench/results/loss20-current.md
python3 bench/validate.py --netem-loss 30 --repeat 3 \
  --tools portensor,portensor-connect --require-tools portensor \
  --output bench/results/loss30-current.json \
  --markdown bench/results/loss30-current.md
python3 bench/scale_baseline.py --repeat 3 \
  --output bench/results/full-range-current.json \
  --markdown bench/results/full-range-current.md
python3 bench/distributed_lab.py \
  --output bench/results/distributed-lab-current.json \
  --markdown bench/results/distributed-lab-current.md
```

The `--baseline` flag records known pre-P3 failures and returns success. After
P3, run the lab without `--baseline`; every scenario must pass. WSL `/tmp` is
ephemeral across VM restarts, so final artifacts belong under
`bench/results/` (the directory itself is ignored by git).
