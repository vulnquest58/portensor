# Rayscan benchmark contract

The benchmark harness consumes the scanner through this contract. Keep it stable
unless the harness and its tests are changed in the same commit.

## Command

```text
rayscan scan --target <host-or-cidr> --ports <list> --json
```

- `--target` is one IPv4 or IPv6 address, CIDR, range, or file of targets.
- `--ports` is a comma-separated list (`80,443,8000-8100`).
- `--json` writes one JSON object to stdout and nothing else to stdout.
- Progress and diagnostics go to stderr.
- Exit code `0` means the scan completed, even if no ports were open.
- Exit code `1` means a runtime failure.
- Exit code `2` means invalid arguments.

## JSON

```json
{
  "target": "10.77.0.2",
  "open": [
    {"host": "10.77.0.2", "port": 80, "state": "open"},
    {"host": "10.77.0.2", "port": 443, "state": "open"}
  ]
}
```

The harness accepts:

- `open` or `results` as the list key;
- objects with `host`, `port`, and optional `state` (`open` by default);
- a bare integer port when the target is singular.

`open` is always present in the object output. `results` is added when a
non-open state is selected with `--show` or `--all-states`; its entries carry
`state`, so non-open entries are ignored by the harness. A JSON-lines stream is
also accepted for streaming experiments (`--format jsonl`).

Port objects may carry additive optional fields (`service`, `version`,
`accuracy`, `advisories`, `tls`, and existing metadata). The harness ignores
unknown fields. `tls` is present only when TLS inspection succeeded and includes
`version`, `cipher`, certificate identity/validity, and trust flags.
`--format sarif` and `--format markdown` are human/dashboard outputs and are not
consumed by the benchmark harness.

The scanner's default verified mode waits briefly for a banner after a
successful handshake. A tarpit or SYN proxy that never supplies a banner is
`silent` or `closed`, not `open`. `--connect-only` disables that verification
and restores handshake-only behaviour.

## SYN mode

`--syn` uses the same command and JSON contract. It requires Linux
root/`CAP_NET_RAW`, or Windows with Npcap and an elevated terminal. Linux
supports IPv4 and IPv6; Windows raw mode is IPv4-only. Mixed families are
partitioned and merged into one result. Raw SYN-ACKs are candidates: by default
each candidate is connect-verified before it appears in `open`. For raw
diagnostics, `--syn --connect-only` reports the layer-3/4 result directly.
`--retries N` controls both raw retransmission and connect-verification retries.
Connect scans cap timeout retries at `min(N, 3)` and recheck an ambiguous
verification result up to `min(N, 2)` times while retaining the strongest
evidence seen.

The exact SYN lab gate is `bench/syn_gate.py` (`make syn-gate`). It scores the
same `open` list against `lab/ground_truth.json` and requires an exact set, so a
tarpit or SYN proxy in `open` is a failure.

## False positives

The harness compares predicted open ports with `lab/ground_truth.json`. A
predicted open port on a closed, filtered, or tarpit port is a false positive.
This is deliberate: a scanner that calls a tarpit open has failed the accuracy
test even though the TCP handshake succeeded.

## Resource reporting

The harness records:

- wall time from `time.perf_counter()`;
- per-run CPU (user + system) and peak RSS from GNU `time -v` when
  `/usr/bin/time` is available;
- CPU-only fallback from `getrusage(RUSAGE_CHILDREN)` deltas when GNU time is
  unavailable. The fallback does not report peak RSS, because `ru_maxrss` is the
  maximum across every child the harness has reaped, not the current run.

It does not pin CPUs or control background load. Those belong in the
performance phase, where the benchmark hardware must be fixed and documented.

## Validation suite

`bench/validate.py` is the standardized unprivileged comparison. It creates a
loopback scenario with banner services, silent tarpits, and closed ports, then
runs interleaved warmup and measured rounds. Verified rayscan and nmap are
scored over all ports to expose handshake-only false positives. A
handshake-only rayscan mode and nmap are scored over the non-tarpit subset so
their wall time, CPU, and peak RSS are compared with matched discovery
semantics.

The suite writes `bench/results/validation.json` and
`bench/results/validation.md`, and exits non-zero when verified or
handshake-equivalent rayscan accuracy is not exact or when the configured wall,
CPU, or RSS ceilings are exceeded. By default loopback runs inject no packet
loss; `--netem-loss PERCENT` re-executes the same suite inside an unprivileged
network namespace with `tc netem` for loss profiles. The privileged
`bench/accuracy_suite.py` remains the multi-target lab loss gate.
