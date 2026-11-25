# Pipeline presets

These presets are covered by binary-level tests in `tests/cli.rs`:

- `pipeline_host_port_output_feeds_an_httpx_style_url_list`
- `pipeline_jsonl_output_feeds_a_nuclei_style_target_list`
- `pipeline_port_list_output_feeds_a_second_stage_scan`

## 1. host-port to an httpx-style URL list

`host-port` emits one `host:port` pair per open TCP port. IPv6 hosts use
brackets, so the same line can be prefixed with a scheme unchanged.

```bash
portensor scan -t 10.0.0.0/24 -p 1-65535 --syn --connect-only --quiet \
  --format host-port \
  | sed 's#^#https://#' \
  | httpx -silent -td -title -tech-detect
```

## 2. JSONL to a nuclei-style target list

`jsonl` is one complete JSON object per line. Extract `host` and `port`
without parsing the final report:

```bash
portensor scan -t 10.0.0.0/24 --top-ports 1000 --format jsonl --quiet \
  | jq -r '"\(.host):\(.port)"' \
  | nuclei -silent -severity critical,high -l /dev/stdin
```

If the downstream tool wants URLs instead of authority pairs, prefix the
result with `http://` or `https://` according to the detected service.

## 3. port-list to a second-stage service scan

`port-list` emits one sorted, comma-separated list of open or silent ports.
It is ready for `-p` in portensor, nmap, netexec, or impacket.

```bash
ports=$(portensor scan -t 10.0.0.5 -p 1-65535 --connect-only --quiet \
  --format port-list)
portensor scan -t 10.0.0.5 -p "$ports" --advisories --scripts-library \
  --format markdown -o second-stage.md
```

## Smart plans

Use `smart --dry-run` to inspect the same profile, mode, port, privilege,
fallback, and risk decisions without sending a probe. Machine-readable plans
are available as JSON:

```bash
portensor smart -t 10.0.0.5 --top-ports 1000 --scope scope.toml \
  --dry-run --plan-json
```

Without `--dry-run`, the plan is printed to stderr and the scan runs with the
selected mode. Saving a plan model from either `smart` or `interactive` writes
the same schema.

## HTML reports

`--format html` writes a self-contained report with inline CSS only. It
includes services and evidence, advisories, script findings, TLS details, OS
fingerprints, and diffs when `--diff` is active. All scan-controlled fields are
HTML-escaped, and the document contains no remote assets.

```bash
portensor scan -t 10.0.0.5 -p 1-1024 --advisories --scripts-library \
  --tls --os --format html -o report.html
```
