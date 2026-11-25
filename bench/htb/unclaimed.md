# Authorized HTB validation: Unclaimed

This directory records an authorized, user-provided Hack The Box lab run against
`Unclaimed`. It contains only network discovery, service/fingerprint inspection,
normal application queries, and scope-guard validation. No exploitation,
credential access, database modification, or post-exploitation activity was
performed. VPN configuration and secrets remain outside the repository.

- Target: `10.129.215.81`
- Machine: `Unclaimed`
- Scope: [`lab-scope-unclaimed.toml`](lab-scope-unclaimed.toml), only this `/32`
- Authorization: the user's explicit instruction and active HTB lab session
- Evidence: [`results-unclaimed/`](results-unclaimed/)
- Evidence hashes: [`results-unclaimed/SHA256SUMS`](results-unclaimed/SHA256SUMS)
- Reference: no write-up was used

This is authorized live-validation evidence for scanner behavior. It is not
P4-2 registry ownership, account-control, package clean-install, or container
digest evidence.

## Environment

The Windows OpenVPN TAP path was used. WSL reached the target through host NAT.
The resolved DNS name was not available locally, so HTTP host-based requests
used `--resolve unclaimed.htb:80:10.129.215.81`.

## Commands

```bash
cd /mnt/e/VulnQuest_Pro/portensor

/usr/bin/time -v ./target/release/rayscan scan --target 10.129.215.81 \
  --scope bench/htb/lab-scope-unclaimed.toml --ports 1-65535 \
  --connect-only --profile fast --timeout 1 --retries 0 --workers 512 \
  --quiet --json -o bench/htb/results-unclaimed/rayscan-full-connect.json \
  2> bench/htb/results-unclaimed/rayscan-full-connect.time.txt

./target/release/rayscan scan --target 10.129.215.81 \
  --scope bench/htb/lab-scope-unclaimed.toml --ports 80,5040,49668 \
  --connect-only --profile careful --timeout 2 --retries 2 --workers 32 \
  --quiet --json -o bench/htb/results-unclaimed/rayscan-focus.json

nmap -Pn -p- --min-rate 1000 10.129.215.81 \
  -oN bench/htb/results-unclaimed/nmap-alltcp.txt \
  -oX bench/htb/results-unclaimed/nmap-alltcp.xml

nmap -Pn -sV -sC \
  -p80,135,139,445,5040,5985,47001,49664,49665,49666,49667,49669,49670 \
  10.129.215.81 \
  -oN bench/htb/results-unclaimed/nmap-services.txt \
  -oX bench/htb/results-unclaimed/nmap-services.xml

./target/release/rayscan scan --target 10.129.215.81 \
  --scope bench/htb/lab-scope-unclaimed.toml \
  --ports 80,135,139,445,5040,5985,47001,49664,49665,49666,49667,49669,49670 \
  --connect-only --tls --scripts packs/official-baseline/pack.toml \
  --advisories --no-db-update --min-severity info \
  --json -o bench/htb/results-unclaimed/rayscan-services.json

curl -sS --max-time 15 \
  --resolve unclaimed.htb:80:10.129.215.81 \
  -D bench/htb/results-unclaimed/http-root-headers.txt \
  -o bench/htb/results-unclaimed/http-root-body.txt \
  http://unclaimed.htb/

curl -sS -D bench/htb/results-unclaimed/http-ask-history-headers.txt \
  -o bench/htb/results-unclaimed/http-ask-history-body.json \
  --max-time 30 -X POST http://10.129.215.81/ask \
  -H 'Host: unclaimed.htb' -H 'Content-Type: application/json' \
  --data @bench/htb/results-unclaimed/ask-history.json

wsl -u root ./target/release/rayscan scan --target 10.129.215.81 \
  --scope bench/htb/lab-scope-unclaimed.toml --ports 80,135,139,445,5985 \
  --os --os-probes 3 --profile balanced --timeout 3 --retries 1 \
  --quiet --json -o bench/htb/results-unclaimed/rayscan-os.json
```

The scope-denial check targeted `10.129.215.82` with the same scope file and
exited `2` before probing.

## Confirmed TCP surface

The confirmed open set is the agreement of the nmap full-TCP scan and the
recovered rayscan connect-only passes. It contains 13 TCP ports:

```text
80, 135, 139, 445, 5040, 5985, 47001,
49664, 49665, 49666, 49667, 49669, 49670
```

| Scanner | Open | Recall vs confirmed set | Precision | Notes |
|---|---:|---:|---:|---|
| nmap all-TCP | 13 | 1.000 | 1.000 | 22 filtered; retransmission cap warning |
| rayscan full connect | 11 | 0.846 | 1.000 | missed 80 and 5040 under rate limiting |
| rayscan focused recheck | 2 | 1.000 | 1.000 | recovered 80 and 5040 |
| rayscan two-pass | 13 | 1.000 | 1.000 | union of full and focused passes |

Confirmed ports exclude the 22 filtered ports reported by nmap. Their state is
not claimed.

## Timing and resources

| Measurement | Result |
|---|---|
| rayscan full discovery | 39.027 s internal, 40.74 s wall |
| rayscan full CPU / peak RSS | 1.66 s user + 8.08 s system / 20.2 MiB |
| rayscan focused recheck | 281.0 ms internal |
| rayscan raw OS scan | 2.17 s |
| nmap all-TCP | 97.08 s |
| nmap service scan | 69.00 s |

Rayscan's defense classifier reported `rate_limiting` on the full pass, with 8
ports requiring retries or backoff. The focused careful pass recovered both
ports missed by the high-concurrency pass.

## Services

- `80/tcp`: Microsoft-HTTPAPI/2.0. A request to the IP returns `302 Found` with
  `Location: http://unclaimed.htb/`. With the host name, it returns `200 OK` and
  a 1,314,823-byte HTML page titled `HTB Airlines - Baggage Services`.
- The page is an unauthenticated chat interface. Inline JavaScript sends
  `POST /ask` with a JSON `{"msg": ...}` body and renders the JSON reply.
- A normal query, `scan history for tag HTB0067890`, returned baggage event rows
  and the generated SQL:
  `SELECT * FROM dbo.BagEvents WHERE tag_number = 'HTB0067890'`. The API response
  also includes the result columns and rows.
- The other suggested normal query, `status for tag HTB0012345`, returned
  `None of the provided tools can be used to answer the question...` with
  `sql: null` and `result: null`.
- `135/tcp`, `139/tcp`, `445/tcp`: Microsoft RPC, NetBIOS session, and SMB.
  SMB2 security mode is `2.02`; message signing is enabled and required.
- `5985/tcp`: WinRM/WSMAN, `HTTP/1.1 401`, identified as Microsoft WinRM.
- `47001/tcp`: Microsoft-HTTPAPI/2.0 listener, `404 Not Found` body.
- `49664`-`49670`: Microsoft RPC endpoints; `49668` was closed on recheck.
- `5040/tcp`: open TCP, but nmap reports `tcpwrapped`. TLS and HTTP probes were
  reset or returned no data. No service identity is claimed.

No SQL injection, prompt injection, credential access, or data modification was
attempted. The `/ask` observations are from normal application use.

## OS and defense result

Rayscan's raw TCP fingerprint reported a Windows host with a member-server role:

- Family: `windows`
- Confidence: `0.933`
- Initial TTL: `128`; hops: `2`
- Samples: `3`; agreement: `1.0`
- Endpoints: `80`, `139`, `5985`
- Evidence: `TTL=126, Window=65535, MSS=1346, WScale=8, SACK=yes, DF=yes`;
  Microsoft-HTTPAPI service evidence on port 80.

The exact Windows edition was not established. The OS scan treated `135` and
`445` as silent, so their individual stack samples are absent.

## Scope guard

The scope file allows only `10.129.215.81/32`. A scan of `10.129.215.82` was
rejected before probing with:

```text
SCOPE VIOLATION: Target IP '10.129.215.82' is outside the authorized scope...
exit=2
```

## Limitations

- The target rate-limited the high-concurrency full scans; the two-pass method
  is required for complete inventory in this environment.
- UDP coverage was not performed.
- `5040/tcp` remains unidentified after safe service, TLS, and HTTP probes.
- No vulnerability or patch-level conclusion is drawn from the exposed banners
  or the unauthenticated chat endpoint.
- The HTTP evidence uses an explicit host header because local DNS does not
  resolve `unclaimed.htb`.
- No exploitation or credential validation was performed.
