# Authorized HTB validation: Garfield

This directory records a real-world validation run against a user-provided,
authorized Hack The Box lab target. It is not a public scanning target and it
does not contain VPN credentials, account tokens, passwords, or captured
credentials.

- Target: `10.129.244.207`
- Host: `DC01.garfield.htb`, domain `GARFIELD.HTB`
- Platform: Windows Server 2019, build `10.0.17763`, Active Directory DC
- Reference: <https://0xdf.gitlab.io/2026/11/07/htb-garfield.html>
- Scope: [`lab-scope.toml`](lab-scope.toml), which allows only this `/32`
- Authorization: the user's active HTB lab session and the target's HTB scope

Only network discovery, service/fingerprint inspection, safe pack checks, and
advisory matching were performed. No exploitation, credential access, or
post-exploitation activity was attempted.

A second authorized target, RedEye, is documented in
[`redeye.md`](redeye.md). It adds explicit SNI handling, an exact four-port
match, and endpoint-aware OS corrections for a mixed Linux-edge/Windows-ADFS
host.

A third authorized target, Unclaimed, is documented in
[`unclaimed.md`](unclaimed.md). It adds a 13-port Windows member-server
inventory, HTTP host-header handling, an unauthenticated chatbot endpoint, and
rate-limiting recovery through a second focused pass.

A fourth authorized target, Scaffold, is documented in
[`scaffold.md`](scaffold.md). It adds a 30-port Windows domain-controller
inventory, anonymous LDAP rootDSE, SMB signing, LDAPS and IIS certificate
evidence, plus high-rate nmap false-negative and slow-scan timeout evidence
documenting the target's rate-limiting behavior. Independent full-port
completeness was not established.

## Environment

The target was reachable through the existing Windows OpenVPN TAP adapter. WSL
used host NAT, so direct WSL OpenVPN and raw-SYN behavior are not representative
of a native Linux VPN interface. The VPN configuration and private keys are
outside the repository and are not recorded here.

## Commands

```bash
PORTS="53,88,135,139,389,445,464,593,636,2179,3268,3269,3389,5985,9389,49668,49676,49677,49679,49680,49906,58166"

# Authorized discovery and fingerprinting.
./target/release/rayscan scan --target 10.129.244.207 \
  --scope bench/htb/lab-scope.toml --preset q \
  --connect-only --profile fast --timeout 2 --retries 1 --workers 256 \
  --json -o bench/htb/results/rayscan-q-timed.json

./target/release/rayscan scan --target 10.129.244.207 \
  --scope bench/htb/lab-scope.toml --ports 1-65535 \
  --connect-only --profile fast --timeout 1 --retries 0 --workers 512 \
  --json -o bench/htb/results/rayscan-full-connect.json

# Recovery of candidates missed by the fast pass.
./target/release/rayscan scan --target 10.129.244.207 \
  --scope bench/htb/lab-scope.toml --ports 593,3268,49668,58166 \
  --connect-only --timeout 2 --retries 2 \
  --json -o bench/htb/results/rayscan-focus-extra.json

# Banner, TLS, script-pack, and advisory inspection.
./target/release/rayscan scan --target 10.129.244.207 \
  --scope bench/htb/lab-scope.toml --ports "$PORTS" \
  --connect-only --tls --scripts packs/official-baseline/pack.toml \
  --advisories --no-db-update --min-severity info \
  --json -o bench/htb/results/rayscan-services-advisories.json

# OS fingerprint requires raw access.
wsl -u root ./target/release/rayscan scan --target 10.129.244.207 \
  --scope bench/htb/lab-scope.toml --ports 445,3389,5985 \
  --os --os-probes 3 --profile balanced --timeout 3 --retries 1 \
  --json -o bench/htb/results/rayscan-os.json

# Self-contained report and no-change differential.
./target/release/rayscan scan --target 10.129.244.207 \
  --scope bench/htb/lab-scope.toml --ports "$PORTS" \
  --connect-only --tls --format html \
  --output bench/htb/results/htb-garfield.html

./target/release/rayscan scan --target 10.129.244.207 \
  --scope bench/htb/lab-scope.toml --ports 445,3389 \
  --save-baseline bench/htb/results/htb-baseline.json
./target/release/rayscan scan --target 10.129.244.207 \
  --scope bench/htb/lab-scope.toml --ports 445,3389 \
  --diff bench/htb/results/htb-baseline.json
```

Port discovery reference scans were:

```bash
nmap -Pn -p- --min-rate 1000 10.129.244.207 \
  -oN bench/htb/results/nmap-alltcp.txt \
  -oX bench/htb/results/nmap-alltcp.xml
nmap -Pn -sV -sC -p "$PORTS" 10.129.244.207 \
  -oN bench/htb/results/nmap-services-full.txt \
  -oX bench/htb/results/nmap-services-full.xml
```

## Results

The confirmed open set is the intersection of the nmap service scan and the
recovered rayscan connect-only passes. It contains 22 TCP ports:

```
53, 88, 135, 139, 389, 445, 464, 593, 636, 2179, 3268, 3269, 3389, 5985,
9389, 49668, 49676, 49677, 49679, 49680, 49906, 58166
```

| Scanner | Open | TP | FP | FN | Recall | Precision |
|---|---:|---:|---:|---:|---:|---:|
| nmap all-TCP | 20 | 20 | 0 | 2 | 0.909 | 1.000 |
| nmap service scan | 22 | 22 | 0 | 0 | 1.000 | 1.000 |
| rayscan full connect | 20 | 20 | 0 | 2 | 0.909 | 1.000 |
| rayscan two-pass | 22 | 22 | 0 | 0 | 1.000 | 1.000 |

- nmap all-TCP missed `49668` and `58166`; rayscan full connect missed `593`
  and `3268`. A focused rayscan recheck of `593,3268,49668,58166` found all
  four, so the two-pass rayscan inventory is 22/22 with no false positives.
- The `q` preset returned 14 confirmed open ports in 7.16 s of scan time
  (9.53 s process wall, 0.23 s CPU, 16.5 MiB peak RSS), with no false positives.
  The remaining eight confirmed ports are outside that preset's top-1000 scope.
- Full connect-only discovery took 141.1 s with 512 workers and 1 s timeouts.

## Additional machine selection

Garfield was the active target made available for this run. The following
retired write-ups are suitable follow-on coverage, but were not launched because
no HTB account/API session was supplied and the user prohibited unauthorized
machine access:

| Machine | Coverage added | 0xdf write-up |
|---|---|---|
| Manager | IIS/HTTP, MSSQL, ADCS, SMB, LDAP, WinRM | <https://0xdf.gitlab.io/2024/03/16/htb-manager.html> |
| Certified | Pure AD, ADCS/ESC9, SMB, LDAP, WinRM | <https://0xdf.gitlab.io/2025/03/15/htb-certified.html> |
| Checkpoint | Windows Server 2025, AD, SMB, WinRM, VMware backup artifacts | <https://0xdf.gitlab.io/2026/10/24/htb-checkpoint.html> |

Launching these requires an authorized HTB session. Use the same single-target
scope pattern and update `lab-scope.toml`; do not reuse this scope file for a
different address.

## Fingerprints and checks

- nmap identified `garfield.htb` LDAP on 389/3268, Kerberos on 88, Microsoft
  RPC on 135, SMB on 445, RDP on 3389, and WinRM on 5985.
- rayscan identified SMB `3.0.2`, RDP `DC01.garfield.htb` / build `10.0.17763`
  with `HYBRID_EX`, WinRM `HTTP/1.1 401`, and RDP TLS 1.2
  (`TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`).
- OS fingerprint: Windows family at 91.5% confidence, two samples and 100%
  agreement. The fine-grained label was Windows 10/11, not Server 2019; the
  family classification is correct, the edition is not exact.
- `rayscan` did not identify DNS, Kerberos, LDAP, ADWS, or RPC-over-HTTP by
  name without banner data. nmap's probe set did.
- The official safe script pack and advisory matching emitted no findings. The
  target does not expose a version banner for most AD services, so the absence
  of advisory matches is not evidence that the host is unpatched.
- The HTML report is self-contained (8.6 KiB, no remote asset references).
  The baseline differential reported no changes across two scans.
- The scope guard rejected `10.129.244.208` with exit code 2 before probing.

## Limitations found

- Banner verification reports no-banner AD services as `silent`. Ports `53` and
  `135` were false negatives in verified mode; connect-only mode found both.
  Complete TCP inventory on AD hosts requires connect-only discovery, or a
  verification fallback for silent-but-accepting ports.
- UDP `53` was silent for both passive and active probing. This run does not
  claim the UDP DNS state.
- Raw SYN scanning through WSL host NAT failed: the seven tested open ports
  produced zero opens, six filtered results, and one silent result. The defense
  classifier also reported a false tarpit. Native Windows Npcap was not
  installed, so the Windows raw path could not be tested. Use connect-only in
  this environment; native Linux or Windows raw execution remains a separate
  validation requirement.
- TLS probing of `636` and `3269` was reset before a certificate could be read.
  This may be target policy or the network path; it is not recorded as a
  successful LDAPS check.
- nmap OS detection could not run because the host exposed no closed TCP port.
  The rayscan OS result came from TCP option characteristics, not a full
  open/closed OS probe set.

## Reproduction

Run `python3 bench/htb/analyze.py` after collecting the result files. It writes
`bench/htb/results/htb-summary.json` and `bench/htb/results/htb-summary.md` with
the port sets, metrics, verified-mode failures, OS fingerprint, and resource
measurements. The target is a live lab machine and may change or be retired.
