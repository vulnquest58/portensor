# Authorized HTB validation: Scaffold

This directory records an authorized, user-provided Hack The Box lab run against
`Scaffold`. It contains only network discovery, service/fingerprint inspection,
safe protocol queries, HTTP header inspection, and scope-guard validation. No
exploitation, credential access, authentication attempts, directory
enumeration, or post-exploitation activity was performed. VPN configuration and
secrets remain outside the repository.

- Target: `10.129.215.153`
- Machine: `Scaffold`
- Platform: Windows domain controller
- Scope: [`lab-scope-scaffold.toml`](lab-scope-scaffold.toml), only this `/32`
- Authorization: the user's explicit target handoff and active HTB lab session
- Evidence: [`results-scaffold/`](results-scaffold/)
- Evidence hashes: [`results-scaffold/SHA256SUMS`](results-scaffold/SHA256SUMS)
- Reference: no write-up was used

This is authorized live-validation evidence for scanner behavior. It is not
P4-2 registry ownership, account-control, package clean-install, or container
digest evidence.

## Environment

The Windows OpenVPN TAP path was used. WSL reached the target through host NAT.
The domain resolves from the target DNS server as `scaffold.htb`, with
`dc.scaffold.htb` at `10.129.215.153`. The portal certificate names
`portal.scaffold.htb`, but the target DNS server returned no A record for that
name; HTTP checks used `--resolve` for the portal host.

## Commands

```bash
cd /mnt/e/VulnQuest_Pro/portensor

/usr/bin/time -v ./target/release/rayscan scan --target 10.129.215.153 \
  --scope bench/htb/lab-scope-scaffold.toml --ports 1-65535 \
  --connect-only --profile fast --timeout 1 --retries 0 --workers 512 \
  --quiet --json -o bench/htb/results-scaffold/rayscan-full-connect.json \
  2> bench/htb/results-scaffold/rayscan-full-connect.time.txt

./target/release/rayscan scan --target 10.129.215.153 \
  --scope bench/htb/lab-scope-scaffold.toml \
  --ports 53,80,88,135,139,389,443,445,464,593,636,3268,3269,5040,5985,9389,9800,9801,47001,49664,49665,49666,49667,52951,56384,56405,56408,61051,61055,64642 \
  --connect-only --profile careful --rate 20 --timeout 3 --retries 2 \
  --workers 10 --quiet --json \
  -o bench/htb/results-scaffold/rayscan-focused-connect.json

./target/release/rayscan scan --target 10.129.215.153 \
  --scope bench/htb/lab-scope-scaffold.toml \
  --ports 53,80,88,135,139,389,443,445,464,593,636,3268,3269,5040,5985,9389,9800,9801,47001,49664,49665,49666,49667,52951,56384,56405,56408,61051,61055,64642 \
  --profile careful --rate 50 --timeout 2 --retries 1 --workers 16 --tls \
  --quiet --json -o bench/htb/results-scaffold/rayscan-services.json

nmap -Pn -p- --min-rate 2000 --max-retries 1 --max-rtt-timeout 400ms \
  --initial-rtt-timeout 100ms --host-timeout 240s 10.129.215.153 \
  -oN bench/htb/results-scaffold/nmap-alltcp-rate-limited.txt \
  -oX bench/htb/results-scaffold/nmap-alltcp-rate-limited.xml

nmap -Pn -p- --max-rate 250 --max-retries 1 --max-rtt-timeout 1s \
  --initial-rtt-timeout 200ms --host-timeout 600s 10.129.215.153 \
  -oN bench/htb/results-scaffold/nmap-alltcp-slow-timed-out.txt \
  -oX bench/htb/results-scaffold/nmap-alltcp-slow-timed-out.xml

nmap -Pn -sV --version-light --max-rate 100 --max-retries 2 \
  --host-timeout 240s \
  -p53,80,88,135,139,389,443,445,464,593,636,3268,3269,5040,5985,9389,9800,9801,47001,49664,49665,49666,49667,52951,56384,56405,56408,61051,61055,64642 \
  10.129.215.153 \
  -oN bench/htb/results-scaffold/nmap-services.txt \
  -oX bench/htb/results-scaffold/nmap-services.xml

nmap -Pn --max-rate 80 --max-retries 2 --host-timeout 240s \
  -p53,88,135,139,389,443,445,464,593,636,3268,3269,5985,9389,9800,9801,47001 \
  --script smb2-security-mode,smb2-time,smb-os-discovery,ldap-rootdse,ssl-cert \
  10.129.215.153 -oN bench/htb/results-scaffold/nmap-scripts.txt

curl -sS --noproxy '*' --max-time 20 \
  -D bench/htb/results-scaffold/http-ip80-headers.txt \
  -o bench/htb/results-scaffold/http-ip80-body.txt \
  http://10.129.215.153/

curl -k -sS --noproxy '*' --max-time 20 \
  -D bench/htb/results-scaffold/http-ip443-headers.txt \
  -o bench/htb/results-scaffold/http-ip443-body.txt \
  https://10.129.215.153/

wsl.exe -u root bash -lc "cd /mnt/e/VulnQuest_Pro/portensor && \
  ./target/release/rayscan scan --target 10.129.215.153 \
  --scope bench/htb/lab-scope-scaffold.toml --ports 80,88,139,389,445,5985 \
  --syn --os --os-probes 3 --profile careful --rate 40 --timeout 2 \
  --retries 1 --workers 8 --quiet --json \
  -o bench/htb/results-scaffold/rayscan-os.json"
```

The scope-denial check targeted `10.129.215.154` with the same scope file and
exited `2` before probing.

## Confirmed TCP surface

The confirmed open set is the agreement of the rayscan full and focused passes
and the nmap targeted service scan. It contains 30 TCP ports:

```text
53, 80, 88, 135, 139, 389, 443, 445, 464, 593, 636, 3268, 3269, 5040,
5985, 9389, 9800, 9801, 47001, 49664, 49665, 49666, 49667,
52951, 56384, 56405, 56408, 61051, 61055, 64642
```

| Scanner | Open | Agreement with 30-port set | Notes |
|---|---:|---:|---|
| rayscan full connect | 30 | 1.000 | 33.78 s wall; rate limited |
| rayscan focused recheck | 30 | 1.000 | 30/30 at low rate |
| nmap targeted service | 30 | 1.000 | all discovered ports; 38.78 s |
| nmap all-TCP | invalid | not claimed | high-rate all-filtered false negative; slow pass timed out |

The all-TCP nmap result was not used, so the 30-port set does not have an
independent full-port completeness reference. A first attempt exceeded 300
seconds with no report. A retry at high rate returned all 65,535 ports filtered
after 67.57 seconds, contradicting the already confirmed open services. A
third attempt at `--max-rate 250` hit the 600-second host timeout without
reporting ports. The outputs are kept as
`nmap-alltcp-rate-limited.txt`/`.xml` and
`nmap-alltcp-slow-timed-out.txt`/`.xml`; they are evidence of rate limiting,
not of a closed surface. After a 90-second pause, a 10-port recheck returned
all 10 open. The targeted nmap service scan then confirmed every port in the
discovered set.

## Timing and resources

| Measurement | Result |
|---|---|
| rayscan full discovery | 31.706 s internal, 33.78 s wall |
| rayscan full CPU / peak RSS | 1.47 s user + 7.13 s system / 20.1 MiB |
| rayscan focused recheck | 1.719 s internal |
| rayscan service scan | 1.964 s internal; 15 service-verified, 15 silent |
| nmap targeted service | 38.78 s |
| nmap script pass | 37.02 s |
| rayscan raw OS scan | 3.184 s |

Rayscan's defense classifier reported `rate_limiting` on the full pass, with 25
ports requiring retries or backoff. The focused careful pass recovered the full
30-port set at a low probe rate.

## Services

- `53/tcp`: DNS. SOA is
  `dc.scaffold.htb hostmaster.scaffold.htb 315 900 600 86400 3600`; NS is
  `dc.scaffold.htb`; `_ldap._tcp.dc._msdcs.scaffold.htb` points to
  `dc.scaffold.htb:389`.
- `80/tcp`: Microsoft-IIS/10.0, `401 Unauthorized`, ASP.NET headers. The
  `portal.scaffold.htb` host header did not change the response.
- `88/tcp`: Kerberos.
- `135/tcp`: Microsoft Windows RPC.
- `139/tcp`: Microsoft Windows NetBIOS session service.
- `389/tcp`: Active Directory LDAP. Anonymous rootDSE reports
  `DC=scaffold,DC=htb`, `dnsHostName: dc.scaffold.htb`, Global Catalog ready,
  and domain/forest/DC functionality level `7`.
- `443/tcp`: Microsoft-IIS/10.0 over TLS 1.3. The certificate subject is
  `CN=portal.scaffold.htb`; SANs are `portal.scaffold.htb` and `DC01`; the
  certificate is self-signed and valid. IP and portal-host requests returned
  `401`; the HTTPS response advertises `Negotiate` and `NTLM`.
- `445/tcp`: SMB 3.0.2. SMB2 security mode is `2.02`; signing is enabled and
  required.
- `464/tcp`: Kerberos password-change service.
- `593/tcp`: Microsoft RPC over HTTP 1.0.
- `636/tcp`: LDAPS over TLS 1.2. The certificate is issued by
  `scaffold-DC-CA` and has SANs `dc.scaffold.htb`, `scaffold.htb`, and
  `SCAFFOLD`.
- `3268/tcp`: Global Catalog LDAP.
- `3269/tcp`: Global Catalog LDAPS, with the same DC certificate SANs.
- `5040/tcp`: open TCP, identity not determined.
- `5985/tcp`: WinRM/WSMAN, Microsoft HTTPAPI, `404 Not Found` on `/`.
- `9389/tcp`: Active Directory Web Services.
- `9800/tcp` and `9801/tcp`: Microsoft-HTTPAPI/2.0, `503 Service Unavailable`.
- `47001/tcp`: Microsoft-HTTPAPI/2.0, `404 Not Found`.
- `49664`-`49667`, `52951`, `56384`, `56405`, `56408`, `61051`, `61055`,
  `64642`: open dynamic/high ports. RPC identity is likely for the
  `49664`-`49667` range; the remaining ports are not individually identified.

No credentials were supplied, no authentication attempt was made, and no
directory enumeration, vulnerability exploitation, or data modification was
performed.

## OS and defense result

Rayscan's raw TCP fingerprint reported a Windows domain controller:

- Family: `windows`
- Role: `domaincontroller`
- Confidence: `0.933`
- Initial TTL: `128`; hops: `2`
- Samples: `3`; agreement: `1.0`
- Endpoints: `80`, `88`, `139`
- Evidence: `TTL=126, Window=65535, MSS=1346, WScale=8, SACK=yes, DF=yes`;
  Microsoft-IIS service evidence on port 80.

The exact Windows Server edition was not established. Independent nmap and
LDAP evidence identifies the host as the domain controller for
`scaffold.htb`.

## Scope guard

The scope file allows only `10.129.215.153/32`. A scan of `10.129.215.154` was
rejected before probing with:

```text
SCOPE VIOLATION: Target IP '10.129.215.154' is outside the authorized scope...
exit=2
```

## Limitations

- The target rate-limited high-concurrency scans. A high-rate nmap all-TCP scan
  produced an invalid all-filtered result, and a slower 250 pps attempt timed
  out at 600 seconds; neither is used as inventory evidence.
- UDP coverage was not performed.
- `5040/tcp` and several high dynamic ports remain unidentified.
- The HTTPS portal advertises `Negotiate` and `NTLM`; no credentials or
  authentication attempts were used. Port 80 also returned `401` but did not
  include an authentication challenge header.
- No vulnerability or patch-level conclusion is drawn from the exposed banners
  or certificate metadata.
- No exploitation or post-exploitation activity was performed.
