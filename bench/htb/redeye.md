# Authorized HTB validation: RedEye

This directory records a second authorized, user-provided HTB lab run. It
contains only network discovery, service inspection, TLS/SNI identification,
and OS fingerprinting. No exploitation, credential access, vhost brute force,
or post-exploitation activity was performed.

- Target: `10.129.214.126`
- Machine: RedEye, active HTB Season 12 Windows/Hard lab
- Scope: [`lab-scope-redeye.toml`](lab-scope-redeye.toml), only this `/32`
- Reference: no 0xdf write-up was used because the machine was still active
- Evidence: [`results-redeye/`](results-redeye/)

## Environment

The same Windows OpenVPN TAP path was used as for Garfield. WSL reached the
target through host NAT. VPN configuration and secrets remain outside the
repository.

## V2 commands

```bash
cd /mnt/e/VulnQuest_Pro/portensor

/usr/bin/time -v ./target/release/rayscan scan --target 10.129.214.126 \
  --scope bench/htb/lab-scope-redeye.toml --ports 1-65535 \
  --connect-only --profile fast --timeout 1 --retries 0 --workers 512 \
  --quiet --json -o bench/htb/results-redeye/rayscan-full-connect-v2.json \
  2> bench/htb/results-redeye/rayscan-full-connect-v2.time.txt

nmap -Pn -p- --min-rate 1000 10.129.214.126 \
  -oN bench/htb/results-redeye/nmap-alltcp.txt \
  -oX bench/htb/results-redeye/nmap-alltcp.xml

nmap -Pn -sV -sC -p22,80,443,3000 10.129.214.126 \
  -oN bench/htb/results-redeye/nmap-services.txt \
  -oX bench/htb/results-redeye/nmap-services.xml

wsl -u root /usr/bin/time -v ./target/release/rayscan scan \
  --target 10.129.214.126 --scope bench/htb/lab-scope-redeye.toml \
  --ports 22,80,443 --tls --sni sts.airways.htb \
  --scripts packs/official-baseline/pack.toml --advisories \
  --os --os-probes 3 --profile balanced --timeout 5 --retries 2 \
  --quiet --json -o bench/htb/results-redeye/rayscan-os-mixed-v2.json \
  2> bench/htb/results-redeye/rayscan-os-mixed-v2.time.txt

wsl -u root /usr/bin/time -v ./target/release/rayscan scan \
  --target 10.129.214.126 --scope bench/htb/lab-scope-redeye.toml \
  --ports 3000 --tls --sni chat.airways.htb \
  --scripts packs/official-baseline/pack.toml --advisories \
  --os --os-probes 1 --profile balanced --timeout 5 --retries 2 \
  --quiet --json -o bench/htb/results-redeye/rayscan-sni-chat-v2.json \
  2> bench/htb/results-redeye/rayscan-sni-chat-v2.time.txt
```

The per-port TLS scans are required because the host serves different virtual
hosts on `443` and `3000`. A no-SNI TLS pass can lose `443` because that
endpoint resets the handshake. Full port discovery remains a separate
connect-only pass.

## Results

Both independent full-TCP scans returned exactly four open ports:

| Port | nmap | rayscan v2 |
|---|---|---|
| 22/tcp | OpenSSH 10.0p2 Debian 13 | `SSH-2.0-OpenSSH_10.0p2 Debian-7+deb13u4`, Linux service evidence |
| 80/tcp | nginx, redirect to `geo.airways.htb` | `HTTP/1.1 302 Moved Temporarily`, nginx, Linux service evidence |
| 443/tcp | https, SNI required | `https`, Microsoft-HTTPAPI/2.0 ADFS, SNI `sts.airways.htb` matched |
| 3000/tcp | nginx, redirect to HTTPS | `https` nginx, TLSv1.3, SNI `chat.airways.htb` matched |

- Full connect-only discovery v2: 4/4 ports, 65,531 filtered, `141.022 s`
  internally, `2:21.71` wall time.
- nmap full-TCP: 4/4 ports, `131.54 s`. nmap service scan: `111.79 s`.
- The nmap and rayscan port sets match exactly: 100% recall and precision on the
  exposed TCP surface.
- The focused mixed scan covers `22/80/443` in `3.20 s` wall time; the focused
  chat scan covers `3000` in `1.65 s` wall time.
- `443/tcp` presents TLSv1.3 with `TLS13_AES_256_GCM_SHA384`, a self-signed
  `CN = sts.airways.htb` certificate, SANs `sts.airways.htb` and
  `airways.htb`, and a `Microsoft-HTTPAPI/2.0` ADFS front.
- `3000/tcp` presents TLSv1.3 with `TLS13_AES_256_GCM_SHA384`, certificate
  `CN = chat.airways.htb` issued by `AIRWAYS-DC01-CA`, and an nginx front. The
  captured headers identify an Express-backed application (`X-Powered-By:
  Express`, `X-Instance-ID`), consistent with Rocket.Chat.
- The official safe pack and advisory matching emitted no findings. No
  version-based vulnerability conclusion is drawn from the exposed banners.

## Endpoint-aware OS result

The raw SYN-ACK stack signature was the same Windows-like fingerprint on every
probed endpoint (`TTL=126`, `Window=65535`, `MSS=1346`, `WScale=8`, `SACK=yes`,
`DF=yes`). Treating that as a host-wide label was wrong.

Rayscan v2 keeps both the raw stack evidence and the service-derived endpoint
correction:

| Endpoint | Raw stack | Effective family | Service evidence | Confidence |
|---|---|---|---|---|
| 22/tcp | Windows-like | Linux | Debian/OpenSSH | 0.95 |
| 80/tcp | Windows-like | Linux | nginx edge | 0.72 |
| 443/tcp | Windows-like | Windows | Microsoft-HTTPAPI/ADFS | 0.97 |
| 3000/tcp | Windows-like | Linux | nginx edge | 0.72 |

Host summary: `mixed OS: linux (22, 80), windows (443)`, confidence `0.96` in
the focused mixed scan. The chat scan independently reports Linux nginx-edge
evidence for `3000/tcp`.

## V1 to V2 comparison

| Item | V1 | V2 |
|---|---|---|
| Full discovery | 4/4, 141.066 s | 4/4, 141.022 s |
| 443 SNI | not supported | `--sni sts.airways.htb` |
| 3000 SNI | not supported | `--sni chat.airways.htb` |
| OS output | single host label, Windows 91.5% | endpoint assignments plus mixed host summary |
| Endpoint corrections | absent | raw stack retained; service evidence corrects 22/80/3000 to Linux |
| Evidence files | `rayscan-full-connect.json`, `rayscan-verified-services.json`, `rayscan-os.json` | `*-v2.json` files plus retained v1 evidence |

The earlier no-SNI limitation and the earlier host-wide Windows conclusion are
superseded. The v1 JSON/XML files and the `openssl`/`curl` captures remain in
`results-redeye/` as historical evidence.

## Accuracy and feature notes

- `--connect-only` intentionally disables banner and verification checks. It is
  correct for port inventory but will not identify SSH/HTTP here. Service
  inspection requires focused verified-mode passes.
- `--sni` is an FQDN-only override. It is normalized to lowercase, rejects IP
  literals and wildcard/underscore names, and conflicts with `--no-tls` and
  `--ack`.
- SNI is used for the rustls server name, DNS SAN/CN matching, and the HTTP
  `Host` header. It is exported as `tls.sni`.
- OS endpoint results are JSON-visible (`os_fingerprints.<host>.endpoints`) and
  appear in terminal, Markdown, HTML, and Nmap XML output.
- Raw SYN through WSL host NAT remains unsupported, as documented for Garfield.
  This run uses connect-only discovery and connect-derived OS probes.
- No UDP scan or UDP service claim is made.

## Reproduction

```bash
python3 bench/htb/analyze_redeye.py
```

This writes `bench/htb/results-redeye/redeye-summary.json` and
`redeye-summary.md`. The target is an active HTB machine and may be reset or
retired; the scope file must be updated for any replacement address.
