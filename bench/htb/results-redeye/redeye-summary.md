# RedEye validation summary

- Target: `10.129.214.126`
- Scope: [`../lab-scope-redeye.toml`](../lab-scope-redeye.toml)
- Open TCP ports: 22, 80, 443, 3000
- nmap, rayscan v2, and verified service sets match: True
- Full discovery: nmap 131.54 s; rayscan v2 141.022 s
- nmap service scan: 111.79 s
- Endpoint OS: mixed OS: linux (22, 80), windows (443) (96%)

## nmap services

| Port | Service | Product |
|---|---|---|
| 22/tcp | ssh | OpenSSH 10.0p2 Debian 7+deb13u4 |
| 80/tcp | http | nginx  |
| 443/tcp | https |   |
| 3000/tcp | http | nginx  |

## rayscan service and endpoint OS

| Port | Service | TLS SNI | Endpoint OS | Raw stack | Detail |
|---|---|---|---|---|---|
| 22/tcp | ssh OpenSSH | - | linux | windows | Linux (debian service evidence) |
| 80/tcp | http nginx | - | linux | windows | Linux (nginx edge service evidence) |
| 443/tcp | https Microsoft-HTTPAPI | sts.airways.htb | windows | windows | Windows (microsoft-httpapi service evidence) |
| 3000/tcp | https nginx | chat.airways.htb | linux | windows | Linux (nginx edge service evidence) |

## TLS

- 443: TLSv1.3 / TLS13_AES_256_GCM_SHA384, SNI `sts.airways.htb`, hostname match True
- 443 certificate: subject CN=sts.airways.htb; issuer CN=sts.airways.htb; self-signed True
- 3000: TLSv1.3 / TLS13_AES_256_GCM_SHA384, SNI `chat.airways.htb`, hostname match True
- 3000 certificate: subject CN=chat.airways.htb; issuer DC=htb, DC=airways, CN=AIRWAYS-DC01-CA; self-signed False

## Limitations

- Raw SYN-ACK stack evidence was Windows-like on every probed endpoint; endpoint labels use service-derived corrections.
- 443/tcp requires SNI sts.airways.htb; without SNI the TLS endpoint can reset and may be omitted from a retained TLS scan.
- 3000/tcp uses SNI chat.airways.htb and identifies an nginx front; the Rocket.Chat/Express application is not fingerprinted by the built-in service matcher.
- Full discovery is connect-only; no raw-SYN or UDP claim is made.
- Only four open TCP ports were exposed.

## Reproduction

```bash
python3 bench/htb/analyze_redeye.py
```
