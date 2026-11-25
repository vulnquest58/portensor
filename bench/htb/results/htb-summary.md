# HTB Garfield validation summary

- Target: `10.129.244.207`
- Reference: <https://0xdf.gitlab.io/2026/11/07/htb-garfield.html>
- Confirmed open TCP ports: 22
- Confirmed set: 53, 88, 135, 139, 389, 445, 464, 593, 636, 2179, 3268, 3269, 3389, 5985, 9389, 49668, 49676, 49677, 49679, 49680, 49906, 58166

## Port discovery

| Scanner | Open | TP | FP | FN | Recall | Precision |
|---|---:|---:|---:|---:|---:|---:|
| nmap_all_tcp | 20 | 20 | 0 | 2 | 0.909 | 1.000 |
| nmap_service_scan | 22 | 22 | 0 | 0 | 1.000 | 1.000 |
| rayscan_full_connect | 20 | 20 | 0 | 2 | 0.909 | 1.000 |
| rayscan_two_pass | 22 | 22 | 0 | 0 | 1.000 | 1.000 |

`nmap_service_scan` is a service probe over the confirmed candidate set, not an
independent all-port discovery pass. `rayscan_two_pass` is the union of the full
connect-only scan and the focused recheck.

## Focused recovery

Rechecked ports: 593, 3268, 49668, 58166. All confirmed ports recovered: True.

## Verified-mode limitation

Ports 53 and 135 were reported as silent by banner verification: {'open': 0, 'closed': 0, 'filtered': 0, 'unfiltered': 0, 'silent': 2, 'unreachable': 0, 'error': 0}.

## OS fingerprint

{
  "10.129.244.207": {
    "family": "windows",
    "role": "memberserver",
    "detail": "Windows 10/11",
    "confidence": 0.9148936,
    "hops": 2,
    "samples": 2,
    "agreement": 1.0
  }
}

## UDP 53

Passive and active probes returned silent; the UDP state remains unverified.

## Raw SYN limitation

Raw SYN over the WSL host-NAT path reported 0 open, 6 filtered, and 1 silent. Native Windows Npcap was unavailable, so this result is environment-specific.
