#!/usr/bin/env python3
"""Summarize authorized HTB Garfield port-discovery and fingerprint evidence."""

from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RESULTS = ROOT / "bench" / "htb" / "results"
DEFAULT_OUTPUT = DEFAULT_RESULTS / "htb-summary.json"
DEFAULT_MARKDOWN = DEFAULT_RESULTS / "htb-summary.md"
TARGET = "10.129.244.207"
REFERENCE = "https://0xdf.gitlab.io/2026/11/07/htb-garfield.html"


def nmap_open_ports(path: Path) -> set[int]:
    root = ET.parse(path).getroot()
    return {
        int(port.attrib["portid"])
        for port in root.findall("./host/ports/port")
        if port.find("state") is not None
        and port.find("state").attrib.get("state") == "open"
    }


def nmap_services(path: Path) -> dict[int, dict[str, str]]:
    root = ET.parse(path).getroot()
    services: dict[int, dict[str, str]] = {}
    for port in root.findall("./host/ports/port"):
        if port.find("state") is None or port.find("state").attrib.get("state") != "open":
            continue
        service = port.find("service")
        if service is None:
            services[int(port.attrib["portid"])] = {}
            continue
        services[int(port.attrib["portid"])] = {
            key: value
            for key, value in service.attrib.items()
            if key in {"name", "product", "version", "tunnel"}
        }
    return services


def rayscan_open_ports(path: Path) -> set[int]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return {int(item["port"]) for item in data.get("open", [])}


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def set_metrics(name: str, observed: set[int], expected: set[int]) -> dict:
    true_positives = observed & expected
    false_positives = observed - expected
    false_negatives = expected - observed
    return {
        "name": name,
        "open_ports": sorted(observed),
        "true_positives": len(true_positives),
        "false_positives": sorted(false_positives),
        "false_negatives": sorted(false_negatives),
        "recall": round(len(true_positives) / len(expected), 6) if expected else None,
        "precision": round(len(true_positives) / len(observed), 6) if observed else None,
        "exact": observed == expected,
    }


def parse_time(path: Path) -> dict:
    if not path.exists():
        return {}
    values: dict[str, float] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if "Maximum resident" in line:
            values["max_rss_kib"] = float(line.split(":", 1)[1])
        elif line.startswith("User time"):
            values["user_seconds"] = float(line.split(":", 1)[1])
        elif line.startswith("System time"):
            values["system_seconds"] = float(line.split(":", 1)[1])
        elif line.startswith("Elapsed"):
            match = re.search(r"\):\s*([0-9:.]+)\s*$", line)
            if not match:
                continue
            parts = [float(part) for part in match.group(1).split(":")]
            if len(parts) == 3:
                values["wall_seconds"] = parts[0] * 3600 + parts[1] * 60 + parts[2]
            elif len(parts) == 2:
                values["wall_seconds"] = parts[0] * 60 + parts[1]
    return values


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--markdown", type=Path, default=DEFAULT_MARKDOWN)
    args = parser.parse_args()

    results = args.results
    nmap_alltcp = nmap_open_ports(results / "nmap-alltcp.xml")
    nmap_services_open = nmap_open_ports(results / "nmap-services-full.xml")
    nmap_service_map = nmap_services(results / "nmap-services-full.xml")
    rayscan_full = rayscan_open_ports(results / "rayscan-full-connect.json")
    rayscan_focus = rayscan_open_ports(results / "rayscan-focus-extra.json")
    rayscan_q = rayscan_open_ports(results / "rayscan-q-timed.json")

    confirmed = nmap_services_open & (rayscan_full | rayscan_focus)
    if confirmed != nmap_services_open or confirmed != (rayscan_full | rayscan_focus):
        print("warning: scanners do not agree on the confirmed open set", file=sys.stderr)

    verified_nobanner = load_json(results / "rayscan-verified-nobanner.json")
    raw_syn = load_json(results / "rayscan-syn.json")
    os_data = load_json(results / "rayscan-os.json")
    os_fingerprints = {
        host: {
            key: value
            for key, value in fingerprint.items()
            if key in {"family", "role", "detail", "confidence", "hops", "samples", "agreement"}
        }
        for host, fingerprint in os_data.get("os_fingerprints", {}).items()
    }

    rayscan_two_pass = rayscan_full | rayscan_focus
    metrics = [
        set_metrics("nmap_all_tcp", nmap_alltcp, confirmed),
        set_metrics("nmap_service_scan", nmap_services_open, confirmed),
        set_metrics("rayscan_full_connect", rayscan_full, confirmed),
        set_metrics("rayscan_two_pass", rayscan_two_pass, confirmed),
    ]
    recovery = {
        "ports": sorted(rayscan_focus),
        "missing_from_full_scan": sorted(confirmed - rayscan_full),
        "not_found_in_full_scan": sorted(rayscan_focus - rayscan_full),
        "recovered_all": confirmed <= rayscan_two_pass,
    }

    payload = {
        "schema": 1,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "target": TARGET,
        "reference": REFERENCE,
        "authorization": "user-provided Hack The Box lab session; scope file allows this host only",
        "confirmed_open_ports": sorted(confirmed),
        "confirmed_open_count": len(confirmed),
        "scanner_metrics": metrics,
        "focus_recovery": recovery,
        "q_preset": {
            "open_ports": sorted(rayscan_q),
            "confirmed_open": len(rayscan_q & confirmed),
            "false_positives": sorted(rayscan_q - confirmed),
            "filtered": load_json(results / "rayscan-q-timed.json")["summary"]["filtered"],
            "elapsed_ms": load_json(results / "rayscan-q-timed.json")["elapsed_ms"],
            "resources": parse_time(results / "rayscan-q-timed.time"),
        },
        "verified_no_banner": {
            "ports": [53, 135],
            "summary": verified_nobanner["summary"],
            "false_negatives": sorted(confirmed & {53, 135}),
        },
        "udp_53": {
            "passive": load_json(results / "rayscan-udp53.json")["summary"],
            "active": load_json(results / "rayscan-udp53-active.json")["summary"],
            "note": "silent; UDP DNS state is not claimed from this result",
        },
        "raw_syn": {
            "open_ports": sorted(item["port"] for item in raw_syn.get("open", [])),
            "summary": raw_syn["summary"],
            "defense": raw_syn.get("defense", {}),
            "note": "WSL host-NAT path; native Windows Npcap was unavailable",
        },
        "os_fingerprints": os_fingerprints,
        "nmap_services": {str(port): service for port, service in sorted(nmap_service_map.items())},
        "limitations": [
            "Rayscan banner verification treats no-banner AD services as silent; connect-only discovery is required for complete TCP inventory.",
            "Nmap could not perform OS detection because the host exposed no closed TCP port.",
            "UDP 53 remained silent to passive and active probing; no UDP service state is claimed.",
        ],
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    table = [
        "| Scanner | Open | TP | FP | FN | Recall | Precision |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for metric in metrics:
        table.append(
            f"| {metric['name']} | {len(metric['open_ports'])} | {metric['true_positives']} | "
            f"{len(metric['false_positives'])} | {len(metric['false_negatives'])} | "
            f"{metric['recall']:.3f} | {metric['precision']:.3f} |"
        )

    markdown = "\n".join(
        [
            "# HTB Garfield validation summary",
            "",
            f"- Target: `{TARGET}`",
            f"- Reference: <{REFERENCE}>",
            f"- Confirmed open TCP ports: {len(confirmed)}",
            f"- Confirmed set: {', '.join(str(port) for port in sorted(confirmed))}",
            "",
            "## Port discovery",
            "",
            *table,
            "",
            "`nmap_service_scan` is a service probe over the confirmed candidate set, not an",
            "independent all-port discovery pass. `rayscan_two_pass` is the union of the full",
            "connect-only scan and the focused recheck.",
            "",
            "## Focused recovery",
            "",
            f"Rechecked ports: {', '.join(str(port) for port in recovery['ports'])}. "
            f"All confirmed ports recovered: {recovery['recovered_all']}.",
            "",
            "## Verified-mode limitation",
            "",
            f"Ports 53 and 135 were reported as silent by banner verification: "
            f"{verified_nobanner['summary']}.",
            "",
            "## OS fingerprint",
            "",
            json.dumps(os_fingerprints, indent=2),
            "",
            "## UDP 53",
            "",
            "Passive and active probes returned silent; the UDP state remains unverified.",
            "",
            "## Raw SYN limitation",
            "",
            f"Raw SYN over the WSL host-NAT path reported {raw_syn['summary']['open']} open, "
            f"{raw_syn['summary']['filtered']} filtered, and {raw_syn['summary']['silent']} silent. "
            "Native Windows Npcap was unavailable, so this result is environment-specific.",
            "",
        ]
    )
    args.markdown.write_text(markdown, encoding="utf-8")
    print(f"wrote {args.output} and {args.markdown}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
