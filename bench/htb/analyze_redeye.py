#!/usr/bin/env python3
"""Summarize authorized RedEye discovery, SNI, and endpoint-OS evidence."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
RESULTS = ROOT / "bench" / "htb" / "results-redeye"


def nmap_ports(path: Path) -> set[int]:
    root = ET.parse(path).getroot()
    return {
        int(port.attrib["portid"])
        for port in root.findall("./host/ports/port")
        if port.find("state") is not None
        and port.find("state").attrib.get("state") == "open"
    }


def nmap_services(path: Path) -> dict[str, dict[str, str]]:
    root = ET.parse(path).getroot()
    result: dict[str, dict[str, str]] = {}
    for port in root.findall("./host/ports/port"):
        if port.find("state") is None or port.find("state").attrib.get("state") != "open":
            continue
        service = port.find("service")
        result[port.attrib["portid"]] = dict(service.attrib) if service is not None else {}
    return result


def nmap_elapsed(path: Path) -> float | None:
    root = ET.parse(path).getroot()
    finished = root.find("./runstats/finished")
    if finished is None:
        return None
    try:
        return float(finished.attrib["elapsed"])
    except (KeyError, ValueError):
        return None


def wall_seconds(path: Path) -> float | None:
    if not path.exists():
        return None
    for line in path.read_text(errors="replace").splitlines():
        if "Elapsed (wall clock) time" not in line:
            continue
        value = line.split("m:ss):", 1)[-1].strip()
        parts = value.split(":")
        try:
            if len(parts) == 3:
                return round(int(parts[0]) * 3600 + int(parts[1]) * 60 + float(parts[2]), 3)
            if len(parts) == 2:
                return round(int(parts[0]) * 60 + float(parts[1]), 3)
        except ValueError:
            return None
    return None


def load(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise SystemExit(f"missing evidence file: {path}")
    return json.loads(path.read_text())


def open_ports(report: dict[str, Any]) -> list[dict[str, Any]]:
    return sorted(report.get("open", []), key=lambda item: int(item["port"]))


def endpoint_os(report: dict[str, Any]) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    fingerprints = report.get("os_fingerprints") or {}
    if not fingerprints:
        return None, []
    guess = next(iter(fingerprints.values()))
    return guess, sorted(guess.get("endpoints", []), key=lambda item: int(item["port"]))


def service_row(item: dict[str, Any]) -> dict[str, Any]:
    service = item.get("service") or {}
    tls = item.get("tls") or {}
    return {
        "port": item["port"],
        "banner": item.get("banner"),
        "service": service.get("name"),
        "product": service.get("product"),
        "service_confidence": service.get("confidence"),
        "detail": item.get("detail"),
        "tls_version": tls.get("version"),
        "tls_sni": tls.get("sni"),
        "tls_hostname_matches": tls.get("hostname_matches"),
    }


def tls_row(item: dict[str, Any]) -> dict[str, Any]:
    tls = item.get("tls") or {}
    return {
        "port": item["port"],
        "version": tls.get("version"),
        "cipher": tls.get("cipher"),
        "sni": tls.get("sni"),
        "hostname_matches": tls.get("hostname_matches"),
        "subject": tls.get("subject"),
        "issuer": tls.get("issuer"),
        "san": tls.get("san"),
        "self_signed": tls.get("self_signed"),
    }


def main() -> int:
    nmap_open = nmap_ports(RESULTS / "nmap-alltcp.xml")
    services = nmap_services(RESULTS / "nmap-services.xml")
    full_v1 = load(RESULTS / "rayscan-full-connect.json")
    full_v2 = load(RESULTS / "rayscan-full-connect-v2.json")
    mixed = load(RESULTS / "rayscan-os-mixed-v2.json")
    chat = load(RESULTS / "rayscan-sni-chat-v2.json")
    os_guess, os_endpoints = endpoint_os(mixed)
    chat_guess, chat_endpoints = endpoint_os(chat)
    all_endpoints = {int(entry["port"]): entry for entry in os_endpoints + chat_endpoints}

    mixed_open = open_ports(mixed)
    chat_open = open_ports(chat)
    verified_ports = {int(item["port"]) for item in mixed_open + chat_open}
    v1_ports = {int(item["port"]) for item in full_v1.get("open", [])}
    v2_ports = {int(item["port"]) for item in full_v2.get("open", [])}

    tls_443 = next((tls_row(item) for item in mixed_open if int(item["port"]) == 443), None)
    tls_3000 = next((tls_row(item) for item in chat_open if int(item["port"]) == 3000), None)

    payload = {
        "schema": 2,
        "target": "10.129.214.126",
        "machine": "RedEye",
        "authorization": "user-provided Hack The Box lab session; scope file allows this host only",
        "nmap_open_ports": sorted(nmap_open),
        "rayscan_v1_open_ports": sorted(v1_ports),
        "rayscan_v2_open_ports": sorted(v2_ports),
        "rayscan_verified_ports": sorted(verified_ports),
        "port_sets_match": nmap_open == v2_ports == verified_ports,
        "nmap_full_elapsed_s": nmap_elapsed(RESULTS / "nmap-alltcp.xml"),
        "nmap_service_elapsed_s": nmap_elapsed(RESULTS / "nmap-services.xml"),
        "rayscan_v1_full_elapsed_s": round(full_v1["elapsed_ms"] / 1000, 3),
        "rayscan_v2_full_elapsed_s": round(full_v2["elapsed_ms"] / 1000, 3),
        "rayscan_scan_wall_s": {
            "full_connect_v2": wall_seconds(RESULTS / "rayscan-full-connect-v2.time.txt"),
            "os_mixed_v2": wall_seconds(RESULTS / "rayscan-os-mixed-v2.time.txt"),
            "sni_chat_v2": wall_seconds(RESULTS / "rayscan-sni-chat-v2.time.txt"),
        },
        "nmap_services": services,
        "rayscan_services": {
            "os_mixed_v2": [service_row(item) for item in mixed_open],
            "sni_chat_v2": [service_row(item) for item in chat_open],
        },
        "os_summary": None
        if os_guess is None
        else {
            "family": os_guess.get("family"),
            "detail": os_guess.get("detail"),
            "confidence": os_guess.get("confidence"),
            "samples": os_guess.get("samples"),
            "endpoints": os_endpoints,
        },
        "chat_os_summary": None
        if chat_guess is None
        else {
            "family": chat_guess.get("family"),
            "detail": chat_guess.get("detail"),
            "confidence": chat_guess.get("confidence"),
            "samples": chat_guess.get("samples"),
            "endpoints": chat_endpoints,
        },
        "tls": {"443": tls_443, "3000": tls_3000},
        "limitations": [
            "Raw SYN-ACK stack evidence was Windows-like on every probed endpoint; endpoint labels use service-derived corrections.",
            "443/tcp requires SNI sts.airways.htb; without SNI the TLS endpoint can reset and may be omitted from a retained TLS scan.",
            "3000/tcp uses SNI chat.airways.htb and identifies an nginx front; the Rocket.Chat/Express application is not fingerprinted by the built-in service matcher.",
            "Full discovery is connect-only; no raw-SYN or UDP claim is made.",
            "Only four open TCP ports were exposed.",
        ],
    }

    output = RESULTS / "redeye-summary.json"
    output.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    nmap_rows = []
    for port, service in sorted(services.items(), key=lambda item: int(item[0])):
        name = service.get("name", "unknown")
        product = service.get("product", "")
        version = service.get("version", "")
        nmap_rows.append(f"| {port}/tcp | {name} | {product} {version} |".rstrip())

    endpoint_rows = []
    for item in mixed_open + chat_open:
        endpoint = all_endpoints.get(int(item["port"]), {})
        tls = item.get("tls") or {}
        endpoint_rows.append(
            "| {port}/tcp | {service} {product} | {tls} | {family} | {stack} | {detail} |".format(
                port=item["port"],
                service=(item.get("service") or {}).get("name", "unknown"),
                product=(item.get("service") or {}).get("product") or "",
                tls=tls.get("sni") or "-",
                family=endpoint.get("family", "unknown"),
                stack=endpoint.get("stack_family", "unknown"),
                detail=endpoint.get("detail", ""),
            ).replace("  ", " ").strip()
        )

    markdown = "\n".join(
        [
            "# RedEye validation summary",
            "",
            "- Target: `10.129.214.126`",
            "- Scope: [`../lab-scope-redeye.toml`](../lab-scope-redeye.toml)",
            f"- Open TCP ports: {', '.join(str(port) for port in sorted(nmap_open))}",
            f"- nmap, rayscan v2, and verified service sets match: {payload['port_sets_match']}",
            f"- Full discovery: nmap {payload['nmap_full_elapsed_s']} s; rayscan v2 {payload['rayscan_v2_full_elapsed_s']} s",
            f"- nmap service scan: {payload['nmap_service_elapsed_s']} s",
            f"- Endpoint OS: {payload['os_summary']['detail']} ({payload['os_summary']['confidence']:.0%})",
            "",
            "## nmap services",
            "",
            "| Port | Service | Product |",
            "|---|---|---|",
            *nmap_rows,
            "",
            "## rayscan service and endpoint OS",
            "",
            "| Port | Service | TLS SNI | Endpoint OS | Raw stack | Detail |",
            "|---|---|---|---|---|---|",
            *endpoint_rows,
            "",
            "## TLS",
            "",
            f"- 443: {tls_443['version']} / {tls_443['cipher']}, SNI `{tls_443['sni']}`, hostname match {tls_443['hostname_matches']}",
            f"- 443 certificate: subject {tls_443['subject']}; issuer {tls_443['issuer']}; self-signed {tls_443['self_signed']}",
            f"- 3000: {tls_3000['version']} / {tls_3000['cipher']}, SNI `{tls_3000['sni']}`, hostname match {tls_3000['hostname_matches']}",
            f"- 3000 certificate: subject {tls_3000['subject']}; issuer {tls_3000['issuer']}; self-signed {tls_3000['self_signed']}",
            "",
            "## Limitations",
            "",
            *[f"- {item}" for item in payload["limitations"]],
            "",
            "## Reproduction",
            "",
            "```bash",
            "python3 bench/htb/analyze_redeye.py",
            "```",
            "",
        ]
    )
    (RESULTS / "redeye-summary.md").write_text(markdown, encoding="utf-8")
    print(f"wrote {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
