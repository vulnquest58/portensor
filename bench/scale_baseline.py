#!/usr/bin/env python3
"""Full-range scale baseline for the v0.10 accuracy and scale gate.

The scenario scans 65,535 TCP ports on 16 loopback addresses with connect-only
discovery, no rate limit, and no retries. It measures wall time, CPU time, and
peak RSS per run and writes JSON plus Markdown artifacts. The result is a
repeatable host baseline, not a remote-network throughput claim.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import platform
import statistics
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bench import bench  # noqa: E402

DEFAULT_BINARY = ROOT / "target" / "release" / "portensor"
DEFAULT_OUTPUT = ROOT / "bench" / "results" / "full-range.json"
DEFAULT_MARKDOWN = ROOT / "bench" / "results" / "full-range.md"


def target_range(base: str, hosts: int) -> str:
    if hosts < 1:
        raise ValueError("hosts must be at least 1")
    if not base.startswith("127."):
        raise ValueError("the scale baseline requires loopback targets")
    return f"{base}-{base.rsplit('.', 1)[0]}.{hosts}"


def command(
    binary: Path,
    targets: str,
    ports: str,
    workers: int,
    rate: int,
    timeout: float,
) -> list[str]:
    return [
        str(binary),
        "scan",
        "--target",
        targets,
        "--ports",
        ports,
        "--connect-only",
        "--retries",
        "0",
        "--workers",
        str(workers),
        "--rate",
        str(rate),
        "--timeout",
        f"{timeout:g}",
        "--json",
    ]


def summarize(values: list[float]) -> dict[str, float | None]:
    if not values:
        return {"median": None, "min": None, "max": None}
    return {
        "median": statistics.median(values),
        "min": min(values),
        "max": max(values),
    }


def cpu_model() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text(
            encoding="utf-8", errors="replace"
        ).splitlines():
            if line.startswith("model name"):
                return line.partition(":")[2].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def memory_kb() -> int | None:
    try:
        for line in Path("/proc/meminfo").read_text(
            encoding="utf-8", errors="replace"
        ).splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1])
    except OSError:
        pass
    return None


def portensor_version(binary: Path) -> str | None:
    try:
        completed = subprocess.run(
            [str(binary), "--version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = (completed.stdout or completed.stderr).strip().splitlines()
    return output[0] if output else None


def format_markdown(
    report: dict[str, object], runs: list[bench.Run]
) -> str:
    wall = report["wall_seconds"]
    cpu = report["cpu_seconds"]
    rss = report["peak_rss_kb"]
    lines = [
        "# Full-range scale baseline",
        "",
        f"Generated: {report['generated_at']}",
        "",
        "## Environment",
        "",
        f"- Platform: {report['environment']['platform']}",
        f"- CPU: {report['environment']['cpu_model']}",
        f"- Memory: {report['environment']['memory_kb']} KiB",
        f"- Portensor: {report['environment']['portensor_version']}",
        "",
        "## Scenario",
        "",
        f"- Targets: `{report['targets']}` ({report['hosts']} hosts)",
        f"- Ports: `{report['ports']}`",
        f"- Mode: connect-only, retries 0, rate {report['rate']}, workers {report['workers']}",
        f"- Runs: {report['runs']}",
        "",
        "## Results",
        "",
        "| Run | Exit | Open | Wall s | CPU s | Peak RSS MiB |",
        "|---:|---:|---:|---:|---:|---:|",
    ]
    for index, run in enumerate(runs, start=1):
        rss_mib = (run.peak_rss_kb or 0) / 1024
        lines.append(
            f"| {index} | {run.exit_code} | {len(run.open_ports)} | "
            f"{run.elapsed_seconds:.3f} | "
            f"{(run.cpu_seconds or 0):.3f} | {rss_mib:.1f} |"
        )
    lines.extend(
        [
            "",
            "## Aggregate",
            "",
            f"- Median wall: {wall['median'] if wall['median'] is not None else 'n/a'} s",
            f"- Median CPU: {cpu['median'] if cpu['median'] is not None else 'n/a'} s",
            f"- Peak RSS: {((rss['max'] or 0) / 1024):.1f} MiB",
            f"- v0.10 RSS gate (128 MiB): "
            f"{'pass' if (rss['max'] or 0) <= 128 * 1024 else 'fail'}",
            "",
            "The v0.10 wall/CPU comparison uses the same scenario and a median at",
            "or below 0.9x this baseline after the optimization phase. Open loopback",
            "services are reported but are not part of the scale gate.",
            "",
        ]
    )
    return "\n".join(lines)


def run(args: argparse.Namespace) -> int:
    if not args.binary.is_file():
        print(f"missing binary: {args.binary}", file=sys.stderr)
        return 2
    targets = target_range(args.base, args.hosts)
    cmd = command(args.binary, targets, args.ports, args.workers, args.rate, args.timeout)
    runs: list[bench.Run] = []
    for index in range(1, args.repeat + 1):
        print(f"full-range run {index}/{args.repeat}: {' '.join(cmd)}", flush=True)
        result = bench.run_tool(
            "portensor-full-range",
            cmd,
            bench.parse_portensor,
            targets,
            set(),
            args.process_timeout,
        )
        runs.append(result)
        status = "ok" if result.ok else result.error
        print(
            f"  {status}; wall={result.elapsed_seconds:.3f}s "
            f"cpu={result.cpu_seconds or 0:.3f}s "
            f"rss={(result.peak_rss_kb or 0) / 1024:.1f}MiB "
            f"open={len(result.open_ports)}",
            flush=True,
        )
        if not result.ok:
            break

    ok_runs = [item for item in runs if item.ok]
    wall_values = [item.elapsed_seconds for item in ok_runs]
    cpu_values = [float(item.cpu_seconds or 0) for item in ok_runs]
    rss_values = [float(item.peak_rss_kb or 0) for item in ok_runs]
    report = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "targets": targets,
        "hosts": args.hosts,
        "ports": args.ports,
        "rate": args.rate,
        "workers": args.workers,
        "repeat": args.repeat,
        "runs": len(runs),
        "ok": len(ok_runs) == len(runs) and bool(runs),
        "environment": {
            "platform": platform.platform(),
            "kernel": platform.release(),
            "cpu_model": cpu_model(),
            "cpu_count": os.cpu_count(),
            "memory_kb": memory_kb(),
            "python": platform.python_version(),
            "portensor_version": portensor_version(args.binary),
        },
        "wall_seconds": summarize(wall_values),
        "cpu_seconds": summarize(cpu_values),
        "peak_rss_kb": summarize(rss_values),
        "observations": [item.to_dict() for item in runs],
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.markdown.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    args.markdown.write_text(format_markdown(report, runs), encoding="utf-8")
    print(f"saved {args.output}")
    print(f"saved {args.markdown}")
    return 0 if report["ok"] else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--base", default="127.0.0.1")
    parser.add_argument("--hosts", type=int, default=16)
    parser.add_argument("--ports", default="1-65535")
    parser.add_argument("--workers", type=int, default=512)
    parser.add_argument("--rate", type=int, default=0)
    parser.add_argument("--timeout", type=float, default=2.0)
    parser.add_argument("--process-timeout", type=float, default=1800.0)
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--markdown", type=Path, default=DEFAULT_MARKDOWN)
    args = parser.parse_args()
    if args.repeat < 1:
        parser.error("--repeat must be at least 1")
    if args.hosts < 1 or args.hosts > 254:
        parser.error("--hosts must be between 1 and 254")
    if args.workers < 1:
        parser.error("--workers must be at least 1")
    if args.rate < 0 or args.rate > 1_000_000:
        parser.error("--rate must be between 0 and 1000000")
    try:
        return run(args)
    except ValueError as error:
        parser.error(str(error))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
