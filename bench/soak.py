#!/usr/bin/env python3
"""High-concurrency and long-duration loopback scan soak test.

The scenario keeps a configurable number of banner listeners open and reserves
the rest of the port set as closed. Each round invokes the release binary and
checks the exact open set, wall time, CPU, and peak RSS. Repeating the scan
under a fixed concurrency exercises worker saturation, connection churn, and
resource cleanup; ``--duration`` turns it into a long-running soak.

This is a localhost reliability harness, not a throughput benchmark. Use
``bench/validate.py`` for the matched scanner comparison.
"""

from __future__ import annotations

import argparse
import datetime
import json
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bench import bench, validate  # noqa: E402

DEFAULT_BINARY = ROOT / "target" / "release" / "portensor"


def scan_command(
    binary: Path,
    ports: list[int],
    workers: int,
    host_concurrency: int,
    discover_only: bool,
) -> list[str]:
    command = [
        str(binary),
        "scan",
        "--target",
        validate.HOST,
        "--ports",
        ",".join(str(port) for port in ports),
        "--json",
        "--quiet",
        "--rate",
        "0",
        "--workers",
        str(workers),
    ]
    if host_concurrency:
        command.extend(["--host-concurrency", str(host_concurrency)])
    if discover_only:
        command.append("--discover-only")
    return command


def percentile(values: list[float], fraction: float) -> float | None:
    return validate.percentile(values, fraction)


def summarize(rounds: list[dict[str, object]]) -> dict[str, object]:
    walls = [float(item["wall_seconds"]) for item in rounds]
    cpus = [
        float(item["cpu_seconds"])
        for item in rounds
        if item["cpu_seconds"] is not None
    ]
    rss = [
        float(item["peak_rss_kb"])
        for item in rounds
        if item["peak_rss_kb"] is not None
    ]
    return {
        "rounds": len(rounds),
        "passed": sum(1 for item in rounds if item["ok"]),
        "failed": sum(1 for item in rounds if not item["ok"]),
        "wall_seconds": {
            "median": statistics.median(walls) if walls else None,
            "p95": percentile(walls, 0.95),
            "max": max(walls) if walls else None,
        },
        "cpu_seconds": {
            "median": statistics.median(cpus) if cpus else None,
            "max": max(cpus) if cpus else None,
        },
        "peak_rss_kb": {
            "median": statistics.median(rss) if rss else None,
            "max": max(rss) if rss else None,
        },
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--rounds", type=int, default=10)
    parser.add_argument(
        "--duration",
        type=float,
        default=0.0,
        help="run until this many seconds have elapsed (0 uses --rounds)",
    )
    parser.add_argument("--interval", type=float, default=0.0)
    parser.add_argument("--open-ports", type=int, default=64)
    parser.add_argument("--closed-ports", type=int, default=960)
    parser.add_argument("--workers", type=int, default=512)
    parser.add_argument("--host-concurrency", type=int, default=0)
    parser.add_argument("--scan-timeout", type=float, default=120.0)
    parser.add_argument("--max-rss-mb", type=float, default=512.0)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--discover-only", action="store_true")
    parser.add_argument("--fail-fast", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)

    if not args.binary.is_file():
        parser.error(f"scanner binary not found: {args.binary}")
    if args.rounds < 1 and args.duration <= 0:
        parser.error("--rounds must be at least 1 when --duration is not set")
    if args.interval < 0 or args.scan_timeout <= 0:
        parser.error("--interval must be non-negative and --scan-timeout positive")
    if args.open_ports < 1 or args.closed_ports < 0:
        parser.error("--open-ports must be positive and --closed-ports non-negative")

    scenario = validate.build_scenario(
        args.seed,
        banners=args.open_ports,
        tarpits=0,
        closed=args.closed_ports,
    )
    try:
        ports = scenario.ports
        command = scan_command(
            args.binary,
            ports,
            args.workers,
            args.host_concurrency,
            args.discover_only,
        )
        truth = scenario.truth
        print(
            f"soak: {args.open_ports} open, {args.closed_ports} closed, "
            f"{len(ports)} total; workers={args.workers} "
            f"host_concurrency={args.host_concurrency or 'unlimited'} "
            f"mode={'discover' if args.discover_only else 'verified'}"
        )
        deadline = time.monotonic() + args.duration if args.duration > 0 else None
        rounds: list[dict[str, object]] = []
        started = time.monotonic()
        while True:
            if deadline is not None:
                if rounds and time.monotonic() >= deadline:
                    break
            elif len(rounds) >= args.rounds:
                break

            run = bench.run_tool(
                "portensor",
                command,
                bench.parse_portensor,
                validate.HOST,
                truth,
                args.scan_timeout,
            )
            missing = sorted(
                truth - run.open_ports, key=lambda target: target.port
            )
            extra = sorted(
                run.open_ports - truth, key=lambda target: target.port
            )
            rss_mb = (
                run.peak_rss_kb / 1024 if run.peak_rss_kb is not None else None
            )
            ok = (
                run.ok
                and not missing
                and not extra
                and (rss_mb is None or rss_mb <= args.max_rss_mb)
            )
            record = {
                "round": len(rounds) + 1,
                "ok": ok,
                "exit_code": run.exit_code,
                "wall_seconds": run.elapsed_seconds,
                "cpu_seconds": run.cpu_seconds,
                "peak_rss_kb": run.peak_rss_kb,
                "missing_ports": [target.port for target in missing],
                "extra_ports": [target.port for target in extra],
                "error": run.error,
            }
            rounds.append(record)
            print(
                f"round {record['round']:>4} {'ok' if ok else 'FAIL'} "
                f"wall={run.elapsed_seconds:.3f}s "
                f"rss={rss_mb:.1f}MiB" if rss_mb is not None else
                f"round {record['round']:>4} {'ok' if ok else 'FAIL'} "
                f"wall={run.elapsed_seconds:.3f}s rss=n/a"
            )
            if missing or extra:
                print(
                    f"  missing={len(missing)} extra={len(extra)} "
                    f"exit={run.exit_code} error={run.error or 'none'}"
                )
            if not ok and args.fail_fast:
                break
            if args.interval:
                time.sleep(args.interval)
    finally:
        scenario.close()

    summary = summarize(rounds)
    summary["elapsed_seconds"] = round(time.monotonic() - started, 3)
    report = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "scenario": {
            "target": validate.HOST,
            "open_ports": len(scenario.banner_ports),
            "closed_ports": len(scenario.closed_ports),
            "ports": len(ports),
            "workers": args.workers,
            "host_concurrency": args.host_concurrency,
            "discover_only": args.discover_only,
        },
        "summary": summary,
        "rounds": rounds,
    }
    wall = summary["wall_seconds"]
    rss = summary["peak_rss_kb"]
    print(
        f"summary: {summary['passed']}/{summary['rounds']} passed, "
        f"median={wall['median']:.3f}s, p95={wall['p95']:.3f}s, "
        f"peak_rss={rss['max'] / 1024:.1f}MiB"
        if wall["median"] is not None and rss["max"] is not None
        else f"summary: {summary['passed']}/{summary['rounds']} passed"
    )
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(report, indent=2) + "\n", encoding="utf-8"
        )
        print(f"saved {args.output}")

    return 0 if summary["failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
