#!/usr/bin/env python3
"""Standardized localhost benchmark validation.

The suite creates a deterministic loopback scenario with banner services,
silent tarpits, and closed ports, then runs rayscan and optional peer scanners
in interleaved rounds. It validates exactness and records wall time, CPU time,
and peak RSS for every run. The output is a machine-readable JSON report plus a
Markdown summary suitable for release notes.

The default loopback condition has no injected packet loss. Pass
``--netem-loss`` to re-execute inside an unprivileged network namespace with a
``tc netem`` profile; the privileged ``bench/accuracy_suite.py`` remains the
multi-target loss gate.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import platform
import random
import shlex
import shutil
import socket
import statistics
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bench import bench  # noqa: E402

DEFAULT_BINARY = ROOT / "target" / "release" / "rayscan"
DEFAULT_OUTPUT = ROOT / "bench" / "results" / "validation.json"
DEFAULT_MARKDOWN = ROOT / "bench" / "results" / "validation.md"
HOST = "127.0.0.1"
PORT_LOW = 20000
PORT_HIGH = 29999
BANNER_COUNT = 8
TARPIT_COUNT = 2
CLOSED_COUNT = 10


@dataclass
class Observation:
    round: int
    run: bench.Run

    def to_dict(self) -> dict[str, object]:
        return {
            "round": self.round,
            "ok": self.run.ok,
            "exit_code": self.run.exit_code,
            "elapsed_seconds": self.run.elapsed_seconds,
            "cpu_seconds": self.run.cpu_seconds,
            "peak_rss_kb": self.run.peak_rss_kb,
            "measurement": self.run.measurement,
            "metrics": self.run.metrics.to_dict() if self.run.metrics else None,
            "open_ports": sorted(target.port for target in self.run.open_ports),
            "error": self.run.error,
        }


@dataclass
class ToolSpec:
    name: str
    command: list[str]
    parser: Callable[[str, str], set[bench.Target]]
    required: bool = False
    mode: str = "accuracy"
    ports: list[int] = field(default_factory=list)
    truth: set[bench.Target] = field(default_factory=set)


@dataclass
class Scenario:
    banner_ports: list[int] = field(default_factory=list)
    tarpit_ports: list[int] = field(default_factory=list)
    closed_ports: list[int] = field(default_factory=list)
    servers: list[object] = field(default_factory=list)
    reservations: list[socket.socket] = field(default_factory=list)

    @property
    def ports(self) -> list[int]:
        return sorted(self.banner_ports + self.tarpit_ports + self.closed_ports)

    @property
    def truth(self) -> set[bench.Target]:
        return {bench.Target(HOST, port) for port in self.banner_ports}

    def close(self) -> None:
        for server in self.servers:
            server.close()
        for reservation in self.reservations:
            reservation.close()


class BannerServer:
    def __init__(self, listener: socket.socket, banner: bytes) -> None:
        self.listener = listener
        self.banner = banner
        self.stop = threading.Event()
        self.listener.listen(32)
        self.listener.settimeout(0.05)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        while not self.stop.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                connection.sendall(self.banner)
            except OSError:
                pass
            finally:
                connection.close()

    def close(self) -> None:
        self.stop.set()
        self.thread.join(timeout=2)
        self.listener.close()


class TarpitServer:
    def __init__(self, listener: socket.socket, hold_seconds: float = 3.0) -> None:
        self.listener = listener
        self.hold_seconds = hold_seconds
        self.stop = threading.Event()
        self.listener.listen(32)
        self.listener.settimeout(0.05)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        while not self.stop.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(
                target=self._hold, args=(connection,), daemon=True
            ).start()

    def _hold(self, connection: socket.socket) -> None:
        try:
            time.sleep(self.hold_seconds)
        finally:
            connection.close()

    def close(self) -> None:
        self.stop.set()
        self.thread.join(timeout=2)
        self.listener.close()


def reserve_port(
    rng: random.Random,
    used: set[int],
    low: int = PORT_LOW,
    high: int = PORT_HIGH,
) -> tuple[int, socket.socket]:
    for _ in range((high - low + 1) * 2):
        port = rng.randint(low, high)
        if port in used:
            continue
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind((HOST, port))
        except OSError:
            listener.close()
            continue
        used.add(port)
        return port, listener
    raise RuntimeError(f"could not reserve a free port in {low}-{high}")


def build_scenario(
    seed: int = 0,
    banners: int = BANNER_COUNT,
    tarpits: int = TARPIT_COUNT,
    closed: int = CLOSED_COUNT,
) -> Scenario:
    total = banners + tarpits + closed
    if total > PORT_HIGH - PORT_LOW + 1:
        raise ValueError("scenario has more ports than the reserved range")
    rng = random.Random(seed)
    used: set[int] = set()
    scenario = Scenario()
    try:
        for _ in range(banners):
            port, listener = reserve_port(rng, used)
            scenario.banner_ports.append(port)
            scenario.servers.append(
                BannerServer(listener, b"rayscan-bench/1.0\r\n")
            )
        for _ in range(tarpits):
            port, listener = reserve_port(rng, used)
            scenario.tarpit_ports.append(port)
            scenario.servers.append(TarpitServer(listener))
        for _ in range(closed):
            port, listener = reserve_port(rng, used)
            scenario.closed_ports.append(port)
            scenario.reservations.append(listener)
    except BaseException:
        scenario.close()
        raise
    return scenario


def tool_available(name: str, binary: Path) -> tuple[bool, str | None]:
    if name in {"rayscan", "rayscan-connect"}:
        if not binary.is_file():
            return False, f"binary not found: {binary}"
        return True, None
    executable = {
        "nmap": "nmap",
        "nmap-speed": "nmap",
        "masscan": "masscan",
        "rustscan": "rustscan",
    }.get(name)
    if executable is None:
        return False, f"unknown tool: {name}"
    if shutil.which(executable) is None:
        return False, f"{executable} not installed"
    if name == "masscan" and os.name == "posix" and os.geteuid() != 0:
        return False, "masscan requires root"
    return True, None


def build_tools(
    names: list[str],
    binary: Path,
    ports: list[int],
    speed_ports: list[int] | None = None,
    truth: set[bench.Target] | None = None,
    speed_truth: set[bench.Target] | None = None,
) -> list[ToolSpec]:
    speed_ports = ports if speed_ports is None else speed_ports
    truth = truth or set()
    speed_truth = speed_truth or set()
    full_text = ",".join(str(port) for port in ports)
    speed_text = ",".join(str(port) for port in speed_ports)
    specs: list[ToolSpec] = []
    for name in names:
        if name == "rayscan":
            specs.append(
                ToolSpec(
                    name=name,
                    command=[
                        str(binary),
                        "scan",
                        "--target",
                        HOST,
                        "--ports",
                        full_text,
                        "--json",
                        "--quiet",
                        "--rate",
                        "0",
                    ],
                    parser=bench.parse_rayscan,
                    mode="verified",
                    ports=ports,
                    truth=truth,
                )
            )
        elif name == "rayscan-connect":
            specs.append(
                ToolSpec(
                    name=name,
                    command=[
                        str(binary),
                        "scan",
                        "--target",
                        HOST,
                        "--ports",
                        speed_text,
                        "--json",
                        "--quiet",
                        "--rate",
                        "0",
                        "--discover-only",
                    ],
                    parser=bench.parse_rayscan,
                    mode="handshake",
                    ports=speed_ports,
                    truth=speed_truth,
                )
            )
        elif name == "nmap":
            specs.append(
                ToolSpec(
                    name=name,
                    command=[
                        "nmap",
                        "-n",
                        "-Pn",
                        "-sT",
                        "--open",
                        "--host-timeout",
                        "30s",
                        "-p",
                        full_text,
                        "-oX",
                        "-",
                        HOST,
                    ],
                    parser=bench.parse_nmap,
                    mode="handshake",
                    ports=ports,
                    truth=truth,
                )
            )
        elif name == "nmap-speed":
            specs.append(
                ToolSpec(
                    name=name,
                    command=[
                        "nmap",
                        "-n",
                        "-Pn",
                        "-sT",
                        "--open",
                        "--host-timeout",
                        "30s",
                        "-p",
                        speed_text,
                        "-oX",
                        "-",
                        HOST,
                    ],
                    parser=bench.parse_nmap,
                    mode="handshake",
                    ports=speed_ports,
                    truth=speed_truth,
                )
            )
        elif name == "masscan":
            specs.append(
                ToolSpec(
                    name=name,
                    command=[
                        "masscan",
                        "-p",
                        speed_text,
                        "--rate",
                        "10000",
                        "--wait",
                        "0",
                        "-oJ",
                        "-",
                        HOST,
                    ],
                    parser=bench.parse_masscan,
                    mode="handshake",
                    ports=speed_ports,
                    truth=speed_truth,
                )
            )
        elif name == "rustscan":
            specs.append(
                ToolSpec(
                    name=name,
                    command=[
                        "rustscan",
                        "-a",
                        HOST,
                        "-p",
                        speed_text,
                        "--no-banner",
                        "--greppable",
                    ],
                    parser=bench.parse_rustscan,
                    mode="handshake",
                    ports=speed_ports,
                    truth=speed_truth,
                )
            )
        else:
            raise ValueError(f"unknown tool: {name}")
    return specs


def percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    if len(ordered) == 1:
        return ordered[0]
    index = max(0, min(len(ordered) - 1, int(round(fraction * (len(ordered) - 1)))))
    return ordered[index]


def summarize_values(values: list[float]) -> dict[str, float | None]:
    if not values:
        return {"median": None, "p95": None, "min": None, "max": None}
    return {
        "median": statistics.median(values),
        "p95": percentile(values, 0.95),
        "min": min(values),
        "max": max(values),
    }


def summarize_tool(
    spec: ToolSpec,
    observations: list[Observation],
    skipped: str | None,
) -> dict[str, object]:
    runs = [observation.run for observation in observations]
    ok_runs = [run for run in runs if run.ok]
    exact_runs = [
        run
        for run in ok_runs
        if run.metrics is not None
        and run.metrics.false_positives == 0
        and run.metrics.false_negatives == 0
    ]
    metrics = [run.metrics for run in ok_runs if run.metrics is not None]
    elapsed = [run.elapsed_seconds for run in ok_runs]
    cpu = [
        run.cpu_seconds
        for run in ok_runs
        if run.cpu_seconds is not None
    ]
    rss = [
        float(run.peak_rss_kb)
        for run in ok_runs
        if run.peak_rss_kb is not None
    ]
    return {
        "tool": spec.name,
        "required": spec.required,
        "mode": spec.mode,
        "ports": spec.ports,
        "command": spec.command,
        "skipped": skipped,
        "runs": len(runs),
        "completed_runs": len(ok_runs),
        "exact_runs": len(exact_runs),
        "exact": len(ok_runs) == len(runs) and len(exact_runs) == len(runs) and bool(runs),
        "min_recall": min((item.recall for item in metrics), default=None),
        "min_precision": min((item.precision for item in metrics), default=None),
        "false_positives": max(
            (item.false_positives for item in metrics), default=None
        ),
        "false_negatives": max(
            (item.false_negatives for item in metrics), default=None
        ),
        "wall_seconds": summarize_values(elapsed),
        "cpu_seconds": summarize_values(cpu),
        "peak_rss_kb": summarize_values(rss),
        "errors": [run.error for run in runs if run.error],
        "observations": [observation.to_dict() for observation in observations],
    }


def read_cpu_model() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text(
            encoding="utf-8", errors="replace"
        ).splitlines():
            if line.startswith("model name"):
                return line.partition(":")[2].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def read_memory_kb() -> int | None:
    try:
        for line in Path("/proc/meminfo").read_text(
            encoding="utf-8", errors="replace"
        ).splitlines():
            if line.startswith("MemTotal:"):
                return int(line.split()[1])
    except OSError:
        pass
    return None


def tool_version(command: list[str]) -> str | None:
    if not command:
        return None
    try:
        completed = subprocess.run(
            [*command, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    output = (completed.stdout or completed.stderr).strip().splitlines()
    return output[0] if output else None


def environment(binary: Path, specs: list[ToolSpec]) -> dict[str, object]:
    try:
        load = list(os.getloadavg())
    except (AttributeError, OSError):
        load = None
    versions: dict[str, str | None] = {}
    for spec in specs:
        if spec.name.startswith("rayscan"):
            versions[spec.name] = tool_version([str(binary)])
        else:
            versions[spec.name] = tool_version([spec.command[0]])
    return {
        "platform": platform.platform(),
        "kernel": platform.release(),
        "machine": platform.machine(),
        "cpu_model": read_cpu_model(),
        "cpu_count": os.cpu_count(),
        "memory_kb": read_memory_kb(),
        "load_average": load,
        "python": platform.python_version(),
        "versions": versions,
    }


def run_suite(
    specs: list[ToolSpec],
    binary: Path,
    repeat: int,
    warmup: int,
    timeout: float,
) -> tuple[dict[str, list[Observation]], dict[str, str]]:
    available: dict[str, bool] = {}
    skipped: dict[str, str] = {}
    observations: dict[str, list[Observation]] = {spec.name: [] for spec in specs}
    for spec in specs:
        available[spec.name], skipped[spec.name] = tool_available(
            spec.name, binary
        )
    active = [spec for spec in specs if available[spec.name]]
    for _ in range(warmup):
        for spec in active:
            bench.run_tool(
                spec.name,
                spec.command,
                spec.parser,
                HOST,
                spec.truth,
                timeout,
            )
    for round_index in range(repeat):
        order = active if round_index % 2 == 0 else list(reversed(active))
        for spec in order:
            run = bench.run_tool(
                spec.name,
                spec.command,
                spec.parser,
                HOST,
                spec.truth,
                timeout,
            )
            observations[spec.name].append(Observation(round_index, run))
    return observations, skipped


def verdict_for(
    summary: dict[str, object],
    max_seconds: float,
    max_cpu_seconds: float,
    max_rss_mb: float,
) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    if not summary["exact"]:
        reasons.append("accuracy mismatch in at least one run")
    wall = summary["wall_seconds"]
    cpu = summary["cpu_seconds"]
    rss = summary["peak_rss_kb"]
    if isinstance(wall, dict) and wall["median"] is not None:
        if wall["median"] > max_seconds:
            reasons.append(f"median wall time {wall['median']:.3f}s exceeds {max_seconds:.3f}s")
    else:
        reasons.append("no wall-time samples")
    if isinstance(cpu, dict) and cpu["median"] is not None:
        if cpu["median"] > max_cpu_seconds:
            reasons.append(f"median CPU {cpu['median']:.3f}s exceeds {max_cpu_seconds:.3f}s")
    else:
        reasons.append("no CPU samples")
    if isinstance(rss, dict) and rss["median"] is not None:
        if rss["median"] / 1024 > max_rss_mb:
            reasons.append(
                f"median peak RSS {rss['median'] / 1024:.1f} MiB exceeds {max_rss_mb:.1f} MiB"
            )
    else:
        reasons.append("no peak-RSS samples")
    return not reasons, reasons


def format_number(value: object, digits: int = 3) -> str:
    if not isinstance(value, (int, float)):
        return "n/a"
    return f"{value:.{digits}f}"


def network_condition(loss: float | None, delay_ms: float) -> str:
    if loss is None:
        return "loopback, no injected loss"
    condition = f"loopback + tc netem loss {loss:g}%"
    if delay_ms:
        condition += f" delay {delay_ms:g}ms"
    return condition


def find_network_tool(name: str) -> str | None:
    found = shutil.which(name)
    if found:
        return found
    for directory in ("/usr/sbin", "/sbin", "/usr/local/sbin"):
        candidate = Path(directory) / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def run_in_network_namespace(
    argv: list[str], loss: float, delay_ms: float
) -> int:
    required = ("unshare", "ip", "tc")
    missing = [name for name in required if find_network_tool(name) is None]
    if missing:
        print(
            "cannot create a lossy network namespace; missing: "
            + ", ".join(missing),
            file=sys.stderr,
        )
        return 1
    inner = [
        sys.executable,
        str(Path(__file__).resolve()),
        *argv,
        "--inside-netns",
    ]
    setup = (
        "set -e; export PATH=\"/usr/sbin:/sbin:$PATH\"; "
        "ip link set lo up; tc qdisc add dev lo root netem loss "
        + f"{loss:g}%"
    )
    if delay_ms:
        setup += f" delay {delay_ms:g}ms"
    setup += "; exec " + shlex.join(inner)
    print(
        f"entering unprivileged network namespace: {network_condition(loss, delay_ms)}",
        flush=True,
    )
    completed = subprocess.run(
        ["unshare", "-Urn", "bash", "-c", setup],
        check=False,
    )
    return completed.returncode


def format_markdown(report: dict[str, object]) -> str:
    env = report["environment"]
    scenario = report["scenario"]
    summaries = report["tools"]
    lines = [
        "# rayscan benchmark validation",
        "",
        f"Generated: {report['generated_at']}",
        "",
        "## Environment",
        "",
        f"- Platform: {env['platform']}",
        f"- CPU: {env['cpu_model']} ({env['cpu_count']} logical CPUs)",
        f"- Memory: {format_number((env['memory_kb'] or 0) / 1024, 0)} MiB",
        f"- Python: {env['python']}",
    ]
    for name, version in env["versions"].items():
        lines.append(f"- {name}: {version or 'unknown'}")
    lines.extend(
        [
            "",
            "## Scenario",
            "",
            f"- Target: `{scenario['target']}`",
            f"- Banner services: {scenario['banner_ports']}",
            f"- Silent tarpits: {scenario['tarpit_ports']}",
            f"- Closed ports: {scenario['closed_ports']}",
            f"- Handshake-timing ports: {len(scenario['handshake_ports'])} non-tarpit ports",
            f"- Network condition: {scenario['network_condition']}",
            "",
            "## Results",
            "",
            "| Tool | Mode | Ports | Exact | Runs | Min recall | Min precision | Median s | p95 s | CPU median s | RSS median MiB |",
            "|---|---|---|---|---|---|---|---|---|---|---|",
        ]
    )
    for summary in summaries:
        wall = summary["wall_seconds"]
        cpu = summary["cpu_seconds"]
        rss = summary["peak_rss_kb"]
        lines.append(
            "| {tool} | {mode} | {ports} | {exact} | {runs}/{total} | {recall} | {precision} | {wall} | {p95} | {cpu} | {rss} |".format(
                tool=summary["tool"],
                mode=summary["mode"],
                ports=len(summary["ports"]),
                exact="yes" if summary["exact"] else "no",
                runs=summary["completed_runs"],
                total=summary["runs"],
                recall=format_number(summary["min_recall"]),
                precision=format_number(summary["min_precision"]),
                wall=format_number(wall["median"]) if wall else "n/a",
                p95=format_number(wall["p95"]) if wall else "n/a",
                cpu=format_number(cpu["median"]) if cpu else "n/a",
                rss=(
                    format_number(rss["median"] / 1024, 1)
                    if rss and rss["median"] is not None
                    else "n/a"
                ),
            )
        )
    lines.extend(
        [
            "",
            "## Verdict",
            "",
            f"**{report['verdict']}**",
        ]
    )
    for reason in report["reasons"]:
        lines.append(f"- {reason}")
    lines.extend(
        [
            "",
            f"Network condition: {scenario['network_condition']}.",
            "The privileged lab suite `bench/accuracy_suite.py` also covers",
            "0%, 5%, and 20% loss profiles with namespace targets.",
            "",
        ]
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--tools", default="rayscan,nmap,rayscan-connect,nmap-speed")
    parser.add_argument("--require-tools", default="rayscan")
    parser.add_argument("--repeat", type=int, default=5)
    parser.add_argument("--warmup", type=int, default=1)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("--max-seconds", type=float, default=30.0)
    parser.add_argument("--max-cpu-seconds", type=float, default=60.0)
    parser.add_argument("--max-rss-mb", type=float, default=512.0)
    parser.add_argument("--seed", type=int, default=0)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--markdown", type=Path, default=DEFAULT_MARKDOWN)
    parser.add_argument("--no-save", action="store_true")
    parser.add_argument(
        "--netem-loss",
        type=float,
        default=None,
        help="run inside an unprivileged network namespace with this loss percentage",
    )
    parser.add_argument(
        "--netem-delay-ms",
        type=float,
        default=0.0,
        help="optional tc netem delay in milliseconds (requires --netem-loss)",
    )
    parser.add_argument("--inside-netns", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    if args.repeat < 1:
        parser.error("--repeat must be at least 1")
    if args.warmup < 0:
        parser.error("--warmup must be non-negative")
    if not args.binary.is_file():
        parser.error(f"scanner binary not found: {args.binary}")
    if args.netem_loss is not None and not 0 <= args.netem_loss <= 100:
        parser.error("--netem-loss must be between 0 and 100")
    if args.netem_delay_ms < 0:
        parser.error("--netem-delay-ms must be non-negative")
    if args.netem_delay_ms and args.netem_loss is None:
        parser.error("--netem-delay-ms requires --netem-loss")
    if args.netem_loss is not None and not args.inside_netns:
        inner_argv = list(argv) if argv is not None else sys.argv[1:]
        return run_in_network_namespace(
            inner_argv, args.netem_loss, args.netem_delay_ms
        )

    names = [name.strip() for name in args.tools.split(",") if name.strip()]
    required = {name.strip() for name in args.require_tools.split(",") if name.strip()}

    scenario = build_scenario(args.seed)
    speed_ports = sorted(scenario.banner_ports + scenario.closed_ports)
    speed_truth = {
        bench.Target(HOST, port) for port in scenario.banner_ports
    }
    try:
        ports = scenario.ports
        specs = build_tools(
            names,
            args.binary,
            ports,
            speed_ports,
            scenario.truth,
            speed_truth,
        )
        for spec in specs:
            spec.required = spec.name in required
        print(
            f"validating {', '.join(names)} over {len(ports)} loopback ports "
            f"({len(scenario.banner_ports)} banner, "
            f"{len(scenario.tarpit_ports)} tarpit, "
            f"{len(scenario.closed_ports)} closed); "
            f"handshake timing on {len(speed_ports)} non-tarpit ports; "
            f"condition: {network_condition(args.netem_loss, args.netem_delay_ms)}"
        )
        observations, skipped = run_suite(
            specs, args.binary, args.repeat, args.warmup, args.timeout
        )
    finally:
        scenario.close()

    summaries = [
        summarize_tool(spec, observations[spec.name], skipped.get(spec.name))
        for spec in specs
    ]
    by_name = {summary["tool"]: summary for summary in summaries}
    rayscan_summary = by_name.get("rayscan")
    reasons: list[str] = []
    verdict = True
    if rayscan_summary is None:
        verdict = False
        reasons.append("rayscan was not selected")
    else:
        verdict, reasons = verdict_for(
            rayscan_summary,
            args.max_seconds,
            args.max_cpu_seconds,
            args.max_rss_mb,
        )
    for name in sorted(required):
        summary = by_name.get(name)
        if summary is None:
            verdict = False
            reasons.append(f"required tool not selected: {name}")
        elif summary["skipped"]:
            verdict = False
            reasons.append(f"required tool unavailable: {name} ({summary['skipped']})")
        elif summary["completed_runs"] != summary["runs"]:
            verdict = False
            reasons.append(f"required tool failed one or more runs: {name}")

    connect_summary = by_name.get("rayscan-connect")
    if connect_summary is not None and not connect_summary["skipped"]:
        if not connect_summary["exact"]:
            verdict = False
            reasons.append("handshake-equivalent accuracy mismatch on non-tarpit ports")
        if connect_summary["completed_runs"] != connect_summary["runs"]:
            verdict = False
            reasons.append("handshake-equivalent mode failed one or more runs")

    nmap_summary = by_name.get("nmap")
    nmap_speed_summary = by_name.get("nmap-speed")
    comparison: dict[str, object] | None = None
    if nmap_summary is not None and not nmap_summary["skipped"]:
        comparison = {
            "nmap_false_positives": nmap_summary["false_positives"],
            "nmap_exact": nmap_summary["exact"],
        }
        if rayscan_summary is not None:
            comparison["rayscan_false_positives"] = rayscan_summary[
                "false_positives"
            ]
            comparison["rayscan_exact"] = rayscan_summary["exact"]
        if (
            connect_summary is not None
            and nmap_speed_summary is not None
            and connect_summary["wall_seconds"]["median"] is not None
            and nmap_speed_summary["wall_seconds"]["median"] not in (None, 0)
        ):
            comparison["handshake_mode"] = "rayscan-connect"
            comparison["handshake_to_nmap_wall_ratio"] = (
                connect_summary["wall_seconds"]["median"]
                / nmap_speed_summary["wall_seconds"]["median"]
            )
            comparison["handshake_ports"] = len(speed_ports)

    report = {
        "schema": 1,
        "generated_at": datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat(),
        "environment": environment(args.binary, specs),
        "scenario": {
            "target": HOST,
            "banner_ports": scenario.banner_ports,
            "tarpit_ports": scenario.tarpit_ports,
            "closed_ports": scenario.closed_ports,
            "handshake_ports": speed_ports,
            "network_condition": network_condition(
                args.netem_loss, args.netem_delay_ms
            ),
            "netem_loss_percent": args.netem_loss,
            "netem_delay_ms": args.netem_delay_ms,
            "repeat": args.repeat,
            "warmup": args.warmup,
        },
        "tools": summaries,
        "comparison": comparison,
        "verdict": "PASS" if verdict else "FAIL",
        "reasons": reasons,
    }

    print(
        f"{'tool':<16} {'mode':<10} {'ports':>5} {'exact':<6} {'runs':>6} "
        f"{'median_s':>9} {'p95_s':>8} {'cpu_s':>8} {'rss_mib':>9}"
    )
    print("-" * 86)
    for summary in summaries:
        wall = summary["wall_seconds"]
        cpu = summary["cpu_seconds"]
        rss = summary["peak_rss_kb"]
        print(
            f"{summary['tool']:<16} "
            f"{summary['mode']:<10} "
            f"{len(summary['ports']):>5} "
            f"{'yes' if summary['exact'] else 'no':<6} "
            f"{summary['completed_runs']}/{summary['runs']:<4} "
            f"{format_number(wall['median']) if wall else 'n/a':>9} "
            f"{format_number(wall['p95']) if wall else 'n/a':>8} "
            f"{format_number(cpu['median']) if cpu else 'n/a':>8} "
            f"{(format_number(rss['median'] / 1024, 1) if rss and rss['median'] is not None else 'n/a'):>9}"
        )
        if summary["skipped"]:
            print(f"  skipped: {summary['skipped']}")
    if comparison is not None:
        if "handshake_to_nmap_wall_ratio" in comparison:
            print(
                "rayscan-connect/nmap median wall ratio: "
                f"{comparison['handshake_to_nmap_wall_ratio']:.2f}x"
            )
        if "rayscan_false_positives" in comparison:
            print(
                f"FP rayscan={comparison['rayscan_false_positives']} "
                f"nmap={comparison['nmap_false_positives']}"
            )
    print(f"{report['verdict']}: {'; '.join(reasons) if reasons else 'all checks passed'}")

    if not args.no_save:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        args.markdown.parent.mkdir(parents=True, exist_ok=True)
        args.markdown.write_text(format_markdown(report), encoding="utf-8")
        print(f"saved {args.output}")
        print(f"saved {args.markdown}")

    return 0 if verdict else 1


if __name__ == "__main__":
    sys.exit(main())
