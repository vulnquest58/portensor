#!/usr/bin/env python3
"""Coordinator crash and uneven-load baseline for the v0.10 scale gate.

The lab uses the public HTTP control plane and fake workers, so it can inject
restart points without running real scans. It records the v0.7.0 behavior:
the coordinator keeps jobs and claims in memory, so a restart loses completed
shards and has no durable report. The uneven-load scenario uses synthetic job
durations to expose worker idle time that a durable scheduler must address.

Run with ``--baseline`` while documenting the pre-v0.10 failure. After the
durable coordinator lands, run without that flag and require all checks to pass.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_BINARY = ROOT / "target" / "release" / "portensor"
DEFAULT_OUTPUT = ROOT / "bench" / "results" / "distributed-lab.json"
DEFAULT_MARKDOWN = ROOT / "bench" / "results" / "distributed-lab.md"
TOKEN = "distributed-lab-token-0123456789"
JOBS = 4
UNEVEN_JOBS = 8
UNEVEN_WORKERS = 4
UNEVEN_DURATIONS = [10.0, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5, 0.5]


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def request(
    base: str,
    method: str,
    path: str,
    payload: dict[str, object] | None = None,
    timeout: float = 25.0,
) -> tuple[int, object]:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        base + path,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {TOKEN}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            body = response.read().decode("utf-8")
            return response.status, json.loads(body) if body else None
    except urllib.error.HTTPError as error:
        body = error.read().decode("utf-8")
        try:
            parsed: object = json.loads(body) if body else None
        except json.JSONDecodeError:
            parsed = body
        return error.code, parsed


class Coordinator:
    def __init__(
        self,
        binary: Path,
        port: int,
        shards: int,
        out: Path,
        lease_secs: int = 30,
    ) -> None:
        self.binary = binary
        self.port = port
        self.shards = shards
        self.out = out
        self.lease_secs = lease_secs
        self.base = f"http://127.0.0.1:{port}"
        self.process: subprocess.Popen[bytes] | None = None
        self.log = tempfile.NamedTemporaryFile(
            prefix="portensor-coordinator-", suffix=".log", delete=False
        )
        self.log_path = Path(self.log.name)

    def start(self) -> None:
        command = [
            str(self.binary),
            "distributed",
            "serve",
            "--listen",
            f"127.0.0.1:{self.port}",
            "--token",
            TOKEN,
            "--shards",
            str(self.shards),
            "--out",
            str(self.out),
            "--lease-secs",
            str(self.lease_secs),
            "--",
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            "1",
        ]
        self.process = subprocess.Popen(
            command,
            stdout=self.log,
            stderr=subprocess.STDOUT,
        )
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(
                    f"coordinator exited during startup:\n{self.log_path.read_text()}"
                )
            try:
                status, _ = request(self.base, "GET", "/v1/healthz", timeout=1)
                if status == 200:
                    ready_status, _ = self.ready()
                    if ready_status == 200:
                        return
            except (urllib.error.URLError, OSError):
                pass
            time.sleep(0.05)
        raise RuntimeError("coordinator did not become healthy")

    def status(self) -> dict[str, object]:
        status, body = request(self.base, "GET", "/v1/status")
        if status != 200 or not isinstance(body, dict):
            raise RuntimeError(f"status failed with HTTP {status}: {body}")
        return body

    def health(self) -> bool:
        status, _ = request(self.base, "GET", "/v1/healthz", timeout=1)
        return status == 200

    def ready(self) -> tuple[int, object]:
        return request(self.base, "GET", "/readyz", timeout=2)

    def metrics(self) -> tuple[int, str]:
        req = urllib.request.Request(
            self.base + "/metrics",
            headers={"Authorization": f"Bearer {TOKEN}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=2) as response:
                return response.status, response.read().decode("utf-8")
        except urllib.error.HTTPError as error:
            return error.code, error.read().decode("utf-8")

    def observability(self) -> dict[str, object]:
        ready_status, ready_body = self.ready()
        metrics_status, metrics_text = self.metrics()
        fields = (
            "portensor_coordinator_ready",
            "portensor_coordinator_restart_count",
            "portensor_jobs{state=\"pending\"}",
            "portensor_active_leases",
            "portensor_expired_leases_total",
            "portensor_duplicate_results_total",
            "portensor_merge_failures_total",
            "portensor_inflight_requests",
        )
        run_id = ready_body.get("run_id") if isinstance(ready_body, dict) else None
        try:
            log_text = self.log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            log_text = ""
        return {
            "readyz_http": ready_status,
            "ready": isinstance(ready_body, dict) and ready_body.get("ready") is True,
            "run_id": run_id,
            "log_correlates_run": bool(run_id and f"run={run_id}" in log_text),
            "metrics_http": metrics_status,
            "metrics_fields": all(field in metrics_text for field in fields),
            "metrics_has_zero_restarts": (
                "portensor_coordinator_restart_count 0" in metrics_text
                or "portensor_coordinator_restart_count 1" in metrics_text
                or "portensor_coordinator_restart_count 2" in metrics_text
            ),
        }

    def report(self) -> tuple[int, object]:
        return request(self.base, "GET", "/v1/report")

    def claim(self, worker_id: str) -> tuple[int, object]:
        return request(
            self.base,
            "POST",
            "/v1/claim",
            {"worker_id": worker_id, "name": worker_id, "capabilities": {"syn": True}},
        )

    def submit(self, worker_id: str, job_id: int, report: dict[str, object]) -> tuple[int, object]:
        return request(
            self.base,
            "POST",
            "/v1/result",
            {
                "worker_id": worker_id,
                "job_id": job_id,
                "report": report,
                "elapsed_ms": 1,
            },
        )

    def kill(self) -> None:
        if self.process is None:
            return
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=5)
        self.process = None

    def close(self) -> None:
        self.kill()
        self.log.close()
        self.log_path.unlink(missing_ok=True)


def report_for(job_id: int) -> dict[str, object]:
    port = 41000 + job_id
    return {
        "target": "127.0.0.1",
        "targets": 1,
        "ports": 1,
        "open": [
            {
                "host": "127.0.0.1",
                "port": port,
                "state": "open",
                "confidence": 95,
            }
        ],
        "summary": {
            "open": 1,
            "closed": 0,
            "filtered": 0,
            "silent": 0,
            "unreachable": 0,
            "error": 0,
        },
    }


def jobs_status(status: dict[str, object]) -> dict[str, object]:
    value = status.get("jobs")
    if not isinstance(value, dict):
        raise RuntimeError(f"unexpected status: {status}")
    return value


def wait_until_complete(coordinator: Coordinator, timeout: float = 30) -> dict[str, object]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            status = coordinator.status()
        except (urllib.error.URLError, OSError):
            if (
                coordinator.process is not None
                and coordinator.process.poll() is not None
                and coordinator.out.is_file()
            ):
                return {
                    "state": "complete",
                    "transport_closed": True,
                    "out": str(coordinator.out),
                }
            time.sleep(0.05)
            continue
        jobs = jobs_status(status)
        if status.get("state") == "complete":
            return status
        if jobs.get("failed"):
            return status
        time.sleep(0.05)
    raise RuntimeError("timed out waiting for coordinator completion")


def wait_for_report(
    coordinator: Coordinator, out: Path, timeout: float = 10
) -> tuple[int | None, bool]:
    deadline = time.monotonic() + timeout
    last_status: int | None = None
    while time.monotonic() < deadline:
        try:
            last_status, _ = coordinator.report()
            if last_status == 200:
                return last_status, out.is_file()
        except (urllib.error.URLError, OSError):
            pass
        if coordinator.process is not None and coordinator.process.poll() is not None:
            return last_status, out.is_file()
        time.sleep(0.05)
    return last_status, out.is_file()


def scenario_completed_restart(binary: Path) -> dict[str, object]:
    port = free_port()
    out = Path(tempfile.mkdtemp(prefix="portensor-distributed-")) / "report.json"
    coordinator = Coordinator(binary, port, JOBS, out)
    observed: dict[str, object] = {}
    try:
        coordinator.start()
        for job_id in range(JOBS):
            status, claim = coordinator.claim(f"worker-{job_id}")
            if status != 200 or not isinstance(claim, dict) or claim.get("job") is None:
                raise RuntimeError(f"claim failed for job {job_id}: {status} {claim}")
            job = claim["job"]
            status, result = coordinator.submit(
                f"worker-{job_id}", int(job["job_id"]), report_for(job_id)
            )
            if status != 200:
                raise RuntimeError(f"result failed for job {job_id}: {status} {result}")
        report_http, report_exists = wait_for_report(coordinator, out)
        observed["report_before_restart_http"] = report_http
        observed["report_before_restart_exists"] = report_exists
        coordinator.kill()
        coordinator = Coordinator(binary, port, JOBS, out)
        coordinator.start()
        observed["after_restart"] = coordinator.status()
        observed["report_after_restart_http"] = coordinator.report()[0]
        jobs = jobs_status(observed["after_restart"])
        durable = (
            jobs.get("done") == JOBS
            and jobs.get("running") == 0
            and observed["report_after_restart_http"] == 200
        )
        return {
            "scenario": "crash-completed-restart",
            "ok": bool(durable),
            "expected": "completed shards and the merged report survive a coordinator restart",
            "observed": observed,
            "reason": None if durable else "in-memory coordinator lost completed shards",
        }
    finally:
        coordinator.close()
        out.unlink(missing_ok=True)
        shutil.rmtree(out.parent, ignore_errors=True)


def scenario_after_result(binary: Path) -> dict[str, object]:
    port = free_port()
    out = Path(tempfile.mkdtemp(prefix="portensor-distributed-")) / "report.json"
    coordinator = Coordinator(binary, port, JOBS, out)
    observed: dict[str, object] = {}
    try:
        coordinator.start()
        status, claim = coordinator.claim("worker-0")
        if status != 200 or not isinstance(claim, dict) or claim.get("job") is None:
            raise RuntimeError(f"claim failed: {status} {claim}")
        job = claim["job"]
        status, result = coordinator.submit("worker-0", int(job["job_id"]), report_for(0))
        observed["result_http"] = status
        if status != 200:
            raise RuntimeError(f"result failed: {status} {result}")
        observed["before_restart"] = coordinator.status()
        coordinator.kill()
        coordinator = Coordinator(binary, port, JOBS, out)
        coordinator.start()
        observed["after_restart"] = coordinator.status()
        observed["report_after_restart_http"] = coordinator.report()[0]
        jobs = jobs_status(observed["after_restart"])
        durable = jobs.get("done", 0) >= 1
        return {
            "scenario": "crash-after-result",
            "ok": bool(durable),
            "expected": "a completed shard is not re-executed after restart",
            "observed": observed,
            "reason": None if durable else "restart forgot the completed shard",
        }
    finally:
        coordinator.close()
        out.unlink(missing_ok=True)
        shutil.rmtree(out.parent, ignore_errors=True)


def scenario_after_claim(binary: Path) -> dict[str, object]:
    port = free_port()
    out = Path(tempfile.mkdtemp(prefix="portensor-distributed-")) / "report.json"
    coordinator = Coordinator(binary, port, JOBS, out)
    observed: dict[str, object] = {}
    try:
        coordinator.start()
        status, claim = coordinator.claim("worker-0")
        if status != 200 or not isinstance(claim, dict) or claim.get("job") is None:
            raise RuntimeError(f"claim failed: {status} {claim}")
        observed["job"] = claim["job"]
        observed["before_restart"] = coordinator.status()
        coordinator.kill()
        coordinator = Coordinator(binary, port, JOBS, out)
        coordinator.start()
        observed["after_restart"] = coordinator.status()
        jobs = jobs_status(observed["after_restart"])
        durable = int(jobs.get("running", 0)) + int(jobs.get("done", 0)) >= 1
        status, body = coordinator.submit(
            "worker-0", int(claim["job"]["job_id"]), report_for(0)
        )
        observed["stale_result_http"] = status
        observed["stale_result_body"] = body
        return {
            "scenario": "crash-after-claim",
            "ok": bool(durable),
            "expected": "an active lease survives restart or is requeued without losing the shard",
            "observed": observed,
            "reason": None
            if durable
            else "restart forgot the active claim and reset the shard to pending",
        }
    finally:
        coordinator.close()
        out.unlink(missing_ok=True)
        shutil.rmtree(out.parent, ignore_errors=True)


def scenario_uneven_load(binary: Path) -> dict[str, object]:
    port = free_port()
    out = Path(tempfile.mkdtemp(prefix="portensor-distributed-")) / "report.json"
    coordinator = Coordinator(binary, port, UNEVEN_JOBS, out, lease_secs=30)
    records: list[dict[str, object]] = []
    lock = threading.Lock()
    barrier = threading.Barrier(UNEVEN_WORKERS)
    completed = threading.Event()
    observed: dict[str, object] = {}
    try:
        coordinator.start()
        started_at = time.monotonic()

        def worker(index: int) -> None:
            worker_id = f"uneven-{index}"
            barrier.wait()
            last_result_at: float | None = None
            last_busy_until: float | None = None
            jobs_done = 0
            claims = 0
            while not completed.is_set():
                try:
                    status, body = coordinator.claim(worker_id)
                except (urllib.error.URLError, OSError):
                    break
                if status != 200 or not isinstance(body, dict):
                    break
                job = body.get("job")
                if job is None:
                    if body.get("complete"):
                        break
                    time.sleep(0.05)
                    continue
                job_id = int(job["job_id"])
                duration = (
                    UNEVEN_DURATIONS[job_id]
                    if job_id < len(UNEVEN_DURATIONS)
                    else 1.0
                )
                claims += 1
                last_busy_until = time.monotonic() + duration
                time.sleep(duration)
                try:
                    status, _ = coordinator.submit(
                        worker_id, job_id, report_for(job_id)
                    )
                except (urllib.error.URLError, OSError):
                    break
                if status == 200:
                    jobs_done += 1
                    last_result_at = time.monotonic()
            with lock:
                records.append(
                    {
                        "worker": worker_id,
                        "jobs": jobs_done,
                        "claims": claims,
                        "last_result_at": last_result_at,
                        "last_busy_until": last_busy_until,
                    }
                )

        threads = [
            threading.Thread(target=worker, args=(index,), daemon=True)
            for index in range(UNEVEN_WORKERS)
        ]
        for thread in threads:
            thread.start()
        try:
            status = wait_until_complete(coordinator, timeout=30)
        except Exception:
            print(
                f"coordinator log after failure:\n{coordinator.log_path.read_text()}",
                file=sys.stderr,
            )
            raise
        completed_at = time.monotonic()
        completed.set()
        join_timeout = max(UNEVEN_DURATIONS) + 30
        for thread in threads:
            thread.join(timeout=join_timeout)
        wall = completed_at - started_at
        idle = []
        for record in records:
            busy_until = record["last_busy_until"]
            last_result = record["last_result_at"]
            last_activity = max(
                float(last_result) if last_result is not None else started_at,
                float(busy_until) if busy_until is not None else started_at,
            )
            idle.append(max(0.0, completed_at - last_activity))
        lower_bound = max(max(UNEVEN_DURATIONS), sum(UNEVEN_DURATIONS) / UNEVEN_WORKERS)
        ratio = wall / lower_bound if lower_bound else 0.0
        max_idle = max(idle, default=0.0)
        ok = bool(
            status.get("state") == "complete"
            and ratio <= 1.2
            and max_idle <= 5.0
        )
        observed = {
            "workers": records,
            "wall_seconds": round(wall, 3),
            "lower_bound_seconds": lower_bound,
            "completion_ratio": round(ratio, 3),
            "max_idle_seconds": round(max_idle, 3),
            "status": status,
        }
        return {
            "scenario": "uneven-load",
            "ok": ok,
            "expected": "completion <= 1.2x lower bound and no worker idle > 5s while work remains",
            "observed": observed,
            "reason": None
            if ok
            else "FIFO shard assignment leaves workers idle while the long shard runs",
        }
    finally:
        coordinator.close()
        out.unlink(missing_ok=True)
        shutil.rmtree(out.parent, ignore_errors=True)


def scenario_before_claim(binary: Path) -> dict[str, object]:
    port = free_port()
    out = Path(tempfile.mkdtemp(prefix="portensor-distributed-")) / "report.json"
    coordinator = Coordinator(binary, port, JOBS, out)
    observed: dict[str, object] = {}
    try:
        coordinator.start()
        observed["before_restart"] = coordinator.status()
        observed["observability_before"] = coordinator.observability()
        coordinator.kill()
        coordinator = Coordinator(binary, port, JOBS, out)
        coordinator.start()
        after = coordinator.status()
        observed["after_restart"] = after
        observed["observability_after"] = coordinator.observability()
        jobs = jobs_status(after)
        durable = (
            jobs.get("pending") == JOBS
            and jobs.get("running") == 0
            and after.get("restart_count") == 1
            and observed["observability_after"]["ready"] is True
        )
        return {
            "scenario": "crash-before-claim",
            "ok": bool(durable),
            "expected": "unclaimed jobs remain pending and readiness recovers",
            "observed": observed,
            "reason": None if durable else "unclaimed jobs changed across restart",
        }
    finally:
        coordinator.close()
        shutil.rmtree(out.parent, ignore_errors=True)


def scenario_mid_result(binary: Path) -> dict[str, object]:
    port = free_port()
    out = Path(tempfile.mkdtemp(prefix="portensor-distributed-")) / "report.json"
    coordinator = Coordinator(binary, port, JOBS, out)
    observed: dict[str, object] = {}
    try:
        coordinator.start()
        status, claim = coordinator.claim("worker-0")
        if status != 200 or not isinstance(claim, dict) or claim.get("job") is None:
            raise RuntimeError(f"claim failed: {status} {claim}")
        job = claim["job"]
        partial = (
            f'{{"worker_id":"worker-0","job_id":{int(job["job_id"])},"report":{{'
        ).encode("utf-8")
        request_head = (
            "POST /v1/result HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            f"Authorization: Bearer {TOKEN}\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(partial) + 500}\r\n"
            "Connection: close\r\n\r\n"
        ).encode("utf-8")
        with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
            sock.sendall(request_head + partial)
        time.sleep(0.2)
        observed["after_partial"] = coordinator.status()
        observed["observability"] = coordinator.observability()
        status, body = coordinator.submit(
            "worker-0", int(job["job_id"]), report_for(int(job["job_id"]))
        )
        observed["retry_http"] = status
        observed["retry_body"] = body
        observed["after_retry"] = coordinator.status()
        jobs = jobs_status(observed["after_retry"])
        ok = (
            status == 200
            and jobs.get("done") == 1
            and jobs.get("failed") == 0
            and observed["observability"]["metrics_fields"] is True
        )
        return {
            "scenario": "mid-result-body",
            "ok": bool(ok),
            "expected": "a truncated result body is not durable and a retry succeeds",
            "observed": observed,
            "reason": None if ok else "partial result was accepted or retry failed",
        }
    finally:
        coordinator.close()
        shutil.rmtree(out.parent, ignore_errors=True)


def scenario_observability(binary: Path) -> dict[str, object]:
    port = free_port()
    out = Path(tempfile.mkdtemp(prefix="portensor-distributed-")) / "report.json"
    coordinator = Coordinator(binary, port, JOBS, out)
    observed: dict[str, object] = {}
    try:
        coordinator.start()
        before = coordinator.observability()
        observed["before"] = before
        status, claim = coordinator.claim("worker-0")
        if status != 200 or not isinstance(claim, dict) or claim.get("job") is None:
            raise RuntimeError(f"claim failed: {status} {claim}")
        job = claim["job"]
        status, body = coordinator.submit(
            "worker-0", int(job["job_id"]), report_for(int(job["job_id"]))
        )
        if status != 200:
            raise RuntimeError(f"result failed: {status} {body}")
        time.sleep(0.1)
        _, metrics_after = coordinator.metrics()
        observed["done_metric_after_submit"] = 'portensor_jobs{state="done"} 1' in metrics_after
        observed["after"] = coordinator.observability()
        ok = (
            before["ready"] is True
            and before["metrics_http"] == 200
            and before["metrics_fields"] is True
            and before["log_correlates_run"] is True
            and observed["done_metric_after_submit"] is True
        )
        return {
            "scenario": "metrics-and-readiness",
            "ok": bool(ok),
            "expected": "readyz, metrics counters, and correlated logs are exposed after recovery",
            "observed": observed,
            "reason": None if ok else "readiness, metrics, or log correlation missing",
        }
    finally:
        coordinator.close()
        shutil.rmtree(out.parent, ignore_errors=True)

def format_markdown(report: dict[str, object]) -> str:
    lines = [
        "# Distributed coordinator baseline",
        "",
        f"Generated: {report['generated_at']}",
        "",
        "These are fake-worker control-plane measurements. They do not claim remote",
        "scan throughput. A pre-P3 baseline fails; the v0.10 gate requires every scenario to pass.",
        "",
        "| Scenario | Result | Reason |",
        "|---|---|---|",
    ]
    for item in report["scenarios"]:
        lines.append(
            f"| {item['scenario']} | {'pass' if item['ok'] else 'fail'} | "
            f"{item['reason'] or ''} |"
        )
    uneven = report.get("uneven")
    if isinstance(uneven, dict):
        observed = uneven["observed"]
        lines.extend(
            [
                "",
                "## Uneven-load detail",
                "",
                f"- Workers: {observed['workers']}",
                f"- Wall: {observed['wall_seconds']} s",
                f"- Lower bound: {observed['lower_bound_seconds']} s",
                f"- Ratio: {observed['completion_ratio']}",
                f"- Max idle: {observed['max_idle_seconds']} s",
                "",
            ]
        )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=DEFAULT_BINARY)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--markdown", type=Path, default=DEFAULT_MARKDOWN)
    parser.add_argument(
        "--baseline",
        action="store_true",
        help="record known pre-P3 failures without failing the harness",
    )
    parser.add_argument(
        "--only",
        choices=("all", "before-claim", "after-claim", "after-result", "completed-restart", "mid-result", "metrics", "uneven"),
        default="all",
    )
    args = parser.parse_args()
    if not args.binary.is_file():
        print(f"missing binary: {args.binary}", file=sys.stderr)
        return 2

    factories = {
        "before-claim": scenario_before_claim,
        "after-claim": scenario_after_claim,
        "after-result": scenario_after_result,
        "completed-restart": scenario_completed_restart,
        "mid-result": scenario_mid_result,
        "metrics": scenario_observability,
        "uneven": scenario_uneven_load,
    }
    selected = list(factories) if args.only == "all" else [args.only]
    results = {name: factories[name](args.binary) for name in selected}
    control_plane = [results[name] for name in selected if name != "uneven"]
    uneven = results.get("uneven")
    report = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "binary": str(args.binary),
        "baseline_mode": args.baseline,
        "scenarios": control_plane,
        "uneven": uneven,
        "ok": all(item["ok"] for item in results.values()),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.markdown.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    args.markdown.write_text(format_markdown(report), encoding="utf-8")
    for item in results.values():
        print(
            f"{item['scenario']}: {'pass' if item['ok'] else 'fail'}"
            + (f" ({item['reason']})" if item["reason"] else "")
        )
    print(f"saved {args.output}")
    print(f"saved {args.markdown}")
    if args.baseline:
        return 0
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
