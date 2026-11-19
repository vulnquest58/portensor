from __future__ import annotations

import io
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

from bench import bench, validate


def make_run(
    tool: str,
    false_positives: int = 0,
    false_negatives: int = 0,
    elapsed: float = 1.0,
    cpu: float = 0.5,
    rss: int = 8192,
) -> bench.Run:
    true_positives = 4
    predicted = true_positives + false_positives
    truth = true_positives + false_negatives
    recall = true_positives / truth if truth else 0.0
    precision = true_positives / predicted if predicted else 0.0
    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall
        else 0.0
    )
    run = bench.Run(
        tool=tool,
        command=[tool],
        elapsed_seconds=elapsed,
        exit_code=0,
        cpu_seconds=cpu,
        peak_rss_kb=rss,
        measurement="gnu-time",
    )
    run.metrics = bench.Metrics(
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
        recall=recall,
        precision=precision,
        f1=f1,
    )
    return run


class SummaryTests(unittest.TestCase):
    def test_percentile(self) -> None:
        self.assertEqual(validate.percentile([], 0.95), None)
        self.assertEqual(validate.percentile([4.0], 0.95), 4.0)
        self.assertEqual(validate.percentile([1.0, 2.0, 3.0, 4.0], 0.5), 3.0)

    def test_summarize_values(self) -> None:
        summary = validate.summarize_values([1.0, 2.0, 3.0])
        self.assertEqual(summary["median"], 2.0)
        self.assertEqual(summary["min"], 1.0)
        self.assertEqual(summary["max"], 3.0)

    def test_exact_summary_and_verdict(self) -> None:
        spec = validate.ToolSpec("rayscan", ["rayscan"], bench.parse_rayscan, True)
        observations = [
            validate.Observation(0, make_run("rayscan", elapsed=1.0)),
            validate.Observation(1, make_run("rayscan", elapsed=1.2)),
        ]
        summary = validate.summarize_tool(spec, observations, None)
        self.assertTrue(summary["exact"])
        self.assertEqual(summary["exact_runs"], 2)
        self.assertEqual(summary["false_positives"], 0)
        verdict, reasons = validate.verdict_for(summary, 30.0, 60.0, 512.0)
        self.assertTrue(verdict)
        self.assertEqual(reasons, [])

    def test_false_positive_fails_verdict(self) -> None:
        spec = validate.ToolSpec("rayscan", ["rayscan"], bench.parse_rayscan, True)
        observations = [
            validate.Observation(0, make_run("rayscan", false_positives=2))
        ]
        summary = validate.summarize_tool(spec, observations, None)
        self.assertFalse(summary["exact"])
        verdict, reasons = validate.verdict_for(summary, 30.0, 60.0, 512.0)
        self.assertFalse(verdict)
        self.assertIn("accuracy mismatch in at least one run", reasons)

    def test_missing_measurements_fail_verdict(self) -> None:
        spec = validate.ToolSpec("rayscan", ["rayscan"], bench.parse_rayscan, True)
        run = make_run("rayscan")
        run.cpu_seconds = None
        run.peak_rss_kb = None
        summary = validate.summarize_tool(
            spec, [validate.Observation(0, run)], None
        )
        verdict, reasons = validate.verdict_for(summary, 30.0, 60.0, 512.0)
        self.assertFalse(verdict)
        self.assertIn("no CPU samples", reasons)
        self.assertIn("no peak-RSS samples", reasons)


class NetworkConditionTests(unittest.TestCase):
    def test_default_condition(self) -> None:
        self.assertEqual(
            validate.network_condition(None, 0.0), "loopback, no injected loss"
        )

    def test_netem_condition(self) -> None:
        self.assertEqual(
            validate.network_condition(5.0, 10.0),
            "loopback + tc netem loss 5% delay 10ms",
        )

    def test_netem_requires_namespace_tools(self) -> None:
        stderr = io.StringIO()
        with mock.patch("bench.validate.shutil.which", return_value=None):
            with redirect_stderr(stderr):
                self.assertEqual(
                    validate.run_in_network_namespace(
                        ["--repeat", "1"], 5.0, 0.0
                    ),
                    1,
                )
        self.assertIn("missing: unshare, ip, tc", stderr.getvalue())


class CommandTests(unittest.TestCase):
    def test_rayscan_command_is_quiet_and_unlimited(self) -> None:
        specs = validate.build_tools(
            ["rayscan"], Path("/tmp/rayscan"), [20001, 20002]
        )
        command = specs[0].command
        self.assertEqual(command[0], "/tmp/rayscan")
        self.assertIn("--json", command)
        self.assertIn("--quiet", command)
        self.assertIn("0", command)

    def test_nmap_uses_connect_scan(self) -> None:
        specs = validate.build_tools(["nmap"], Path("/tmp/rayscan"), [20001])
        self.assertIn("-sT", specs[0].command)
        self.assertIn("20001", specs[0].command)

    def test_handshake_mode_uses_discovery_and_speed_ports(self) -> None:
        specs = validate.build_tools(
            ["rayscan-connect"],
            Path("/tmp/rayscan"),
            [20001, 20002, 20003],
            speed_ports=[20001, 20003],
        )
        self.assertEqual(specs[0].ports, [20001, 20003])
        self.assertEqual(specs[0].mode, "handshake")
        self.assertIn("--discover-only", specs[0].command)
        self.assertIn("20001,20003", specs[0].command)

    def test_required_unknown_tool_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            validate.build_tools(["unknown"], Path("/tmp/rayscan"), [20001])


class ReportTests(unittest.TestCase):
    def test_markdown_contains_verdict_and_tools(self) -> None:
        spec = validate.ToolSpec("rayscan", ["rayscan"], bench.parse_rayscan, True)
        summary = validate.summarize_tool(
            spec, [validate.Observation(0, make_run("rayscan"))], None
        )
        report = {
            "generated_at": "2026-01-01T00:00:00+00:00",
            "environment": {
                "platform": "test",
                "cpu_model": "test cpu",
                "cpu_count": 2,
                "memory_kb": 2048,
                "python": "3.12",
                "versions": {"rayscan": "rayscan 0.6.0"},
            },
            "scenario": {
                "target": validate.HOST,
                "banner_ports": [20001],
                "tarpit_ports": [20002],
                "closed_ports": [20003],
                "handshake_ports": [20001, 20003],
                "network_condition": "loopback",
            },
            "tools": [summary],
            "verdict": "PASS",
            "reasons": [],
        }
        markdown = validate.format_markdown(report)
        self.assertIn("rayscan benchmark validation", markdown)
        self.assertIn("| rayscan | accuracy |", markdown)
        self.assertIn("| yes |", markdown)
        self.assertIn("**PASS**", markdown)


if __name__ == "__main__":
    unittest.main()
