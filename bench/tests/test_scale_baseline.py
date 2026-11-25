from __future__ import annotations

import unittest
from pathlib import Path

from bench import bench, scale_baseline


class TargetTests(unittest.TestCase):
    def test_loopback_range_covers_requested_hosts(self) -> None:
        self.assertEqual(
            scale_baseline.target_range("127.0.0.1", 16),
            "127.0.0.1-127.0.0.16",
        )

    def test_non_loopback_target_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            scale_baseline.target_range("10.0.0.1", 16)

    def test_zero_hosts_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            scale_baseline.target_range("127.0.0.1", 0)


class CommandTests(unittest.TestCase):
    def test_command_uses_bounded_full_range_options(self) -> None:
        command = scale_baseline.command(
            Path("/tmp/portensor"),
            "127.0.0.1-127.0.0.16",
            "1-65535",
            512,
            0,
            2.0,
        )
        self.assertEqual(command[1:3], ["scan", "--target"])
        self.assertEqual(command[command.index("--ports") + 1], "1-65535")
        self.assertEqual(command[command.index("--workers") + 1], "512")
        self.assertEqual(command[command.index("--rate") + 1], "0")
        self.assertIn("--connect-only", command)
        self.assertIn("--json", command)


class SummaryTests(unittest.TestCase):
    def test_summarize_empty(self) -> None:
        self.assertIsNone(scale_baseline.summarize([])["median"])

    def test_summarize_values(self) -> None:
        summary = scale_baseline.summarize([3.0, 1.0, 2.0])
        self.assertEqual(summary["median"], 2.0)
        self.assertEqual(summary["min"], 1.0)
        self.assertEqual(summary["max"], 3.0)

    def test_markdown_reports_rss_gate(self) -> None:
        run = bench.Run(
            tool="portensor",
            command=["portensor"],
            elapsed_seconds=1.0,
            exit_code=0,
            cpu_seconds=0.5,
            peak_rss_kb=64 * 1024,
        )
        report = {
            "generated_at": "now",
            "targets": "127.0.0.1-127.0.0.16",
            "hosts": 16,
            "ports": "1-65535",
            "rate": 0,
            "workers": 512,
            "runs": 1,
            "environment": {
                "platform": "linux",
                "cpu_model": "test",
                "memory_kb": 1024,
                "portensor_version": "portensor 0.7.0",
            },
            "wall_seconds": {"median": 1.0},
            "cpu_seconds": {"median": 0.5},
            "peak_rss_kb": {"max": 64 * 1024},
        }
        markdown = scale_baseline.format_markdown(report, [run])
        self.assertIn("v0.10 RSS gate (128 MiB): pass", markdown)


if __name__ == "__main__":
    unittest.main()
