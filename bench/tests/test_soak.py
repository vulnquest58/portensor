import unittest
from pathlib import Path

from bench import soak


class CommandTests(unittest.TestCase):
    def test_verified_command_has_workers_and_ports(self) -> None:
        command = soak.scan_command(Path("/tmp/portensor"), [80, 443], 64, 32, False)
        self.assertIn("--workers", command)
        self.assertEqual(command[command.index("--workers") + 1], "64")
        self.assertEqual(command[command.index("--ports") + 1], "80,443")
        self.assertIn("--host-concurrency", command)
        self.assertNotIn("--discover-only", command)

    def test_discover_mode_omits_zero_host_cap(self) -> None:
        command = soak.scan_command(Path("/tmp/portensor"), [80], 8, 0, True)
        self.assertNotIn("--host-concurrency", command)
        self.assertIn("--discover-only", command)


class SummaryTests(unittest.TestCase):
    def test_summary_counts_and_percentiles(self) -> None:
        summary = soak.summarize(
            [
                {
                    "ok": True,
                    "wall_seconds": 1.0,
                    "cpu_seconds": 0.5,
                    "peak_rss_kb": 1024,
                },
                {
                    "ok": False,
                    "wall_seconds": 3.0,
                    "cpu_seconds": None,
                    "peak_rss_kb": None,
                },
            ]
        )
        self.assertEqual(summary["rounds"], 2)
        self.assertEqual(summary["passed"], 1)
        self.assertEqual(summary["failed"], 1)
        self.assertEqual(summary["wall_seconds"]["median"], 2.0)
        self.assertEqual(summary["peak_rss_kb"]["max"], 1024)

    def test_empty_summary_is_safe(self) -> None:
        summary = soak.summarize([])
        self.assertEqual(summary["rounds"], 0)
        self.assertIsNone(summary["wall_seconds"]["median"])
        self.assertIsNone(summary["peak_rss_kb"]["max"])


if __name__ == "__main__":
    unittest.main()
