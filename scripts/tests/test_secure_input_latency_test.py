import unittest
from pathlib import Path
import sys
from unittest import mock

sys.path.insert(0, str(Path(__file__).parents[1]))
import secure_input_latency_test as probe


class InputLatencyTests(unittest.TestCase):
    def line(self, raw="1:10,2:20,3:30,4:40"):
        return (
            "input-latency: session_id=7 authorization_epoch=9 route_epoch=1 samples=4 min_us=10 p50_us=20 p95_us=40 p99_us=40 max_us=40 mean_us=25 raw_us="
            + raw
        )

    def test_parse_and_recompute(self):
        parsed = probe.parse_input_latency(self.line())
        self.assertEqual(probe.recompute(parsed["samples"]), parsed["summary"])

    def test_tampered_summary(self):
        parsed = probe.parse_input_latency(
            self.line().replace("mean_us=25", "mean_us=99")
        )
        self.assertTrue(
            any(
                "summary" in e
                for e in probe.validate_probe(parsed, 4, [(7, 9)], [(7, 9)])
            )
        )

    def test_gaps_and_duplicates(self):
        parsed = probe.parse_input_latency(self.line("1:10,2:20,2:30,4:40"))
        self.assertTrue(
            any(
                "contiguous" in e
                for e in probe.validate_probe(parsed, 4, [(7, 9)], [(7, 9)])
            )
        )

    def test_wrong_identity_and_epoch(self):
        parsed = probe.parse_input_latency(self.line())
        self.assertTrue(
            any(
                "lifecycle" in e
                for e in probe.validate_probe(parsed, 4, [(8, 9)], [(7, 10)])
            )
        )

    def test_p95_ceiling(self):
        parsed = probe.parse_input_latency(self.line("1:10,2:20,3:30,4:100001"))
        self.assertTrue(
            any(
                "ceiling" in e
                for e in probe.validate_probe(parsed, 4, [(7, 9)], [(7, 9)])
            )
        )

    def test_nonfinite_rejected(self):
        with self.assertRaises(ValueError):
            probe.parse_input_latency(self.line("1:nan,2:20,3:30,4:40"))

    def test_command_safety(self):
        self.assertTrue(probe.command_is_safe(["client", "--connect", "x"]))
        self.assertFalse(probe.command_is_safe(["client", "--unsafe-udp-lab"]))
        host, client = probe.build_commands(
            Path("host"),
            Path("client"),
            "127.0.0.1:4000",
            Path("ids/host"),
            Path("ids/client"),
            128,
        )
        self.assertEqual(client[client.index("--input-latency-probes") + 1], "128")
        self.assertNotIn(probe.UNSAFE, host + client)

    def test_linux_display_skip(self):
        with (
            mock.patch.object(
                probe, "prerequisite_skip_reason", return_value="Linux X11 required"
            ),
            mock.patch.object(probe, "write_report") as write_report,
            mock.patch("builtins.print"),
        ):
            self.assertEqual(probe.main(["--output", "ignored.json"]), 0)
        artifact = write_report.call_args.args[1]
        self.assertEqual(artifact["status"], "skipped")
        self.assertFalse(artifact["ok"])


if __name__ == "__main__":
    unittest.main()
