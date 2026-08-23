from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "compare-latency.py"
STAGES = (
    "capture_to_convert",
    "convert_to_encode",
    "encode_latency",
    "transport_delivery",
    "receive_to_decode",
    "decode_to_present",
    "total_pipeline",
)


def valid_report(product: str, version: str, commit: str) -> dict:
    return {
        "schema_version": 1,
        "product": {
            "name": product,
            "version": version,
            "commit": commit,
        },
        "hardware": {
            "host": {"cpu": "Example CPU", "gpu": "Example GPU", "driver": "1.2.3"},
            "client": {"cpu": "Example CPU 2", "gpu": "Example GPU 2", "driver": "4.5.6"},
        },
        "display_mode": {
            "resolution": "1920x1080",
            "fps": 60,
            "color_space": "BT.709 limited SDR",
        },
        "codec": {"name": "H.264", "profile": "high", "rate_control": "CBR"},
        "bitrate": {"value": 20, "unit": "Mbps"},
        "network_profile": {
            "profile_id": "lan-clean-v1",
            "rtt_ms": 1.0,
            "loss_percent": 0.0,
            "jitter_ms": 0.2,
        },
        "workload": {"id": "ide-scroll-v1", "trace_sha256": "a" * 64},
        "configuration": {"quality_preset": "matched", "warmup_seconds": 30},
        "latency_unit": "us",
        "metrics": {
            stage: {
                "p50": 100.0 + index,
                "p95": 150.0 + index,
                "p99": 200.0 + index,
                "sample_count": 1_000,
            }
            for index, stage in enumerate(STAGES)
        },
    }


class CompareLatencyCliTests(unittest.TestCase):
    def run_pair(
        self, baseline_text: str, candidate_text: str, *args: str
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            baseline = root / "baseline.json"
            candidate = root / "candidate.json"
            baseline.write_text(baseline_text, encoding="utf-8")
            candidate.write_text(candidate_text, encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(SCRIPT), str(baseline), str(candidate), *args],
                text=True,
                capture_output=True,
                check=False,
            )

    def reports(self) -> tuple[dict, dict]:
        baseline = valid_report("BaselineProduct", "8.0.0", "baseline-commit")
        candidate = valid_report("LatencyDesk", "0.1.0", "candidate-commit")
        return baseline, candidate

    def test_empty_file_fails_closed(self) -> None:
        _, candidate = self.reports()
        result = self.run_pair("", json.dumps(candidate), "--json")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("is empty", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_nan_is_rejected(self) -> None:
        baseline, candidate = self.reports()
        baseline["metrics"]["encode_latency"]["p99"] = float("nan")
        result = self.run_pair(json.dumps(baseline), json.dumps(candidate), "--json")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("baseline.metrics.encode_latency.p99 must be finite", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_missing_fields_report_all_errors(self) -> None:
        _, candidate = self.reports()
        result = self.run_pair("{}", json.dumps(candidate), "--json")
        self.assertNotEqual(result.returncode, 0)
        for field in (
            "baseline.schema_version",
            "baseline.product.version",
            "baseline.product.commit",
            "baseline.hardware",
            "baseline.resolution",
            "baseline.fps",
            "baseline.codec",
            "baseline.bitrate.unit",
            "baseline.network_profile",
            "baseline.workload",
            "baseline.metrics.total_pipeline",
        ):
            self.assertIn(field, result.stderr)

    def test_mismatched_configuration_lists_each_difference(self) -> None:
        baseline, candidate = self.reports()
        candidate["display_mode"]["fps"] = 120
        candidate["workload"] = {"id": "video-v1", "trace_sha256": "b" * 64}
        result = self.run_pair(json.dumps(baseline), json.dumps(candidate), "--json")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("comparison.fps mismatch", result.stderr)
        self.assertIn("comparison.workload mismatch", result.stderr)

    def test_boolean_numeric_zero_samples_and_nonmonotonic_values_fail(self) -> None:
        baseline, candidate = self.reports()
        baseline["fps"] = True
        del baseline["display_mode"]["fps"]
        baseline["metrics"]["capture_to_convert"]["sample_count"] = 0
        baseline["metrics"]["decode_to_present"].update(
            {"p50": 200, "p95": 150, "p99": 100}
        )
        result = self.run_pair(json.dumps(baseline), json.dumps(candidate), "--json")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("boolean values are not numbers", result.stderr)
        self.assertIn("must be a positive integer", result.stderr)
        self.assertIn("percentiles must be monotonic", result.stderr)

    def test_negative_and_inconsistent_or_missing_units_fail(self) -> None:
        baseline, candidate = self.reports()
        baseline["metrics"]["encode_latency"]["p50"] = -1
        baseline["metrics"]["transport_delivery"]["unit"] = "ms"
        result = self.run_pair(json.dumps(baseline), json.dumps(candidate), "--json")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("must be non-negative", result.stderr)
        self.assertIn("use inconsistent latency units", result.stderr)
        self.assertIn("must match baseline.latency_unit", result.stderr)

        baseline, candidate = self.reports()
        del baseline["latency_unit"]
        result = self.run_pair(json.dumps(baseline), json.dumps(candidate), "--json")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unit is required when latency_unit is absent", result.stderr)

    def test_valid_pair_reports_counts_and_evidence_notice(self) -> None:
        baseline, candidate = self.reports()
        candidate = deepcopy(candidate)
        candidate["metrics"]["total_pipeline"]["sample_count"] = 1_200
        result = self.run_pair(json.dumps(baseline), json.dumps(candidate), "--json")
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        self.assertTrue(output["valid"])
        self.assertTrue(output["not_independent_proof"])
        self.assertIn("not independent proof", output["evidence_notice"])
        total = output["stages"]["total_pipeline"]
        self.assertEqual(total["baseline"]["sample_count"], 1_000)
        self.assertEqual(total["candidate"]["sample_count"], 1_200)


if __name__ == "__main__":
    unittest.main()
