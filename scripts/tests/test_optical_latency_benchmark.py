from __future__ import annotations

import csv
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "optical_latency_benchmark.py"


def valid_optical_report(product: str, version: str, commit: str | None = None) -> dict:
    samples = [
        23.4, 24.1, 22.8, 25.2, 23.9, 24.7, 26.1, 23.0, 22.5, 24.4,
        25.0, 23.8, 24.2, 27.3, 23.1, 22.9, 24.8, 25.5, 23.6, 24.0,
        23.2, 24.5, 25.1, 26.8, 23.5, 24.3, 22.7, 25.9, 24.6, 23.7,
        24.9, 25.3, 23.3, 24.2, 26.0
    ]
    return {
        "schema_version": 1,
        "product": {
            "name": product,
            "version": version,
            "commit": commit or "test-commit-hash",
        },
        "hardware": {
            "cpu": "Intel Core i7-12700H",
            "gpu": "NVIDIA GeForce RTX 3050 Ti Laptop GPU",
            "driver": "32.0.15.9144",
            "ram": "16GB",
            "os": "Windows 11 Home",
        },
        "display": {
            "resolution": "1920x1080",
            "stream_fps": 60,
            "refresh_rate_hz": 144,
            "color_space": "bt709",
        },
        "stream_config": {
            "codec": "h264",
            "bitrate": {"value": 20, "unit": "Mbps"},
            "quality_preset": "low_latency",
            "cursor_mode": "local_predictive",
            "presentation_mode": "vsync_off",
        },
        "network_profile": {
            "name": "Clean LAN",
            "rtt_ms": 1.0,
            "loss_percent": 0.0,
            "jitter_ms": 0.1,
            "bandwidth_mbps": 1000,
        },
        "workload": "static_ide_typing",
        "optical_setup": {
            "method": "photodiode_oscilloscope",
            "sensor_model": "Thorlabs PDA36A2",
            "clock_domain": "unified_single_clock",
            "trigger_type": "microcontroller_hid",
        },
        "warmup_samples": 5,
        "repetitions": 30,
        "samples": samples,
    }


class OpticalLatencyBenchmarkTests(unittest.TestCase):
    def run_cli(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            text=True,
            capture_output=True,
            check=False,
        )

    def test_inventory_subcommand(self) -> None:
        result = self.run_cli("inventory")
        self.assertEqual(result.returncode, 0)
        data = json.loads(result.stdout)
        self.assertIn("competitors", data)
        self.assertIn("optical_rig_status", data)
        self.assertIn("can_execute_physical_benchmark", data["optical_rig_status"])
        self.assertFalse(data["optical_rig_status"]["can_execute_physical_benchmark"])
        self.assertTrue(len(data["optical_rig_status"]["blocker_reasons"]) > 0)

    def test_generate_template_subcommand(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            out_dir = Path(tmp_dir) / "templates"
            result = self.run_cli("generate-template", "--out-dir", str(out_dir))
            self.assertEqual(result.returncode, 0)
            manifest = out_dir / "optical_manifest_template.json"
            csv_file = out_dir / "optical_samples_template.csv"
            self.assertTrue(manifest.is_file())
            self.assertTrue(csv_file.is_file())

            parsed_manifest = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(parsed_manifest["schema_version"], 1)
            self.assertEqual(parsed_manifest["product"]["name"], "LatencyDesk")

    def test_analyze_valid_report(self) -> None:
        report = valid_optical_report("LatencyDesk", "0.1.0")
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(report, f)
            temp_path = f.name

        try:
            result = self.run_cli("analyze", temp_path)
            self.assertEqual(result.returncode, 0)
            analyzed = json.loads(result.stdout)
            metrics = analyzed["metrics"]
            self.assertIn("p50", metrics)
            self.assertIn("p95", metrics)
            self.assertIn("p99", metrics)
            self.assertIn("ci_95", metrics)
            self.assertTrue(metrics["min"] <= metrics["p50"] <= metrics["p95"] <= metrics["p99"] <= metrics["max"])
            self.assertEqual(metrics["sample_count"], 30)
            self.assertEqual(analyzed["provenance"]["warmup_samples"], 5)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_high_speed_camera_frames_ingestion(self) -> None:
        report = valid_optical_report("LatencyDesk", "0.1.0")
        report["optical_setup"]["method"] = "high_speed_camera"
        report["optical_setup"]["clock_domain"] = "high_speed_camera_frames"
        events = [
            {"trigger_frame": i * 1000, "photon_frame": i * 1000 + 20 + (i % 7), "camera_fps": 1000}
            for i in range(35)
        ]
        report["samples"] = events

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(report, f)
            temp_path = f.name

        try:
            result = self.run_cli("analyze", temp_path)
            self.assertEqual(result.returncode, 0)
            analyzed = json.loads(result.stdout)
            metrics = analyzed["metrics"]
            self.assertTrue(20.0 <= metrics["p50"] <= 26.0)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_photodiode_microsecond_timestamps_ingestion(self) -> None:
        report = valid_optical_report("LatencyDesk", "0.1.0")
        events = [
            {"trigger_ts": i * 1_000_000, "photon_ts": i * 1_000_000 + 24_000 + (i * 100), "unit": "us"}
            for i in range(35)
        ]
        report["samples"] = events

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(report, f)
            temp_path = f.name

        try:
            result = self.run_cli("analyze", temp_path)
            self.assertEqual(result.returncode, 0)
            analyzed = json.loads(result.stdout)
            metrics = analyzed["metrics"]
            self.assertTrue(24.0 <= metrics["p50"] <= 28.0)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_external_csv_samples_file_ingestion(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            csv_path = Path(tmp_dir) / "samples.csv"
            with open(csv_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["trigger_ts", "photon_ts", "unit"])
                for i in range(35):
                    writer.writerow([i * 1000, i * 1000 + 22 + (i % 5), "ms"])

            report = valid_optical_report("LatencyDesk", "0.1.0")
            del report["samples"]
            report["samples_file"] = str(csv_path)

            json_path = Path(tmp_dir) / "report.json"
            json_path.write_text(json.dumps(report), encoding="utf-8")

            result = self.run_cli("analyze", str(json_path))
            self.assertEqual(result.returncode, 0)
            analyzed = json.loads(result.stdout)
            self.assertEqual(analyzed["metrics"]["sample_count"], 30)

    def test_rejection_of_clock_domain_split(self) -> None:
        report = valid_optical_report("LatencyDesk", "0.1.0")
        report["optical_setup"]["clock_domain"] = "host_client_split"

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(report, f)
            temp_path = f.name

        try:
            result = self.run_cli("analyze", temp_path)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Host and client monotonic timestamps belong to different clock domains", result.stderr)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_rejection_of_software_clock_subtraction(self) -> None:
        report = valid_optical_report("LatencyDesk", "0.1.0")
        report["optical_setup"]["clock_domain"] = "software_clock_subtraction"

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(report, f)
            temp_path = f.name

        try:
            result = self.run_cli("analyze", temp_path)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("cannot be directly subtracted", result.stderr)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_rejection_of_fabricated_zero_variance_samples(self) -> None:
        report = valid_optical_report("LatencyDesk", "0.1.0")
        report["samples"] = [25.0] * 35

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(report, f)
            temp_path = f.name

        try:
            result = self.run_cli("analyze", temp_path)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("standard deviation is 0.0", result.stderr)
            self.assertIn("fabricated/mock optical traces are rejected", result.stderr)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_rejection_of_impossible_physical_latency(self) -> None:
        report = valid_optical_report("LatencyDesk", "0.1.0")
        report["samples"] = [0.1, 0.2, 0.3] + [24.0] * 32

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(report, f)
            temp_path = f.name

        try:
            result = self.run_cli("analyze", temp_path)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("physically impossible input-to-photon latency", result.stderr)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_rejection_of_reverse_frame_indices(self) -> None:
        report = valid_optical_report("LatencyDesk", "0.1.0")
        report["optical_setup"]["clock_domain"] = "high_speed_camera_frames"
        report["samples"] = [
            {"trigger_frame": 100, "photon_frame": 50, "camera_fps": 1000}
        ] * 35

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(report, f)
            temp_path = f.name

        try:
            result = self.run_cli("analyze", temp_path)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("photon_frame (50) must be > trigger_frame (100)", result.stderr)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_rejection_of_insufficient_repetitions(self) -> None:
        report = valid_optical_report("LatencyDesk", "0.1.0")
        report["repetitions"] = 50
        report["samples"] = [24.0 + (i * 0.1) for i in range(20)]

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(report, f)
            temp_path = f.name

        try:
            result = self.run_cli("analyze", temp_path)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("sample count (20) is less than declared repetitions (50)", result.stderr)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_rejection_of_nan_and_inf_inputs(self) -> None:
        report = valid_optical_report("LatencyDesk", "0.1.0")
        report["display"]["stream_fps"] = float("nan")

        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
            json.dump(report, f)
            temp_path = f.name

        try:
            result = self.run_cli("analyze", temp_path)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("finite number", result.stderr)
        finally:
            Path(temp_path).unlink(missing_ok=True)

    def test_rejection_of_synthetic_in_benchmark_evidence(self) -> None:
        baseline_report = valid_optical_report("AnyDesk", "9.7.12", commit="test-commit-hash")
        candidate_report = valid_optical_report("LatencyDesk", "0.1.0", commit="test-commit-hash")

        with tempfile.TemporaryDirectory() as tmp_dir:
            b_path = Path(tmp_dir) / "baseline.json"
            c_path = Path(tmp_dir) / "candidate.json"
            b_path.write_text(json.dumps(baseline_report), encoding="utf-8")
            c_path.write_text(json.dumps(candidate_report), encoding="utf-8")

            # Without --allow-synthetic, must reject synthetic/template fixture
            result = self.run_cli("compare", str(b_path), str(c_path))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("cannot be used as real benchmark evidence", result.stderr)

    def test_compare_matched_reports_with_allow_synthetic(self) -> None:
        baseline_report = valid_optical_report("AnyDesk", "9.7.12", commit="test-commit-hash")
        baseline_report["samples"] = [30.0 + (i % 5) * 1.1 for i in range(35)]

        candidate_report = valid_optical_report("LatencyDesk", "0.1.0", commit="test-commit-hash")
        candidate_report["samples"] = [20.0 + (i % 5) * 0.9 for i in range(35)]

        with tempfile.TemporaryDirectory() as tmp_dir:
            b_path = Path(tmp_dir) / "baseline.json"
            c_path = Path(tmp_dir) / "candidate.json"
            b_path.write_text(json.dumps(baseline_report), encoding="utf-8")
            c_path.write_text(json.dumps(candidate_report), encoding="utf-8")

            result = self.run_cli("compare", str(b_path), str(c_path), "--allow-synthetic", "--json")
            self.assertEqual(result.returncode, 0)
            comp = json.loads(result.stdout)
            self.assertEqual(comp["baseline_product"]["name"], "AnyDesk")
            self.assertEqual(comp["candidate_product"]["name"], "LatencyDesk")
            self.assertIn("p95", comp["metrics"])
            self.assertLess(comp["metrics"]["p95"]["candidate"], comp["metrics"]["p95"]["baseline"])
            self.assertIn("Workload-specific conclusion per docs/BENCHMARKING.md", comp["disclaimer"])
            self.assertIn("must not be generalized as 'faster everywhere'", comp["disclaimer"])

    def test_compare_mismatched_workload_rejected(self) -> None:
        baseline = valid_optical_report("AnyDesk", "9.7.12")
        candidate = valid_optical_report("LatencyDesk", "0.1.0")
        candidate["workload"] = "terminal_scroll"

        with tempfile.TemporaryDirectory() as tmp_dir:
            b_path = Path(tmp_dir) / "baseline.json"
            c_path = Path(tmp_dir) / "candidate.json"
            b_path.write_text(json.dumps(baseline), encoding="utf-8")
            c_path.write_text(json.dumps(candidate), encoding="utf-8")

            result = self.run_cli("compare", str(b_path), str(c_path), "--allow-synthetic")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("comparison.workload mismatch", result.stderr)

    def test_compare_mismatched_display_resolution_rejected(self) -> None:
        baseline = valid_optical_report("AnyDesk", "9.7.12")
        candidate = valid_optical_report("LatencyDesk", "0.1.0")
        candidate["display"]["resolution"] = "2560x1440"

        with tempfile.TemporaryDirectory() as tmp_dir:
            b_path = Path(tmp_dir) / "baseline.json"
            c_path = Path(tmp_dir) / "candidate.json"
            b_path.write_text(json.dumps(baseline), encoding="utf-8")
            c_path.write_text(json.dumps(candidate), encoding="utf-8")

            result = self.run_cli("compare", str(b_path), str(c_path), "--allow-synthetic")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("comparison.resolution mismatch", result.stderr)

    def test_compare_mismatched_codec_rejected(self) -> None:
        baseline = valid_optical_report("AnyDesk", "9.7.12")
        candidate = valid_optical_report("LatencyDesk", "0.1.0")
        candidate["stream_config"]["codec"] = "av1"

        with tempfile.TemporaryDirectory() as tmp_dir:
            b_path = Path(tmp_dir) / "baseline.json"
            c_path = Path(tmp_dir) / "candidate.json"
            b_path.write_text(json.dumps(baseline), encoding="utf-8")
            c_path.write_text(json.dumps(candidate), encoding="utf-8")

            result = self.run_cli("compare", str(b_path), str(c_path), "--allow-synthetic")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("comparison.codec mismatch", result.stderr)

    def test_compare_mismatched_network_profile_rejected(self) -> None:
        baseline = valid_optical_report("AnyDesk", "9.7.12")
        candidate = valid_optical_report("LatencyDesk", "0.1.0")
        candidate["network_profile"] = {
            "name": "Good WAN",
            "rtt_ms": 20.0,
            "loss_percent": 0.5,
            "jitter_ms": 5.0,
            "bandwidth_mbps": 50,
        }

        with tempfile.TemporaryDirectory() as tmp_dir:
            b_path = Path(tmp_dir) / "baseline.json"
            c_path = Path(tmp_dir) / "candidate.json"
            b_path.write_text(json.dumps(baseline), encoding="utf-8")
            c_path.write_text(json.dumps(candidate), encoding="utf-8")

            result = self.run_cli("compare", str(b_path), str(c_path), "--allow-synthetic")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("comparison.network_profile mismatch", result.stderr)


if __name__ == "__main__":
    unittest.main()
