from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "optical_crossover_gate.py"
SPEC = importlib.util.spec_from_file_location("optical_crossover_gate", SCRIPT)
assert SPEC and SPEC.loader
GATE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = GATE
SPEC.loader.exec_module(GATE)


def raw_hash(block_id, order, warmup, samples):
    raw = json.dumps(
        {"block_id": block_id, "order": order, "warmup": warmup, "samples": samples},
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    return hashlib.sha256(raw).hexdigest()


def report(product: str, profile_class: str, latency: float) -> dict:
    blocks = []
    for block_id in range(1, 11):
        block_offset = block_id * 0.2
        clock_hz = 100_000
        order = GATE.expected_schedule(42)[block_id - 1]
        warmup = [
            {
                "event_id": f"{block_id}:warmup:{index}",
                "latency_ms": latency + block_offset + (index % 3) * 0.1,
                "trigger_tick": block_id * 100_000_000 + index * 300_000,
                "photon_tick": block_id * 100_000_000
                + index * 300_000
                + round((latency + block_offset + (index % 3) * 0.1) * clock_hz / 1000),
                "clock_hz": clock_hz,
            }
            for index in range(20)
        ]
        samples = [
            {
                "event_id": f"{block_id}:analyzed:{index}",
                "latency_ms": latency + block_offset + (index % 5) * 0.1,
                "trigger_tick": block_id * 100_000_000 + 10_000_000 + index * 300_000,
                "photon_tick": block_id * 100_000_000
                + 10_000_000
                + index * 300_000
                + round((latency + block_offset + (index % 5) * 0.1) * clock_hz / 1000),
                "clock_hz": clock_hz,
            }
            for index in range(100)
        ]
        blocks.append(
            {
                "block_id": block_id,
                "order": order,
                "warmup": warmup,
                "samples": samples,
                "raw_sha256": raw_hash(block_id, order, warmup, samples),
                "raw_path": f"test://raw/{product}/{profile_class}/{block_id}",
            }
        )
    manifest = {
        "schema_version": 2,
        "product": {
            "name": product,
            "version": "1.0-test",
            "build": "build-test",
            "binary_sha256": "a" * 64 if product == "AnyDesk" else "b" * 64,
            "binary_path": "test://anydesk"
            if product == "AnyDesk"
            else "test://latencydesk",
        },
        "profile": {
            "id": f"{profile_class}-profile",
            "class": profile_class,
            "route_class": "direct",
            "route_evidence_sha256": "e" * 64,
            "route_evidence_path": "test://route-evidence",
            "hardware": {
                "host": "host-a",
                "client": "client-a",
                "display": "display-a",
            },
            "network": {
                "rtt_ms": 1 if profile_class == "lan" else 40,
                "jitter_ms": 0.2 if profile_class == "lan" else 5,
                "loss_percent": 0 if profile_class == "lan" else 1,
                "bandwidth_mbps": 1000 if profile_class == "lan" else 50,
            },
            "display": {"resolution": "1920x1080", "refresh_hz": 120},
            "codec": {"name": "h264", "fps": 60, "bitrate_cap_mbps": 20},
            "workload": {"id": "typing-v1", "trace_sha256": "c" * 64},
            "rig": {
                "method": "photodiode_oscilloscope",
                "sensor_model": "test-rig",
                "clock_domain": "single_oscilloscope",
                "sample_rate_hz": 100_000,
                "calibration_sha256": "d" * 64,
                "calibration_path": "test://calibration",
                "device_path": "test://photodiode",
                "device_fingerprint_sha256": "4" * 64,
            },
        },
        "guardrails": {
            "quality": {
                "vmaf": 95.0,
                "ssim": 0.99,
                "raw_sha256": "f" * 64,
                "raw_path": "test://quality",
            },
            "bandwidth": {
                "measured_mbps": 10.0,
                "pcap_sha256": "1" * 64,
                "pcap_path": "test://pcap",
            },
            "reliability": {
                "completion_rate": 1.0,
                "disconnects": 0,
                "log_sha256": "2" * 64,
                "log_path": "test://reliability",
            },
        },
        "anydesk_settings": (
            {
                "quality_preset": 2,
                "viewmode": 0,
                "direct_enabled": True,
                "direct_indicator_verified": True,
                "settings_snapshot_sha256": "3" * 64,
                "settings_snapshot_path": "test://anydesk-settings",
            }
            if product == "AnyDesk"
            else None
        ),
        "randomization_seed": 42,
        "blocks": blocks,
    }
    manifest["preregistration_sha256"] = GATE.preregistration_hash(manifest)
    manifest["preregistration_path"] = "test://preregistration"
    manifest["preregistration_signature_path"] = "test://preregistration.sig"
    manifest["results_sha256"] = GATE.results_commitment_hash(manifest)
    manifest["results_manifest_path"] = "test://results"
    manifest["results_signature_path"] = "test://results.sig"
    return manifest


def inventory() -> dict:
    return {
        "physical_sensor_present": True,
        "sensor_paths": ["test://photodiode"],
        "sensor_fingerprints": {"test://photodiode": "4" * 64},
        "sensor_kinds": {"test://photodiode": "serial_optical_rig"},
        "anydesk_binary": "test://anydesk",
        "anydesk_sha256": "a" * 64,
        "anydesk_version": "1.0-test",
        "latencydesk_binary": "test://latencydesk",
        "latencydesk_sha256": "b" * 64,
        "latencydesk_version": "1.0-test",
    }


def rehash(block: dict) -> None:
    block["raw_sha256"] = raw_hash(
        block["block_id"], block["order"], block["warmup"], block["samples"]
    )


def recommit_results(manifest: dict) -> None:
    manifest["results_sha256"] = GATE.results_commitment_hash(manifest)


def mark_missed(event: dict) -> dict:
    return {
        "event_id": event["event_id"],
        "missed": True,
        "trigger_tick": event["trigger_tick"],
        "deadline_tick": event["trigger_tick"] + event["clock_hz"] * 2,
        "clock_hz": event["clock_hz"],
    }


def set_latency(event: dict, latency_ms: float) -> None:
    event["latency_ms"] = latency_ms
    event["photon_tick"] = event["trigger_tick"] + round(
        latency_ms * event["clock_hz"] / 1000
    )


class OpticalCrossoverGateTests(unittest.TestCase):
    def pairs(self):
        return [
            (report("AnyDesk", "lan", 100), report("LatencyDesk", "lan", 60)),
            (report("AnyDesk", "wan", 140), report("LatencyDesk", "wan", 80)),
        ]

    def evaluate(self, pairs=None, inv=None):
        return GATE.evaluate_pairs(
            pairs or self.pairs(),
            inventory_override=inv or inventory(),
            bootstrap_repetitions=128,
            allow_test_inventory=True,
        )

    def test_valid_paired_crossover_passes_all_guardrails(self):
        result = self.evaluate()
        self.assertTrue(result["passed"], result["errors"])
        self.assertEqual(
            {profile["class"] for profile in result["profiles"]}, {"lan", "wan"}
        )
        self.assertTrue(
            all(
                profile["analyzed_per_product"] == 1000
                for profile in result["profiles"]
            )
        )

    def test_production_inventory_cannot_be_faked_or_missing(self):
        result = GATE.evaluate_pairs(self.pairs(), bootstrap_repetitions=16)
        self.assertFalse(result["passed"])
        self.assertTrue(
            any("physical" in error or "AnyDesk" in error for error in result["errors"])
        )
        self.assertTrue(any("fixed at 2000" in error for error in result["errors"]))
        self.assertTrue(
            any("notary key is not committed" in error for error in result["errors"])
        )

    def test_exact_block_and_sample_counts_are_required(self):
        pairs = self.pairs()
        pairs[0][1]["blocks"].pop()
        result = self.evaluate(pairs)
        self.assertFalse(result["passed"])
        self.assertTrue(any("exactly 10" in error for error in result["errors"]))
        pairs = self.pairs()
        pairs[0][1]["blocks"][0]["samples"].pop()
        result = self.evaluate(pairs)
        self.assertTrue(any("exactly 100" in error for error in result["errors"]))

    def test_missed_samples_are_censored_and_cannot_be_dropped(self):
        pairs = self.pairs()
        for _, candidate in pairs:
            for block in candidate["blocks"]:
                block["samples"][0] = mark_missed(block["samples"][0])
                rehash(block)
        result = self.evaluate(pairs)
        self.assertFalse(result["passed"])
        self.assertTrue(any("miss rate" in error for error in result["errors"]))
        pairs[0][1]["blocks"][0]["samples"][0] = None
        rehash(pairs[0][1]["blocks"][0])
        result = self.evaluate(pairs)
        self.assertTrue(any("invalid event" in error for error in result["errors"]))
        pairs = self.pairs()
        for _, candidate in pairs:
            for block in candidate["blocks"]:
                block["warmup"][0] = mark_missed(block["warmup"][0])
                rehash(block)
        result = self.evaluate(pairs)
        self.assertTrue(any("miss rate" in error for error in result["errors"]))

    def test_route_network_display_codec_and_workload_must_match(self):
        for path, value in [
            (("profile", "route_class"), "relay"),
            (("profile", "network", "rtt_ms"), 999),
            (("profile", "display", "refresh_hz"), 60),
            (("profile", "codec", "fps"), 30),
            (("profile", "workload", "id"), "other"),
        ]:
            pairs = self.pairs()
            cursor = pairs[0][1]
            for key in path[:-1]:
                cursor = cursor[key]
            cursor[path[-1]] = value
            result = self.evaluate(pairs)
            self.assertFalse(result["passed"], path)
            self.assertTrue(
                any("mismatch" in error for error in result["errors"]), path
            )

    def test_quality_bandwidth_and_reliability_gaming_fail(self):
        mutations = [
            ("quality", "vmaf", 80.0),
            ("quality", "ssim", 0.8),
            ("bandwidth", "measured_mbps", 12.0),
            ("reliability", "completion_rate", 0.9),
            ("reliability", "disconnects", 1),
        ]
        for group, field, value in mutations:
            pairs = self.pairs()
            pairs[0][1]["guardrails"][group][field] = value
            result = self.evaluate(pairs)
            self.assertFalse(result["passed"], (group, field))
            self.assertTrue(
                any(group in error for error in result["errors"]), (group, field)
            )
        pairs = self.pairs()
        for baseline, candidate in pairs:
            for manifest in (baseline, candidate):
                manifest["guardrails"]["quality"].update(vmaf=0.0, ssim=0.0)
                manifest["guardrails"]["reliability"]["completion_rate"] = 0.0
        result = self.evaluate(pairs)
        self.assertTrue(any("quality" in error for error in result["errors"]))
        self.assertTrue(any("reliability" in error for error in result["errors"]))

    def test_p95_margin_and_confidence_interval_must_both_clear_twenty_percent(self):
        pairs = [
            (report("AnyDesk", "lan", 100), report("LatencyDesk", "lan", 85)),
            (report("AnyDesk", "wan", 140), report("LatencyDesk", "wan", 125)),
        ]
        result = self.evaluate(pairs)
        self.assertFalse(result["passed"])
        self.assertTrue(any("20.0%" in error for error in result["errors"]))

    def test_p99_may_not_regress_even_when_p95_wins(self):
        pairs = self.pairs()
        for _, candidate in pairs:
            for block in candidate["blocks"]:
                for event in block["samples"][-2:]:
                    set_latency(event, 500.0)
                rehash(block)
        result = self.evaluate(pairs)
        self.assertFalse(result["passed"])
        self.assertTrue(any("p99" in error for error in result["errors"]))

    def test_raw_trace_hash_tamper_is_rejected(self):
        pairs = self.pairs()
        pairs[0][1]["blocks"][0]["samples"][0] = 1.0
        result = self.evaluate(pairs)
        self.assertFalse(result["passed"])
        self.assertTrue(any("raw_sha256" in error for error in result["errors"]))

    def test_degenerate_identical_blocks_are_not_physical_superiority_evidence(self):
        pairs = self.pairs()
        for baseline, candidate in pairs:
            for manifest in (baseline, candidate):
                source = manifest["blocks"][0]
                for block in manifest["blocks"]:
                    for event, source_event in zip(block["warmup"], source["warmup"]):
                        set_latency(event, source_event["latency_ms"])
                    for event, source_event in zip(block["samples"], source["samples"]):
                        set_latency(event, source_event["latency_ms"])
                    rehash(block)
        result = self.evaluate(pairs)
        self.assertFalse(result["passed"])
        self.assertTrue(any("variability" in error for error in result["errors"]))

    def test_raw_traces_cannot_be_relabelled_and_reused_across_lan_wan(self):
        pairs = self.pairs()
        pairs[1][0]["blocks"] = json.loads(json.dumps(pairs[0][0]["blocks"]))
        pairs[1][1]["blocks"] = json.loads(json.dumps(pairs[0][1]["blocks"]))
        result = self.evaluate(pairs)
        self.assertFalse(result["passed"])
        self.assertTrue(
            any("reused across profiles" in error for error in result["errors"])
        )
        pairs = self.pairs()
        for product_index in (0, 1):
            pairs[1][product_index]["blocks"] = json.loads(
                json.dumps(pairs[0][product_index]["blocks"])
            )
            for block in pairs[1][product_index]["blocks"]:
                for event_index, event in enumerate(block["warmup"] + block["samples"]):
                    event["trigger_tick"] += 9_000_000_000
                    if "photon_tick" in event:
                        event["photon_tick"] += 9_000_000_000 + event_index % 3 + 1
                        event["latency_ms"] = (
                            (event["photon_tick"] - event["trigger_tick"])
                            * 1000.0
                            / event["clock_hz"]
                        )
                    if "deadline_tick" in event:
                        event["deadline_tick"] += 9_000_000_000
                rehash(block)
            recommit_results(pairs[1][product_index])
        result = self.evaluate(pairs)
        self.assertTrue(
            any("normalized event traces" in error for error in result["errors"])
        )

    def test_schedule_requires_matching_balanced_ab_ba_blocks(self):
        pairs = self.pairs()
        current = pairs[0][1]["blocks"][0]["order"]
        pairs[0][1]["blocks"][0]["order"] = "AB" if current == "BA" else "BA"
        result = self.evaluate(pairs)
        self.assertTrue(any("schedule" in error for error in result["errors"]))
        pairs = self.pairs()
        for baseline, candidate in pairs:
            for block in baseline["blocks"] + candidate["blocks"]:
                block["order"] = "AB"
        result = self.evaluate(pairs)
        self.assertTrue(any("balanced" in error for error in result["errors"]))

    def test_posthoc_schedule_rewrite_breaks_preregistration_commitment(self):
        pairs = self.pairs()
        for manifest in pairs[0]:
            block = manifest["blocks"][0]
            block["order"] = "AB" if block["order"] == "BA" else "BA"
            rehash(block)
        result = self.evaluate(pairs)
        self.assertFalse(result["passed"])
        self.assertTrue(
            any("preregistration_sha256" in error for error in result["errors"])
        )

    def test_block_ids_warmup_rig_and_guardrail_ranges_are_strict(self):
        pairs = self.pairs()
        pairs[0][1]["blocks"][0]["block_id"] = 99
        pairs[0][1]["blocks"][0]["warmup"][0] = None
        rehash(pairs[0][1]["blocks"][0])
        pairs[0][1]["profile"]["rig"]["calibration_sha256"] = "bad"
        pairs[0][1]["profile"]["rig"]["sample_rate_hz"] = 1000
        result = self.evaluate(pairs)
        self.assertFalse(result["passed"])
        for phrase in (
            "block_id",
            "invalid event_id",
            "calibration",
            "100000",
        ):
            self.assertTrue(any(phrase in error for error in result["errors"]), phrase)

    def test_anydesk_binary_hash_must_match_inventory(self):
        bad_inventory = inventory()
        bad_inventory["anydesk_sha256"] = "f" * 64
        result = self.evaluate(inv=bad_inventory)
        self.assertFalse(result["passed"])
        self.assertTrue(any("binary SHA-256" in error for error in result["errors"]))
        bad_inventory = inventory()
        bad_inventory["latencydesk_sha256"] = "f" * 64
        bad_inventory["sensor_fingerprints"] = {"test://photodiode": "9" * 64}
        result = self.evaluate(inv=bad_inventory)
        self.assertTrue(
            any("LatencyDesk binary SHA-256" in error for error in result["errors"])
        )
        self.assertTrue(
            any("not bound to local sensor" in error for error in result["errors"])
        )

    def test_reported_latency_must_match_single_clock_ticks(self):
        pairs = self.pairs()
        event = pairs[0][1]["blocks"][0]["samples"][0]
        event["latency_ms"] += 10
        rehash(pairs[0][1]["blocks"][0])
        result = self.evaluate(pairs)
        self.assertFalse(result["passed"])
        self.assertTrue(
            any("physical clock ticks" in error for error in result["errors"])
        )

    def test_cli_has_no_synthetic_bypass(self):
        with tempfile.TemporaryDirectory() as temporary:
            arguments = []
            for index, (baseline, candidate) in enumerate(self.pairs()):
                baseline_path = Path(temporary) / f"baseline-{index}.json"
                candidate_path = Path(temporary) / f"candidate-{index}.json"
                baseline_path.write_text(json.dumps(baseline), encoding="utf-8")
                candidate_path.write_text(json.dumps(candidate), encoding="utf-8")
                arguments.extend(["--pair", str(baseline_path), str(candidate_path)])
            with contextlib.redirect_stdout(io.StringIO()):
                result = GATE.main(arguments)
            self.assertEqual(result, 2)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            GATE.main(["--bootstrap-repetitions", "16"])

    def test_production_candidate_must_be_native_binary(self):
        with tempfile.TemporaryDirectory() as temporary:
            script = Path(temporary) / "candidate"
            script.write_text("#!/bin/sh\necho LatencyDesk 1.0\n", encoding="utf-8")
            script.chmod(0o755)
            result = GATE.probe_inventory(script)
            self.assertIsNone(result["latencydesk_binary"])
        if Path("/usr/bin/true").is_file():
            result = GATE.probe_inventory(Path("/usr/bin/true"))
            self.assertIsNone(result["latencydesk_binary"])

    @unittest.skipUnless(Path("/usr/bin/openssl").is_file(), "openssl unavailable")
    def test_notary_uses_fixed_openssl_and_verifies_both_documents(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            private = root / "private.pem"
            public = root / "public.pem"
            prereg = root / "prereg.json"
            results = root / "results.json"
            prereg_sig = root / "prereg.sig"
            results_sig = root / "results.sig"
            subprocess.run(
                ["/usr/bin/openssl", "genrsa", "-out", str(private), "2048"],
                check=True,
                capture_output=True,
            )
            subprocess.run(
                [
                    "/usr/bin/openssl",
                    "rsa",
                    "-in",
                    str(private),
                    "-pubout",
                    "-out",
                    str(public),
                ],
                check=True,
                capture_output=True,
            )
            prereg.write_text("prereg", encoding="utf-8")
            results.write_text("results", encoding="utf-8")
            for document, signature in ((prereg, prereg_sig), (results, results_sig)):
                subprocess.run(
                    [
                        "/usr/bin/openssl",
                        "dgst",
                        "-sha256",
                        "-sign",
                        str(private),
                        "-out",
                        str(signature),
                        str(document),
                    ],
                    check=True,
                    capture_output=True,
                )
            manifest = report("AnyDesk", "lan", 10.0)
            manifest.update(
                {
                    "preregistration_path": str(prereg),
                    "preregistration_signature_path": str(prereg_sig),
                    "results_manifest_path": str(results),
                    "results_signature_path": str(results_sig),
                }
            )
            old_hash = GATE.TRUSTED_NOTARY_KEY_SHA256
            try:
                GATE.TRUSTED_NOTARY_KEY_SHA256 = GATE._file_sha256(public)
                fake = root / "openssl"
                fake.write_text("#!/bin/sh\nexit 99\n", encoding="utf-8")
                fake.chmod(0o755)
                old_path = os.environ.get("PATH", "")
                os.environ["PATH"] = f"{root}:{old_path}"
                try:
                    errors: list[str] = []
                    parsed = GATE._parse_report(manifest, "test", errors)
                    self.assertIsNotNone(parsed)
                    snapshots = {
                        id(parsed): {
                            "preregistration": prereg.read_bytes(),
                            "results": results.read_bytes(),
                        }
                    }
                    self.assertEqual(
                        GATE._notary_errors([parsed], public, snapshots), []
                    )
                finally:
                    os.environ["PATH"] = old_path
                prereg.write_text("swapped-after-hash", encoding="utf-8")
                subprocess.run(
                    [
                        "/usr/bin/openssl",
                        "dgst",
                        "-sha256",
                        "-sign",
                        str(private),
                        "-out",
                        str(prereg_sig),
                        str(prereg),
                    ],
                    check=True,
                    capture_output=True,
                )
                self.assertTrue(GATE._notary_errors([parsed], public, snapshots))
                prereg.write_bytes(snapshots[id(parsed)]["preregistration"])
                subprocess.run(
                    [
                        "/usr/bin/openssl",
                        "dgst",
                        "-sha256",
                        "-sign",
                        str(private),
                        "-out",
                        str(prereg_sig),
                        str(prereg),
                    ],
                    check=True,
                    capture_output=True,
                )
                results_sig.write_bytes(b"bad")
                self.assertTrue(GATE._notary_errors([parsed], public, snapshots))
            finally:
                GATE.TRUSTED_NOTARY_KEY_SHA256 = old_hash


if __name__ == "__main__":
    unittest.main()
