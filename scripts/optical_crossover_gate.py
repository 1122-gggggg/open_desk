#!/usr/bin/env python3
"""Fail-closed physical input-to-photon crossover gate against AnyDesk."""

from __future__ import annotations

import argparse
import glob
import hashlib
import json
import math
import os
import random
import re
import shutil
import subprocess
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

SCHEMA_VERSION = 2
BLOCK_COUNT = 10
WARMUP_PER_BLOCK = 20
ANALYZED_PER_BLOCK = 100
CENSOR_MS = 2000.0
BOOTSTRAP_SEED = 42
BOOTSTRAP_REPETITIONS = 2000
MIN_P95_IMPROVEMENT_PERCENT = 20.0
MAX_FILE_BYTES = 25_000_000
MAX_BANDWIDTH_REGRESSION_RATIO = 1.0
# A trusted notary key must be registered in a repository commit before the
# physical run. None deliberately keeps production claims blocked today.
TRUSTED_NOTARY_KEY_SHA256: str | None = None


@dataclass(frozen=True)
class ParsedReport:
    raw: dict[str, Any]
    product_name: str
    product_binary_sha256: str
    profile_class: str
    blocks: tuple[tuple[float, ...], ...]
    misses: int
    warmup_misses: int
    raw_hashes: tuple[str, ...]
    semantic_hashes: tuple[str, ...]


def expected_schedule(seed: int) -> list[str]:
    schedule = ["AB"] * (BLOCK_COUNT // 2) + ["BA"] * (BLOCK_COUNT // 2)
    random.Random(seed).shuffle(schedule)
    return schedule


def canonical_raw_hash(
    block_id: int, order: str, warmup: list[Any], samples: list[Any]
) -> str:
    encoded = json.dumps(
        {"block_id": block_id, "order": order, "warmup": warmup, "samples": samples},
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def preregistration_hash(report: dict[str, Any]) -> str:
    blocks = report.get("blocks") if isinstance(report.get("blocks"), list) else []
    commitment = {
        "schema_version": report.get("schema_version"),
        "product": report.get("product"),
        "profile": report.get("profile"),
        "anydesk_settings": report.get("anydesk_settings"),
        "randomization_seed": report.get("randomization_seed"),
        "schedule": [
            {"block_id": block.get("block_id"), "order": block.get("order")}
            for block in blocks
            if isinstance(block, dict)
        ],
        "protocol": {
            "blocks": BLOCK_COUNT,
            "warmup_per_block": WARMUP_PER_BLOCK,
            "analyzed_per_block": ANALYZED_PER_BLOCK,
            "censor_ms": CENSOR_MS,
            "bootstrap_seed": BOOTSTRAP_SEED,
            "bootstrap_repetitions": BOOTSTRAP_REPETITIONS,
            "minimum_p95_improvement_percent": MIN_P95_IMPROVEMENT_PERCENT,
        },
    }
    encoded = json.dumps(
        commitment,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def results_commitment_hash(report: dict[str, Any]) -> str:
    committed = {
        key: value
        for key, value in report.items()
        if key
        not in {
            "results_sha256",
            "results_manifest_path",
            "results_signature_path",
        }
    }
    encoded = json.dumps(
        committed,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def _read_bounded_snapshot(path: Path, *, max_bytes: int = MAX_FILE_BYTES) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size > max_bytes:
            raise OSError("not a bounded regular file")
        content = bytearray()
        while len(content) < before.st_size:
            chunk = os.read(descriptor, min(1024 * 1024, before.st_size - len(content)))
            if not chunk:
                raise OSError("short read")
            content.extend(chunk)
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ):
            raise OSError("file changed during snapshot")
        return bytes(content)
    finally:
        os.close(descriptor)


def _file_sha256(path: Path, *, max_bytes: int = MAX_FILE_BYTES) -> str:
    return hashlib.sha256(_read_bounded_snapshot(path, max_bytes=max_bytes)).hexdigest()


def _trusted_system_binary(path: Path) -> bool:
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError:
        return False
    if not resolved.is_file() or metadata.st_mode & 0o022:
        return False
    trusted_roots = (
        (Path(r"C:\Program Files"), Path(r"C:\Program Files (x86)"))
        if os.name == "nt"
        else (Path("/usr/bin"), Path("/opt/anydesk"))
    )
    root = next(
        (
            candidate
            for candidate in trusted_roots
            if resolved == candidate or resolved.is_relative_to(candidate)
        ),
        None,
    )
    if root is None:
        return False
    if os.name != "nt":
        for component in (resolved, *resolved.parents):
            component_metadata = component.stat()
            if component_metadata.st_uid != 0 or component_metadata.st_mode & 0o022:
                return False
            if component == root:
                break
    return True


def probe_inventory(candidate_binary: Path | None = None) -> dict[str, Any]:
    candidates = [
        "/usr/bin/anydesk",
        "/opt/anydesk/anydesk",
        os.path.join(os.environ.get("ProgramFiles", ""), "AnyDesk", "AnyDesk.exe"),
        os.path.join(os.environ.get("ProgramFiles(x86)", ""), "AnyDesk", "AnyDesk.exe"),
        shutil.which("anydesk"),
    ]
    anydesk = next(
        (
            Path(candidate).resolve()
            for candidate in candidates
            if candidate and _trusted_system_binary(Path(candidate))
        ),
        None,
    )
    video_paths = sorted(glob.glob("/dev/video*"))
    serial_candidates = sorted({*glob.glob("/dev/ttyACM*"), *glob.glob("/dev/ttyUSB*")})
    serial_paths: list[str] = []
    for serial_path in serial_candidates:
        try:
            metadata = os.lstat(serial_path)
            if not stat.S_ISCHR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                continue
            descriptor = os.open(
                serial_path,
                os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0),
            )
            os.close(descriptor)
            serial_paths.append(serial_path)
        except OSError:
            continue
    high_speed_video: list[str] = []
    v4l2_path = Path("/usr/bin/v4l2-ctl")
    v4l2 = str(v4l2_path) if _trusted_system_binary(v4l2_path) else None
    if v4l2:
        for video_path in video_paths:
            try:
                completed = subprocess.run(
                    [v4l2, "--device", video_path, "--list-formats-ext"],
                    text=True,
                    capture_output=True,
                    timeout=3,
                    check=False,
                )
                rates = [
                    float(value)
                    for value in re.findall(r"\(([0-9.]+) fps\)", completed.stdout)
                ]
                if completed.returncode == 0 and rates and max(rates) >= 1000:
                    high_speed_video.append(video_path)
            except (OSError, subprocess.TimeoutExpired, ValueError):
                continue
    sensor_paths = sorted({*serial_paths, *high_speed_video})
    sensor_kinds = {
        **{path: "serial_unverified" for path in serial_paths},
        **{path: "high_speed_camera" for path in high_speed_video},
    }
    sensor_fingerprints = {}
    for sensor_path in sensor_paths:
        metadata = os.stat(sensor_path)
        identity = f"{Path(sensor_path).resolve()}:{metadata.st_rdev}:{metadata.st_ino}".encode()
        sensor_fingerprints[sensor_path] = hashlib.sha256(identity).hexdigest()
    anydesk_version = None
    if anydesk:
        try:
            completed = subprocess.run(
                [str(anydesk), "--version"],
                text=True,
                capture_output=True,
                timeout=3,
                check=False,
            )
            version = completed.stdout.strip()
            if completed.returncode == 0 and 0 < len(version) <= 128:
                anydesk_version = version
        except (OSError, subprocess.TimeoutExpired):
            pass
    latencydesk_binary = None
    latencydesk_sha256 = None
    latencydesk_version = None
    if candidate_binary and candidate_binary.is_file():
        try:
            resolved_candidate = candidate_binary.resolve(strict=True)
            metadata = resolved_candidate.stat()
            with resolved_candidate.open("rb") as candidate_stream:
                magic = candidate_stream.read(4)
            is_native_binary = magic == b"\x7fELF" or magic[:2] == b"MZ"
            if (
                is_native_binary
                and os.access(resolved_candidate, os.X_OK)
                and not metadata.st_mode & 0o002
            ):
                completed = subprocess.run(
                    [str(resolved_candidate), "--version"],
                    text=True,
                    capture_output=True,
                    timeout=3,
                    check=False,
                )
                version = completed.stdout.strip()
                if completed.returncode == 0 and re.fullmatch(
                    r"latencydesk-client [0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?",
                    version,
                ):
                    latencydesk_binary = str(resolved_candidate)
                    latencydesk_sha256 = _file_sha256(resolved_candidate)
                    latencydesk_version = version
        except (OSError, subprocess.TimeoutExpired):
            pass
    return {
        "physical_sensor_present": bool(sensor_paths),
        "sensor_paths": sensor_paths,
        "sensor_fingerprints": sensor_fingerprints,
        "sensor_kinds": sensor_kinds,
        "detected_video_paths": video_paths,
        "high_speed_video_paths": high_speed_video,
        "serial_instrument_paths": serial_paths,
        "anydesk_binary": str(anydesk) if anydesk else None,
        "anydesk_sha256": _file_sha256(anydesk, max_bytes=256 * 1024 * 1024)
        if anydesk
        else None,
        "anydesk_version": anydesk_version,
        "latencydesk_binary": latencydesk_binary,
        "latencydesk_sha256": latencydesk_sha256,
        "latencydesk_version": latencydesk_version,
    }


def _finite(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def _sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * percentile / 100.0
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] * (upper - position) + ordered[upper] * (position - lower)


def _event_value(
    value: Any,
    label: str,
    expected_event_id: str,
    expected_clock_hz: int,
    errors: list[str],
) -> tuple[float | None, bool, int | None]:
    if not isinstance(value, dict) or value.get("event_id") != expected_event_id:
        errors.append(f"{label}: invalid event_id or event object")
        return None, False, None
    trigger = value.get("trigger_tick")
    clock_hz = value.get("clock_hz")
    if (
        isinstance(trigger, bool)
        or not isinstance(trigger, int)
        or trigger < 0
        or clock_hz != expected_clock_hz
    ):
        errors.append(f"{label}: invalid physical clock ticks")
        return None, False, None
    missed = value.get("missed", False)
    if missed is True and set(value).issubset(
        {"event_id", "missed", "reason", "trigger_tick", "deadline_tick", "clock_hz"}
    ):
        deadline = value.get("deadline_tick")
        if (
            isinstance(deadline, bool)
            or not isinstance(deadline, int)
            or deadline - trigger != expected_clock_hz * 2
        ):
            errors.append(f"{label}: missed event deadline is not the 2000 ms censor")
            return None, False, trigger
        return CENSOR_MS, True, trigger
    latency = value.get("latency_ms")
    photon = value.get("photon_tick")
    if (
        set(value)
        != {"event_id", "latency_ms", "trigger_tick", "photon_tick", "clock_hz"}
        or missed is not False
        or not _finite(latency)
        or isinstance(photon, bool)
        or not isinstance(photon, int)
        or photon <= trigger
        or not 0 < float(latency) < CENSOR_MS
    ):
        errors.append(
            f"{label}: invalid analyzed sample; latency must be in (0, {CENSOR_MS})"
        )
        return None, False, trigger
    measured = (photon - trigger) * 1000.0 / expected_clock_hz
    if abs(measured - float(latency)) > 0.011:
        errors.append(f"{label}: latency does not match physical clock ticks")
        return None, False, trigger
    return float(latency), False, trigger


def _parse_report(raw: Any, label: str, errors: list[str]) -> ParsedReport | None:
    if not isinstance(raw, dict) or raw.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"{label}: schema_version must be {SCHEMA_VERSION}")
        return None
    try:
        expected_preregistration = preregistration_hash(raw)
    except (TypeError, ValueError):
        expected_preregistration = ""
    if raw.get("preregistration_sha256") != expected_preregistration:
        errors.append(f"{label}: preregistration_sha256 mismatch")
    if not isinstance(raw.get("preregistration_path"), str):
        errors.append(f"{label}: preregistration_path is required")
    if not isinstance(raw.get("preregistration_signature_path"), str):
        errors.append(f"{label}: preregistration_signature_path is required")
    try:
        expected_results = results_commitment_hash(raw)
    except (TypeError, ValueError):
        expected_results = ""
    if raw.get("results_sha256") != expected_results:
        errors.append(f"{label}: results_sha256 mismatch")
    if not isinstance(raw.get("results_manifest_path"), str) or not isinstance(
        raw.get("results_signature_path"), str
    ):
        errors.append(f"{label}: signed results manifest paths are required")
    product = raw.get("product")
    profile = raw.get("profile")
    guardrails = raw.get("guardrails")
    if (
        not isinstance(product, dict)
        or not isinstance(profile, dict)
        or not isinstance(guardrails, dict)
    ):
        errors.append(f"{label}: product/profile/guardrails objects are required")
        return None
    for field in ("name", "version", "build", "binary_sha256"):
        if not isinstance(product.get(field), str) or not product[field]:
            errors.append(f"{label}: product.{field} is required")
    binary_hash = product.get("binary_sha256", "")
    if not _sha256(binary_hash):
        errors.append(f"{label}: product.binary_sha256 must be lowercase SHA-256")
    profile_class = profile.get("class")
    if profile_class not in {"lan", "wan"}:
        errors.append(f"{label}: profile.class must be lan or wan")
    required_profile = (
        "id",
        "route_class",
        "hardware",
        "network",
        "display",
        "codec",
        "workload",
        "rig",
    )
    for field in required_profile:
        if field not in profile or profile[field] in ({}, "", None):
            errors.append(f"{label}: profile.{field} is required")
    if profile.get("route_class") not in {"direct", "relay"}:
        errors.append(f"{label}: profile.route_class must be direct or relay")
    if not _sha256(profile.get("route_evidence_sha256")):
        errors.append(f"{label}: profile.route_evidence_sha256 is required")
    if not isinstance(profile.get("route_evidence_path"), str):
        errors.append(f"{label}: profile.route_evidence_path is required")
    network = profile.get("network", {})
    if isinstance(network, dict) and _finite(network.get("rtt_ms")):
        if profile_class == "lan" and network["rtt_ms"] > 5:
            errors.append(f"{label}: LAN RTT must be <= 5 ms")
        if profile_class == "wan" and network["rtt_ms"] < 20:
            errors.append(f"{label}: WAN RTT must be >= 20 ms")
    else:
        errors.append(f"{label}: profile.network.rtt_ms is required")
    rig = profile.get("rig", {})
    if not isinstance(rig, dict) or rig.get("clock_domain") not in {
        "single_oscilloscope",
        "single_logic_analyzer",
        "high_speed_camera_frames",
        "unified_single_clock",
    }:
        errors.append(f"{label}: rig must use one physical clock domain")
    method = rig.get("method")
    minimum_sample_rate = 1000 if method == "high_speed_camera" else 100_000
    if (
        isinstance(rig.get("sample_rate_hz"), bool)
        or not isinstance(rig.get("sample_rate_hz"), int)
        or rig.get("sample_rate_hz", 0) < minimum_sample_rate
    ):
        errors.append(f"{label}: rig sample_rate_hz must be >= {minimum_sample_rate}")
    rig_clock_hz = (
        rig["sample_rate_hz"]
        if isinstance(rig.get("sample_rate_hz"), int)
        and not isinstance(rig.get("sample_rate_hz"), bool)
        else 0
    )
    if method not in {
        "photodiode_oscilloscope",
        "microcontroller_optical_rig",
        "high_speed_camera",
    } or not isinstance(rig.get("sensor_model"), str):
        errors.append(f"{label}: physical rig method and sensor_model are required")
    if not isinstance(rig.get("device_path"), str) or not _sha256(
        rig.get("device_fingerprint_sha256")
    ):
        errors.append(f"{label}: rig device path/fingerprint are required")
    calibration = rig.get("calibration_sha256")
    if not _sha256(calibration):
        errors.append(f"{label}: rig calibration_sha256 is invalid")
    if not isinstance(rig.get("calibration_path"), str):
        errors.append(f"{label}: rig calibration_path is required")
    if product.get("name", "").casefold() == "anydesk":
        settings = raw.get("anydesk_settings")
        direct = profile.get("route_class") == "direct"
        if (
            not isinstance(settings, dict)
            or settings.get("quality_preset") != 2
            or settings.get("viewmode") != 0
            or settings.get("direct_enabled") is not direct
            or (direct and settings.get("direct_indicator_verified") is not True)
            or not _sha256(settings.get("settings_snapshot_sha256"))
            or not isinstance(settings.get("settings_snapshot_path"), str)
        ):
            errors.append(
                f"{label}: required AnyDesk advanced settings/route evidence are missing"
            )
    seed = raw.get("randomization_seed")
    if isinstance(seed, bool) or not isinstance(seed, int):
        errors.append(f"{label}: randomization_seed must be an integer")
        seed = 0
    blocks = raw.get("blocks")
    if not isinstance(blocks, list) or len(blocks) != BLOCK_COUNT:
        errors.append(f"{label}: exactly 10 crossover blocks are required")
        return None
    schedule = expected_schedule(seed)
    parsed_blocks: list[tuple[float, ...]] = []
    raw_hashes: list[str] = []
    semantic_hashes: list[str] = []
    misses = 0
    warmup_misses = 0
    last_trigger_tick = -1
    seen_ids: set[int] = set()
    for index, block in enumerate(blocks):
        block_label = f"{label}.blocks[{index}]"
        if not isinstance(block, dict):
            errors.append(f"{block_label}: block must be an object")
            continue
        block_id = block.get("block_id")
        if (
            isinstance(block_id, bool)
            or not isinstance(block_id, int)
            or block_id in seen_ids
        ):
            errors.append(f"{block_label}: unique integer block_id is required")
        else:
            seen_ids.add(block_id)
        if block.get("order") != schedule[index]:
            errors.append(f"{block_label}: order does not match randomized schedule")
        warmup = block.get("warmup")
        samples = block.get("samples")
        if not isinstance(warmup, list) or len(warmup) != WARMUP_PER_BLOCK:
            errors.append(f"{block_label}: exactly 20 warmup samples are required")
            warmup = []
        if not isinstance(samples, list) or len(samples) != ANALYZED_PER_BLOCK:
            errors.append(f"{block_label}: exactly 100 analyzed samples are required")
            samples = []
        try:
            computed_hash = canonical_raw_hash(
                block_id, block.get("order"), warmup, samples
            )
        except (TypeError, ValueError):
            computed_hash = ""
        if block.get("raw_sha256") != computed_hash:
            errors.append(f"{block_label}: raw_sha256 mismatch")
        if not isinstance(block.get("raw_path"), str):
            errors.append(f"{block_label}: raw_path is required")
        raw_hashes.append(computed_hash)
        for warmup_index, event in enumerate(warmup):
            _, warmup_missed, trigger_tick = _event_value(
                event,
                f"{block_label}.warmup[{warmup_index}]",
                f"{block_id}:warmup:{warmup_index}",
                rig_clock_hz,
                errors,
            )
            if trigger_tick is not None and trigger_tick <= last_trigger_tick:
                errors.append(
                    f"{block_label}: acquisition trigger ticks are not monotonic"
                )
            elif trigger_tick is not None:
                last_trigger_tick = trigger_tick
            warmup_misses += int(warmup_missed)
        values: list[float] = []
        for sample_index, sample in enumerate(samples):
            value, missed, trigger_tick = _event_value(
                sample,
                f"{block_label}.samples[{sample_index}]",
                f"{block_id}:analyzed:{sample_index}",
                rig_clock_hz,
                errors,
            )
            if trigger_tick is not None and trigger_tick <= last_trigger_tick:
                errors.append(
                    f"{block_label}: acquisition trigger ticks are not monotonic"
                )
            elif trigger_tick is not None:
                last_trigger_tick = trigger_tick
            if value is not None:
                values.append(value)
            misses += int(missed)
        if len(values) == ANALYZED_PER_BLOCK:
            parsed_blocks.append(tuple(values))
            semantic_hashes.append(
                hashlib.sha256(
                    json.dumps(
                        {
                            "order": block.get("order"),
                            # One-to-three 100 kHz ticks are quantization noise,
                            # not an independent capture. Coarse canonicalization
                            # prevents that trivial cross-profile relabelling.
                            "latency_0_1ms": [round(value, 1) for value in values],
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                        allow_nan=False,
                    ).encode()
                ).hexdigest()
            )
    if seen_ids != set(range(1, BLOCK_COUNT + 1)):
        errors.append(f"{label}: block_id values must be exactly 1..10")
    if len(parsed_blocks) != BLOCK_COUNT:
        return None
    return ParsedReport(
        raw=raw,
        product_name=product.get("name", ""),
        product_binary_sha256=binary_hash,
        profile_class=str(profile_class),
        blocks=tuple(parsed_blocks),
        misses=misses,
        warmup_misses=warmup_misses,
        raw_hashes=tuple(raw_hashes),
        semantic_hashes=tuple(semantic_hashes),
    )


def _paired_bootstrap(
    baseline: ParsedReport,
    candidate: ParsedReport,
    repetitions: int,
) -> tuple[tuple[float, float], tuple[float, float]]:
    rng = random.Random(BOOTSTRAP_SEED)
    differences: list[float] = []
    improvements: list[float] = []
    for _ in range(repetitions):
        indices = [rng.randrange(BLOCK_COUNT) for _ in range(BLOCK_COUNT)]
        baseline_values = [
            value for index in indices for value in baseline.blocks[index]
        ]
        candidate_values = [
            value for index in indices for value in candidate.blocks[index]
        ]
        baseline_p95 = _percentile(baseline_values, 95)
        candidate_p95 = _percentile(candidate_values, 95)
        differences.append(baseline_p95 - candidate_p95)
        improvements.append((baseline_p95 - candidate_p95) / baseline_p95 * 100.0)
    differences.sort()
    improvements.sort()
    lower = max(0, math.floor(repetitions * 0.025))
    upper = min(repetitions - 1, math.ceil(repetitions * 0.975) - 1)
    return (differences[lower], differences[upper]), (
        improvements[lower],
        improvements[upper],
    )


def _comparability_errors(
    baseline: ParsedReport, candidate: ParsedReport, label: str
) -> list[str]:
    errors: list[str] = []
    if baseline.product_name.casefold() != "anydesk":
        errors.append(f"{label}: baseline product must be AnyDesk")
    if candidate.product_name.casefold() != "latencydesk":
        errors.append(f"{label}: candidate product must be LatencyDesk")
    for field in (
        "id",
        "class",
        "route_class",
        "hardware",
        "network",
        "display",
        "codec",
        "workload",
        "rig",
    ):
        if baseline.raw["profile"].get(field) != candidate.raw["profile"].get(field):
            errors.append(f"{label}: profile.{field} mismatch")
    if baseline.raw.get("randomization_seed") != candidate.raw.get(
        "randomization_seed"
    ):
        errors.append(f"{label}: randomization schedule mismatch")
    baseline_orders = [block["order"] for block in baseline.raw["blocks"]]
    candidate_orders = [block["order"] for block in candidate.raw["blocks"]]
    baseline_ids = [block["block_id"] for block in baseline.raw["blocks"]]
    candidate_ids = [block["block_id"] for block in candidate.raw["blocks"]]
    if baseline_ids != candidate_ids:
        errors.append(f"{label}: paired block_id mismatch")
    if baseline_orders != candidate_orders:
        errors.append(f"{label}: randomized schedule mismatch")
    if baseline_orders.count("AB") != 5 or baseline_orders.count("BA") != 5:
        errors.append(f"{label}: randomized schedule must be balanced AB/BA")
    for baseline_block, candidate_block in zip(
        baseline.raw["blocks"], candidate.raw["blocks"]
    ):
        for phase in ("warmup", "samples"):
            baseline_stimulus = [
                (
                    event.get("event_id"),
                    event.get("trigger_tick"),
                    event.get("clock_hz"),
                )
                for event in baseline_block[phase]
                if isinstance(event, dict)
            ]
            candidate_stimulus = [
                (
                    event.get("event_id"),
                    event.get("trigger_tick"),
                    event.get("clock_hz"),
                )
                for event in candidate_block[phase]
                if isinstance(event, dict)
            ]
            if baseline_stimulus != candidate_stimulus:
                errors.append(f"{label}: paired {phase} stimulus schedule mismatch")
    return errors


def _guardrail_errors(
    baseline: ParsedReport, candidate: ParsedReport, label: str
) -> list[str]:
    errors: list[str] = []
    baseline_guard = baseline.raw["guardrails"]
    candidate_guard = candidate.raw["guardrails"]
    for report_label, guardrail in (
        ("baseline", baseline_guard),
        ("candidate", candidate_guard),
    ):
        for group, hash_field, path_field in (
            ("quality", "raw_sha256", "raw_path"),
            ("bandwidth", "pcap_sha256", "pcap_path"),
            ("reliability", "log_sha256", "log_path"),
        ):
            if not _sha256(guardrail.get(group, {}).get(hash_field)):
                errors.append(
                    f"{label}: {report_label} {group}.{hash_field} is required"
                )
            if not isinstance(guardrail.get(group, {}).get(path_field), str):
                errors.append(
                    f"{label}: {report_label} {group}.{path_field} is required"
                )
    for metric in ("vmaf", "ssim"):
        before = baseline_guard.get("quality", {}).get(metric)
        after = candidate_guard.get("quality", {}).get(metric)
        upper = 100.0 if metric == "vmaf" else 1.0
        minimum = 80.0 if metric == "vmaf" else 0.95
        if (
            not _finite(before)
            or not _finite(after)
            or not 0 <= before <= upper
            or not 0 <= after <= upper
            or before < minimum
            or after < minimum
            or after < before
        ):
            errors.append(f"{label}: quality.{metric} regression")
    before_bandwidth = baseline_guard.get("bandwidth", {}).get("measured_mbps")
    after_bandwidth = candidate_guard.get("bandwidth", {}).get("measured_mbps")
    cap = candidate.raw["profile"].get("codec", {}).get("bitrate_cap_mbps")
    if (
        not _finite(before_bandwidth)
        or not _finite(after_bandwidth)
        or not _finite(cap)
        or before_bandwidth <= 0
        or after_bandwidth <= 0
        or cap <= 0
        or after_bandwidth > cap
        or before_bandwidth > cap
        or after_bandwidth > before_bandwidth * MAX_BANDWIDTH_REGRESSION_RATIO
    ):
        errors.append(f"{label}: bandwidth guardrail failed")
    before_reliability = baseline_guard.get("reliability", {})
    after_reliability = candidate_guard.get("reliability", {})
    before_completion = before_reliability.get("completion_rate")
    after_completion = after_reliability.get("completion_rate")
    before_disconnects = before_reliability.get("disconnects")
    after_disconnects = after_reliability.get("disconnects")
    attempts = BLOCK_COUNT * (ANALYZED_PER_BLOCK + WARMUP_PER_BLOCK)
    baseline_expected_completion = (
        attempts - baseline.misses - baseline.warmup_misses
    ) / attempts
    candidate_expected_completion = (
        attempts - candidate.misses - candidate.warmup_misses
    ) / attempts
    if (
        not _finite(before_completion)
        or not _finite(after_completion)
        or not 0 <= before_completion <= 1
        or not 0 <= after_completion <= 1
        or before_completion < 0.99
        or after_completion < 0.99
        or after_completion < before_completion
        or not isinstance(before_disconnects, int)
        or not isinstance(after_disconnects, int)
        or isinstance(before_disconnects, bool)
        or isinstance(after_disconnects, bool)
        or before_disconnects < 0
        or after_disconnects < 0
        or before_disconnects != 0
        or after_disconnects != 0
        or after_disconnects > before_disconnects
        or abs(before_completion - baseline_expected_completion) > 1e-12
        or abs(after_completion - candidate_expected_completion) > 1e-12
    ):
        errors.append(f"{label}: reliability guardrail failed")
    if (
        candidate.misses + candidate.warmup_misses
        > baseline.misses + baseline.warmup_misses
    ):
        errors.append(
            f"{label}: miss rate regression "
            f"({candidate.misses + candidate.warmup_misses}/"
            f"{BLOCK_COUNT * (ANALYZED_PER_BLOCK + WARMUP_PER_BLOCK)} > "
            f"{baseline.misses + baseline.warmup_misses}/"
            f"{BLOCK_COUNT * (ANALYZED_PER_BLOCK + WARMUP_PER_BLOCK)})"
        )
    return errors


def _evidence_file_errors(
    report: ParsedReport,
    label: str,
    notary_documents: dict[int, dict[str, bytes]],
) -> list[str]:
    raw = report.raw
    profile = raw["profile"]
    guardrails = raw["guardrails"]
    expected: list[tuple[Any, Any, str, str | None]] = [
        (
            raw.get("preregistration_path"),
            raw.get("preregistration_sha256"),
            "preregistration",
            "preregistration",
        ),
        (
            raw.get("results_manifest_path"),
            raw.get("results_sha256"),
            "results manifest",
            "results",
        ),
        (
            profile.get("route_evidence_path"),
            profile.get("route_evidence_sha256"),
            "route evidence",
            None,
        ),
        (
            profile["rig"].get("calibration_path"),
            profile["rig"].get("calibration_sha256"),
            "rig calibration",
            None,
        ),
        (
            guardrails["quality"].get("raw_path"),
            guardrails["quality"].get("raw_sha256"),
            "quality raw data",
            None,
        ),
        (
            guardrails["bandwidth"].get("pcap_path"),
            guardrails["bandwidth"].get("pcap_sha256"),
            "bandwidth capture",
            None,
        ),
        (
            guardrails["reliability"].get("log_path"),
            guardrails["reliability"].get("log_sha256"),
            "reliability log",
            None,
        ),
    ]
    settings = raw.get("anydesk_settings")
    if isinstance(settings, dict):
        expected.append(
            (
                settings.get("settings_snapshot_path"),
                settings.get("settings_snapshot_sha256"),
                "AnyDesk settings snapshot",
                None,
            )
        )
    expected.extend(
        (
            block.get("raw_path"),
            block.get("raw_sha256"),
            f"block {block.get('block_id')} raw trace",
            None,
        )
        for block in raw["blocks"]
    )
    errors: list[str] = []
    for path_value, expected_hash, description, snapshot_key in expected:
        try:
            content = _read_bounded_snapshot(Path(path_value))
            actual_hash = hashlib.sha256(content).hexdigest()
        except (OSError, TypeError):
            errors.append(f"{label}: {description} file is missing or oversized")
            continue
        if actual_hash != expected_hash:
            errors.append(f"{label}: {description} file SHA-256 mismatch")
        elif snapshot_key is not None:
            notary_documents.setdefault(id(report), {})[snapshot_key] = content
    return errors


def _notary_errors(
    reports: list[ParsedReport],
    public_key: Path | None,
    notary_documents: dict[int, dict[str, bytes]],
) -> list[str]:
    if TRUSTED_NOTARY_KEY_SHA256 is None:
        return [
            "trusted preregistration notary key is not committed; physical claim remains blocked"
        ]
    if public_key is None:
        return ["trusted preregistration notary public key is missing"]
    try:
        public_key_bytes = _read_bounded_snapshot(public_key)
    except OSError:
        return ["trusted preregistration notary public key is missing or unsafe"]
    if hashlib.sha256(public_key_bytes).hexdigest() != TRUSTED_NOTARY_KEY_SHA256:
        return ["preregistration notary public key SHA-256 is not trusted"]
    openssl = Path("/usr/bin/openssl")
    if not _trusted_system_binary(openssl):
        return ["trusted /usr/bin/openssl is missing or unsafe"]
    errors: list[str] = []
    with tempfile.TemporaryDirectory(prefix="opendesk-notary-") as temporary:
        root = Path(temporary)
        key_snapshot = root / "key.pem"
        key_snapshot.write_bytes(public_key_bytes)
        key_snapshot.chmod(0o600)
        for report in reports:
            for kind, _document_field, signature_field in (
                (
                    "preregistration",
                    "preregistration_path",
                    "preregistration_signature_path",
                ),
                ("results", "results_manifest_path", "results_signature_path"),
            ):
                signature = Path(report.raw[signature_field])
                try:
                    document_bytes = notary_documents[id(report)][kind]
                    signature_bytes = _read_bounded_snapshot(signature)
                    document_snapshot = root / f"{len(errors)}-{kind}.document"
                    signature_snapshot = root / f"{len(errors)}-{kind}.signature"
                    document_snapshot.write_bytes(document_bytes)
                    signature_snapshot.write_bytes(signature_bytes)
                    document_snapshot.chmod(0o600)
                    signature_snapshot.chmod(0o600)
                    completed = subprocess.run(
                        [
                            str(openssl),
                            "dgst",
                            "-sha256",
                            "-verify",
                            str(key_snapshot),
                            "-signature",
                            str(signature_snapshot),
                            str(document_snapshot),
                        ],
                        text=True,
                        capture_output=True,
                        timeout=5,
                        check=False,
                    )
                except (KeyError, OSError, subprocess.TimeoutExpired):
                    completed = None
                if completed is None or completed.returncode != 0:
                    errors.append(
                        f"{report.product_name}/{report.profile_class}: {kind} notary signature failed"
                    )
    return errors


def evaluate_pairs(
    pairs: list[tuple[dict[str, Any], dict[str, Any]]],
    *,
    inventory_override: dict[str, Any] | None = None,
    bootstrap_repetitions: int = BOOTSTRAP_REPETITIONS,
    allow_test_inventory: bool = False,
    candidate_binary_path: Path | None = None,
    notary_public_key: Path | None = None,
) -> dict[str, Any]:
    errors: list[str] = []
    if inventory_override is not None and not allow_test_inventory:
        errors.append("inventory overrides are test-only")
    inventory = (
        inventory_override
        if allow_test_inventory and inventory_override is not None
        else probe_inventory(candidate_binary_path)
    )
    if not inventory.get("physical_sensor_present") or not inventory.get(
        "sensor_paths"
    ):
        errors.append("physical optical sensor is not present")
    if not inventory.get("anydesk_binary") or not inventory.get("anydesk_sha256"):
        errors.append("AnyDesk binary is not installed or hashable")
    if not inventory.get("latencydesk_binary") or not inventory.get(
        "latencydesk_sha256"
    ):
        errors.append("LatencyDesk candidate binary is not supplied or hashable")
    if not allow_test_inventory and bootstrap_repetitions != BOOTSTRAP_REPETITIONS:
        errors.append("production bootstrap repetitions are fixed at 2000")
        bootstrap_repetitions = BOOTSTRAP_REPETITIONS
    elif not 16 <= bootstrap_repetitions <= 100_000:
        errors.append("bootstrap repetitions must be in 16..=100000")
        bootstrap_repetitions = BOOTSTRAP_REPETITIONS
    profiles: list[dict[str, Any]] = []
    classes: set[str] = set()
    profile_ids: set[str] = set()
    seen_raw_hashes: dict[str, set[str]] = {"baseline": set(), "candidate": set()}
    seen_semantic_hashes: dict[str, set[str]] = {
        "baseline": set(),
        "candidate": set(),
    }
    parsed_reports: list[ParsedReport] = []
    notary_documents: dict[int, dict[str, bytes]] = {}
    for index, pair in enumerate(pairs):
        label = f"pairs[{index}]"
        baseline = _parse_report(pair[0], f"{label}.baseline", errors)
        candidate = _parse_report(pair[1], f"{label}.candidate", errors)
        if baseline is None or candidate is None:
            continue
        parsed_reports.extend((baseline, candidate))
        errors.extend(_comparability_errors(baseline, candidate, label))
        errors.extend(_guardrail_errors(baseline, candidate, label))
        if not allow_test_inventory:
            errors.extend(
                _evidence_file_errors(baseline, f"{label}.baseline", notary_documents)
            )
            errors.extend(
                _evidence_file_errors(candidate, f"{label}.candidate", notary_documents)
            )
        rig = baseline.raw["profile"]["rig"]
        if inventory.get("sensor_fingerprints", {}).get(
            rig.get("device_path")
        ) != rig.get("device_fingerprint_sha256"):
            errors.append(f"{label}: rig device is not bound to local sensor inventory")
        expected_sensor_kind = (
            "high_speed_camera"
            if rig.get("method") == "high_speed_camera"
            else "serial_optical_rig"
        )
        if (
            inventory.get("sensor_kinds", {}).get(rig.get("device_path"))
            != expected_sensor_kind
        ):
            errors.append(
                f"{label}: rig method is not verified by sensor inventory/protocol"
            )
        for product_label, parsed in (("baseline", baseline), ("candidate", candidate)):
            overlap = seen_raw_hashes[product_label].intersection(parsed.raw_hashes)
            if overlap:
                errors.append(
                    f"{label}: {product_label} raw traces are reused across profiles"
                )
            seen_raw_hashes[product_label].update(parsed.raw_hashes)
            semantic_overlap = seen_semantic_hashes[product_label].intersection(
                parsed.semantic_hashes
            )
            if semantic_overlap:
                errors.append(
                    f"{label}: {product_label} normalized event traces are reused across profiles"
                )
            seen_semantic_hashes[product_label].update(parsed.semantic_hashes)
        if inventory.get("anydesk_sha256") != baseline.product_binary_sha256:
            errors.append(f"{label}: AnyDesk binary SHA-256 does not match inventory")
        if inventory.get("anydesk_binary") != baseline.raw["product"].get(
            "binary_path"
        ):
            errors.append(
                f"{label}: AnyDesk binary path does not match trusted inventory"
            )
        if inventory.get("anydesk_version") != baseline.raw["product"].get("version"):
            errors.append(
                f"{label}: AnyDesk version does not match installed comparator"
            )
        if inventory.get("latencydesk_sha256") != candidate.product_binary_sha256:
            errors.append(
                f"{label}: LatencyDesk binary SHA-256 does not match inventory"
            )
        if inventory.get("latencydesk_binary") != candidate.raw["product"].get(
            "binary_path"
        ):
            errors.append(f"{label}: LatencyDesk binary path does not match inventory")
        if inventory.get("latencydesk_version") != candidate.raw["product"].get(
            "version"
        ):
            errors.append(
                f"{label}: LatencyDesk version does not match candidate binary"
            )
        baseline_values = [value for block in baseline.blocks for value in block]
        candidate_values = [value for block in candidate.blocks for value in block]
        if (
            len({_percentile(list(block), 95) for block in baseline.blocks}) < 3
            or len({_percentile(list(block), 95) for block in candidate.blocks}) < 3
        ):
            errors.append(f"{label}: physical block variability is degenerate")
        baseline_p95 = _percentile(baseline_values, 95)
        candidate_p95 = _percentile(candidate_values, 95)
        baseline_p99 = _percentile(baseline_values, 99)
        candidate_p99 = _percentile(candidate_values, 99)
        improvement = (baseline_p95 - candidate_p95) / baseline_p95 * 100.0
        difference_ci, improvement_ci = _paired_bootstrap(
            baseline, candidate, bootstrap_repetitions
        )
        if (
            improvement < MIN_P95_IMPROVEMENT_PERCENT
            or improvement_ci[0] < MIN_P95_IMPROVEMENT_PERCENT
        ):
            errors.append(
                f"{label}: p95 must improve by at least {MIN_P95_IMPROVEMENT_PERCENT:.1f}% "
                "and the paired-block 95% CI must clear the margin"
            )
        if candidate_p99 > baseline_p99:
            errors.append(
                f"{label}: p99 regression ({candidate_p99:.3f} > {baseline_p99:.3f} ms)"
            )
        classes.add(baseline.profile_class)
        profile_id = baseline.raw["profile"]["id"]
        if profile_id in profile_ids:
            errors.append(f"{label}: duplicate profile.id")
        profile_ids.add(profile_id)
        profiles.append(
            {
                "id": profile_id,
                "class": baseline.profile_class,
                "route_class": baseline.raw["profile"]["route_class"],
                "analyzed_per_product": len(baseline_values),
                "baseline_p95_ms": baseline_p95,
                "candidate_p95_ms": candidate_p95,
                "p95_improvement_percent": improvement,
                "p95_difference_ci_ms": list(difference_ci),
                "p95_improvement_ci_percent": list(improvement_ci),
                "baseline_p99_ms": baseline_p99,
                "candidate_p99_ms": candidate_p99,
                "baseline_misses": baseline.misses,
                "candidate_misses": candidate.misses,
                "baseline_warmup_misses": baseline.warmup_misses,
                "candidate_warmup_misses": candidate.warmup_misses,
                "baseline_raw_sha256": list(baseline.raw_hashes),
                "candidate_raw_sha256": list(candidate.raw_hashes),
            }
        )
    if classes != {"lan", "wan"}:
        errors.append("matched LAN and WAN profiles are both required")
    if not allow_test_inventory:
        errors.extend(
            _notary_errors(parsed_reports, notary_public_key, notary_documents)
        )
    return {
        "schema_version": SCHEMA_VERSION,
        "passed": not errors,
        "blocked": bool(errors),
        "test_inventory_override": bool(
            allow_test_inventory and inventory_override is not None
        ),
        "evidence_scope": (
            "unit-test-only"
            if allow_test_inventory and inventory_override is not None
            else "physical-local"
        ),
        "errors": errors,
        "inventory": inventory,
        "profiles": profiles,
        "preregistration": {
            "blocks": BLOCK_COUNT,
            "warmup_per_block": WARMUP_PER_BLOCK,
            "analyzed_per_block": ANALYZED_PER_BLOCK,
            "miss_censor_ms": CENSOR_MS,
            "bootstrap_seed": BOOTSTRAP_SEED,
            "bootstrap_repetitions": bootstrap_repetitions,
            "minimum_p95_improvement_percent": MIN_P95_IMPROVEMENT_PERCENT,
        },
    }


def _load(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"{path}: missing or oversized report")
    return json.loads(
        path.read_text(encoding="utf-8"),
        parse_constant=lambda value: (_ for _ in ()).throw(
            ValueError(f"non-finite {value}")
        ),
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--pair", nargs=2, action="append", type=Path, default=[])
    parser.add_argument("--inventory", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--candidate-binary", type=Path)
    parser.add_argument("--notary-public-key", type=Path)
    args = parser.parse_args(argv)
    if args.inventory:
        inventory = probe_inventory(args.candidate_binary)
        errors = ["inventory mode does not evaluate physical measurement reports"]
        if not inventory["physical_sensor_present"]:
            errors.append("physical optical sensor is not present")
        if not inventory["anydesk_binary"]:
            errors.append("AnyDesk binary is not installed")
        result = {
            "schema_version": SCHEMA_VERSION,
            "passed": False,
            "blocked": bool(errors),
            "errors": errors,
            "inventory": inventory,
            "profiles": [],
        }
        rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding="utf-8")
        print(rendered, end="")
        return 2
    if not args.pair:
        parser.error("at least one --pair is required unless --inventory is used")
    try:
        pairs = [(_load(pair[0]), _load(pair[1])) for pair in args.pair]
        result = evaluate_pairs(
            pairs,
            candidate_binary_path=args.candidate_binary,
            notary_public_key=args.notary_public_key,
        )
    except (
        AttributeError,
        KeyError,
        OSError,
        TypeError,
        UnicodeError,
        ValueError,
        json.JSONDecodeError,
    ) as error:
        result = {
            "schema_version": SCHEMA_VERSION,
            "passed": False,
            "blocked": True,
            "errors": [str(error)],
            "profiles": [],
        }
    rendered = json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
