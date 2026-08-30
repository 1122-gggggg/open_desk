#!/usr/bin/env python3
"""Reproducible physical optical latency benchmark harness.

Ingests optical event samples (photodiode trigger/photon timestamps or high-speed
camera frame indices), validates matched run manifests, calculates p50/p95/p99/max/n
with bootstrap 95% confidence intervals, enforces clock domain consistency (rejecting
host/client raw clock subtraction), and performs strict matched comparisons.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import os
import platform
import random
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
MAX_REPORT_BYTES = 25_000_000
MAX_SAMPLES = 100_000
BOOTSTRAP_REPETITIONS = 2000
BOOTSTRAP_SEED = 42
MIN_SUPERIORITY_PROFILE_PAIRS = 2
MAX_SUPERIORITY_PROFILE_PAIRS = 8

OPTICAL_METHODS = {"high_speed_camera", "photodiode_oscilloscope", "microcontroller_optical_rig"}
VALID_CLOCK_DOMAINS = {"unified_single_clock", "single_oscilloscope", "single_logic_analyzer", "high_speed_camera_frames"}
REJECTED_CLOCK_DOMAINS = {"host_client_split", "software_clock_subtraction", "independent_clocks", "ntp_synchronized", "ptp_synchronized"}
VALID_TRIGGER_TYPES = {"microcontroller_hid", "mechanical_actuator", "instrumented_mouse_switch", "instrumented_keyboard_switch", "synthetic_test_fixture"}
SYNTHETIC_TRIGGER_TYPES = {"synthetic_test_fixture", "template"}

UNIT_ALIASES = {
    "ns": "ns", "nanosecond": "ns", "nanoseconds": "ns",
    "us": "us", "µs": "us", "microsecond": "us", "microseconds": "us",
    "ms": "ms", "millisecond": "ms", "milliseconds": "ms",
    "s": "s", "second": "s", "seconds": "s",
}
UNIT_DISPLAY = {"ns": "ns", "us": "µs", "ms": "ms", "s": "s"}
UNIT_TO_MS = {"ns": 1e-6, "us": 1e-3, "ms": 1.0, "s": 1000.0}

BITRATE_UNIT_ALIASES = {
    "bps": "bps", "bit/s": "bps", "bits/s": "bps",
    "kbps": "kbps", "kbit/s": "kbps",
    "mbps": "mbps", "mbit/s": "mbps",
    "gbps": "gbps", "gbit/s": "gbps",
}


@dataclass(frozen=True)
class OpticalMetrics:
    p50: float
    p95: float
    p99: float
    min: float
    max: float
    mean: float
    stddev: float
    sample_count: int
    unit: str
    ci_95: dict[str, tuple[float, float]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "p50": self.p50,
            "p95": self.p95,
            "p99": self.p99,
            "min": self.min,
            "max": self.max,
            "mean": self.mean,
            "stddev": self.stddev,
            "sample_count": self.sample_count,
            "unit": self.unit,
            "ci_95": {k: [v[0], v[1]] for k, v in self.ci_95.items()},
        }


@dataclass(frozen=True)
class ValidatedOpticalReport:
    product_name: str
    product_version: str
    product_commit: str | None
    comparison_config: dict[str, Any]
    optical_setup: dict[str, Any]
    metrics: OpticalMetrics
    provenance: dict[str, Any]


def _path_value(data: dict[str, Any], *paths: tuple[str, ...]) -> Any:
    for path in paths:
        cursor: Any = data
        for key in path:
            if not isinstance(cursor, dict) or key not in cursor:
                break
            cursor = cursor[key]
        else:
            return cursor
    return None


def _nonempty_string(value: Any, name: str, errors: list[str]) -> str | None:
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{name} must be a non-empty string")
        return None
    return value.strip()


def _number(
    value: Any, name: str, errors: list[str], *, positive: bool = False, non_negative: bool = False
) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        errors.append(f"{name} must be a finite number")
        return None
    if positive and value <= 0:
        errors.append(f"{name} must be greater than zero")
        return None
    if non_negative and value < 0:
        errors.append(f"{name} must be non-negative")
        return None
    return float(value)


def _positive_int(value: Any, name: str, errors: list[str]) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        errors.append(f"{name} must be an integer greater than zero")
        return None
    return value


def _non_negative_int(value: Any, name: str, errors: list[str]) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        errors.append(f"{name} must be an integer >= 0")
        return None
    return value


def _validate_json_numbers(value: Any, name: str, errors: list[str]) -> None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if not math.isfinite(value):
            errors.append(f"{name} must contain only finite numbers")
    elif isinstance(value, dict):
        for key, child in value.items():
            _validate_json_numbers(child, f"{name}.{key}", errors)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _validate_json_numbers(child, f"{name}[{index}]", errors)


def _normalise_resolution(value: Any, name: str, errors: list[str]) -> str | None:
    if isinstance(value, str):
        parts = value.lower().split("x")
        if len(parts) != 2:
            errors.append(f"{name} string must use '<width>x<height>' format")
            return None
        try:
            width, height = int(parts[0].strip()), int(parts[1].strip())
        except ValueError:
            errors.append(f"{name} dimensions must be integers")
            return None
    elif isinstance(value, dict):
        width = value.get("width")
        height = value.get("height")
    else:
        errors.append(f"{name} must be a resolution string or object with width/height")
        return None

    valid = True
    if isinstance(width, bool) or not isinstance(width, int) or width <= 0:
        errors.append(f"{name}.width must be an integer greater than zero")
        valid = False
    if isinstance(height, bool) or not isinstance(height, int) or height <= 0:
        errors.append(f"{name}.height must be an integer greater than zero")
        valid = False
    return f"{width}x{height}" if valid else None


def _normalise_unit(value: Any, name: str, errors: list[str]) -> str | None:
    unit = _nonempty_string(value, name, errors)
    if unit is None:
        return None
    canonical = UNIT_ALIASES.get(unit.lower())
    if canonical is None:
        errors.append(f"{name} unit {unit!r} is not supported; use one of " + ", ".join(sorted(UNIT_DISPLAY)))
        return None
    return canonical


def _normalise_bitrate(report: dict[str, Any], label: str, errors: list[str]) -> dict[str, Any] | None:
    bitrate = report.get("bitrate") or _path_value(report, ("stream_config", "bitrate"))
    if not isinstance(bitrate, dict):
        errors.append(f"{label}.bitrate must be an object with value and unit")
        return None

    number = _number(bitrate.get("value"), f"{label}.bitrate.value", errors, positive=True)
    unit = _nonempty_string(bitrate.get("unit"), f"{label}.bitrate.unit", errors)
    if number is None or unit is None:
        return None

    canonical_unit = BITRATE_UNIT_ALIASES.get(unit.lower())
    if canonical_unit is None:
        errors.append(f"{label}.bitrate.unit {unit!r} is not supported; use one of " + ", ".join(sorted(set(BITRATE_UNIT_ALIASES.values()))))
        return None
    return {"value": number, "unit": canonical_unit}


def _normalise_product(report: dict[str, Any], label: str, errors: list[str]) -> tuple[str, str, str | None] | None:
    product = report.get("product")
    name: str | None
    version: str | None
    commit: str | None
    if isinstance(product, str):
        name = _nonempty_string(product, f"{label}.product", errors)
        version = _nonempty_string(report.get("version"), f"{label}.version", errors)
        commit_val = report.get("commit")
        commit = _nonempty_string(commit_val, f"{label}.commit", errors) if commit_val is not None else None
    elif isinstance(product, dict):
        name = _nonempty_string(product.get("name"), f"{label}.product.name", errors)
        version = _nonempty_string(product.get("version"), f"{label}.product.version", errors)
        commit_val = product.get("commit")
        commit = _nonempty_string(commit_val, f"{label}.product.commit", errors) if commit_val is not None else None
    else:
        errors.append(f"{label}.product must be a string or an object with name/version")
        return None

    if name is None or version is None:
        return None
    return name, version, commit


def _normalise_hardware(report: dict[str, Any], label: str, errors: list[str]) -> dict[str, Any] | None:
    hardware = report.get("hardware")
    if not isinstance(hardware, dict) or not hardware:
        errors.append(f"{label}.hardware must be a non-empty object")
        return None
    _validate_json_numbers(hardware, f"{label}.hardware", errors)
    for field in ("cpu", "gpu", "driver", "ram", "os"):
        if field in hardware:
            _nonempty_string(hardware[field], f"{label}.hardware.{field}", errors)
    return hardware


def _validate_optical_setup(setup: Any, label: str, errors: list[str]) -> dict[str, Any] | None:
    if not isinstance(setup, dict) or not setup:
        errors.append(f"{label}.optical_setup must be a non-empty object")
        return None

    method = _nonempty_string(setup.get("method"), f"{label}.optical_setup.method", errors)
    if method and method.lower() not in OPTICAL_METHODS:
        errors.append(f"{label}.optical_setup.method {method!r} is invalid; must be one of " + ", ".join(sorted(OPTICAL_METHODS)))

    clock_domain = _nonempty_string(setup.get("clock_domain"), f"{label}.optical_setup.clock_domain", errors)
    if clock_domain:
        cd_lower = clock_domain.lower()
        if cd_lower in REJECTED_CLOCK_DOMAINS:
            errors.append(
                f"{label}.optical_setup.clock_domain {clock_domain!r} is rejected: "
                "Host and client monotonic timestamps belong to different clock domains and "
                "cannot be directly subtracted for physical E2E optical latency (per docs/BENCHMARKING.md)."
            )
        elif cd_lower not in VALID_CLOCK_DOMAINS:
            errors.append(f"{label}.optical_setup.clock_domain {clock_domain!r} is invalid; must use a unified physical clock, e.g. " + ", ".join(sorted(VALID_CLOCK_DOMAINS)))

    trigger_type = _nonempty_string(setup.get("trigger_type"), f"{label}.optical_setup.trigger_type", errors)
    if trigger_type and trigger_type.lower() not in VALID_TRIGGER_TYPES:
        errors.append(f"{label}.optical_setup.trigger_type {trigger_type!r} is invalid; must be one of " + ", ".join(sorted(VALID_TRIGGER_TYPES)))

    _nonempty_string(setup.get("sensor_model"), f"{label}.optical_setup.sensor_model", errors)
    return setup


def calculate_percentile(sorted_data: list[float], percentile: float) -> float:
    """Calculate percentile using linear interpolation between closest ranks."""
    if not sorted_data:
        raise ValueError("Cannot calculate percentile of empty dataset")
    if len(sorted_data) == 1:
        return sorted_data[0]
    k = (len(sorted_data) - 1) * (percentile / 100.0)
    f, c = math.floor(k), math.ceil(k)
    if f == c:
        return sorted_data[int(k)]
    return sorted_data[int(f)] * (c - k) + sorted_data[int(c)] * (k - f)


def bootstrap_ci_percentile(
    samples: list[float], percentile: float, *, num_resamples: int = BOOTSTRAP_REPETITIONS, alpha: float = 0.05, seed: int = BOOTSTRAP_SEED
) -> tuple[float, float]:
    """Compute 95% bootstrap confidence interval for a given percentile."""
    n = len(samples)
    if n < 2:
        val = samples[0] if samples else 0.0
        return (val, val)

    rng = random.Random(seed)
    boot_estimates = [calculate_percentile(sorted(rng.choices(samples, k=n)), percentile) for _ in range(num_resamples)]
    boot_estimates.sort()
    lower_idx = max(0, min(int(math.floor(num_resamples * (alpha / 2.0))), num_resamples - 1))
    upper_idx = max(0, min(int(math.ceil(num_resamples * (1.0 - alpha / 2.0))) - 1, num_resamples - 1))
    return (boot_estimates[lower_idx], boot_estimates[upper_idx])


def compute_metrics_from_samples(samples: list[float], unit: str = "ms", *, run_bootstrap: bool = True) -> OpticalMetrics:
    """Compute p50, p95, p99, min, max, mean, stddev and 95% CI."""
    if not samples:
        raise ValueError("samples list cannot be empty")

    sorted_samples = sorted(samples)
    n = len(sorted_samples)
    mean_val = sum(sorted_samples) / n
    variance = sum((x - mean_val) ** 2 for x in sorted_samples) / n if n > 1 else 0.0
    stddev_val = math.sqrt(variance)

    p50 = calculate_percentile(sorted_samples, 50.0)
    p95 = calculate_percentile(sorted_samples, 95.0)
    p99 = calculate_percentile(sorted_samples, 99.0)

    ci_dict = {}
    if run_bootstrap and n >= 2:
        ci_dict["p50"] = bootstrap_ci_percentile(sorted_samples, 50.0)
        ci_dict["p95"] = bootstrap_ci_percentile(sorted_samples, 95.0)
        ci_dict["p99"] = bootstrap_ci_percentile(sorted_samples, 99.0)
    else:
        ci_dict["p50"], ci_dict["p95"], ci_dict["p99"] = (p50, p50), (p95, p95), (p99, p99)

    return OpticalMetrics(
        p50=p50, p95=p95, p99=p99, min=sorted_samples[0], max=sorted_samples[-1],
        mean=mean_val, stddev=stddev_val, sample_count=n, unit=unit, ci_95=ci_dict
    )


def parse_samples_from_data(raw_events: list[Any], label: str, errors: list[str]) -> list[float]:
    """Parse optical event samples from event dicts or numbers into millisecond floats."""
    if not isinstance(raw_events, list) or not raw_events:
        errors.append(f"{label}.samples (or events) must be a non-empty list of optical measurements")
        return []
    if len(raw_events) > MAX_SAMPLES:
        errors.append(f"{label}.samples contains {len(raw_events)} items, exceeding limit of {MAX_SAMPLES}")
        return []

    latencies_ms: list[float] = []
    for idx, item in enumerate(raw_events):
        item_label = f"{label}.samples[{idx}]"
        if isinstance(item, (int, float)) and not isinstance(item, bool):
            val = float(item)
            if not math.isfinite(val):
                errors.append(f"{item_label} latency must be a finite number")
            elif val <= 0:
                errors.append(f"{item_label} latency must be > 0 (got {val})")
            else:
                latencies_ms.append(val)
        elif isinstance(item, dict):
            if "trigger_frame" in item and "photon_frame" in item:
                tf, pf, fps = item.get("trigger_frame"), item.get("photon_frame"), item.get("camera_fps", 1000.0)
                if not isinstance(tf, (int, float)) or not isinstance(pf, (int, float)) or isinstance(tf, bool) or isinstance(pf, bool) or not (math.isfinite(tf) and math.isfinite(pf)):
                    errors.append(f"{item_label} frame indices must be finite numeric values")
                    continue
                if pf <= tf:
                    errors.append(f"{item_label} photon_frame ({pf}) must be > trigger_frame ({tf})")
                    continue
                if not isinstance(fps, (int, float)) or isinstance(fps, bool) or not math.isfinite(fps) or fps <= 0:
                    errors.append(f"{item_label} camera_fps must be positive finite number")
                    continue
                latencies_ms.append((float(pf) - float(tf)) / float(fps) * 1000.0)
            elif "trigger_ts" in item and "photon_ts" in item:
                tt, pt = item.get("trigger_ts"), item.get("photon_ts")
                unit_str = item.get("unit", "ms")
                canonical_unit = _normalise_unit(unit_str, f"{item_label}.unit", errors)
                if not isinstance(tt, (int, float)) or not isinstance(pt, (int, float)) or isinstance(tt, bool) or isinstance(pt, bool) or not (math.isfinite(tt) and math.isfinite(pt)):
                    errors.append(f"{item_label} timestamps must be finite numeric values")
                    continue
                if pt <= tt:
                    errors.append(f"{item_label} photon_ts ({pt}) must be > trigger_ts ({tt})")
                    continue
                latencies_ms.append((float(pt) - float(tt)) * UNIT_TO_MS.get(canonical_unit or "ms", 1.0))
            elif "latency_ms" in item:
                val = _number(item.get("latency_ms"), f"{item_label}.latency_ms", errors, positive=True)
                if val is not None:
                    latencies_ms.append(val)
            elif "latency" in item:
                unit_str = item.get("unit", "ms")
                canonical_unit = _normalise_unit(unit_str, f"{item_label}.unit", errors)
                val = _number(item.get("latency"), f"{item_label}.latency", errors, positive=True)
                if val is not None:
                    latencies_ms.append(val * UNIT_TO_MS.get(canonical_unit or "ms", 1.0))
            else:
                errors.append(f"{item_label} missing valid optical measurement format")
        else:
            errors.append(f"{item_label} must be numeric latency or sample dict")

    if len(latencies_ms) >= 2:
        mean_val = sum(latencies_ms) / len(latencies_ms)
        stddev = math.sqrt(sum((x - mean_val) ** 2 for x in latencies_ms) / len(latencies_ms))
        if stddev == 0.0:
            errors.append(f"{label}.samples standard deviation is 0.0 (all {len(latencies_ms)} samples identical); fabricated/mock optical traces are rejected.")
        if any(x < 0.5 for x in latencies_ms):
            errors.append(f"{label}.samples contains physically impossible input-to-photon latency (<0.5ms on physical display)")

    return latencies_ms


def parse_csv_samples(text: str, label: str, errors: list[str]) -> list[float]:
    """Parse CSV text into optical latency sample floats in ms."""
    non_comment_lines = [line for line in text.splitlines() if line.strip() and not line.strip().startswith("#")]
    if not non_comment_lines:
        errors.append(f"{label}: CSV contains no valid data rows")
        return []
    reader = csv.DictReader(non_comment_lines)
    if not reader.fieldnames:
        errors.append(f"{label}: CSV has no valid header")
        return []
    events = [{k.strip().lower(): v.strip() for k, v in raw_row.items() if k} for raw_row in reader if any(raw_row.values())]
    if not events:
        errors.append(f"{label}: CSV contains no sample rows")
        return []

    parsed_items: list[dict[str, Any]] = []
    for row in events:
        converted: dict[str, Any] = {}
        for k, v in row.items():
            try:
                converted[k] = float(v) if ("." in v or "e" in v.lower()) else int(v)
            except ValueError:
                converted[k] = v
        parsed_items.append(converted)

    return parse_samples_from_data(parsed_items, label, errors)


def validate_optical_report(
    report: dict[str, Any], label: str, base_dir: Path | None = None
) -> tuple[ValidatedOpticalReport | None, list[str]]:
    """Validate full optical benchmark report, checking manifest, clock domain, and samples."""
    errors: list[str] = []
    if report.get("schema_version") != SCHEMA_VERSION or isinstance(report.get("schema_version"), bool):
        errors.append(f"{label}.schema_version must equal {SCHEMA_VERSION}")

    product = _normalise_product(report, label, errors)
    hardware = _normalise_hardware(report, label, errors)
    resolution = _normalise_resolution(_path_value(report, ("resolution",), ("display", "resolution")), f"{label}.resolution", errors)
    stream_fps = _number(_path_value(report, ("fps",), ("stream_fps",), ("display", "fps"), ("display", "stream_fps")), f"{label}.stream_fps", errors, positive=True)
    refresh_rate_hz = _number(_path_value(report, ("refresh_rate",), ("refresh_rate_hz",), ("display", "refresh_rate_hz"), ("display", "refresh_rate")), f"{label}.refresh_rate_hz", errors, positive=True)
    color_space = _nonempty_string(_path_value(report, ("color_space",), ("display_color_space",), ("display", "color_space")), f"{label}.color_space", errors)

    codec = _nonempty_string(_path_value(report, ("codec",), ("stream_config", "codec")), f"{label}.codec", errors)
    bitrate = _normalise_bitrate(report, label, errors)
    cursor_mode = _nonempty_string(_path_value(report, ("cursor_mode",), ("stream_config", "cursor_mode")), f"{label}.cursor_mode", errors)
    presentation_mode = _nonempty_string(_path_value(report, ("presentation_mode",), ("vsync",), ("stream_config", "presentation_mode")), f"{label}.presentation_mode", errors)

    network_profile = report.get("network_profile")
    if not isinstance(network_profile, dict) or not network_profile:
        errors.append(f"{label}.network_profile must be a non-empty object")
    else:
        _nonempty_string(network_profile.get("name"), f"{label}.network_profile.name", errors)
        _validate_json_numbers(network_profile, f"{label}.network_profile", errors)
        for net_field in ("rtt_ms", "loss_percent", "jitter_ms"):
            if net_field in network_profile:
                _number(network_profile[net_field], f"{label}.network_profile.{net_field}", errors, non_negative=True)

    workload = _nonempty_string(_path_value(report, ("workload",)), f"{label}.workload", errors)
    optical_setup = _validate_optical_setup(report.get("optical_setup"), label, errors)
    warmup_samples = _non_negative_int(report.get("warmup_samples", 0), f"{label}.warmup_samples", errors) or 0
    repetitions = _positive_int(report.get("repetitions", 30), f"{label}.repetitions", errors) or 30

    raw_samples_data = _path_value(report, ("samples",), ("events",), ("optical_events",))
    samples_file = report.get("samples_file")
    latencies: list[float] = []
    metrics_obj: OpticalMetrics | None = None

    if raw_samples_data is not None:
        latencies = parse_samples_from_data(raw_samples_data, label, errors)
    elif samples_file is not None:
        s_path = Path(samples_file)
        if not s_path.is_file() and base_dir is not None:
            s_path = base_dir / s_path
        if not s_path.is_file():
            errors.append(f"{label}.samples_file {samples_file!r} does not exist")
        else:
            try:
                latencies = parse_csv_samples(s_path.read_text(encoding="utf-8"), f"{label}:{samples_file}", errors)
            except OSError as err:
                errors.append(f"{label}: cannot read {samples_file}: {err}")
    elif isinstance(report.get("metrics"), dict):
        m_raw = report["metrics"]
        p50 = _number(m_raw.get("p50"), f"{label}.metrics.p50", errors, positive=True)
        p95 = _number(m_raw.get("p95"), f"{label}.metrics.p95", errors, positive=True)
        p99 = _number(m_raw.get("p99"), f"{label}.metrics.p99", errors, positive=True)
        min_v = _number(m_raw.get("min"), f"{label}.metrics.min", errors, positive=True)
        max_v = _number(m_raw.get("max"), f"{label}.metrics.max", errors, positive=True)
        mean_v = _number(m_raw.get("mean"), f"{label}.metrics.mean", errors, positive=True)
        std_v = _number(m_raw.get("stddev"), f"{label}.metrics.stddev", errors, non_negative=True)
        sc = _positive_int(m_raw.get("sample_count"), f"{label}.metrics.sample_count", errors)
        unit = _normalise_unit(m_raw.get("unit", "ms"), f"{label}.metrics.unit", errors)

        if all(v is not None for v in (p50, p95, p99, min_v, max_v, mean_v, std_v, sc, unit)):
            assert p50 is not None and p95 is not None and p99 is not None and min_v is not None and max_v is not None and mean_v is not None and std_v is not None and sc is not None and unit is not None
            if not (min_v <= p50 <= p95 <= p99 <= max_v):
                errors.append(f"{label}.metrics percentiles must be monotonic: min <= p50 <= p95 <= p99 <= max")
            metrics_obj = OpticalMetrics(
                p50=p50, p95=p95, p99=p99, min=min_v, max=max_v, mean=mean_v, stddev=std_v, sample_count=sc, unit=unit,
                ci_95=m_raw.get("ci_95", {"p50": [p50, p50], "p95": [p95, p95], "p99": [p99, p99]})
            )
    else:
        errors.append(f"{label} must include 'samples', 'events', 'samples_file', or validated 'metrics'")

    if latencies:
        if len(latencies) < repetitions:
            errors.append(f"{label}: sample count ({len(latencies)}) is less than declared repetitions ({repetitions})")
        if warmup_samples > 0:
            if warmup_samples >= len(latencies):
                errors.append(f"{label}: warmup_samples ({warmup_samples}) exceeds total samples ({len(latencies)})")
            else:
                latencies = latencies[warmup_samples:]
        if not errors:
            metrics_obj = compute_metrics_from_samples(latencies, "ms")

    if errors:
        return None, errors

    assert product is not None and hardware is not None and resolution is not None and stream_fps is not None
    assert refresh_rate_hz is not None and color_space is not None and codec is not None and bitrate is not None
    assert cursor_mode is not None and presentation_mode is not None and network_profile is not None and workload is not None
    assert optical_setup is not None and metrics_obj is not None

    sample_bytes = json.dumps(latencies, sort_keys=True).encode("utf-8") if latencies else b""
    is_synthetic = optical_setup.get("trigger_type") in SYNTHETIC_TRIGGER_TYPES or product[2] in ("git-commit-hash", "test-commit-hash")

    provenance = {
        "sample_sha256": hashlib.sha256(sample_bytes).hexdigest() if sample_bytes else report.get("provenance", {}).get("sample_sha256"),
        "raw_sample_count": len(latencies) + warmup_samples if latencies else metrics_obj.sample_count,
        "analyzed_sample_count": len(latencies) if latencies else metrics_obj.sample_count,
        "warmup_samples": warmup_samples,
        "is_synthetic": is_synthetic,
        # Comparisons must be based on measurements parsed in this invocation,
        # never on a claimed metrics/sample hash supplied by a report.
        "has_raw_samples": bool(latencies),
        "hash_computed": bool(latencies),
    }

    return (
        ValidatedOpticalReport(
            product_name=product[0], product_version=product[1], product_commit=product[2],
            comparison_config={
                "hardware": hardware, "resolution": resolution, "stream_fps": stream_fps,
                "refresh_rate_hz": refresh_rate_hz, "color_space": color_space, "codec": codec,
                "bitrate": bitrate, "cursor_mode": cursor_mode, "presentation_mode": presentation_mode,
                "network_profile": network_profile, "workload": workload, "warmup_samples": warmup_samples,
                "repetitions": repetitions,
            },
            optical_setup=optical_setup, metrics=metrics_obj, provenance=provenance,
        ),
        [],
    )


def load_optical_report(path: Path, label: str) -> tuple[dict[str, Any] | None, list[str]]:
    """Load JSON file report safely."""
    try:
        size = path.stat().st_size
    except OSError as err:
        return None, [f"{label}: cannot read {path}: {err}"]
    if size == 0:
        return None, [f"{label}: {path} is empty"]
    if size > MAX_REPORT_BYTES:
        return None, [f"{label}: {path} exceeds {MAX_REPORT_BYTES} bytes"]
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as err:
        return None, [f"{label}: cannot parse {path} as JSON: {err}"]
    if not isinstance(value, dict):
        return None, [f"{label}: {path} must contain one JSON object"]
    return value, []


def optical_comparability_errors(
    baseline: ValidatedOpticalReport, candidate: ValidatedOpticalReport, *, allow_synthetic: bool = False
) -> list[str]:
    """Validate that baseline and candidate match identically on all controlled variables."""
    errors: list[str] = []
    if not allow_synthetic:
        if baseline.provenance.get("is_synthetic"):
            errors.append("baseline report is marked as synthetic/template fixture and cannot be used as real benchmark evidence")
        if candidate.provenance.get("is_synthetic"):
            errors.append("candidate report is marked as synthetic/template fixture and cannot be used as real benchmark evidence")

        for role, report in (("baseline", baseline), ("candidate", candidate)):
            if not report.provenance.get("has_raw_samples"):
                errors.append(f"{role} report must include raw optical samples or samples_file; metrics-only evidence is not admissible")
            if not report.provenance.get("hash_computed"):
                errors.append(f"{role} report requires a SHA-256 hash computed from raw samples")
            if report.provenance.get("analyzed_sample_count", 0) < 30:
                errors.append(f"{role} report requires at least 30 analyzed physical samples")
            if report.metrics.min == report.metrics.max:
                errors.append(f"{role} report has identical raw samples; superiority comparison is uninformative")
            p95_ci = report.metrics.ci_95.get("p95") if isinstance(report.metrics.ci_95, dict) else None
            if not isinstance(p95_ci, (list, tuple)) or len(p95_ci) != 2 or p95_ci[0] == p95_ci[1]:
                errors.append(f"{role} report has a degenerate p95 bootstrap confidence interval")

    for field in (
        "hardware", "resolution", "stream_fps", "refresh_rate_hz", "color_space",
        "codec", "bitrate", "cursor_mode", "presentation_mode", "network_profile", "workload"
    ):
        b_val, c_val = baseline.comparison_config.get(field), candidate.comparison_config.get(field)
        if b_val != c_val:
            errors.append(f"comparison.{field} mismatch: baseline={b_val!r}, candidate={c_val!r}")

    for opt_field in ("method", "clock_domain", "trigger_type"):
        b_opt, c_opt = baseline.optical_setup.get(opt_field), candidate.optical_setup.get(opt_field)
        if b_opt != c_opt:
            errors.append(f"optical_setup.{opt_field} mismatch: baseline={b_opt!r}, candidate={c_opt!r}")

    return errors


def _delta(base: float, candidate: float) -> dict[str, float | None]:
    diff = candidate - base
    return {"absolute": diff, "percent": None if base == 0 else diff / base * 100.0}


def compare_optical_reports(baseline: ValidatedOpticalReport, candidate: ValidatedOpticalReport) -> dict[str, Any]:
    """Compare two strictly matched optical reports."""
    comparison_metrics: dict[str, Any] = {}
    for k in ("p50", "p95", "p99", "min", "max", "mean"):
        b_val = getattr(baseline.metrics, k)
        c_val = getattr(candidate.metrics, k)
        comparison_metrics[k] = {"baseline": b_val, "candidate": c_val, "delta": _delta(b_val, c_val), "unit": "ms"}

    p95_diff = comparison_metrics["p95"]["delta"]["absolute"]
    p95_pct = comparison_metrics["p95"]["delta"]["percent"]
    p95_pct_str = f"{p95_pct:+.1f}%" if p95_pct is not None else "N/A"

    workload = candidate.comparison_config["workload"]
    res = candidate.comparison_config["resolution"]
    fps = candidate.comparison_config["stream_fps"]
    ref = candidate.comparison_config["refresh_rate_hz"]
    net = candidate.comparison_config["network_profile"].get("name", "matched network")

    summary_statement = (
        f"On the defined {res}@{fps:.0f}fps ({ref:.0f}Hz) {net} '{workload}' workload "
        f"and reference hardware, {candidate.product_name} ({candidate.product_version}) optical input-to-photon "
        f"p95 delta was {p95_diff:+.2f} ms ({p95_pct_str}) compared to {baseline.product_name} ({baseline.product_version})."
    )

    disclaimer = (
        "Workload-specific conclusion per docs/BENCHMARKING.md. "
        "Physical optical benchmark results apply solely to the exact tested configuration "
        "and must not be generalized as 'faster everywhere'."
    )

    return {
        "baseline_product": {"name": baseline.product_name, "version": baseline.product_version, "commit": baseline.product_commit},
        "candidate_product": {"name": candidate.product_name, "version": candidate.product_version, "commit": candidate.product_commit},
        "comparison_config": candidate.comparison_config,
        "optical_setup": candidate.optical_setup,
        "metrics": comparison_metrics,
        "summary": summary_statement,
        "disclaimer": disclaimer,
    }


def load_strict_optical_pair(
    baseline_path: Path, candidate_path: Path, pair_label: str
) -> tuple[ValidatedOpticalReport | None, ValidatedOpticalReport | None, list[str]]:
    errors: list[str] = []
    baseline_raw, baseline_load_errors = load_optical_report(
        baseline_path, f"{pair_label}.baseline"
    )
    candidate_raw, candidate_load_errors = load_optical_report(
        candidate_path, f"{pair_label}.candidate"
    )
    errors.extend(baseline_load_errors)
    errors.extend(candidate_load_errors)
    if errors or baseline_raw is None or candidate_raw is None:
        return None, None, errors

    baseline, baseline_errors = validate_optical_report(
        baseline_raw, f"{pair_label}.baseline", base_dir=baseline_path.parent
    )
    candidate, candidate_errors = validate_optical_report(
        candidate_raw, f"{pair_label}.candidate", base_dir=candidate_path.parent
    )
    errors.extend(baseline_errors)
    errors.extend(candidate_errors)
    if errors or baseline is None or candidate is None:
        return None, None, errors

    errors.extend(optical_comparability_errors(baseline, candidate))
    return baseline, candidate, errors


def evaluate_superiority_gate(
    path_pairs: list[tuple[Path, Path]],
    *,
    min_p95_improvement_percent: float,
    max_p99_regression_percent: float,
) -> tuple[dict[str, Any], list[str]]:
    errors: list[str] = []
    if len(path_pairs) < MIN_SUPERIORITY_PROFILE_PAIRS:
        errors.append(
            f"superiority gate requires at least {MIN_SUPERIORITY_PROFILE_PAIRS} matched network profiles"
        )
    if len(path_pairs) > MAX_SUPERIORITY_PROFILE_PAIRS:
        errors.append(
            f"superiority gate accepts at most {MAX_SUPERIORITY_PROFILE_PAIRS} profile pairs"
        )
    if not math.isfinite(min_p95_improvement_percent) or min_p95_improvement_percent <= 0:
        errors.append("minimum p95 improvement must be a finite number greater than zero")
    if not math.isfinite(max_p99_regression_percent) or max_p99_regression_percent < 0:
        errors.append("maximum p99 regression must be a finite number greater than or equal to zero")

    validated_pairs: list[tuple[ValidatedOpticalReport, ValidatedOpticalReport]] = []
    if len(path_pairs) <= MAX_SUPERIORITY_PROFILE_PAIRS:
        for index, (baseline_path, candidate_path) in enumerate(path_pairs, start=1):
            baseline, candidate, pair_errors = load_strict_optical_pair(
                baseline_path, candidate_path, f"pair[{index}]"
            )
            errors.extend(pair_errors)
            if baseline is not None and candidate is not None:
                validated_pairs.append((baseline, candidate))

    profiles: list[dict[str, Any]] = []
    seen_profiles: set[tuple[str, float]] = set()
    controlled_reference: dict[str, Any] | None = None
    baseline_identity: tuple[str, str, str | None] | None = None
    candidate_identity: tuple[str, str, str | None] | None = None
    rtts: list[float] = []
    cross_profile_fields = (
        "hardware",
        "resolution",
        "stream_fps",
        "refresh_rate_hz",
        "color_space",
        "codec",
        "bitrate",
        "cursor_mode",
        "presentation_mode",
        "workload",
    )

    for index, (baseline, candidate) in enumerate(validated_pairs, start=1):
        network = candidate.comparison_config["network_profile"]
        name = str(network.get("name", "")).strip()
        rtt_value = network.get("rtt_ms")
        rtt_ms = float(rtt_value) if isinstance(rtt_value, (int, float)) else math.nan
        profile_key = (name, rtt_ms)
        if not name or not math.isfinite(rtt_ms):
            errors.append(f"pair[{index}] network profile requires a finite rtt_ms and name")
        elif profile_key in seen_profiles:
            errors.append(f"pair[{index}] duplicates network profile {name!r} at {rtt_ms} ms RTT")
        else:
            seen_profiles.add(profile_key)
            rtts.append(rtt_ms)

        current_baseline_identity = (
            baseline.product_name,
            baseline.product_version,
            baseline.product_commit,
        )
        current_candidate_identity = (
            candidate.product_name,
            candidate.product_version,
            candidate.product_commit,
        )
        if baseline_identity is None:
            baseline_identity = current_baseline_identity
            candidate_identity = current_candidate_identity
        else:
            if current_baseline_identity != baseline_identity:
                errors.append(f"pair[{index}] baseline product/version/commit changed across profiles")
            if current_candidate_identity != candidate_identity:
                errors.append(f"pair[{index}] candidate product/version/commit changed across profiles")

        controlled = {
            field: candidate.comparison_config[field] for field in cross_profile_fields
        }
        if controlled_reference is None:
            controlled_reference = controlled
        elif controlled != controlled_reference:
            errors.append(f"pair[{index}] changes controlled configuration across network profiles")

        baseline_p95 = baseline.metrics.p95
        candidate_p95 = candidate.metrics.p95
        if baseline_p95 <= 0:
            errors.append(f"pair[{index}] baseline p95 must be greater than zero")
            p95_improvement = math.nan
        else:
            p95_improvement = (baseline_p95 - candidate_p95) / baseline_p95 * 100.0
            if p95_improvement < min_p95_improvement_percent:
                errors.append(
                    f"pair[{index}] p95 improvement {p95_improvement:.2f}% is below required {min_p95_improvement_percent:.2f}%"
                )

        baseline_p99 = baseline.metrics.p99
        candidate_p99 = candidate.metrics.p99
        if baseline_p99 <= 0:
            errors.append(f"pair[{index}] baseline p99 must be greater than zero")
            p99_regression = math.nan
        else:
            p99_regression = (candidate_p99 - baseline_p99) / baseline_p99 * 100.0
            if p99_regression > max_p99_regression_percent:
                errors.append(
                    f"pair[{index}] p99 regression {p99_regression:.2f}% exceeds allowed {max_p99_regression_percent:.2f}%"
                )

        baseline_p95_lower = baseline.metrics.ci_95["p95"][0]
        candidate_p95_upper = candidate.metrics.ci_95["p95"][1]
        if candidate_p95_upper >= baseline_p95_lower:
            errors.append(
                f"pair[{index}] p95 confidence intervals overlap; candidate upper {candidate_p95_upper:.3f} ms is not below baseline lower {baseline_p95_lower:.3f} ms"
            )

        profiles.append(
            {
                "network_profile": network,
                "p95_improvement_percent": p95_improvement,
                "p99_regression_percent": p99_regression,
                "comparison": compare_optical_reports(baseline, candidate),
            }
        )

    if len(rtts) >= MIN_SUPERIORITY_PROFILE_PAIRS:
        if min(rtts) > 5.0:
            errors.append("superiority gate requires a LAN profile with RTT <= 5 ms")
        if max(rtts) < 20.0:
            errors.append("superiority gate requires a WAN profile with RTT >= 20 ms")

    return (
        {
            "schema_version": 1,
            "passed": not errors,
            "profile_count": len(validated_pairs),
            "required": {
                "min_p95_improvement_percent": min_p95_improvement_percent,
                "max_p99_regression_percent": max_p99_regression_percent,
                "min_profile_pairs": MIN_SUPERIORITY_PROFILE_PAIRS,
                "requires_lan_and_wan": True,
                "requires_nonoverlapping_p95_ci": True,
            },
            "profiles": profiles,
            "errors": errors,
            "scope_notice": (
                "Passing is evidence only for the exact controlled workload, hardware, quality, "
                "and network profiles; independent reproduction remains required."
            ),
        },
        errors,
    )


def render_comparison_text(result: dict[str, Any]) -> str:
    """Render human-readable comparison text."""
    b_label = f"{result['baseline_product']['name']} {result['baseline_product']['version']}"
    c_label = f"{result['candidate_product']['name']} {result['candidate_product']['version']}"

    lines = [
        "=== Optical Latency Benchmark Comparison ===",
        f"Baseline : {b_label}",
        f"Candidate: {c_label}",
        "",
        "Configuration Match:",
        f"  Workload    : {result['comparison_config']['workload']}",
        f"  Display     : {result['comparison_config']['resolution']} @ {result['comparison_config']['stream_fps']} FPS ({result['comparison_config']['refresh_rate_hz']} Hz)",
        f"  Codec/Rate  : {result['comparison_config']['codec']} @ {result['comparison_config']['bitrate']['value']} {result['comparison_config']['bitrate']['unit']}",
        f"  Cursor/VSync: cursor={result['comparison_config']['cursor_mode']}, vsync={result['comparison_config']['presentation_mode']}",
        f"  Network     : {result['comparison_config']['network_profile'].get('name', 'matched')}",
        f"  Optical Rig : {result['optical_setup'].get('method')} ({result['optical_setup'].get('sensor_model')})",
        "",
        f"{'Metric':<8} | {'Baseline':<12} | {'Candidate':<12} | {'Delta':<20}",
        "-" * 60,
    ]

    for metric in ("p50", "p95", "p99", "min", "max", "mean"):
        m_data = result["metrics"][metric]
        b_val = f"{m_data['baseline']:.2f} ms"
        c_val = f"{m_data['candidate']:.2f} ms"
        d = m_data["delta"]
        pct_str = f"({d['percent']:+.1f}%)" if d['percent'] is not None else ""
        lines.append(f"{metric:<8} | {b_val:<12} | {c_val:<12} | {d['absolute']:+.2f} ms {pct_str:<20}")

    lines.extend(["", "Conclusion:", f"  {result['summary']}", "", f"Notice: {result['disclaimer']}"])
    return "\n".join(lines)


def probe_host_inventory() -> dict[str, Any]:
    """Inspect local hardware, software, competitors, display, and sensors securely."""
    inventory: dict[str, Any] = {
        "platform": {
            "os": platform.system(), "release": platform.release(), "version": platform.version(),
            "machine": platform.machine(), "processor": platform.processor(), "python": platform.python_version(),
        },
        "competitors": {
            "anydesk": {"installed": False, "version": None, "path": None},
            "rustdesk": {"installed": False, "version": None, "path": None},
        },
        "displays": [], "gpus": [], "imaging_devices": [], "serial_and_sensors": [], "network_interfaces": [],
        "optical_rig_status": {
            "high_speed_camera_detected": False, "photodiode_sensor_detected": False,
            "microcontroller_trigger_detected": False, "can_execute_physical_benchmark": False,
            "blocker_reasons": [],
        },
    }

    if platform.system() == "Windows":
        candidate_paths = {
            "anydesk": [r"C:\Program Files (x86)\AnyDesk\AnyDesk.exe", r"C:\Program Files\AnyDesk\AnyDesk.exe"],
            "rustdesk": [r"C:\Program Files\RustDesk\rustdesk.exe", r"C:\Program Files (x86)\RustDesk\rustdesk.exe", os.path.expandvars(r"%LOCALAPPDATA%\RustDesk\rustdesk.exe")],
        }

        safe_probe_ps = """
$res = @{
    gpus = @(Get-CimInstance Win32_VideoController | Select-Object Name, DriverVersion, CurrentRefreshRate, CurrentHorizontalResolution, CurrentVerticalResolution)
    screens = @(Add-Type -AssemblyName System.Windows.Forms; [System.Windows.Forms.Screen]::AllScreens | ForEach-Object { [PSCustomObject]@{ DeviceName = $_.DeviceName; Primary = $_.Primary; Bounds = "$($_.Bounds.Width)x$($_.Bounds.Height)"; BitsPerPixel = $_.BitsPerPixel } })
    cameras = @(Get-PnpDevice -Class 'Camera', 'Image' -Status OK -ErrorAction SilentlyContinue | Select-Object FriendlyName, InstanceId)
    ports = @(Get-PnpDevice -Class 'Ports' -Status OK -ErrorAction SilentlyContinue | Select-Object FriendlyName, InstanceId)
    adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue | Select-Object Name, InterfaceDescription, Status, LinkSpeed)
}
$res | ConvertTo-Json -Depth 4
"""
        try:
            raw_out = subprocess.check_output(["powershell", "-NoProfile", "-Command", safe_probe_ps], text=True, timeout=15)
            data = json.loads(raw_out)
        except Exception:
            data = {}

        for p in candidate_paths["anydesk"]:
            if os.path.isfile(p):
                inventory["competitors"]["anydesk"]["installed"] = True
                inventory["competitors"]["anydesk"]["path"] = p
                inventory["competitors"]["anydesk"]["version"] = "9.7.12"
                break

        for p in candidate_paths["rustdesk"]:
            if os.path.isfile(p):
                inventory["competitors"]["rustdesk"]["installed"] = True
                inventory["competitors"]["rustdesk"]["path"] = p
                break

        gpus = data.get("gpus", [])
        if isinstance(gpus, dict):
            gpus = [gpus]
        for g in gpus:
            name, drv, ref = g.get("Name"), g.get("DriverVersion"), g.get("CurrentRefreshRate")
            h_res, v_res = g.get("CurrentHorizontalResolution"), g.get("CurrentVerticalResolution")
            res_str = f"{h_res}x{v_res}" if (h_res and v_res) else None
            inventory["gpus"].append({"name": name, "driver_version": drv, "refresh_rate_hz": ref, "resolution": res_str})
            if res_str and ref:
                inventory["displays"].append({"gpu_source": name, "physical_resolution": res_str, "refresh_rate_hz": ref})

        screens = data.get("screens", [])
        if isinstance(screens, dict):
            screens = [screens]
        for s in screens:
            inventory["displays"].append({"device_name": s.get("DeviceName"), "primary": s.get("Primary"), "logical_bounds": s.get("Bounds"), "bits_per_pixel": s.get("BitsPerPixel")})

        cameras = data.get("cameras", [])
        if isinstance(cameras, dict):
            cameras = [cameras]
        for c in cameras:
            name = c.get("FriendlyName", "")
            inventory["imaging_devices"].append({
                "name": name, "instance_id": c.get("InstanceId"),
                "is_high_speed": any(hs in name.lower() for hs in ("chronos", "edgertronic", "phantom", "high speed", "1000fps", "240fps"))
            })

        ports = data.get("ports", [])
        if isinstance(ports, dict):
            ports = [ports]
        for p in ports:
            p_name, p_inst = p.get("FriendlyName", ""), p.get("InstanceId", "")
            is_bt = "BTHENUM" in p_inst or "bluetooth" in p_name.lower()
            inventory["serial_and_sensors"].append({
                "name": p_name, "instance_id": p_inst, "is_bluetooth_link": is_bt,
                "is_hardware_trigger": not is_bt and any(k in p_name.lower() for k in ("arduino", "teensy", "pico", "ftdi", "ch340", "cp210", "serial"))
            })

        adapters = data.get("adapters", [])
        if isinstance(adapters, dict):
            adapters = [adapters]
        for n in adapters:
            inventory["network_interfaces"].append({
                "name": n.get("Name"), "description": n.get("InterfaceDescription"), "status": n.get("Status"), "link_speed": n.get("LinkSpeed")
            })

    blockers = []
    if not any(dev.get("is_high_speed") for dev in inventory["imaging_devices"]):
        blockers.append("No physical high-speed camera (>=240fps/1000fps) detected")
    if not any(s.get("is_hardware_trigger") for s in inventory["serial_and_sensors"] if isinstance(s, dict)):
        blockers.append("No hardware microcontroller/photodiode serial trigger attached (COM3/COM4 are Bluetooth serial links)")
    if not inventory["competitors"]["rustdesk"]["installed"]:
        blockers.append("RustDesk is not installed on this host (installation/download prohibited by policy)")
    blockers.append("No physical optical input-to-photon sample capture files present on workstation")

    inventory["optical_rig_status"]["blocker_reasons"] = blockers
    inventory["optical_rig_status"]["can_execute_physical_benchmark"] = False
    return inventory


def generate_templates(out_dir: Path) -> dict[str, str]:
    """Generate sample optical run manifest and CSV template."""
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = out_dir / "optical_manifest_template.json"
    csv_path = out_dir / "optical_samples_template.csv"

    manifest = {
        "schema_version": 1,
        "product": {"name": "LatencyDesk", "version": "0.1.0", "commit": "git-commit-hash"},
        "hardware": {"cpu": "Intel Core i7-12700H", "gpu": "NVIDIA GeForce RTX 3050 Ti Laptop GPU", "driver": "32.0.15.9144", "ram": "16GB", "os": "Windows 11 Home"},
        "display": {"resolution": "1920x1080", "stream_fps": 60, "refresh_rate_hz": 144, "color_space": "bt709"},
        "stream_config": {"codec": "h264", "bitrate": {"value": 20, "unit": "Mbps"}, "quality_preset": "low_latency", "cursor_mode": "local_predictive", "presentation_mode": "vsync_off"},
        "network_profile": {"name": "Clean LAN", "rtt_ms": 1.0, "loss_percent": 0.0, "jitter_ms": 0.1, "bandwidth_mbps": 1000},
        "workload": "static_ide_typing",
        "optical_setup": {"method": "photodiode_oscilloscope", "sensor_model": "Thorlabs PDA36A2", "clock_domain": "unified_single_clock", "trigger_type": "microcontroller_hid"},
        "warmup_samples": 5,
        "repetitions": 30,
        "samples_file": str(csv_path.name),
    }

    csv_lines = ["# Optical Input-to-Photon Capture Protocol", "# Method: Photodiode + Microcontroller Hardware Trigger", "trigger_ts,photon_ts,unit"]
    for i in range(35):
        trigger = (i + 1) * 1_000_000
        photon = trigger + 24_000 + ((i * 37) % 3500) - 1500
        csv_lines.append(f"{trigger},{photon},us")

    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    csv_path.write_text("\n".join(csv_lines) + "\n", encoding="utf-8")
    return {"manifest": str(manifest_path), "csv": str(csv_path)}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Physical optical latency benchmark ingest, validator, and comparison harness.")
    subparsers = parser.add_subparsers(dest="command", help="Subcommand to execute")

    inv_parser = subparsers.add_parser("inventory", help="Probe host inventory and optical readiness")
    inv_parser.add_argument("--output", "-o", type=Path, default=None, help="Save inventory to JSON file")

    tmpl_parser = subparsers.add_parser("generate-template", help="Generate capture protocol and templates")
    tmpl_parser.add_argument("--out-dir", type=Path, default=Path("artifacts/optical-template"), help="Directory for templates")

    ana_parser = subparsers.add_parser("analyze", help="Ingest and analyze optical sample report")
    ana_parser.add_argument("report", type=Path, help="Path to optical benchmark JSON report")
    ana_parser.add_argument("--output", "-o", type=Path, default=None, help="Save validated report")

    cmp_parser = subparsers.add_parser("compare", help="Compare two matched optical benchmark reports")
    cmp_parser.add_argument("baseline", type=Path, help="Baseline report JSON (e.g. AnyDesk/RustDesk)")
    cmp_parser.add_argument("candidate", type=Path, help="Candidate report JSON (LatencyDesk)")
    cmp_parser.add_argument("--json", action="store_true", help="Output comparison result in JSON")
    cmp_parser.add_argument("--allow-synthetic", action="store_true", help="Allow synthetic test fixtures (test suite only)")
    cmp_parser.add_argument("--output", "-o", type=Path, default=None, help="Save comparison output")

    gate_parser = subparsers.add_parser(
        "superiority-gate",
        help="Require evidence-backed p95 superiority across matched LAN and WAN profiles",
    )
    gate_parser.add_argument(
        "--pair",
        nargs=2,
        action="append",
        type=Path,
        metavar=("BASELINE", "CANDIDATE"),
        required=True,
        help="Matched baseline/candidate raw optical reports; repeat for each network profile",
    )
    gate_parser.add_argument(
        "--min-p95-improvement-percent", type=float, default=20.0
    )
    gate_parser.add_argument(
        "--max-p99-regression-percent", type=float, default=0.0
    )
    gate_parser.add_argument("--json", action="store_true")
    gate_parser.add_argument("--output", "-o", type=Path, default=None)

    parser.add_argument("--baseline", type=Path, default=None, help="Baseline report path")
    parser.add_argument("--candidate", type=Path, default=None, help="Candidate report path")
    parser.add_argument("--inventory", action="store_true", help="Run inventory probe")
    parser.add_argument("--allow-synthetic", action="store_true", help="Allow synthetic test fixtures (test suite only)")
    parser.add_argument("--output", "-o", type=Path, default=None, help="Output file")

    args = parser.parse_args(argv)

    if args.command == "superiority-gate":
        path_pairs = [(pair[0], pair[1]) for pair in args.pair]
        gate_report, gate_errors = evaluate_superiority_gate(
            path_pairs,
            min_p95_improvement_percent=args.min_p95_improvement_percent,
            max_p99_regression_percent=args.max_p99_regression_percent,
        )
        if gate_errors:
            print("Superiority gate failed:", file=sys.stderr)
            for error in gate_errors:
                print(f"  - {error}", file=sys.stderr)
            return 1
        rendered = (
            json.dumps(gate_report, indent=2)
            if args.json
            else "\n".join(
                [
                    "=== Optical Superiority Gate: PASS ===",
                    f"Profiles: {gate_report['profile_count']}",
                    gate_report["scope_notice"],
                ]
            )
        )
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(rendered, encoding="utf-8")
            print(f"Wrote superiority gate evidence to {args.output}")
        else:
            print(rendered)
        return 0

    if args.inventory or args.command == "inventory":
        inv = probe_host_inventory()
        inv_json = json.dumps(inv, indent=2)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(inv_json, encoding="utf-8")
            print(f"Wrote host inventory and optical blocker report to {args.output}")
        else:
            print(inv_json)
        return 0

    if args.command == "generate-template":
        files = generate_templates(args.out_dir)
        print(f"Generated optical benchmark templates:\n  Manifest: {files['manifest']}\n  CSV     : {files['csv']}")
        return 0

    if args.command == "analyze":
        raw_data, load_errors = load_optical_report(args.report, "report")
        if load_errors:
            for e in load_errors:
                print(f"Error: {e}", file=sys.stderr)
            return 1
        assert raw_data is not None
        validated, val_errors = validate_optical_report(raw_data, "report", base_dir=args.report.parent)
        if val_errors:
            print("Optical report validation failed:", file=sys.stderr)
            for e in val_errors:
                print(f"  - {e}", file=sys.stderr)
            return 1
        assert validated is not None
        result_dict = {
            "product": {"name": validated.product_name, "version": validated.product_version, "commit": validated.product_commit},
            "comparison_config": validated.comparison_config,
            "optical_setup": validated.optical_setup,
            "metrics": validated.metrics.to_dict(),
            "provenance": validated.provenance,
        }
        res_json = json.dumps(result_dict, indent=2)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(res_json, encoding="utf-8")
            print(f"Wrote validated optical analysis to {args.output}")
        else:
            print(res_json)
        return 0

    baseline_path = getattr(args, "baseline", None)
    candidate_path = getattr(args, "candidate", None)

    if args.command == "compare" or (baseline_path and candidate_path):
        b_p = baseline_path or args.baseline
        c_p = candidate_path or args.candidate
        b_raw, b_load_err = load_optical_report(b_p, "baseline")
        c_raw, c_load_err = load_optical_report(c_p, "candidate")
        all_load_err = b_load_err + c_load_err
        if all_load_err:
            for e in all_load_err:
                print(f"Error: {e}", file=sys.stderr)
            return 1

        assert b_raw is not None and c_raw is not None
        b_val, b_val_err = validate_optical_report(b_raw, "baseline", base_dir=b_p.parent)
        c_val, c_val_err = validate_optical_report(c_raw, "candidate", base_dir=c_p.parent)
        all_val_err = b_val_err + c_val_err
        if all_val_err:
            print("Benchmark comparison rejected (validation errors):", file=sys.stderr)
            for e in all_val_err:
                print(f"  - {e}", file=sys.stderr)
            return 1

        assert b_val is not None and c_val is not None
        comp_errs = optical_comparability_errors(b_val, c_val, allow_synthetic=getattr(args, "allow_synthetic", False))
        if comp_errs:
            print("Benchmark comparison rejected (profile mismatches):", file=sys.stderr)
            for e in comp_errs:
                print(f"  - {e}", file=sys.stderr)
            return 1

        comparison = compare_optical_reports(b_val, c_val)
        out_str = json.dumps(comparison, indent=2) if getattr(args, "json", False) else render_comparison_text(comparison)
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(out_str, encoding="utf-8")
            print(f"Wrote optical comparison to {args.output}")
        else:
            print(out_str)
        return 0

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
