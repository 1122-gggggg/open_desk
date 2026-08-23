#!/usr/bin/env python3
"""Strictly compare two matched latency benchmark reports.

Schema version 1 deliberately fails closed. A report must identify the product
build, hardware, workload, display/codec/network configuration, and all latency
stages. Every stage must provide p50/p95/p99, a positive sample count, and an
explicit unit (or inherit one explicit report-level unit).

This tool checks and describes submitted reports; it is not independent proof
of a performance claim and it never selects a winner.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
MAX_REPORT_BYTES = 10_000_000
STAGES = (
    ("capture_to_convert", "Capture to Color Convert"),
    ("convert_to_encode", "Convert to Encode Submit"),
    ("encode_latency", "Video Encode"),
    ("transport_delivery", "Transport Delivery"),
    ("receive_to_decode", "Receive to Decode"),
    ("decode_to_present", "Decode to Present Fence"),
    ("total_pipeline", "Reported Total Pipeline"),
)
PERCENTILES = ("p50", "p95", "p99")
UNIT_ALIASES = {
    "ns": "ns",
    "nanosecond": "ns",
    "nanoseconds": "ns",
    "us": "us",
    "µs": "us",
    "μs": "us",
    "microsecond": "us",
    "microseconds": "us",
    "ms": "ms",
    "millisecond": "ms",
    "milliseconds": "ms",
}
UNIT_DISPLAY = {"ns": "ns", "us": "µs", "ms": "ms"}
BITRATE_UNIT_ALIASES = {
    "bps": "bps",
    "bit/s": "bps",
    "kbps": "kbps",
    "kbit/s": "kbps",
    "mbps": "mbps",
    "mbit/s": "mbps",
    "gbps": "gbps",
    "gbit/s": "gbps",
}


@dataclass(frozen=True)
class StageMetrics:
    p50: float
    p95: float
    p99: float
    sample_count: int
    unit: str


@dataclass(frozen=True)
class ValidatedReport:
    product_name: str
    product_version: str
    product_commit: str
    comparison_config: dict[str, Any]
    stages: dict[str, StageMetrics]


def _path_value(data: dict[str, Any], *paths: tuple[str, ...]) -> Any:
    """Return the first present path without treating false-y values as absent."""
    for path in paths:
        value: Any = data
        for component in path:
            if not isinstance(value, dict) or component not in value:
                break
            value = value[component]
        else:
            return value
    return None


def _nonempty_string(value: Any, name: str, errors: list[str]) -> str | None:
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{name} must be a non-empty string")
        return None
    return value.strip()


def _number(
    value: Any,
    name: str,
    errors: list[str],
    *,
    positive: bool = False,
) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        errors.append(f"{name} must be a number (boolean values are not numbers)")
        return None
    if not math.isfinite(value):
        errors.append(f"{name} must be finite (NaN and Infinity are forbidden)")
        return None
    if positive and value <= 0:
        errors.append(f"{name} must be greater than zero")
        return None
    if not positive and value < 0:
        errors.append(f"{name} must be non-negative")
        return None
    return float(value)


def _positive_int(value: Any, name: str, errors: list[str]) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        errors.append(f"{name} must be a positive integer")
        return None
    return value


def _validate_json_numbers(value: Any, name: str, errors: list[str]) -> None:
    """Reject non-finite values hidden in comparison metadata."""
    if isinstance(value, float) and not math.isfinite(value):
        errors.append(f"{name} must not contain NaN or Infinity")
    elif isinstance(value, dict):
        for key, child in value.items():
            _validate_json_numbers(child, f"{name}.{key}", errors)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _validate_json_numbers(child, f"{name}[{index}]", errors)


def _nonempty_config(value: Any, name: str, errors: list[str]) -> Any | None:
    if isinstance(value, str):
        return _nonempty_string(value, name, errors)
    if not isinstance(value, dict) or not value:
        errors.append(f"{name} must be a non-empty object or string")
        return None
    _validate_json_numbers(value, name, errors)
    return value


def _normalise_resolution(value: Any, name: str, errors: list[str]) -> str | None:
    width: Any
    height: Any
    if isinstance(value, str):
        match = re.fullmatch(r"\s*(\d+)\s*[xX]\s*(\d+)\s*", value)
        if match is None:
            errors.append(f"{name} must use WIDTHxHEIGHT or width/height fields")
            return None
        width, height = int(match.group(1)), int(match.group(2))
    elif isinstance(value, dict):
        width, height = value.get("width"), value.get("height")
    elif isinstance(value, (list, tuple)) and len(value) == 2:
        width, height = value
    else:
        errors.append(f"{name} must use WIDTHxHEIGHT or width/height fields")
        return None

    valid = True
    for dimension, dimension_name in ((width, "width"), (height, "height")):
        if isinstance(dimension, bool) or not isinstance(dimension, int) or dimension <= 0:
            errors.append(f"{name}.{dimension_name} must be a positive integer")
            valid = False
    return f"{width}x{height}" if valid else None


def _normalise_unit(value: Any, name: str, errors: list[str]) -> str | None:
    unit = _nonempty_string(value, name, errors)
    if unit is None:
        return None
    canonical = UNIT_ALIASES.get(unit.lower())
    if canonical is None:
        errors.append(f"{name} has unsupported latency unit {unit!r}; use ns, us/µs, or ms")
    return canonical


def _normalise_bitrate(
    report: dict[str, Any], label: str, errors: list[str]
) -> dict[str, Any] | None:
    bitrate = report.get("bitrate")
    if isinstance(bitrate, dict):
        value = bitrate.get("value")
        unit_value = bitrate.get("unit")
    else:
        value = bitrate
        unit_value = report.get("bitrate_unit")

    number = _number(value, f"{label}.bitrate.value", errors, positive=True)
    unit = _nonempty_string(unit_value, f"{label}.bitrate.unit", errors)
    canonical_unit = None
    if unit is not None:
        canonical_unit = BITRATE_UNIT_ALIASES.get(unit.lower())
        if canonical_unit is None:
            errors.append(
                f"{label}.bitrate.unit has unsupported unit {unit!r}; "
                "use bps, kbps, Mbps, or Gbps"
            )
    if number is None or canonical_unit is None:
        return None
    return {"value": number, "unit": canonical_unit}


def _normalise_product(
    report: dict[str, Any], label: str, errors: list[str]
) -> tuple[str, str, str] | None:
    product = report.get("product")
    if isinstance(product, dict):
        name_value = product.get("name")
        version_value = product.get("version")
        commit_value = product.get("commit", product.get("revision"))
    else:
        name_value = product
        version_value = _path_value(report, ("product_version",), ("version",))
        commit_value = _path_value(
            report,
            ("product_commit",),
            ("commit",),
            ("git_commit",),
            ("revision",),
        )

    name = _nonempty_string(name_value, f"{label}.product.name", errors)
    version = _nonempty_string(version_value, f"{label}.product.version", errors)
    commit = _nonempty_string(commit_value, f"{label}.product.commit", errors)
    if name is None or version is None or commit is None:
        return None
    return name, version, commit


def _normalise_hardware(
    report: dict[str, Any], label: str, errors: list[str]
) -> dict[str, Any] | None:
    hardware = report.get("hardware")
    if not isinstance(hardware, dict) or not hardware:
        errors.append(f"{label}.hardware must be a non-empty object")
        return None
    for role in ("host", "client"):
        if (
            role not in hardware
            or not isinstance(hardware[role], (dict, str))
            or not hardware[role]
        ):
            errors.append(f"{label}.hardware.{role} must identify the {role} hardware")
    _validate_json_numbers(hardware, f"{label}.hardware", errors)
    return hardware


def _validate_network_numbers(
    network_profile: dict[str, Any], label: str, errors: list[str]
) -> None:
    """Validate common network fields when present without inventing defaults."""
    for field in (
        "rtt_ms",
        "latency_ms",
        "jitter_ms",
        "loss_percent",
        "loss_ppm",
        "reorder_percent",
    ):
        if field in network_profile:
            _number(network_profile[field], f"{label}.{field}", errors)
    for field in ("bandwidth_mbps", "bandwidth_bps", "link_mbps"):
        if field in network_profile:
            _number(network_profile[field], f"{label}.{field}", errors, positive=True)


def _normalise_stage(
    report: dict[str, Any],
    stage_key: str,
    label: str,
    report_unit: str | None,
    errors: list[str],
) -> StageMetrics | None:
    metrics = report.get("metrics")
    container = metrics if isinstance(metrics, dict) else report
    stage = container.get(stage_key)
    path = f"{label}.metrics.{stage_key}"
    if not isinstance(stage, dict):
        errors.append(f"{path} must be an object")
        return None

    percentile_container = stage.get("percentiles", stage)
    if not isinstance(percentile_container, dict):
        errors.append(f"{path}.percentiles must be an object")
        percentile_container = {}

    values: dict[str, float] = {}
    for percentile in PERCENTILES:
        value = _number(
            percentile_container.get(percentile),
            f"{path}.{percentile}",
            errors,
        )
        if value is not None:
            values[percentile] = value

    count_value = stage.get("sample_count", stage.get("count"))
    sample_count = _positive_int(count_value, f"{path}.sample_count", errors)

    if "unit" in stage:
        stage_unit = _normalise_unit(stage.get("unit"), f"{path}.unit", errors)
    elif report_unit is not None:
        stage_unit = report_unit
    else:
        errors.append(f"{path}.unit is required when latency_unit is absent")
        stage_unit = None

    if len(values) == len(PERCENTILES):
        if not values["p50"] <= values["p95"] <= values["p99"]:
            errors.append(f"{path} percentiles must be monotonic: p50 <= p95 <= p99")

    if len(values) != len(PERCENTILES) or sample_count is None or stage_unit is None:
        return None
    return StageMetrics(
        p50=values["p50"],
        p95=values["p95"],
        p99=values["p99"],
        sample_count=sample_count,
        unit=stage_unit,
    )


def validate_report(
    report: dict[str, Any], label: str
) -> tuple[ValidatedReport | None, list[str]]:
    errors: list[str] = []
    schema_version = report.get("schema_version")
    if isinstance(schema_version, bool) or schema_version != SCHEMA_VERSION:
        errors.append(f"{label}.schema_version must equal {SCHEMA_VERSION}")

    product = _normalise_product(report, label, errors)
    hardware = _normalise_hardware(report, label, errors)

    display_mode = report.get("display_mode")
    if display_mode is not None and not isinstance(display_mode, dict):
        errors.append(f"{label}.display_mode must be an object")

    resolution = _normalise_resolution(
        _path_value(report, ("resolution",), ("display_mode", "resolution")),
        f"{label}.resolution",
        errors,
    )
    fps = _number(
        _path_value(report, ("fps",), ("display_mode", "fps")),
        f"{label}.fps",
        errors,
        positive=True,
    )
    color_space = _nonempty_string(
        _path_value(
            report,
            ("display_color_space",),
            ("display_mode", "color_space"),
        ),
        f"{label}.display_color_space",
        errors,
    )

    codec = _nonempty_config(report.get("codec"), f"{label}.codec", errors)
    bitrate = _normalise_bitrate(report, label, errors)
    network_profile = report.get("network_profile")
    if not isinstance(network_profile, dict) or not network_profile:
        errors.append(f"{label}.network_profile must be a non-empty object")
        network_profile = None
    else:
        if not any(
            isinstance(network_profile.get(key), str) and network_profile[key].strip()
            for key in ("name", "type", "profile_id")
        ):
            errors.append(
                f"{label}.network_profile must contain a non-empty name, type, or profile_id"
            )
        _validate_json_numbers(network_profile, f"{label}.network_profile", errors)
        _validate_network_numbers(network_profile, f"{label}.network_profile", errors)

    workload = _nonempty_config(report.get("workload"), f"{label}.workload", errors)
    extra_config = _path_value(
        report,
        ("configuration",),
        ("config",),
        ("settings",),
    )
    if extra_config is not None:
        if not isinstance(extra_config, dict):
            errors.append(f"{label}.configuration must be an object when present")
            extra_config = None
        else:
            _validate_json_numbers(extra_config, f"{label}.configuration", errors)

    latency_unit_value = report.get("latency_unit")
    report_unit = None
    if latency_unit_value is not None:
        report_unit = _normalise_unit(latency_unit_value, f"{label}.latency_unit", errors)

    stages: dict[str, StageMetrics] = {}
    for stage_key, _ in STAGES:
        stage = _normalise_stage(report, stage_key, label, report_unit, errors)
        if stage is not None:
            stages[stage_key] = stage

    stage_units = {stage.unit for stage in stages.values()}
    if len(stage_units) > 1:
        errors.append(
            f"{label}.metrics use inconsistent latency units: "
            + ", ".join(sorted(stage_units))
        )
    if report_unit is not None:
        for stage_key, stage in stages.items():
            if stage.unit != report_unit:
                errors.append(
                    f"{label}.metrics.{stage_key}.unit must match "
                    f"{label}.latency_unit ({report_unit})"
                )

    if errors:
        return None, errors
    assert product is not None
    assert hardware is not None
    assert resolution is not None
    assert fps is not None
    assert color_space is not None
    assert codec is not None
    assert bitrate is not None
    assert network_profile is not None
    assert workload is not None
    return (
        ValidatedReport(
            product_name=product[0],
            product_version=product[1],
            product_commit=product[2],
            comparison_config={
                "hardware": hardware,
                "resolution": resolution,
                "fps": fps,
                "display_color_space": color_space,
                "codec": codec,
                "bitrate": bitrate,
                "network_profile": network_profile,
                "workload": workload,
                "configuration": extra_config,
            },
            stages=stages,
        ),
        [],
    )


def load_report(path: Path, label: str) -> tuple[dict[str, Any] | None, list[str]]:
    try:
        size = path.stat().st_size
    except OSError as error:
        return None, [f"{label}: cannot read {path}: {error}"]
    if size == 0:
        return None, [f"{label}: {path} is empty"]
    if size > MAX_REPORT_BYTES:
        return None, [f"{label}: {path} exceeds {MAX_REPORT_BYTES} bytes"]
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        return None, [f"{label}: cannot parse {path} as JSON: {error}"]
    if not isinstance(value, dict):
        return None, [f"{label}: {path} must contain one JSON object"]
    return value, []


def comparability_errors(
    baseline: ValidatedReport,
    candidate: ValidatedReport,
) -> list[str]:
    errors: list[str] = []
    for field in (
        "hardware",
        "resolution",
        "fps",
        "display_color_space",
        "codec",
        "bitrate",
        "network_profile",
        "workload",
        "configuration",
    ):
        baseline_value = baseline.comparison_config[field]
        candidate_value = candidate.comparison_config[field]
        if baseline_value != candidate_value:
            errors.append(
                f"comparison.{field} mismatch: "
                f"baseline={baseline_value!r}, candidate={candidate_value!r}"
            )

    for stage_key, _ in STAGES:
        baseline_unit = baseline.stages[stage_key].unit
        candidate_unit = candidate.stages[stage_key].unit
        if baseline_unit != candidate_unit:
            errors.append(
                f"comparison.metrics.{stage_key}.unit mismatch: "
                f"baseline={baseline_unit!r}, candidate={candidate_unit!r}"
            )
    return errors


def _delta(base: float, candidate: float) -> dict[str, float | None]:
    difference = candidate - base
    percent = None if base == 0 else difference / base * 100.0
    return {"absolute": difference, "percent": percent}


def compare_reports(
    baseline: ValidatedReport,
    candidate: ValidatedReport,
) -> dict[str, Any]:
    stages: dict[str, Any] = {}
    for stage_key, stage_name in STAGES:
        baseline_stage = baseline.stages[stage_key]
        candidate_stage = candidate.stages[stage_key]
        stages[stage_key] = {
            "name": stage_name,
            "unit": baseline_stage.unit,
            "baseline": {
                "p50": baseline_stage.p50,
                "p95": baseline_stage.p95,
                "p99": baseline_stage.p99,
                "sample_count": baseline_stage.sample_count,
            },
            "candidate": {
                "p50": candidate_stage.p50,
                "p95": candidate_stage.p95,
                "p99": candidate_stage.p99,
                "sample_count": candidate_stage.sample_count,
            },
            "delta": {
                percentile: _delta(
                    getattr(baseline_stage, percentile),
                    getattr(candidate_stage, percentile),
                )
                for percentile in PERCENTILES
            },
        }

    return {
        "comparison_schema_version": SCHEMA_VERSION,
        "valid": True,
        "not_independent_proof": True,
        "evidence_notice": (
            "not independent proof: this output only validates and compares the "
            "submitted matched reports; it does not verify how measurements were collected"
        ),
        "baseline": {
            "product": baseline.product_name,
            "version": baseline.product_version,
            "commit": baseline.product_commit,
        },
        "candidate": {
            "product": candidate.product_name,
            "version": candidate.product_version,
            "commit": candidate.product_commit,
        },
        "comparison_config": baseline.comparison_config,
        "stages": stages,
    }


def _format_delta(delta: dict[str, float | None], unit: str) -> str:
    absolute = delta["absolute"]
    percent = delta["percent"]
    assert absolute is not None
    if percent is None:
        return f"{absolute:+.2f} {UNIT_DISPLAY[unit]} (n/a)"
    return f"{absolute:+.2f} {UNIT_DISPLAY[unit]} ({percent:+.1f}%)"


def render_text(result: dict[str, Any]) -> str:
    lines = [
        "=" * 112,
        "STRICT MATCHED LATENCY BENCHMARK COMPARISON",
        "=" * 112,
        (
            f"Baseline:  {result['baseline']['product']} "
            f"{result['baseline']['version']} @ {result['baseline']['commit']}"
        ),
        (
            f"Candidate: {result['candidate']['product']} "
            f"{result['candidate']['version']} @ {result['candidate']['commit']}"
        ),
        "NOTICE: not independent proof; submitted measurements were not independently verified.",
        "-" * 112,
        (
            f"{'Stage':<28} | {'Metric':<6} | {'Baseline':<14} | {'N(base)':<8} | "
            f"{'Candidate':<14} | {'N(cand)':<8} | Delta"
        ),
        "-" * 112,
    ]
    for stage_key, _ in STAGES:
        stage = result["stages"][stage_key]
        unit_display = UNIT_DISPLAY[stage["unit"]]
        for percentile in PERCENTILES:
            lines.append(
                f"{stage['name']:<28} | {percentile:<6} | "
                f"{stage['baseline'][percentile]:>10.2f} {unit_display:<2} | "
                f"{stage['baseline']['sample_count']:>8} | "
                f"{stage['candidate'][percentile]:>10.2f} {unit_display:<2} | "
                f"{stage['candidate']['sample_count']:>8} | "
                f"{_format_delta(stage['delta'][percentile], stage['unit'])}"
            )
        lines.append("-" * 112)
    return "\n".join(lines)


def _print_errors(errors: list[str]) -> None:
    print("Benchmark comparison rejected:", file=sys.stderr)
    for error in errors:
        print(f"  - {error}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Strictly compare two matched latency benchmark reports"
    )
    parser.add_argument("baseline", type=Path, help="Path to baseline benchmark JSON")
    parser.add_argument("candidate", type=Path, help="Path to candidate benchmark JSON")
    parser.add_argument("--json", action="store_true", help="Output comparison as JSON")
    parser.add_argument("--out", type=Path, help="Write the JSON comparison to a file")
    args = parser.parse_args(argv)

    baseline_data, baseline_load_errors = load_report(args.baseline, "baseline")
    candidate_data, candidate_load_errors = load_report(args.candidate, "candidate")
    errors = [*baseline_load_errors, *candidate_load_errors]

    baseline = None
    candidate = None
    if baseline_data is not None:
        baseline, validation_errors = validate_report(baseline_data, "baseline")
        errors.extend(validation_errors)
    if candidate_data is not None:
        candidate, validation_errors = validate_report(candidate_data, "candidate")
        errors.extend(validation_errors)
    if errors:
        _print_errors(errors)
        return 2
    assert baseline is not None and candidate is not None

    errors = comparability_errors(baseline, candidate)
    if errors:
        _print_errors(errors)
        return 3

    result = compare_reports(baseline, candidate)
    json_output = json.dumps(result, indent=2, allow_nan=False)
    if args.out:
        args.out.write_text(json_output + "\n", encoding="utf-8")
    if args.json:
        print(json_output)
    else:
        print(render_text(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
