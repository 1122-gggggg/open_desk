#!/usr/bin/env python3
"""LatencyDesk vs. Baseline Latency Comparison Tool.

Enforces strict benchmark comparability before computing per-stage latency deltas.
Rejects any comparison where display resolution, frame rate, color space,
or network profile differ between baseline and candidate runs.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict


def load_report(path: Path) -> Dict[str, Any]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"Error loading report {path}: {e}", file=sys.stderr)
        sys.exit(1)


def validate_comparability(baseline: Dict[str, Any], candidate: Dict[str, Any]) -> None:
    errors = []

    # 1. Display mode validation
    base_res = baseline.get("resolution", baseline.get("display_mode", {}).get("resolution"))
    cand_res = candidate.get("resolution", candidate.get("display_mode", {}).get("resolution"))
    if base_res and cand_res and base_res != cand_res:
        errors.append(f"Resolution mismatch: baseline={base_res}, candidate={cand_res}")

    base_fps = baseline.get("fps", baseline.get("display_mode", {}).get("fps"))
    cand_fps = candidate.get("fps", candidate.get("display_mode", {}).get("fps"))
    if base_fps and cand_fps and base_fps != cand_fps:
        errors.append(f"FPS mismatch: baseline={base_fps}, candidate={cand_fps}")

    # 2. Color space validation
    base_color = baseline.get("display_color_space", baseline.get("display_mode", {}).get("color_space"))
    cand_color = candidate.get("display_color_space", candidate.get("display_mode", {}).get("color_space"))
    if base_color and cand_color and base_color != cand_color:
        errors.append(f"Color space mismatch: baseline={base_color}, candidate={cand_color}")

    # 3. Network profile validation
    base_net = baseline.get("network_profile", {}).get("type", "direct_lan")
    cand_net = candidate.get("network_profile", {}).get("type", "direct_lan")
    if base_net != cand_net:
        errors.append(f"Network profile mismatch: baseline={base_net}, candidate={cand_net}")

    if errors:
        print("Error: Benchmarks are not strictly comparable:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        sys.exit(2)


def extract_percentiles(data: Dict[str, Any], key: str) -> Dict[str, float]:
    val = data.get(key, {})
    if isinstance(val, dict):
        return {
            "p50": float(val.get("p50", 0)),
            "p95": float(val.get("p95", 0)),
            "p99": float(val.get("p99", 0)),
        }
    return {"p50": 0.0, "p95": 0.0, "p99": 0.0}


def format_delta(base: float, cand: float) -> str:
    diff = cand - base
    if base == 0:
        return f"{cand:.2f} µs"
    pct = (diff / base) * 100.0
    sign = "+" if diff > 0 else ""
    return f"{diff:+.2f} µs ({sign}{pct:.1f}%)"


def compare_reports(baseline: Dict[str, Any], candidate: Dict[str, Any]) -> Dict[str, Any]:
    validate_comparability(baseline, candidate)

    stages = [
        ("capture_to_convert", "Capture to Color Convert"),
        ("convert_to_encode", "Convert to Encode Submit"),
        ("encode_latency", "Hardware Video Encode"),
        ("transport_delivery", "QUIC Transport Delivery"),
        ("receive_to_decode", "Receive to Decode"),
        ("decode_to_present", "Decode to Present Fence"),
        ("total_pipeline", "Total Pipeline Processing"),
    ]

    comparison = {
        "valid": True,
        "stages": {},
        "summary": {
            "baseline_product": baseline.get("product", "baseline"),
            "candidate_product": candidate.get("product", "LatencyDesk"),
        },
    }

    print("================================================================================")
    print("                    LATENCYDESK BENCHMARK COMPARISON REPORT                     ")
    print("================================================================================")
    print(f"Baseline:  {comparison['summary']['baseline_product']}")
    print(f"Candidate: {comparison['summary']['candidate_product']}")
    print("--------------------------------------------------------------------------------")
    print(f"{'Stage':<30} | {'Metric':<6} | {'Baseline':<12} | {'Candidate':<12} | {'Delta':<18}")
    print("--------------------------------------------------------------------------------")

    for stage_key, stage_name in stages:
        base_p = extract_percentiles(baseline, stage_key)
        cand_p = extract_percentiles(candidate, stage_key)

        comparison["stages"][stage_key] = {
            "name": stage_name,
            "baseline": base_p,
            "candidate": cand_p,
            "delta": {m: cand_p[m] - base_p[m] for m in ["p50", "p95", "p99"]},
        }

        for metric in ["p50", "p95", "p99"]:
            b_val = base_p[metric]
            c_val = cand_p[metric]
            delta_str = format_delta(b_val, c_val)
            print(f"{stage_name:<30} | {metric:<6} | {b_val:>9.2f} µs | {c_val:>9.2f} µs | {delta_str:<18}")
        print("--------------------------------------------------------------------------------")

    return comparison


def main():
    parser = argparse.ArgumentParser(description="Compare LatencyDesk benchmark reports")
    parser.add_argument("baseline", type=Path, help="Path to baseline benchmark JSON")
    parser.add_argument("candidate", type=Path, help="Path to candidate benchmark JSON")
    parser.add_argument("--json", action="store_true", help="Output comparison as JSON")
    parser.add_argument("--out", type=Path, help="Write output to file")

    args = parser.parse_args()

    base_data = load_report(args.baseline)
    cand_data = load_report(args.candidate)

    result = compare_reports(base_data, cand_data)

    if args.json:
        out_str = json.dumps(result, indent=2)
        if args.out:
            args.out.write_text(out_str, encoding="utf-8")
        else:
            print(out_str)


if __name__ == "__main__":
    main()
