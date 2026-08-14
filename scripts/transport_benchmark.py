#!/usr/bin/env python3
"""Adjudicate real EXP-02 candidate reports without implementing a transport."""
from __future__ import annotations

import argparse
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "artifacts" / "exp-02-transport.json"
MAX_REPORT_BYTES = 1_000_000


@dataclass(frozen=True)
class CandidateVerdict:
    candidate: str
    eligible: bool
    failures: tuple[str, ...]
    frame_age_p99_ms: float | None
    input_p99_ms: float | None
    report: dict[str, Any]


def read_json(path: Path) -> dict[str, Any]:
    if path.stat().st_size > MAX_REPORT_BYTES:
        raise ValueError(f"{path} exceeds {MAX_REPORT_BYTES} bytes")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain one JSON object")
    return value


def number(value: Any, name: str, failures: list[str]) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        failures.append(f"{name} must be a finite non-negative number")
        return None
    return float(value)


def positive_int(value: Any, name: str, failures: list[str]) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        failures.append(f"{name} must be a positive integer")
        return None
    return value


def boolean(value: Any, name: str, failures: list[str]) -> bool | None:
    if not isinstance(value, bool):
        failures.append(f"{name} must be boolean")
        return None
    return value


def transition_sequences(value: Any, name: str, failures: list[str]) -> list[int] | None:
    if not isinstance(value, list) or any(isinstance(item, bool) or not isinstance(item, int) or item < 0 for item in value):
        failures.append(f"{name} must be an array of non-negative integer transition sequences")
        return None
    return value


def validate_candidate(
    report: dict[str, Any],
    candidate: str,
    profile_id: str,
    require_relay: bool,
) -> CandidateVerdict:
    failures: list[str] = []
    if report.get("schema") != 1:
        failures.append("schema must equal 1")
    if report.get("candidate") != candidate:
        failures.append(f"candidate must equal {candidate!r}")
    if report.get("profile_id") != profile_id:
        failures.append(f"profile_id must equal {profile_id!r}")
    if not isinstance(report.get("profile"), dict) or not report["profile"]:
        failures.append("profile must be a non-empty object")

    memory = report.get("memory")
    if not isinstance(memory, dict):
        failures.append("memory must be an object")
        memory = {}
    bound = positive_int(memory.get("bound_bytes"), "memory.bound_bytes", failures)
    observed = number(memory.get("max_observed_bytes"), "memory.max_observed_bytes", failures)
    if bound is not None and observed is not None and observed > bound:
        failures.append("memory.max_observed_bytes exceeds memory.bound_bytes")

    input_result = report.get("input")
    if not isinstance(input_result, dict):
        failures.append("input must be an object")
        input_result = {}
    expected = transition_sequences(input_result.get("expected_transition_sequences"), "input.expected_transition_sequences", failures)
    applied = transition_sequences(input_result.get("applied_transition_sequences"), "input.applied_transition_sequences", failures)
    converged = boolean(input_result.get("snapshot_converged"), "input.snapshot_converged", failures)
    if expected is not None and applied is not None and expected != applied:
        failures.append("discrete input outcomes were lost, duplicated, or reordered")
    if converged is not True:
        failures.append("input snapshot did not converge")

    media = report.get("media")
    if not isinstance(media, dict):
        failures.append("media must be an object")
        media = {}
    complete = positive_int(media.get("complete_access_units"), "media.complete_access_units", failures)
    if complete is not None and complete < 1:
        failures.append("media.complete_access_units must include at least one frame")
    number(media.get("expired_frame_drops"), "media.expired_frame_drops", failures)
    recovered = boolean(media.get("recovery_after_loss"), "media.recovery_after_loss", failures)
    if recovered is not True:
        failures.append("media did not prove recovery after loss")
    frame_age_p99 = number(media.get("frame_age_p99_ms"), "media.frame_age_p99_ms", failures)
    input_p99 = number(input_result.get("delivery_p99_ms"), "input.delivery_p99_ms", failures)

    connectivity = report.get("connectivity")
    if not isinstance(connectivity, dict):
        failures.append("connectivity must be an object")
        connectivity = {}
    if boolean(connectivity.get("direct_success"), "connectivity.direct_success", failures) is not True:
        failures.append("direct connectivity did not succeed")
    if require_relay and boolean(connectivity.get("relay_success"), "connectivity.relay_success", failures) is not True:
        failures.append("required relay connectivity did not succeed")

    return CandidateVerdict(
        candidate=candidate,
        eligible=not failures,
        failures=tuple(failures),
        frame_age_p99_ms=frame_age_p99,
        input_p99_ms=input_p99,
        report=report,
    )


def compare_profiles(quic: CandidateVerdict, webrtc: CandidateVerdict) -> tuple[str, ...]:
    if not quic.eligible or not webrtc.eligible:
        return ()
    if quic.report["profile"] != webrtc.report["profile"]:
        return ("candidate reports do not use identical profile objects",)
    return ()


def adjudicate(
    quic_report: dict[str, Any],
    webrtc_report: dict[str, Any],
    profile_id: str,
    required_margin_ms: float,
    require_relay: bool,
) -> dict[str, Any]:
    quic = validate_candidate(quic_report, "quic", profile_id, require_relay)
    webrtc = validate_candidate(webrtc_report, "webrtc", profile_id, require_relay)
    comparison_failures = compare_profiles(quic, webrtc)
    candidates = (quic, webrtc)
    eligible = [candidate for candidate in candidates if candidate.eligible]
    selected: str | None = None
    reason: str
    if comparison_failures:
        reason = "; ".join(comparison_failures)
    elif len(eligible) == 0:
        reason = "neither candidate meets correctness, recovery, bounded-memory, and connectivity gates"
    elif len(eligible) == 1:
        selected = eligible[0].candidate
        reason = "only one candidate meets all gates"
    else:
        assert quic.frame_age_p99_ms is not None and webrtc.frame_age_p99_ms is not None
        delta = abs(quic.frame_age_p99_ms - webrtc.frame_age_p99_ms)
        if delta < required_margin_ms:
            reason = f"P99 frame-age delta {delta:.3f}ms is below the predeclared {required_margin_ms:.3f}ms margin"
        else:
            selected = "quic" if quic.frame_age_p99_ms < webrtc.frame_age_p99_ms else "webrtc"
            reason = "selected lower P99 frame age after all correctness gates passed"
    return {
        "experiment": "EXP-02",
        "question": "Which real QUIC-DATAGRAM or native WebRTC candidate meets the correctness and connectivity gates with a meaningful P99 frame-age advantage?",
        "profile_id": profile_id,
        "required_margin_ms": required_margin_ms,
        "require_relay": require_relay,
        "candidates": [
            {
                "candidate": candidate.candidate,
                "eligible": candidate.eligible,
                "failures": candidate.failures,
                "frame_age_p99_ms": candidate.frame_age_p99_ms,
                "input_delivery_p99_ms": candidate.input_p99_ms,
            }
            for candidate in candidates
        ],
        "comparison_failures": comparison_failures,
        "selected": selected,
        "promotion_eligible": selected is not None and not comparison_failures,
        "reason": reason,
        "note": "This script adjudicates reports from real candidate adapters; it neither sends packets nor represents a custom UDP candidate.",
    }


def candidate_schema() -> dict[str, Any]:
    return {
        "schema": 1,
        "candidate": "quic",
        "profile_id": "matched-profile-id",
        "profile": {"rtt_ms": 60, "loss_ppm": 10_000, "jitter_ms": 15, "payload_bytes": 1100},
        "memory": {"bound_bytes": 67_108_864, "max_observed_bytes": 1_048_576},
        "input": {
            "expected_transition_sequences": [1, 2, 3],
            "applied_transition_sequences": [1, 2, 3],
            "snapshot_converged": True,
            "delivery_p99_ms": 12.5,
        },
        "media": {
            "complete_access_units": 120,
            "expired_frame_drops": 4,
            "recovery_after_loss": True,
            "frame_age_p99_ms": 22.1,
        },
        "connectivity": {"direct_success": True, "relay_success": False},
    }


def self_test() -> int:
    quic = candidate_schema()
    quic["profile_id"] = "self-test"
    webrtc = candidate_schema()
    webrtc.update({"candidate": "webrtc", "profile_id": "self-test"})
    webrtc["media"] = dict(webrtc["media"], frame_age_p99_ms=27.0)
    result = adjudicate(quic, webrtc, "self-test", 1.0, False)
    if result["selected"] != "quic" or not result["promotion_eligible"]:
        raise AssertionError("lower-P99 eligible candidate must be selected")
    reordered = candidate_schema()
    reordered["profile_id"] = "self-test"
    reordered["input"] = dict(reordered["input"], applied_transition_sequences=[1, 3, 2])
    rejected = validate_candidate(reordered, "quic", "self-test", False)
    if rejected.eligible or not any("reordered" in failure for failure in rejected.failures):
        raise AssertionError("reordered discrete input must reject a candidate")
    print(json.dumps({"self_test": "passed", "selected": result["selected"]}))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--print-candidate-schema", action="store_true")
    parser.add_argument("--quic-result", type=Path)
    parser.add_argument("--webrtc-result", type=Path)
    parser.add_argument("--profile-id", default="exp-02-matched-profile-v1")
    parser.add_argument("--required-margin-ms", type=float, default=1.0)
    parser.add_argument("--require-relay", action="store_true")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    if args.self_test:
        return self_test()
    if args.print_candidate_schema:
        print(json.dumps(candidate_schema(), indent=2))
        return 0
    if args.required_margin_ms <= 0 or not math.isfinite(args.required_margin_ms):
        parser.error("required margin must be finite and positive")
    if args.quic_result is None or args.webrtc_result is None:
        parser.error("both --quic-result and --webrtc-result are required")
    try:
        report = adjudicate(
            read_json(args.quic_result),
            read_json(args.webrtc_result),
            args.profile_id,
            args.required_margin_ms,
            args.require_relay,
        )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        parser.error(str(error))
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if report["promotion_eligible"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
