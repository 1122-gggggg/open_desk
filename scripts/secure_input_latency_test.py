#!/usr/bin/env python3
"""Fail-closed Linux/Xvfb application-ACK input latency probe.

The Client measures its local send-to-ACK interval. The Host creates the ACK
only after reconciliation, XTEST submission, and a following X11 reply. This is
application-ACK RTT, not input-to-photon latency and not an AnyDesk comparison.
"""
from __future__ import annotations

import argparse
import math
import os
import re
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

from secure_connect_test import (  # type: ignore[import-not-found]
    CERTIFICATE_FILE,
    PRIVATE_KEY_FILE,
    TrackedProcess,
    bounded_int,
    commands_contain_unsafe_flag,
    file_sha256,
    find_binary,
    generate_identity,
    parse_client_session_ids,
    parse_client_routes,
    parse_host_desktop_streams,
    parse_host_lifecycles,
    parse_host_session_ids,
    prerequisite_skip_reason,
    pick_distinct_free_udp_ports,
    repository_state,
    sanitize_log,
    write_report,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "artifacts" / "secure-input-latency.json"
INPUT_RE = re.compile(r"^input-latency:\s*(.*)$", re.MULTILINE | re.IGNORECASE)
FIELD_RE = re.compile(r"(\w+)=(.*?)(?=\s+\w+=|$)")
SAMPLE_RE = re.compile(r"^(\d+):(\d+)$")
UNSAFE = "--unsafe-udp-lab"
HOST_LIFECYCLE_RE = re.compile(
    r"^session-lifecycle:\s*generation=(\d+)\s+authorization_epoch=(\d+)\s+display_epoch=(\d+)\s+codec_epoch=(\d+)\s*$",
    re.I | re.M,
)
CLIENT_LIFECYCLE_RE = re.compile(
    r"^handshake-lifecycle:\s*generation=(\d+)\s+authorization_epoch=(\d+)\s+display_epoch=(\d+)\s+codec_epoch=(\d+)\s*$",
    re.I | re.M,
)


def nearest_rank(values: Sequence[int], percentile: float) -> int:
    if not values or not 0 < percentile <= 100:
        raise ValueError("percentile requires non-empty values and 0<p<=100")
    ordered = sorted(values)
    return ordered[max(0, math.ceil(percentile * len(ordered) / 100) - 1)]


def recompute(samples: Sequence[tuple[int, int]]) -> dict[str, int]:
    values = [value for _, value in samples]
    if not values or any(not math.isfinite(value) or value < 0 for value in values):
        raise ValueError("latencies must be finite and non-negative")
    return {"samples": len(values), "min_us": min(values), "p50_us": nearest_rank(values, 50),
            "p95_us": nearest_rank(values, 95), "p99_us": nearest_rank(values, 99),
            "max_us": max(values), "mean_us": sum(values) // len(values)}


def parse_input_latency(output: str) -> dict[str, object]:
    matches = INPUT_RE.findall(output)
    if len(matches) != 1:
        raise ValueError("expected exactly one input-latency line")
    fields = dict(FIELD_RE.findall(matches[0]))
    required = {"session_id", "authorization_epoch", "raw_us", "samples", "min_us",
                "p50_us", "p95_us", "p99_us", "max_us", "mean_us"}
    if not required <= fields.keys():
        raise ValueError("input-latency line is missing fields")
    try:
        samples = []
        for token in fields["raw_us"].split(","):
            match = SAMPLE_RE.fullmatch(token)
            if not match:
                raise ValueError("invalid raw sample")
            samples.append((int(match.group(1)), int(match.group(2))))
        result: dict[str, object] = {"session_id": int(fields["session_id"]),
            "authorization_epoch": int(fields["authorization_epoch"]), "samples": samples}
        result["summary"] = {key: int(fields[key])
                              for key in ("samples", "min_us", "p50_us", "p95_us", "p99_us", "max_us", "mean_us")}
        return result
    except (TypeError, ValueError) as error:
        raise ValueError("malformed input-latency fields") from error


def validate_probe(parsed: dict[str, object], requested: int, host_lifecycle: Sequence[tuple[int, int]],
                   client_lifecycle: Sequence[tuple[int, int]], ceiling_us: float = 100_000) -> list[str]:
    errors: list[str] = []
    samples = parsed.get("samples", [])
    if not isinstance(samples, list) or len(samples) != requested:
        errors.append("sample count does not equal requested count")
    sequences = [item[0] for item in samples] if isinstance(samples, list) else []
    if sequences != list(range(1, requested + 1)):
        errors.append("raw sample sequence is not contiguous")
    try:
        stats = recompute(samples)
        if parsed.get("summary") != stats:
            errors.append("summary does not match recomputed nearest-rank statistics")
        if float(stats["p95_us"]) > ceiling_us:
            errors.append("loopback p95 exceeds sanity ceiling")
    except (TypeError, ValueError):
        errors.append("raw samples are invalid")
    stamp = (int(parsed.get("session_id", 0)), int(parsed.get("authorization_epoch", 0)))
    if stamp[0] <= 0 or stamp[1] <= 0 or stamp not in set(host_lifecycle) or stamp not in set(client_lifecycle):
        errors.append("session/authorization epoch does not match both lifecycle logs")
    return errors


def command_is_safe(command: Sequence[str]) -> bool:
    return UNSAFE not in command and all("--unsafe" not in arg for arg in command)


def build_commands(
    host_bin: Path,
    client_bin: Path,
    listen_addr: str,
    host_dir: Path,
    client_dir: Path,
    samples: int,
) -> tuple[list[str], list[str]]:
    host_command = [
        str(host_bin),
        "--listen",
        listen_addr,
        "--identity-cert",
        str(host_dir / CERTIFICATE_FILE),
        "--identity-key",
        str(host_dir / PRIVATE_KEY_FILE),
        "--peer-cert",
        str(client_dir / CERTIFICATE_FILE),
        "--pairing-timeout",
        "30",
        "--max-width",
        "320",
        "--max-height",
        "180",
        "--fps",
        "10",
        "--max-sessions",
        "1",
    ]
    client_command = [
        str(client_bin),
        "--connect",
        listen_addr,
        "--bind",
        "127.0.0.1:0",
        "--identity-cert",
        str(client_dir / CERTIFICATE_FILE),
        "--identity-key",
        str(client_dir / PRIVATE_KEY_FILE),
        "--peer-cert",
        str(host_dir / CERTIFICATE_FILE),
        "--pairing-timeout",
        "30",
        "--input-latency-probes",
        str(samples),
    ]
    return host_command, client_command


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host-bin", type=Path)
    parser.add_argument("--client-bin", type=Path)
    parser.add_argument("--identity-bin", type=Path)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--samples", type=bounded_int("samples", 100, 1024), default=128)
    parser.add_argument("--timeout", type=bounded_int("timeout", 10, 120), default=30)
    args = parser.parse_args(argv)
    revision, dirty = repository_state()
    artifact: dict[str, object] = {
        "schema_version": 1,
        "status": "pending",
        "ok": False,
        "executed": False,
        "scope": "single-machine Linux X11 exact-mTLS application ACK RTT",
        "honest_scope": (
            "Client send to Host post-reconciliation/post-XTEST X11-sync ACK and back; "
            "not input-to-photon, cross-machine typing latency, or AnyDesk comparison"
        ),
        "requested_samples": args.samples,
        "p95_sanity_ceiling_us": 100_000,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source": {
            "repository_revision_at_test": revision,
            "worktree_dirty_at_test": dirty,
        },
    }
    reason = prerequisite_skip_reason(
        platform=sys.platform, display=os.environ.get("DISPLAY")
    )
    if reason:
        artifact.update({"status": "skipped", "reason": reason})
        write_report(args.output, artifact)
        print(f"SKIPPED: {reason}")
        print(f"Report: {args.output}")
        return 0
    artifact["executed"] = True
    temporary = tempfile.TemporaryDirectory(prefix="open-desk-input-latency-")
    temporary_root = Path(temporary.name)
    processes: list[TrackedProcess] = []
    host_process: TrackedProcess | None = None
    client_process: TrackedProcess | None = None
    host_output = ""
    client_output = ""
    host_exit = client_exit = None
    host_timed_out = client_timed_out = False
    identity_generation_ok = False
    runtime_error: str | None = None
    commands: tuple[list[str], list[str]] = ([], [])
    listen_addr: str | None = None
    binary_hashes: dict[str, str] = {}
    try:
        host_bin = find_binary("latencydesk-host", args.host_bin)
        client_bin = find_binary("latencydesk-client", args.client_bin)
        identity_bin = find_binary("latencydesk-identity", args.identity_bin)
        binary_hashes = {
            "host_sha256": file_sha256(host_bin),
            "client_sha256": file_sha256(client_bin),
            "identity_sha256": file_sha256(identity_bin),
        }
        host_dir = temporary_root / "host"
        client_dir = temporary_root / "client"
        generate_identity(identity_bin, "input-latency-host", host_dir, 10)
        generate_identity(identity_bin, "input-latency-client", client_dir, 10)
        identity_generation_ok = True
        listen_port, _ = pick_distinct_free_udp_ports()
        listen_addr = f"127.0.0.1:{listen_port}"
        host_command, client_command = build_commands(
            host_bin, client_bin, listen_addr, host_dir, client_dir, args.samples
        )
        commands = (host_command, client_command)
        if commands_contain_unsafe_flag(commands) or not all(
            command_is_safe(command) for command in commands
        ):
            raise RuntimeError("unsafe transport flag present")

        host_process = TrackedProcess(host_command, ROOT)
        processes.append(host_process)
        if not host_process.wait_for_text("Listening securely on", 15):
            raise RuntimeError("Host did not become ready")
        client_process = TrackedProcess(client_command, ROOT)
        processes.append(client_process)
        client_exit, client_timed_out = client_process.finish(args.timeout)
        client_output = client_process.output()
        host_exit, host_timed_out = host_process.finish(15)
        host_output = host_process.output()
    except Exception as error:
        runtime_error = sanitize_log(str(error), temporary_root, 1_000)
    finally:
        for process in reversed(processes):
            process.close()
        if host_process is not None:
            host_output = host_process.output()
            host_exit = host_process.poll() if host_exit is None else host_exit
        if client_process is not None:
            client_output = client_process.output()
            client_exit = client_process.poll() if client_exit is None else client_exit
        temporary.cleanup()

    parsed: dict[str, object] | None = None
    validation_errors: list[str] = []
    try:
        parsed = parse_input_latency(client_output)
        host_ids = parse_host_session_ids(host_output)
        client_ids = parse_client_session_ids(client_output)
        host_lifecycles = parse_host_lifecycles(host_output)
        client_lifecycles = [
            tuple(int(value) for value in match)
            for match in CLIENT_LIFECYCLE_RE.findall(client_output)
        ]
        host_pairs = [
            (session_id, lifecycle[1])
            for session_id, lifecycle in zip(host_ids, host_lifecycles)
        ]
        client_pairs = [
            (session_id, lifecycle[1])
            for session_id, lifecycle in zip(client_ids, client_lifecycles)
        ]
        validation_errors.extend(
            validate_probe(parsed, args.samples, host_pairs, client_pairs)
        )
    except (TypeError, ValueError) as error:
        validation_errors.append(str(error))
        host_ids = parse_host_session_ids(host_output)
        client_ids = parse_client_session_ids(client_output)
        host_lifecycles = parse_host_lifecycles(host_output)
        client_lifecycles = []

    checks = {
        "identity_generation_ok": identity_generation_ok,
        "host_exit_zero": host_exit == 0 and not host_timed_out,
        "client_exit_zero": client_exit == 0 and not client_timed_out,
        "exact_mtls_both_sides": host_output.count(
            "mTLS: exact client certificate authenticated"
        )
        == 1
        and client_output.count("mTLS: exact host certificate authenticated") == 1,
        "one_exact_route": listen_addr is not None
        and parse_client_routes(client_output) == [(listen_addr, 1)],
        "one_matching_lifecycle": len(host_ids) == 1
        and len(client_ids) == 1
        and len(host_lifecycles) == 1
        and len(client_lifecycles) == 1
        and host_ids == client_ids
        and host_lifecycles == client_lifecycles,
        "one_real_desktop_stream": parse_host_desktop_streams(host_output) == 1,
        "release_all_completed": "input: ReleaseAll applied" in host_output,
        "probe_payload_valid": parsed is not None and not validation_errors,
        "binary_hashes_complete": len(binary_hashes) == 3
        and all(len(value) == 64 for value in binary_hashes.values()),
        "no_unsafe_transport_flag": not commands_contain_unsafe_flag(commands),
        "temporary_credentials_removed": not temporary_root.exists(),
        "no_runtime_error": runtime_error is None,
    }
    errors = [name for name, passed in checks.items() if not passed]
    errors.extend(validation_errors)
    if runtime_error:
        errors.insert(0, runtime_error)
    passed = all(checks.values()) and not errors
    raw_samples = [] if parsed is None else parsed["samples"]
    summary = {} if parsed is None else parsed["summary"]
    artifact.update(
        status="passed" if passed else "failed",
        ok=passed,
        checks=checks,
        errors=errors,
        results={
            "session_id": None if parsed is None else parsed["session_id"],
            "authorization_epoch": None
            if parsed is None
            else parsed["authorization_epoch"],
            "summary": summary,
            "raw_samples": [
                {"sequence": sequence, "latency_us": latency_us}
                for sequence, latency_us in raw_samples
            ],
            "host_session_ids": host_ids,
            "client_session_ids": client_ids,
            "host_lifecycles": host_lifecycles,
            "client_lifecycles": client_lifecycles,
            "routes": parse_client_routes(client_output),
        },
        binaries=binary_hashes,
        logs={
            "host_tail": sanitize_log(host_output, temporary_root),
            "client_tail": sanitize_log(client_output, temporary_root),
        },
    )
    write_report(args.output, artifact)
    print(f"Report: {args.output}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
