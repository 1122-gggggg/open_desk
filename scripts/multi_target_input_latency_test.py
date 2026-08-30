#!/usr/bin/env python3
"""Fail-closed two-Host concurrent input application-ACK latency evidence.

One Client supervisor launches two exact-pinned children. Both probe intervals
must overlap, and every raw sample remains bound to its target and full product
lifecycle. This is single-machine application-ACK RTT, not input-to-photon or a
competitor comparison.
"""
from __future__ import annotations

import argparse
import os
import re
import sys
import tempfile
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import secure_connect_test as secure  # noqa: E402
import secure_input_latency_test as input_probe  # noqa: E402


ROOT = SCRIPT_DIR.parent
DEFAULT_OUTPUT = ROOT / "artifacts" / "multi-target-input-latency.json"
START_PREFIX_RE = re.compile(r"^input-latency-start:", re.MULTILINE | re.IGNORECASE)
START_RE = re.compile(
    r"^input-latency-start:\s+target=(\S+)\s+session_id=(\d+)\s+"
    r"generation=(\d+)\s+authorization_epoch=(\d+)\s+display_epoch=(\d+)\s+"
    r"codec_epoch=(\d+)\s+samples=(\d+)\s*$",
    re.MULTILINE | re.IGNORECASE,
)
STOP_PREFIX_RE = re.compile(r"^input-latency-stop:", re.MULTILINE | re.IGNORECASE)
STOP_RE = re.compile(
    r"^input-latency-stop:\s+target=(\S+)\s+session_id=(\d+)\s+"
    r"generation=(\d+)\s+authorization_epoch=(\d+)\s+display_epoch=(\d+)\s+"
    r"codec_epoch=(\d+)\s+samples=(\d+)\s*$",
    re.MULTILINE | re.IGNORECASE,
)
HOST_CERTIFICATE_RE = re.compile(
    r"^Host certificate:\s*([0-9a-f]{64})\s*$", re.MULTILINE | re.IGNORECASE
)


def _positive_int(fields: dict[str, str], name: str) -> int:
    try:
        value = int(fields[name])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError(f"invalid {name}") from error
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    return value


def parse_probe_records(output: str) -> list[dict[str, object]]:
    bodies = input_probe.INPUT_RE.findall(output)
    records: list[dict[str, object]] = []
    for body in bodies:
        fields = dict(input_probe.FIELD_RE.findall(body))
        required = {
            "target",
            "session_id",
            "generation",
            "authorization_epoch",
            "display_epoch",
            "codec_epoch",
        }
        if not required <= fields.keys():
            raise ValueError("input-latency record is missing target/full lifecycle fields")
        parsed = input_probe.parse_input_latency(f"input-latency: {body}")
        stamp = (
            _positive_int(fields, "session_id"),
            _positive_int(fields, "generation"),
            _positive_int(fields, "authorization_epoch"),
            _positive_int(fields, "display_epoch"),
            _positive_int(fields, "codec_epoch"),
        )
        parsed.update(target=fields["target"], stamp=stamp)
        records.append(parsed)
    if not records:
        raise ValueError("no input-latency records found")
    targets = [str(record["target"]) for record in records]
    sessions = [record["stamp"][0] for record in records]
    if len(set(targets)) != len(targets) or len(set(sessions)) != len(sessions):
        raise ValueError("input-latency targets and session IDs must be unique")
    return records


def _parse_probe_boundaries(
    output: str,
    pattern: re.Pattern[str],
    prefix_pattern: re.Pattern[str],
    label: str,
) -> list[dict[str, object]]:
    matches = pattern.findall(output)
    if len(matches) != len(prefix_pattern.findall(output)):
        raise ValueError(f"malformed input-latency-{label} record")
    boundaries = [
        {
            "target": target,
            "stamp": tuple(int(value) for value in values[:5]),
            "samples": int(values[5]),
        }
        for target, *values in matches
    ]
    if any(
        value <= 0
        for boundary in boundaries
        for value in (*boundary["stamp"], boundary["samples"])
    ):
        raise ValueError(f"input-latency-{label} fields must be positive")
    targets = [str(boundary["target"]) for boundary in boundaries]
    sessions = [boundary["stamp"][0] for boundary in boundaries]
    if len(set(targets)) != len(targets) or len(set(sessions)) != len(sessions):
        raise ValueError(
            f"input-latency-{label} targets and session IDs must be unique"
        )
    return boundaries


def parse_probe_starts(output: str) -> list[dict[str, object]]:
    return _parse_probe_boundaries(output, START_RE, START_PREFIX_RE, "start")


def parse_probe_stops(output: str) -> list[dict[str, object]]:
    return _parse_probe_boundaries(output, STOP_RE, STOP_PREFIX_RE, "stop")


def concurrent_probe_overlap(
    output: str,
    expected_targets: set[str],
    requested_samples: int,
    parent_alive: bool,
    host_alive: Sequence[bool],
) -> bool:
    if not parent_alive or len(host_alive) != len(expected_targets) or not all(host_alive):
        return False
    try:
        starts = parse_probe_starts(output)
    except ValueError:
        return False
    return (
        len(starts) == len(expected_targets)
        and {str(start["target"]) for start in starts} == expected_targets
        and all(start["samples"] == requested_samples for start in starts)
        and not STOP_RE.search(output)
        and not input_probe.INPUT_RE.search(output)
    )


def target_value(address: str, certificate: Path) -> str:
    return f"{address},{certificate}"


def build_commands(
    host_bin: Path,
    client_bin: Path,
    ports: tuple[int, int],
    dirs: dict[str, Path],
    samples: int,
) -> tuple[list[list[str]], list[str]]:
    hosts: list[list[str]] = []
    for index, port in enumerate(ports, 1):
        host_dir = dirs[f"host{index}"]
        hosts.append(
            [
                str(host_bin),
                "--listen",
                f"127.0.0.1:{port}",
                "--identity-cert",
                str(host_dir / secure.CERTIFICATE_FILE),
                "--identity-key",
                str(host_dir / secure.PRIVATE_KEY_FILE),
                "--peer-cert",
                str(dirs["client"] / secure.CERTIFICATE_FILE),
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
        )
    parent = [
        str(client_bin),
        "--bind",
        "127.0.0.1:0",
        "--identity-cert",
        str(dirs["client"] / secure.CERTIFICATE_FILE),
        "--identity-key",
        str(dirs["client"] / secure.PRIVATE_KEY_FILE),
        "--pairing-timeout",
        "30",
        "--input-latency-probes",
        str(samples),
    ]
    for index, port in enumerate(ports, 1):
        parent.extend(
            [
                "--target",
                target_value(
                    f"127.0.0.1:{port}",
                    dirs[f"host{index}"] / secure.CERTIFICATE_FILE,
                ),
            ]
        )
    return hosts, parent


def validate_target_evidence(
    address: str,
    expected_certificate: str,
    host_output: str,
    record: dict[str, object],
    start: dict[str, object],
    stop: dict[str, object],
    host_exit: int | None,
    host_timed_out: bool,
    requested_samples: int,
    ceiling_us: int,
) -> tuple[dict[str, bool], list[str]]:
    host_ids = secure.parse_host_session_ids(host_output)
    host_lifecycles = secure.parse_host_lifecycles(host_output)
    stamp = tuple(record.get("stamp", ()))
    start_stamp = tuple(start.get("stamp", ()))
    stop_stamp = tuple(stop.get("stamp", ()))
    probe_errors = input_probe.validate_probe(
        record,
        requested_samples,
        [(host_ids[0], host_lifecycles[0][1])]
        if len(host_ids) == len(host_lifecycles) == 1
        else [],
        [(stamp[0], stamp[2])] if len(stamp) == 5 else [],
        ceiling_us,
    )
    certificates = [value.lower() for value in HOST_CERTIFICATE_RE.findall(host_output)]
    checks = {
        "host_exit_zero": host_exit == 0 and not host_timed_out,
        "target_matches_plan": record.get("target") == address
        and start.get("target") == address
        and stop.get("target") == address,
        "full_stamp_matches_host": len(host_ids) == 1
        and len(host_lifecycles) == 1
        and len(stamp) == 5
        and stamp[0] == host_ids[0]
        and stamp[1:] == host_lifecycles[0],
        "boundaries_match_completion": start_stamp == stamp
        and stop_stamp == stamp
        and start.get("samples") == requested_samples
        and stop.get("samples") == requested_samples,
        "certificate_matches_plan": certificates == [expected_certificate.lower()],
        "exact_mtls": host_output.lower().count(
            "mtls: exact client certificate authenticated"
        )
        == 1,
        "one_real_desktop_stream": secure.parse_host_desktop_streams(host_output) == 1,
        "release_all_completed": host_output.count("input: ReleaseAll applied") == 1,
        "probe_payload_valid": not probe_errors,
    }
    errors = [name for name, passed in checks.items() if not passed]
    errors.extend(f"probe:{error}" for error in probe_errors)
    return checks, errors


def validate_global_evidence(
    parent_output: str,
    records: Sequence[dict[str, object]],
    starts: Sequence[dict[str, object]],
    stops: Sequence[dict[str, object]],
    expected_targets: set[str],
    parent_exit: int | None,
    parent_timed_out: bool,
    overlap_proven: bool,
    requested_samples: int,
) -> tuple[dict[str, bool], list[str]]:
    record_targets = [str(record.get("target", "")) for record in records]
    start_targets = [str(start.get("target", "")) for start in starts]
    stop_targets = [str(stop.get("target", "")) for stop in stops]
    record_stamps = [tuple(record.get("stamp", ())) for record in records]
    start_by_target = {
        str(start.get("target", "")): start for start in starts
    }
    stop_by_target = {str(stop.get("target", "")): stop for stop in stops}
    client_ids = secure.parse_client_session_ids(parent_output)
    client_lifecycles = [
        tuple(int(value) for value in match)
        for match in input_probe.CLIENT_LIFECYCLE_RE.findall(parent_output)
    ]
    routes = secure.parse_client_routes(parent_output)
    checks = {
        "parent_exit_zero": parent_exit == 0 and not parent_timed_out,
        "exact_record_targets": len(records) == len(expected_targets)
        and set(record_targets) == expected_targets,
        "exact_start_targets": len(starts) == len(expected_targets)
        and set(start_targets) == expected_targets,
        "exact_stop_targets": len(stops) == len(expected_targets)
        and set(stop_targets) == expected_targets,
        "boundaries_match_completions": all(
            target in start_by_target
            and target in stop_by_target
            and tuple(start_by_target[target].get("stamp", ()))
            == tuple(record.get("stamp", ()))
            and tuple(stop_by_target[target].get("stamp", ()))
            == tuple(record.get("stamp", ()))
            and start_by_target[target].get("samples") == requested_samples
            and stop_by_target[target].get("samples") == requested_samples
            for target, record in zip(record_targets, records)
        ),
        "distinct_session_ids": len(record_stamps) == len(expected_targets)
        and all(len(stamp) == 5 for stamp in record_stamps)
        and len({stamp[0] for stamp in record_stamps}) == len(expected_targets),
        "exact_client_session_ids": len(client_ids) == len(expected_targets)
        and set(client_ids) == {stamp[0] for stamp in record_stamps if len(stamp) == 5},
        "exact_client_lifecycles": Counter(client_lifecycles)
        == Counter(stamp[1:] for stamp in record_stamps if len(stamp) == 5),
        "exact_routes": len(routes) == len(expected_targets)
        and {route for route, _ in routes} == expected_targets
        and all(attempts == 1 for _, attempts in routes),
        "exact_mtls": parent_output.lower().count(
            "mtls: exact host certificate authenticated"
        )
        == len(expected_targets),
        "concurrent_probe_overlap": overlap_proven,
    }
    errors = [name for name, passed in checks.items() if not passed]
    return checks, errors


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host-bin", type=Path)
    parser.add_argument("--client-bin", type=Path)
    parser.add_argument("--identity-bin", type=Path)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--samples", type=secure.bounded_int("samples", 100, 1024), default=256
    )
    parser.add_argument(
        "--timeout", type=secure.bounded_int("timeout", 10, 120), default=45
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    revision, dirty = secure.repository_state()
    report: dict[str, object] = {
        "schema_version": 1,
        "status": "pending",
        "ok": False,
        "executed": False,
        "scope": (
            "one supervisor, two concurrent Linux X11 exact-mTLS Hosts, "
            "single-machine IPv4 loopback application-ACK RTT"
        ),
        "honest_scope": (
            "two overlapping Client send to post-XTEST/X11-sync ACK intervals; "
            "not physical input-to-photon, cross-machine scale, or AnyDesk comparison"
        ),
        "requested_samples_per_target": args.samples,
        "p95_sanity_ceiling_us": 100_000,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source": {
            "repository_revision_at_test": revision,
            "worktree_dirty_at_test": dirty,
        },
    }
    skip = secure.prerequisite_skip_reason(
        platform=sys.platform, display=os.environ.get("DISPLAY")
    )
    if skip:
        report.update(status="skipped", skip_reason=skip)
        secure.write_report(args.output, report)
        print(f"SKIPPED: {skip}")
        print(f"Report: {args.output}")
        return 0

    report["executed"] = True
    temporary = tempfile.TemporaryDirectory(prefix="open-desk-multi-input-latency-")
    temporary_root = Path(temporary.name)
    dirs = {name: temporary_root / name for name in ("client", "host1", "host2")}
    processes: list[secure.TrackedProcess] = []
    hosts: list[secure.TrackedProcess] = []
    parent: secure.TrackedProcess | None = None
    host_outputs = ["", ""]
    host_exits: list[int | None] = [None, None]
    host_timeouts = [False, False]
    parent_output = ""
    parent_exit: int | None = None
    parent_timed_out = False
    commands: list[Sequence[str]] = []
    target_plan: list[dict[str, str]] = []
    binary_hashes: dict[str, str] = {}
    identity_generation_ok = False
    overlap_proven = False
    overlap_observed_at_monotonic_ns: int | None = None
    runtime_error: str | None = None

    try:
        host_bin = secure.find_binary("latencydesk-host", args.host_bin)
        client_bin = secure.find_binary("latencydesk-client", args.client_bin)
        identity_bin = secure.find_binary("latencydesk-identity", args.identity_bin)
        binary_hashes = {
            "host_sha256": secure.file_sha256(host_bin),
            "client_sha256": secure.file_sha256(client_bin),
            "identity_sha256": secure.file_sha256(identity_bin),
        }
        for name, directory in dirs.items():
            secure.generate_identity(identity_bin, name, directory, 10)
        identity_generation_ok = True
        ports = secure.pick_distinct_free_udp_ports()
        target_plan = [
            {
                "address": f"127.0.0.1:{port}",
                "peer_certificate_sha256": secure.file_sha256(
                    dirs[f"host{index}"] / secure.CERTIFICATE_FILE
                ),
            }
            for index, port in enumerate(ports, 1)
        ]
        host_commands, parent_command = build_commands(
            host_bin, client_bin, ports, dirs, args.samples
        )
        commands = [*host_commands, parent_command]
        if secure.commands_contain_unsafe_flag(commands):
            raise RuntimeError("unsafe transport flag present")

        for command in host_commands:
            host = secure.TrackedProcess(command, ROOT)
            hosts.append(host)
            processes.append(host)
        if not all(host.wait_for_text(secure.HOST_READY_MARKER, 15) for host in hosts):
            raise RuntimeError("both Hosts did not become ready")

        parent = secure.TrackedProcess(parent_command, ROOT)
        processes.append(parent)
        expected_targets = {item["address"] for item in target_plan}
        overlap_deadline = time.monotonic() + min(args.timeout, 30)
        while time.monotonic() < overlap_deadline:
            parent_output = parent.output()
            overlap_proven = concurrent_probe_overlap(
                parent_output,
                expected_targets,
                args.samples,
                parent.poll() is None,
                [host.poll() is None for host in hosts],
            )
            if overlap_proven:
                overlap_observed_at_monotonic_ns = time.monotonic_ns()
                break
            if parent.poll() is not None:
                break
            time.sleep(0.005)

        parent_exit, parent_timed_out = parent.finish(args.timeout)
        parent_output = parent.output()
        host_results = [host.finish(15) for host in hosts]
        host_outputs = [host.output() for host in hosts]
        host_exits = [result[0] for result in host_results]
        host_timeouts = [result[1] for result in host_results]
    except Exception as error:
        runtime_error = secure.sanitize_log(str(error), temporary_root, 1_000)
    finally:
        for process in reversed(processes):
            process.close()
        if parent is not None:
            parent_output = parent.output()
            parent_exit = parent.poll() if parent_exit is None else parent_exit
        for index, host in enumerate(hosts):
            host_outputs[index] = host.output()
            if host_exits[index] is None:
                host_exits[index] = host.poll()
        temporary.cleanup()

    records: list[dict[str, object]] = []
    starts: list[dict[str, object]] = []
    stops: list[dict[str, object]] = []
    phase_checks: dict[str, bool] = {}
    validation_errors: list[str] = []
    try:
        records = parse_probe_records(parent_output)
        starts = parse_probe_starts(parent_output)
        stops = parse_probe_stops(parent_output)
        expected_targets = {item["address"] for item in target_plan}
        global_checks, global_errors = validate_global_evidence(
            parent_output,
            records,
            starts,
            stops,
            expected_targets,
            parent_exit,
            parent_timed_out,
            overlap_proven,
            args.samples,
        )
        phase_checks.update(
            {f"global_{name}": passed for name, passed in global_checks.items()}
        )
        validation_errors.extend(f"global:{error}" for error in global_errors)
        record_by_target = {str(record["target"]): record for record in records}
        start_by_target = {str(start["target"]): start for start in starts}
        stop_by_target = {str(stop["target"]): stop for stop in stops}
        for index, item in enumerate(target_plan, 1):
            address = item["address"]
            if (
                address not in record_by_target
                or address not in start_by_target
                or address not in stop_by_target
            ):
                validation_errors.append(f"target{index}:missing probe evidence")
                continue
            checks, errors = validate_target_evidence(
                address,
                item["peer_certificate_sha256"],
                host_outputs[index - 1],
                record_by_target[address],
                start_by_target[address],
                stop_by_target[address],
                host_exits[index - 1],
                host_timeouts[index - 1],
                args.samples,
                100_000,
            )
            phase_checks.update(
                {f"target{index}_{name}": passed for name, passed in checks.items()}
            )
            validation_errors.extend(f"target{index}:{error}" for error in errors)
    except (IndexError, KeyError, TypeError, ValueError) as error:
        validation_errors.append(str(error))

    cleanup_checks = {
        "identity_generation_ok": identity_generation_ok,
        "two_distinct_certificates": len(target_plan) == 2
        and len({item["peer_certificate_sha256"] for item in target_plan}) == 2,
        "one_supervisor_two_targets": len(commands) == 3
        and commands[-1].count("--target") == 2,
        "binary_hashes_complete": len(binary_hashes) == 3
        and all(len(value) == 64 for value in binary_hashes.values()),
        "no_unsafe_transport_flag": not secure.commands_contain_unsafe_flag(commands),
        "temporary_credentials_removed": not temporary_root.exists(),
        "no_runtime_error": runtime_error is None,
    }
    checks = {**phase_checks, **cleanup_checks}
    errors = [name for name, passed in checks.items() if not passed]
    errors.extend(validation_errors)
    if runtime_error:
        errors.insert(0, runtime_error)
    passed = bool(phase_checks) and all(checks.values()) and not errors

    report.update(
        status="passed" if passed else "failed",
        ok=passed,
        checks=checks,
        errors=errors,
        concurrent_probe_overlap=overlap_proven,
        overlap_observed_at_monotonic_ns=overlap_observed_at_monotonic_ns,
        target_plan=target_plan,
        results=[
            {
                "target": record.get("target"),
                "stamp": record.get("stamp"),
                "summary": record.get("summary"),
                "raw_samples": [
                    {"sequence": sequence, "latency_us": latency_us}
                    for sequence, latency_us in record.get("samples", [])
                ],
            }
            for record in records
        ],
        binaries=binary_hashes,
        logs={
            "parent_tail": secure.sanitize_log(parent_output, temporary_root),
            "host_tails": [
                secure.sanitize_log(output, temporary_root) for output in host_outputs
            ],
        },
    )
    secure.write_report(args.output, report)
    print(f"Report: {args.output}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
