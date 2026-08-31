#!/usr/bin/env python3
"""Fail-closed multi-Host concurrent input application-ACK latency evidence.

One Client supervisor launches 2, 4, 8, or 16 exact-pinned children. Every
probe interval must overlap, and every raw sample remains bound to its target
and full product lifecycle. This is single-machine application-ACK RTT, not
input-to-photon or a competitor comparison.
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
    r"codec_epoch=(\d+)\s+route_epoch=(\d+)\s+samples=(\d+)\s*$",
    re.MULTILINE | re.IGNORECASE,
)
STOP_PREFIX_RE = re.compile(r"^input-latency-stop:", re.MULTILINE | re.IGNORECASE)
STOP_RE = re.compile(
    r"^input-latency-stop:\s+target=(\S+)\s+session_id=(\d+)\s+"
    r"generation=(\d+)\s+authorization_epoch=(\d+)\s+display_epoch=(\d+)\s+"
    r"codec_epoch=(\d+)\s+route_epoch=(\d+)\s+samples=(\d+)\s*$",
    re.MULTILINE | re.IGNORECASE,
)
HOST_CERTIFICATE_RE = re.compile(
    r"^Host certificate:\s*([0-9a-f]{64})\s*$", re.MULTILINE | re.IGNORECASE
)
HOST_LISTEN_RE = re.compile(
    r"^Listening securely on\s+(\S+)\s*$", re.MULTILINE | re.IGNORECASE
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
            "route_epoch",
        }
        if not required <= fields.keys():
            raise ValueError(
                "input-latency record is missing target/full lifecycle fields"
            )
        parsed = input_probe.parse_input_latency(f"input-latency: {body}")
        stamp = (
            _positive_int(fields, "session_id"),
            _positive_int(fields, "generation"),
            _positive_int(fields, "authorization_epoch"),
            _positive_int(fields, "display_epoch"),
            _positive_int(fields, "codec_epoch"),
            _positive_int(fields, "route_epoch"),
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
            "stamp": tuple(int(value) for value in values[:6]),
            "samples": int(values[6]),
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


def parse_host_listen_address(output: str) -> str:
    matches = HOST_LISTEN_RE.findall(output)
    if len(matches) != 1:
        raise ValueError("expected exactly one Host listen address")
    address = matches[0]
    host, separator, raw_port = address.rpartition(":")
    try:
        port = int(raw_port)
    except ValueError as error:
        raise ValueError("Host listen address has an invalid port") from error
    if separator != ":" or host != "127.0.0.1" or not 1 <= port <= 65_535:
        raise ValueError("Host did not bind a real IPv4 loopback port")
    return address


def parse_proc_stat(text: str) -> dict[str, int | str]:
    open_paren = text.find("(")
    close_paren = text.rfind(")")
    if open_paren <= 0 or close_paren <= open_paren:
        raise ValueError("malformed /proc stat record")
    try:
        pid = int(text[:open_paren].strip())
        remainder = text[close_paren + 1 :].split()
        if len(remainder) < 20:
            raise ValueError("truncated /proc stat record")
        return {
            "pid": pid,
            "comm": text[open_paren + 1 : close_paren],
            "state": remainder[0],
            "ppid": int(remainder[1]),
            "pgrp": int(remainder[2]),
            "utime_ticks": int(remainder[11]),
            "stime_ticks": int(remainder[12]),
            "starttime_ticks": int(remainder[19]),
        }
    except (IndexError, ValueError) as error:
        raise ValueError("malformed /proc stat fields") from error


def _status_value(status: str, name: str, *, kilobytes: bool = False) -> int:
    prefix = f"{name}:"
    for line in status.splitlines():
        if line.startswith(prefix):
            parts = line[len(prefix) :].split()
            if not parts:
                break
            value = int(parts[0])
            if kilobytes and (len(parts) != 2 or parts[1] != "kB"):
                raise ValueError(f"unexpected {name} unit")
            return value
    raise ValueError(f"missing {name} in /proc status")


def read_process_sample(pid: int, proc_root: Path = Path("/proc")) -> dict[str, object]:
    process_dir = proc_root / str(pid)
    stat_before = parse_proc_stat((process_dir / "stat").read_text(encoding="utf-8"))
    if stat_before["pid"] != pid:
        raise ValueError("/proc PID identity mismatch")
    status = (process_dir / "status").read_text(encoding="utf-8")
    executable = (process_dir / "exe").resolve(strict=True)
    executable_stat = executable.stat()
    fd_count = sum(1 for _ in (process_dir / "fd").iterdir())
    stat_after = parse_proc_stat((process_dir / "stat").read_text(encoding="utf-8"))
    identity_before = tuple(
        stat_before[name] for name in ("pid", "pgrp", "starttime_ticks")
    )
    identity_after = tuple(
        stat_after[name] for name in ("pid", "pgrp", "starttime_ticks")
    )
    if identity_before != identity_after:
        raise ValueError("/proc PID identity changed during resource sampling")
    return {
        **stat_after,
        "exe_name": executable.name,
        "exe_device": executable_stat.st_dev,
        "exe_inode": executable_stat.st_ino,
        "rss_kib": _status_value(status, "VmRSS", kilobytes=True),
        "peak_rss_kib": _status_value(status, "VmHWM", kilobytes=True),
        "threads": _status_value(status, "Threads"),
        "fd_count": fd_count,
    }


def _group_identity(
    snapshot: dict[str, object],
) -> list[tuple[int, int, int, int, int]]:
    return [
        (
            int(member["pid"]),
            int(member["starttime_ticks"]),
            int(member["pgrp"]),
            int(member["exe_device"]),
            int(member["exe_inode"]),
        )
        for member in snapshot["members"]
    ]


def _discover_group_members(
    process_groups: set[int], proc_root: Path = Path("/proc")
) -> dict[int, list[int]]:
    members = {process_group: [] for process_group in process_groups}
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            stat = parse_proc_stat((entry / "stat").read_text(encoding="utf-8"))
        except (FileNotFoundError, PermissionError, ProcessLookupError, ValueError):
            continue
        process_group = int(stat["pgrp"])
        if process_group in members:
            members[process_group].append(int(stat["pid"]))
    for group_members in members.values():
        group_members.sort()
    return members


def _snapshot_known_group(
    leader_pid: int,
    process_group: int,
    member_pids: Sequence[int],
    expected_executable: Path,
) -> dict[str, object]:
    if leader_pid not in member_pids:
        raise ValueError("process-group discovery lost its leader")
    members = [read_process_sample(pid) for pid in member_pids]
    expected_stat = expected_executable.resolve(strict=True).stat()
    return {
        "leader_pid": leader_pid,
        "process_group": process_group,
        "members": members,
        "all_expected_executable": all(
            member["exe_device"] == expected_stat.st_dev
            and member["exe_inode"] == expected_stat.st_ino
            for member in members
        ),
        "all_expected_process_group": all(
            int(member["pgrp"]) == process_group for member in members
        ),
        "totals": {
            "member_count": len(members),
            "rss_kib": sum(int(member["rss_kib"]) for member in members),
            "peak_rss_kib": sum(int(member["peak_rss_kib"]) for member in members),
            "cpu_ticks": sum(
                int(member["utime_ticks"]) + int(member["stime_ticks"])
                for member in members
            ),
            "fd_count": sum(int(member["fd_count"]) for member in members),
            "threads": sum(int(member["threads"]) for member in members),
        },
    }


def _capture_resource_topology_once(
    parent: secure.TrackedProcess,
    hosts: Sequence[secure.TrackedProcess],
    client_bin: Path,
    host_bin: Path,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    parent_pid = parent.proc.pid
    host_pids = [host.proc.pid for host in hosts]
    parent_group = os.getpgid(parent_pid)
    host_groups = [os.getpgid(pid) for pid in host_pids]
    all_groups = {parent_group, *host_groups}
    if len(all_groups) != len(host_groups) + 1:
        raise ValueError("supervisor and Hosts must have distinct process groups")
    members = _discover_group_members(all_groups)
    client_snapshot = _snapshot_known_group(
        parent_pid, parent_group, members[parent_group], client_bin
    )
    host_snapshots = [
        _snapshot_known_group(pid, group, members[group], host_bin)
        for pid, group in zip(host_pids, host_groups)
    ]
    return client_snapshot, host_snapshots


def capture_resource_topology(
    parent: secure.TrackedProcess,
    hosts: Sequence[secure.TrackedProcess],
    client_bin: Path,
    host_bin: Path,
    target_count: int,
) -> tuple[dict[str, object], dict[str, bool]]:
    first_client, first_hosts = _capture_resource_topology_once(
        parent, hosts, client_bin, host_bin
    )
    time.sleep(0.002)
    second_client, second_hosts = _capture_resource_topology_once(
        parent, hosts, client_bin, host_bin
    )
    checks = {
        "client_process_group_exact": second_client["totals"]["member_count"]
        == target_count + 1
        and second_client["all_expected_executable"] is True
        and second_client["all_expected_process_group"] is True,
        "host_process_groups_exact": len(second_hosts) == target_count
        and all(
            snapshot["totals"]["member_count"] == 1
            and snapshot["all_expected_executable"] is True
            and snapshot["all_expected_process_group"] is True
            for snapshot in second_hosts
        ),
        "process_identities_stable": _group_identity(first_client)
        == _group_identity(second_client)
        and len(first_hosts) == len(second_hosts)
        and all(
            _group_identity(before) == _group_identity(after)
            for before, after in zip(first_hosts, second_hosts)
        ),
        "runtime_threads_bounded": int(second_client["totals"]["threads"])
        <= 1 + target_count * 6
        and sum(int(snapshot["totals"]["threads"]) for snapshot in second_hosts)
        <= target_count * 4,
    }
    return (
        {
            "available": True,
            "observed_at_monotonic_ns": time.monotonic_ns(),
            "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"),
            "note": (
                "RSS sums may double-count shared pages; CPU/FD/thread/RSS values are "
                "observational; process topology, identity, and the bounded two-worker "
                "runtime plus output-forwarder thread budget are hard gates"
            ),
            "client_group": second_client,
            "host_groups": second_hosts,
        },
        checks,
    )


def concurrent_probe_overlap(
    output: str,
    expected_targets: set[str],
    requested_samples: int,
    parent_alive: bool,
    host_alive: Sequence[bool],
) -> bool:
    if (
        not parent_alive
        or len(host_alive) != len(expected_targets)
        or not all(host_alive)
    ):
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


def build_host_commands(
    host_bin: Path,
    listen_addresses: Sequence[str],
    dirs: dict[str, Path],
) -> list[list[str]]:
    hosts: list[list[str]] = []
    for index, listen_address in enumerate(listen_addresses, 1):
        host_dir = dirs[f"host{index}"]
        hosts.append(
            [
                str(host_bin),
                "--listen",
                listen_address,
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
    return hosts


def build_parent_command(
    client_bin: Path,
    target_addresses: Sequence[str],
    dirs: dict[str, Path],
    samples: int,
) -> list[str]:
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
    for index, address in enumerate(target_addresses, 1):
        parent.extend(
            [
                "--target",
                target_value(
                    address,
                    dirs[f"host{index}"] / secure.CERTIFICATE_FILE,
                ),
            ]
        )
    return parent


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
        [(stamp[0], stamp[2])] if len(stamp) == 6 else [],
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
        and len(stamp) == 6
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
    start_by_target = {str(start.get("target", "")): start for start in starts}
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
        and all(len(stamp) == 6 for stamp in record_stamps)
        and len({stamp[0] for stamp in record_stamps}) == len(expected_targets),
        "exact_client_session_ids": len(client_ids) == len(expected_targets)
        and set(client_ids) == {stamp[0] for stamp in record_stamps if len(stamp) == 6},
        "exact_client_lifecycles": Counter(client_lifecycles)
        == Counter(stamp[1:] for stamp in record_stamps if len(stamp) == 6),
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
    parser.add_argument("--target-count", type=int, choices=(2, 4, 8, 16), default=2)
    parser.add_argument(
        "--samples", type=secure.bounded_int("samples", 100, 1024), default=256
    )
    parser.add_argument(
        "--timeout", type=secure.bounded_int("timeout", 10, 120), default=45
    )
    args = parser.parse_args(argv)
    minimum_samples = 1024 if args.target_count >= 8 else 256
    if args.samples < minimum_samples:
        parser.error(
            f"--target-count {args.target_count} requires at least {minimum_samples} samples "
            "so every process remains alive through both topology snapshots"
        )
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    revision, dirty = secure.repository_state()
    report: dict[str, object] = {
        "schema_version": 2,
        "status": "pending",
        "ok": False,
        "executed": False,
        "target_count": args.target_count,
        "scope": {
            "topology": "single_machine",
            "transport": "ipv4_loopback",
            "measurement": "client_to_host_application_ack_rtt",
            "not_proven": [
                "cross_machine",
                "input_to_photon",
                "AnyDesk_or_RustDesk_comparison",
            ],
        },
        "honest_scope": (
            f"{args.target_count} overlapping Client send to post-XTEST/X11-sync ACK intervals; "
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
    dirs = {"client": temporary_root / "client"}
    dirs.update(
        {
            f"host{index}": temporary_root / f"host{index}"
            for index in range(1, args.target_count + 1)
        }
    )
    processes: list[secure.TrackedProcess] = []
    hosts: list[secure.TrackedProcess] = []
    parent: secure.TrackedProcess | None = None
    host_outputs = [""] * args.target_count
    host_exits: list[int | None] = [None] * args.target_count
    host_timeouts = [False] * args.target_count
    parent_output = ""
    parent_exit: int | None = None
    parent_timed_out = False
    commands: list[Sequence[str]] = []
    target_plan: list[dict[str, object]] = []
    binary_hashes: dict[str, str] = {}
    identity_generation_ok = False
    overlap_proven = False
    overlap_observed_at_monotonic_ns: int | None = None
    resource_evidence: dict[str, object] = {}
    resource_checks: dict[str, bool] = {}
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
        host_commands = build_host_commands(
            host_bin,
            ["127.0.0.1:0"] * args.target_count,
            dirs,
        )
        commands = [*host_commands]
        if secure.commands_contain_unsafe_flag(commands):
            raise RuntimeError("unsafe transport flag present")

        for command in host_commands:
            host = secure.TrackedProcess(command, ROOT)
            hosts.append(host)
            processes.append(host)
        if not all(host.wait_for_text(secure.HOST_READY_MARKER, 15) for host in hosts):
            raise RuntimeError("not every Host became ready")

        actual_addresses = [parse_host_listen_address(host.output()) for host in hosts]
        if (
            len(actual_addresses) != args.target_count
            or len(set(actual_addresses)) != args.target_count
        ):
            raise RuntimeError("Hosts did not bind distinct loopback addresses")
        target_plan = [
            {
                "index": index,
                "address": address,
                "actual_listen_address": address,
                "peer_certificate_sha256": secure.file_sha256(
                    dirs[f"host{index}"] / secure.CERTIFICATE_FILE
                ),
            }
            for index, address in enumerate(actual_addresses, 1)
        ]
        parent_command = build_parent_command(
            client_bin, actual_addresses, dirs, args.samples
        )
        commands.append(parent_command)
        if secure.commands_contain_unsafe_flag(commands):
            raise RuntimeError("unsafe transport flag present")

        parent = secure.TrackedProcess(parent_command, ROOT)
        processes.append(parent)
        expected_targets = {str(item["address"]) for item in target_plan}
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
                resource_evidence, resource_checks = capture_resource_topology(
                    parent,
                    hosts,
                    client_bin,
                    host_bin,
                    args.target_count,
                )
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
        expected_targets = {str(item["address"]) for item in target_plan}
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
            address = str(item["address"])
            if (
                address not in record_by_target
                or address not in start_by_target
                or address not in stop_by_target
            ):
                validation_errors.append(f"target{index}:missing probe evidence")
                continue
            checks, errors = validate_target_evidence(
                address,
                str(item["peer_certificate_sha256"]),
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
        "all_certificates_distinct": len(target_plan) == args.target_count
        and len({item["peer_certificate_sha256"] for item in target_plan})
        == args.target_count,
        "one_supervisor_exact_target_count": len(commands) == args.target_count + 1
        and commands[-1].count("--target") == args.target_count,
        "binary_hashes_complete": len(binary_hashes) == 3
        and all(len(value) == 64 for value in binary_hashes.values()),
        "resource_topology_captured": bool(resource_checks),
        "no_unsafe_transport_flag": not secure.commands_contain_unsafe_flag(commands),
        "temporary_credentials_removed": not temporary_root.exists(),
        "no_runtime_error": runtime_error is None,
    }
    checks = {**phase_checks, **resource_checks, **cleanup_checks}
    errors = [name for name, passed in checks.items() if not passed]
    errors.extend(validation_errors)
    if runtime_error:
        errors.insert(0, runtime_error)
    passed = bool(phase_checks) and all(checks.values()) and not errors

    p95_values = [
        int(record["summary"]["p95_us"])
        for record in records
        if isinstance(record.get("summary"), dict) and "p95_us" in record["summary"]
    ]
    aggregate = {
        "target_count": len(records),
        "total_raw_samples": sum(len(record.get("samples", [])) for record in records),
        "p95_min_us": min(p95_values) if p95_values else None,
        "p95_max_us": max(p95_values) if p95_values else None,
        "note": "p95 range preserves per-target distributions; samples are not pooled",
    }
    target_indexes = {str(item["address"]): int(item["index"]) for item in target_plan}

    report.update(
        status="passed" if passed else "failed",
        ok=passed,
        checks=checks,
        errors=errors,
        concurrent_probe_overlap=overlap_proven,
        overlap_observed_at_monotonic_ns=overlap_observed_at_monotonic_ns,
        resource_evidence=resource_evidence,
        target_plan=target_plan,
        aggregate=aggregate,
        results=[
            {
                "index": target_indexes.get(str(record.get("target", ""))),
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
