#!/usr/bin/env python3
"""Fail-closed Linux/X11 proof that Ctrl-C reaps every multi-target child.

The gate starts four distinct exact-pinned Hosts and one Client supervisor.
After all four input-probe intervals overlap, SIGINT is sent only to the
supervisor PID. The supervisor must kill and reap its four direct children,
join eight captured-output forwarders, and exit nonzero without leaving any
recorded process identity behind. This is cancellation cleanup evidence, not a
cross-machine reliability, optical-latency, or competitor comparison result.
"""
from __future__ import annotations

import argparse
import os
import re
import signal
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import multi_target_input_latency_test as scale  # noqa: E402
import secure_connect_test as secure  # noqa: E402
import secure_input_latency_test as input_probe  # noqa: E402


ROOT = SCRIPT_DIR.parent
DEFAULT_OUTPUT = ROOT / "artifacts" / "multi-target-cancel.json"
TARGET_COUNT = 4
SAMPLES_PER_TARGET = 1_024
HOST_CLEANUP_TIMEOUT = 15.0

SPAWN_PREFIX_RE = re.compile(r"^multi-target:\s+spawned", re.I | re.M)
SPAWN_RE = re.compile(
    r"^multi-target:\s+spawned\s+target=(\S+)\s+pid=(\d+)\s*$",
    re.I | re.M,
)
CANCEL_PREFIX_RE = re.compile(r"^multi-target:\s+cancellation requested", re.I | re.M)
CANCEL_RE = re.compile(
    r"^multi-target:\s+cancellation requested\s+targets=(\d+)\s*$",
    re.I | re.M,
)
COMPLETE_PREFIX_RE = re.compile(r"^multi-target:\s+completed", re.I | re.M)
COMPLETE_RE = re.compile(
    r"^multi-target:\s+completed\s+reaped=(\d+)\s+forwarders_joined=(\d+)\s*$",
    re.I | re.M,
)
CANCELLATION_ERROR_MARKER = (
    "multi-target supervisor cancelled reaped=4 forwarders_joined=8"
)


def parse_spawn_events(output: str) -> list[dict[str, object]]:
    matches = SPAWN_RE.findall(output)
    if len(matches) != len(SPAWN_PREFIX_RE.findall(output)):
        raise ValueError("malformed multi-target spawn record")
    events = [{"target": target, "pid": int(pid)} for target, pid in matches]
    targets = [str(event["target"]) for event in events]
    pids = [int(event["pid"]) for event in events]
    if (
        len(events) != TARGET_COUNT
        or any(pid <= 0 for pid in pids)
        or len(set(targets)) != TARGET_COUNT
        or len(set(pids)) != TARGET_COUNT
    ):
        raise ValueError("spawn targets and PIDs must be four positive unique values")
    return events


def parse_precancel_state(
    output: str, expected_targets: set[str]
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    spawned = parse_spawn_events(output)
    starts = scale.parse_probe_starts(output)
    if (
        {str(event["target"]) for event in spawned} != expected_targets
        or len(starts) != TARGET_COUNT
        or {str(start["target"]) for start in starts} != expected_targets
        or any(start["samples"] != SAMPLES_PER_TARGET for start in starts)
    ):
        raise ValueError("spawn/start targets or sample counts do not match the plan")
    if (
        scale.STOP_PREFIX_RE.search(output)
        or input_probe.INPUT_RE.search(output)
        or CANCEL_PREFIX_RE.search(output)
        or COMPLETE_PREFIX_RE.search(output)
    ):
        raise ValueError("probe completion or cancellation appeared before SIGINT")
    return spawned, starts


def parse_final_events(
    output: str, expected_targets: set[str]
) -> tuple[list[dict[str, object]], list[dict[str, object]], dict[str, int]]:
    spawned = parse_spawn_events(output)
    starts = scale.parse_probe_starts(output)
    if (
        {str(event["target"]) for event in spawned} != expected_targets
        or len(starts) != TARGET_COUNT
        or {str(start["target"]) for start in starts} != expected_targets
    ):
        raise ValueError("final spawn/start records no longer match the plan")
    cancellations = CANCEL_RE.findall(output)
    completions = COMPLETE_RE.findall(output)
    if len(cancellations) != 1 or len(CANCEL_PREFIX_RE.findall(output)) != 1:
        raise ValueError("expected exactly one complete cancellation record")
    if len(completions) != 1 or len(COMPLETE_PREFIX_RE.findall(output)) != 1:
        raise ValueError("expected exactly one complete supervisor result")
    cancelled_targets = int(cancellations[0])
    reaped, forwarders_joined = (int(value) for value in completions[0])
    if (cancelled_targets, reaped, forwarders_joined) != (
        TARGET_COUNT,
        TARGET_COUNT,
        TARGET_COUNT * 2,
    ):
        raise ValueError("cancellation/reap/forwarder counters do not match")
    if output.count(CANCELLATION_ERROR_MARKER) != 1:
        raise ValueError("bounded cancellation error summary is missing or duplicated")
    if scale.STOP_PREFIX_RE.search(output) or input_probe.INPUT_RE.search(output):
        raise ValueError("a child completed its probe instead of being cancelled")
    return spawned, starts, {
        "cancelled_targets": cancelled_targets,
        "reaped": reaped,
        "forwarders_joined": forwarders_joined,
    }


def process_identity_is_gone(
    identity: dict[str, object], proc_root: Path = Path("/proc")
) -> bool:
    pid = int(identity["pid"])
    try:
        current = scale.read_process_sample(pid, proc_root)
    except (FileNotFoundError, ProcessLookupError):
        return True
    except (PermissionError, ValueError):
        return False
    names = ("pid", "starttime_ticks", "exe_device", "exe_inode")
    return any(int(current[name]) != int(identity[name]) for name in names)


def _finish_hosts_with_common_deadline(
    hosts: Sequence[secure.TrackedProcess], timeout: float
) -> list[tuple[int | None, bool]]:
    deadline = time.monotonic() + timeout
    results: list[tuple[int | None, bool]] = []
    for host in hosts:
        remaining = max(0.1, deadline - time.monotonic())
        results.append(host.finish(remaining))
    return results


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host-bin", type=Path)
    parser.add_argument("--client-bin", type=Path)
    parser.add_argument("--identity-bin", type=Path)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--timeout", type=secure.bounded_int("timeout", 15, 120), default=45
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    revision, dirty = secure.repository_state()
    report: dict[str, object] = {
        "schema_version": 2,
        "status": "pending",
        "ok": False,
        "executed": False,
        "scope": "four-target Linux process cancellation and direct-child cleanup",
        "honest_scope": (
            "single-machine SIGINT/direct-child evidence only; not process-tree cleanup, "
            "cross-machine soak, physical input-to-photon, or AnyDesk comparison"
        ),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "source": {
            "repository_revision_at_test": revision,
            "worktree_dirty_at_test": dirty,
        },
        "target_count": TARGET_COUNT,
        "samples_per_target": SAMPLES_PER_TARGET,
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
    temporary = tempfile.TemporaryDirectory(prefix="open-desk-multi-target-cancel-")
    temporary_root = Path(temporary.name)
    dirs = {"client": temporary_root / "client"}
    dirs.update(
        {
            f"host{index}": temporary_root / f"host{index}"
            for index in range(1, TARGET_COUNT + 1)
        }
    )
    processes: list[secure.TrackedProcess] = []
    hosts: list[secure.TrackedProcess] = []
    parent: secure.TrackedProcess | None = None
    commands: list[list[str]] = []
    target_plan: list[dict[str, object]] = []
    binary_hashes: dict[str, str] = {}
    identity_generation_ok = False
    overlap_proven = False
    resource_evidence: dict[str, object] = {}
    resource_checks: dict[str, bool] = {}
    child_identities: list[dict[str, object]] = []
    supervisor_result: dict[str, int] = {}
    parent_output = ""
    parent_exit: int | None = None
    parent_timed_out = False
    host_outputs = [""] * TARGET_COUNT
    host_exits: list[int | None] = [None] * TARGET_COUNT
    host_timeouts = [False] * TARGET_COUNT
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

        host_commands = scale.build_host_commands(
            host_bin, ["127.0.0.1:0"] * TARGET_COUNT, dirs
        )
        commands.extend(host_commands)
        if secure.commands_contain_unsafe_flag(commands):
            raise RuntimeError("unsafe transport flag present")
        for command in host_commands:
            host = secure.TrackedProcess(command, ROOT)
            hosts.append(host)
            processes.append(host)
        if not all(host.wait_for_text(secure.HOST_READY_MARKER, 15) for host in hosts):
            raise RuntimeError("not every Host became ready")

        addresses = [scale.parse_host_listen_address(host.output()) for host in hosts]
        if len(set(addresses)) != TARGET_COUNT:
            raise RuntimeError("Hosts did not bind four distinct loopback addresses")
        target_plan = [
            {
                "index": index,
                "address": address,
                "peer_certificate_sha256": secure.file_sha256(
                    dirs[f"host{index}"] / secure.CERTIFICATE_FILE
                ),
            }
            for index, address in enumerate(addresses, 1)
        ]
        expected_targets = set(addresses)
        parent_command = scale.build_parent_command(
            client_bin, addresses, dirs, SAMPLES_PER_TARGET
        )
        commands.append(parent_command)
        if secure.commands_contain_unsafe_flag(commands):
            raise RuntimeError("unsafe transport flag present")

        parent = secure.TrackedProcess(parent_command, ROOT)
        processes.append(parent)
        overlap_deadline = time.monotonic() + min(args.timeout, 30)
        while time.monotonic() < overlap_deadline:
            parent_output = parent.output()
            overlap_proven = scale.concurrent_probe_overlap(
                parent_output,
                expected_targets,
                SAMPLES_PER_TARGET,
                parent.poll() is None,
                [host.poll() is None for host in hosts],
            )
            if overlap_proven:
                spawned, _ = parse_precancel_state(parent_output, expected_targets)
                resource_evidence, resource_checks = scale.capture_resource_topology(
                    parent, hosts, client_bin, host_bin, TARGET_COUNT
                )
                members = resource_evidence["client_group"]["members"]
                child_identities = [
                    member
                    for member in members
                    if int(member["pid"]) != parent.proc.pid
                ]
                if {int(member["pid"]) for member in child_identities} != {
                    int(event["pid"]) for event in spawned
                }:
                    raise RuntimeError("spawn logs do not match the exact Client process group")
                break
            if parent.poll() is not None:
                break
            time.sleep(0.005)
        if not overlap_proven:
            raise RuntimeError("four overlapping input-probe intervals were not observed")

        os.kill(parent.proc.pid, signal.SIGINT)
        parent_exit, parent_timed_out = parent.finish(args.timeout)
        parent_output = parent.output()
        _finish_spawned, _finish_starts, supervisor_result = parse_final_events(
            parent_output, expected_targets
        )
        host_results = _finish_hosts_with_common_deadline(
            hosts, HOST_CLEANUP_TIMEOUT
        )
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

    child_identities_absent = bool(child_identities) and all(
        process_identity_is_gone(identity) for identity in child_identities
    )
    checks = {
        "identity_generation_ok": identity_generation_ok,
        "binary_hashes_complete": len(binary_hashes) == 3
        and all(len(value) == 64 for value in binary_hashes.values()),
        "no_unsafe_transport_flag": bool(commands)
        and not secure.commands_contain_unsafe_flag(commands),
        "four_probe_intervals_overlap": overlap_proven,
        "client_process_group_exact": resource_checks.get(
            "client_process_group_exact"
        )
        is True,
        "host_process_groups_exact": resource_checks.get("host_process_groups_exact")
        is True,
        "process_identities_stable": resource_checks.get(
            "process_identities_stable"
        )
        is True,
        "runtime_threads_bounded": resource_checks.get("runtime_threads_bounded")
        is True,
        "parent_exit_bounded_nonzero": parent_exit is not None
        and parent_exit != 0
        and not parent_timed_out,
        "cancelled_all_targets": supervisor_result.get("cancelled_targets")
        == TARGET_COUNT,
        "all_children_reaped": supervisor_result.get("reaped") == TARGET_COUNT,
        "all_forwarders_joined": supervisor_result.get("forwarders_joined")
        == TARGET_COUNT * 2,
        "child_process_identities_absent": child_identities_absent,
        "hosts_release_all": len(host_outputs) == TARGET_COUNT
        and all(output.count("input: ReleaseAll applied") == 1 for output in host_outputs),
        "hosts_exact_mtls": len(host_outputs) == TARGET_COUNT
        and all(
            output.count("mTLS: exact client certificate authenticated") == 1
            for output in host_outputs
        ),
        "hosts_observe_authenticated_peer_loss": len(host_outputs) == TARGET_COUNT
        and all(
            output.count("session: authenticated peer transport lost") == 1
            for output in host_outputs
        ),
        "hosts_exit_naturally": len(host_exits) == TARGET_COUNT
        and all(code is not None for code in host_exits)
        and not any(host_timeouts),
        "temporary_credentials_removed": not temporary_root.exists(),
        "no_runtime_error": runtime_error is None,
    }
    errors = [name for name, passed in checks.items() if not passed]
    if runtime_error:
        errors.insert(0, runtime_error)
    passed = all(checks.values()) and not errors
    report.update(
        status="passed" if passed else "failed",
        ok=passed,
        checks=checks,
        errors=errors,
        target_plan=target_plan,
        supervisor=supervisor_result,
        parent_exit=parent_exit,
        host_exits=host_exits,
        child_identities=child_identities,
        resource_evidence=resource_evidence,
        binaries=binary_hashes,
        commands=[
            secure.sanitize_log(" ".join(command), temporary_root, 4_000)
            for command in commands
        ],
        logs={
            "parent_tail": secure.sanitize_log(parent_output, temporary_root, 8_000),
            "host_tails": [
                secure.sanitize_log(output, temporary_root, 4_000)
                for output in host_outputs
            ],
        },
    )
    secure.write_report(args.output, report)
    print(f"Report: {args.output}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
