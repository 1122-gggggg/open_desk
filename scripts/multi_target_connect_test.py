#!/usr/bin/env python3
"""Linux/X11 evidence smoke for concurrent multi-target sessions.

This is deliberately a bounded, single-machine test: two loopback Hosts are
authenticated by one Client process and a second phase proves one bad target
does not hide a healthy target's result.
"""
from __future__ import annotations

import argparse
import importlib.util
import re
import tempfile
import time
from pathlib import Path
from typing import Sequence

ROOT = Path(__file__).resolve().parents[1]
HELPER_PATH = ROOT / "scripts" / "secure_connect_test.py"
SPEC = importlib.util.spec_from_file_location("secure_connect_test", HELPER_PATH)
assert SPEC and SPEC.loader
secure = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(secure)

HOST_ACTIVE_RE = re.compile(r"^session:\s*active\s+session_id=(\d+)\s*$", re.M | re.I)
CLIENT_ACTIVE_RE = re.compile(r"^handshake:\s*active\s+session_id=(\d+)\s*$", re.M | re.I)
RECEIVED_RE = re.compile(r"^received:\s*session_id=(\d+)\s+frames=(\d+)\s*$", re.M | re.I)
ROUTE_RE = re.compile(r"^route:\s*authenticated\s+(\S+)\s+after\s+racing\s+(\d+)\s+candidate", re.M | re.I)
STREAM_RE = re.compile(r"^stream:\s+(?:H\.264 4:2:0|explicit Raw NV12)\s+\d+x\d+\s+over QUIC DATAGRAM", re.M | re.I)
HOST_CERTIFICATE_RE = re.compile(r"^Host certificate:\s*([0-9a-f]{64})\s*$", re.M | re.I)


def pick_ports() -> tuple[int, int]:
    return secure.pick_distinct_free_udp_ports()


def target(address: str, certificate: Path) -> str:
    return f"{address},{certificate}"


def build_commands(
    host_bin: Path, client_bin: Path, ports: tuple[int, int], dirs: dict[str, Path],
    frames: int, fps: int, max_width: int, max_height: int,
) -> tuple[list[str], list[str], list[str], list[str]]:
    hosts = []
    for index, port in enumerate(ports, 1):
        folder = dirs[f"host{index}"]
        hosts.append([
            str(host_bin), "--listen", f"127.0.0.1:{port}",
            "--identity-cert", str(folder / secure.CERTIFICATE_FILE),
            "--identity-key", str(folder / secure.PRIVATE_KEY_FILE),
            "--peer-cert", str(dirs["client"] / secure.CERTIFICATE_FILE),
            "--pairing-timeout", "30", "--max-width", str(max_width),
            "--max-height", str(max_height), "--fps", str(fps),
            "--frames", str(max(frames * 2, frames + 8)), "--max-sessions", "1",
        ])
    client_base = [str(client_bin), "--bind", "127.0.0.1:0",
                   "--identity-cert", str(dirs["client"] / secure.CERTIFICATE_FILE),
                   "--identity-key", str(dirs["client"] / secure.PRIVATE_KEY_FILE),
                   "--pairing-timeout", "30",
                   "--frames", str(frames)]
    valid = client_base + ["--target", target(f"127.0.0.1:{ports[0]}", dirs["host1"] / secure.CERTIFICATE_FILE),
                           "--target", target(f"127.0.0.1:{ports[1]}", dirs["host2"] / secure.CERTIFICATE_FILE)]
    bad_base = client_base.copy()
    bad_base[bad_base.index("--pairing-timeout") + 1] = "8"
    bad = bad_base + ["--target", target("127.0.0.1:1", dirs["host1"] / secure.CERTIFICATE_FILE),
                      "--target", target(f"127.0.0.1:{ports[0]}", dirs["host1"] / secure.CERTIFICATE_FILE)]
    return hosts[0], hosts[1], valid, bad


def parse_evidence(output: str) -> dict[str, object]:
    return {"host_session_ids": [int(x) for x in HOST_ACTIVE_RE.findall(output)],
            "client_session_ids": [int(x) for x in CLIENT_ACTIVE_RE.findall(output)],
            "received": [(int(a), int(b)) for a, b in RECEIVED_RE.findall(output)],
            "routes": [(a, int(b)) for a, b in ROUTE_RE.findall(output)],
            "desktop_streams": len(STREAM_RE.findall(output)),
            "host_certificates": [value.lower() for value in HOST_CERTIFICATE_RE.findall(output)],
            "client_exact_mtls": output.lower().count("exact host certificate authenticated"),
            "host_exact_mtls": output.lower().count("exact client certificate authenticated")}


def concurrent_markers(
    host_outputs: Sequence[str], host_alive: Sequence[bool], client_alive: bool
) -> bool:
    return client_alive and len(host_outputs) == 2 and len(host_alive) == 2 and all(host_alive) and all(
        "mTLS: exact client certificate authenticated" in text and HOST_ACTIVE_RE.search(text)
        for text in host_outputs
    )


def validate_phase1(
    host_outputs: Sequence[str],
    client_output: str,
    host_exits: Sequence[int | None],
    host_timeouts: Sequence[bool],
    parent_exit: int | None,
    parent_timed_out: bool,
    frames: int,
    concurrency_proven: bool,
    expected_routes: set[str],
    expected_certificates: set[str],
) -> tuple[dict[str, bool], list[str]]:
    hosts = [parse_evidence(text) for text in host_outputs]
    client = parse_evidence(client_output)
    host_ids = [
        evidence["host_session_ids"][0]
        for evidence in hosts
        if len(evidence["host_session_ids"]) == 1
    ]
    client_ids = client["client_session_ids"]
    received = client["received"]
    received_ids = [session_id for session_id, _ in received]
    host_certificates = [
        evidence["host_certificates"][0]
        for evidence in hosts
        if len(evidence["host_certificates"]) == 1
    ]
    checks = {
        "parent_exit_zero": parent_exit == 0 and not parent_timed_out,
        "two_hosts_exit_zero": len(host_exits) == 2
        and len(host_timeouts) == 2
        and not any(host_timeouts)
        and all(exit_code == 0 for exit_code in host_exits),
        "concurrent_authenticated_hosts": concurrency_proven,
        "two_distinct_host_certificates": len(host_certificates) == 2
        and set(host_certificates) == expected_certificates,
        "two_distinct_host_sessions": len(host_ids) == 2 and len(set(host_ids)) == 2,
        "exact_session_id_sets": len(client_ids) == 2
        and len(received) == 2
        and set(host_ids) == set(client_ids) == set(received_ids),
        "both_requested_frames": len(received) == 2
        and all(count >= frames for _, count in received),
        "two_exact_routes": len(client["routes"]) == 2
        and {route for route, _ in client["routes"]} == expected_routes
        and all(attempts == 1 for _, attempts in client["routes"]),
        "both_desktop_streams": len(hosts) == 2
        and all(evidence["desktop_streams"] == 1 for evidence in hosts),
        "exact_mtls_both_sides": len(hosts) == 2
        and all(evidence["host_exact_mtls"] == 1 for evidence in hosts)
        and client["client_exact_mtls"] == 2,
    }
    errors = [name for name, passed in checks.items() if not passed]
    return checks, errors


def validate_phase2(
    healthy_output: str,
    parent_output: str,
    parent_exit: int | None,
    parent_timed_out: bool,
    healthy_exit: int | None,
    healthy_timed_out: bool,
    frames: int,
    healthy_route: str,
    failed_route: str,
    healthy_certificate: str,
) -> tuple[dict[str, bool], list[str]]:
    evidence = parse_evidence(healthy_output)
    parent = parse_evidence(parent_output)
    host_ids = evidence["host_session_ids"]
    parent_ids = parent["client_session_ids"]
    received = parent["received"]
    checks = {
        "parent_aggregates_failed_target": parent_exit is not None
        and parent_exit != 0
        and not parent_timed_out
        and "target children failed" in parent_output
        and failed_route in parent_output,
        "healthy_exit_zero": healthy_exit == 0 and not healthy_timed_out,
        "healthy_exact_mtls_both_sides": evidence["host_exact_mtls"] == 1
        and parent["client_exact_mtls"] == 1,
        "healthy_certificate_matches_plan": evidence["host_certificates"]
        == [healthy_certificate],
        "healthy_stream": evidence["desktop_streams"] == 1,
        "healthy_route_only": parent["routes"] == [(healthy_route, 1)],
        "healthy_ids_and_frames_match": len(host_ids) == 1
        and parent_ids == host_ids
        and len(received) == 1
        and received[0][0] == host_ids[0]
        and received[0][1] >= frames,
    }
    return checks, [name for name, passed in checks.items() if not passed]


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host-bin", "--host-binary", dest="host_binary", type=Path)
    parser.add_argument("--client-bin", "--client-binary", dest="client_binary", type=Path)
    parser.add_argument("--identity-bin", "--identity-binary", dest="identity_binary", type=Path)
    parser.add_argument("--output", type=Path, default=ROOT / "artifacts" / "multi-target-connect.json")
    parser.add_argument("--frames", type=secure.bounded_int("frames", 2, 120), default=5)
    parser.add_argument("--fps", type=secure.bounded_int("fps", 1, 120), default=10)
    parser.add_argument(
        "--max-width", type=secure.bounded_int("max-width", 2, 3840), default=320
    )
    parser.add_argument(
        "--max-height", type=secure.bounded_int("max-height", 2, 2160), default=180
    )
    args = parser.parse_args(argv)
    if args.max_width % 2 or args.max_height % 2:
        parser.error("--max-width and --max-height must be even for NV12")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    skip = secure.prerequisite_skip_reason()
    report: dict[str, object] = {
        "schema_version": 1,
        "status": "pending",
        "ok": False,
        "executed": False,
        "scope": (
            "two concurrent Linux X11 Hosts on one-machine IPv4 loopback; "
            "not a 16-Host soak, cross-machine result, or AnyDesk superiority claim"
        ),
        "requested_frames": args.frames,
        "checks": {},
        "errors": [],
    }
    if skip:
        report.update(status="skipped", skip_reason=skip)
        secure.write_report(args.output, report)
        print(f"SKIPPED: {skip}")
        print(f"Report: {args.output}")
        return 0
    report["executed"] = True
    root = Path(tempfile.mkdtemp(prefix="latencydesk-multi-"))
    dirs = {name: root / name for name in ("client", "host1", "host2")}
    commands: list[Sequence[str]] = []
    all_processes: list[secure.TrackedProcess] = []
    identity_generation_ok = False
    phase_checks: dict[str, bool] = {}
    runtime_error: str | None = None
    evidence: dict[str, object] = {}
    try:
        for folder in dirs.values():
            folder.mkdir()
        identity = secure.find_binary("latencydesk-identity", args.identity_binary)
        host_bin = secure.find_binary("latencydesk-host", args.host_binary)
        client_bin = secure.find_binary("latencydesk-client", args.client_binary)
        for name, folder in dirs.items():
            secure.generate_identity(identity, name, folder, 10)
        identity_generation_ok = True
        ports = pick_ports()
        target_plan = [
            {
                "address": f"127.0.0.1:{ports[index - 1]}",
                "peer_certificate_sha256": secure.file_sha256(
                    dirs[f"host{index}"] / secure.CERTIFICATE_FILE
                ),
            }
            for index in (1, 2)
        ]
        expected_certificates = {
            item["peer_certificate_sha256"] for item in target_plan
        }
        host1, host2, valid, bad = build_commands(host_bin, client_bin, ports, dirs, args.frames, args.fps, args.max_width, args.max_height)
        commands.extend((host1, host2, valid, bad))
        phase1_hosts: list[secure.TrackedProcess] = []
        for command in (host1, host2):
            process = secure.TrackedProcess(command, ROOT)
            phase1_hosts.append(process)
            all_processes.append(process)
        if not all(
            process.wait_for_text(secure.HOST_READY_MARKER, 10)
            for process in phase1_hosts
        ):
            raise RuntimeError("both Hosts did not become ready")
        client_process = secure.TrackedProcess(valid, ROOT)
        all_processes.append(client_process)
        # Capture the proof while the Client and both Host processes overlap.
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and not all(
            HOST_ACTIVE_RE.search(process.output()) for process in phase1_hosts
        ):
            time.sleep(0.05)
        concurrent_snapshots = [process.output() for process in phase1_hosts]
        concurrent_alive = [process.poll() is None for process in phase1_hosts]
        concurrency_proven = concurrent_markers(
            concurrent_snapshots,
            concurrent_alive,
            client_process.poll() is None,
        )
        client_exit, client_timeout = client_process.finish(45)
        client_output = client_process.output()
        host_results = [process.finish(10) for process in phase1_hosts]
        host_outputs = [process.output() for process in phase1_hosts]
        host_exits = [result[0] for result in host_results]
        host_timeouts = [result[1] for result in host_results]
        expected_routes = {f"127.0.0.1:{ports[0]}", f"127.0.0.1:{ports[1]}"}
        checks1, _ = validate_phase1(
            host_outputs,
            client_output,
            host_exits,
            host_timeouts,
            client_exit,
            client_timeout,
            args.frames,
            concurrency_proven,
            expected_routes,
            expected_certificates,
        )

        # Phase 2 uses a fresh healthy Host on the first address.
        healthy = secure.TrackedProcess(host1, ROOT)
        all_processes.append(healthy)
        if not healthy.wait_for_text(secure.HOST_READY_MARKER, 10):
            raise RuntimeError("healthy phase-2 Host did not become ready")
        bad_parent = secure.TrackedProcess(bad, ROOT)
        all_processes.append(bad_parent)
        bad_exit, bad_timeout = bad_parent.finish(30)
        bad_output = bad_parent.output()
        healthy_output = healthy.output()
        healthy_exit, healthy_timeout = healthy.finish(15)
        checks2, _ = validate_phase2(
            healthy_output,
            bad_output,
            bad_exit,
            bad_timeout,
            healthy_exit,
            healthy_timeout,
            args.frames,
            f"127.0.0.1:{ports[0]}",
            "127.0.0.1:1",
            target_plan[0]["peer_certificate_sha256"],
        )
        phase_checks = {
            **{f"phase1_{name}": passed for name, passed in checks1.items()},
            **{f"phase2_{name}": passed for name, passed in checks2.items()},
        }
        evidence = {
            "target_plan": target_plan,
            "phase1_client": parse_evidence(client_output),
            "phase1_hosts": [parse_evidence(output) for output in host_outputs],
            "phase2_client": parse_evidence(bad_output),
            "phase2_host": parse_evidence(healthy_output),
            "logs": {
                "phase1_client": secure.sanitize_log(client_output, root),
                "phase1_hosts": [
                    secure.sanitize_log(output, root) for output in host_outputs
                ],
                "phase2_client": secure.sanitize_log(bad_output, root),
                "phase2_host": secure.sanitize_log(healthy_output, root),
            },
        }
    except Exception as error:
        runtime_error = secure.sanitize_log(str(error), root, 1_000)
    finally:
        for process in reversed(all_processes):
            process.close()
        # Keep credentials out of artifacts and remove only our private temp root.
        import shutil
        shutil.rmtree(root, ignore_errors=True)
        cleanup_checks = {
            "identity_generation_ok": identity_generation_ok,
            "no_unsafe_transport_flag": not secure.commands_contain_unsafe_flag(commands),
            "temporary_credentials_removed": not root.exists(),
            "no_runtime_error": runtime_error is None,
        }
        checks = {**phase_checks, **cleanup_checks}
        errors = [name for name, passed in checks.items() if not passed]
        if runtime_error:
            errors.insert(0, runtime_error)
        passed = bool(phase_checks) and all(checks.values()) and not errors
        report.update(
            status="passed" if passed else "failed",
            ok=passed,
            checks=checks,
            errors=errors,
            evidence=evidence,
            real_desktop_capture=passed
            and checks.get("phase1_both_desktop_streams", False)
            and checks.get("phase2_healthy_stream", False),
        )
        secure.write_report(args.output, report)
        print(f"Report: {args.output}")
    return 0 if report.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
