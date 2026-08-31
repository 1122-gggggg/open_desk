#!/usr/bin/env python3
"""Fail-closed Linux process evidence for the isolated ICE connectivity probe."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import socket
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import secure_connect_test as secure  # noqa: E402


CLIENT_REPORT_RE = re.compile(r"^ice-connectivity-probe:\s+(.*)$", re.I | re.M)
HOST_REPORT_RE = re.compile(r"^ice-connectivity-probe-host:\s+(.*)$", re.I | re.M)
CLIENT_SCOPE_RE = re.compile(r"^ice-connectivity-probe-scope:\s+(.*)$", re.I | re.M)
CLIENT_ACTIVE_LOCAL_RE = re.compile(r"^Local Binding Address:\s*(\S+)\s*$", re.I | re.M)
HOST_ACTIVE_REMOTE_RE = re.compile(r"^quic-peer:\s+source=(\S+)\s*$", re.I | re.M)
FIELD_RE = re.compile(r"([a-z_]+)=([^\s]+)")
SECRET_RE = re.compile(
    r"(?:private[-_ ]?key|(?:ice[-_ ]?)?(?:ufrag|password)|"
    r"BEGIN [^-\n]*PRIVATE|known-secret-sentinel)",
    re.I,
)

BOOLEAN_FIELDS = (
    "authenticated",
    "success",
    "exact_mtls",
    "full_stamp_bound",
    "control_nonces_bound",
    "route_changed",
)
INTEGER_FIELDS = (
    "session_id",
    "generation",
    "requests_sent",
    "successes_received",
    "requests_received",
    "nominations_sent",
    "ice_elapsed_ms",
    "quic_echo_elapsed_ms",
)


def _parse_boolean(value: str, name: str) -> bool:
    if value not in {"true", "false"}:
        raise ValueError(f"invalid {name} boolean")
    return value == "true"


def parse_probe_report(output: str, *, role: str) -> dict[str, object]:
    pattern = CLIENT_REPORT_RE if role == "client" else HOST_REPORT_RE
    matches = pattern.findall(output)
    if len(matches) != 1:
        raise ValueError(f"expected exactly one {role} ICE probe report")
    fields: dict[str, object] = dict(FIELD_RE.findall(matches[0]))
    required = (
        "authenticated",
        "success",
        "role",
        "session_id",
        "generation",
        "local",
        "remote",
        "requests_sent",
        "successes_received",
        "requests_received",
        "nominations_sent",
        "ice_elapsed_ms",
        "quic_echo_elapsed_ms",
        "exact_mtls",
        "full_stamp_bound",
        "control_nonces_bound",
        "route_changed",
        "active_route",
    )
    missing = [name for name in required if name not in fields]
    if missing:
        raise ValueError(f"incomplete {role} ICE probe report: {missing}")

    expected_role = "controlling" if role == "client" else "controlled"
    if fields["role"] != expected_role:
        raise ValueError(f"unexpected {role} ICE role")
    for name in INTEGER_FIELDS:
        fields[name] = int(str(fields[name]))
    for name in BOOLEAN_FIELDS:
        fields[name] = _parse_boolean(str(fields[name]), name)
    if role == "client":
        if "frames_after_probe" not in fields:
            raise ValueError("client report lacks post-probe frame evidence")
        fields["frames_after_probe"] = int(str(fields["frames_after_probe"]))
    return fields


def parse_probe_output(output: str, *, role: str) -> dict[str, object]:
    if SECRET_RE.search(output):
        raise ValueError(f"{role} output contains a secret-like token")
    report = parse_probe_report(output, role=role)
    required_true = (
        "authenticated",
        "success",
        "exact_mtls",
        "full_stamp_bound",
        "control_nonces_bound",
    )
    if not all(bool(report[name]) for name in required_true):
        raise ValueError(f"{role} probe missed an authentication/transcript gate")
    if report["route_changed"]:
        raise ValueError(f"{role} probe reported an active-route change")
    if int(report["successes_received"]) < 1 or int(report["nominations_sent"]) < 1:
        raise ValueError(f"{role} probe did not complete checks and nomination")

    if role == "client":
        scopes = CLIENT_SCOPE_RE.findall(output)
        if len(scopes) != 1:
            raise ValueError("expected exactly one Client ICE probe scope line")
        scope = dict(FIELD_RE.findall(scopes[0]))
        for name in (
            "fresh_socket",
            "same_socket_handoff",
            "connectivity_checks",
            "nomination",
            "client_nonce_nonzero",
            "host_nonce_nonzero",
        ):
            if not _parse_boolean(scope.get(name, ""), name):
                raise ValueError(f"Client scope gate {name} failed")
        for name in ("route_promotion", "nat_traversal_claim", "internet_claim"):
            if _parse_boolean(scope.get(name, ""), name):
                raise ValueError(f"Client scope overclaimed {name}")
        if int(report["frames_after_probe"]) < 1:
            raise ValueError("Client did not receive a post-probe frame")
    return report


def build_commands(
    host_bin: Path,
    client_bin: Path,
    listen: str,
    host_dir: Path,
    client_dir: Path,
    frames: int = 3,
) -> tuple[list[str], list[str]]:
    host_certificate = host_dir / secure.CERTIFICATE_FILE
    client_certificate = client_dir / secure.CERTIFICATE_FILE
    host = [
        str(host_bin),
        "--ice-connectivity-probe",
        "--listen",
        listen,
        "--frames",
        str(frames),
        "--identity-cert",
        str(host_certificate),
        "--identity-key",
        str(host_dir / secure.PRIVATE_KEY_FILE),
        "--peer-cert",
        str(client_certificate),
    ]
    client = [
        str(client_bin),
        "--ice-connectivity-probe",
        "--connect",
        listen,
        "--bind",
        "127.0.0.1:0",
        "--identity-cert",
        str(client_certificate),
        "--identity-key",
        str(client_dir / secure.PRIVATE_KEY_FILE),
        "--peer-cert",
        str(host_certificate),
    ]
    return host, client


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _one_match(pattern: re.Pattern[str], output: str, label: str) -> str:
    values = pattern.findall(output)
    if len(values) != 1:
        raise ValueError(f"expected one {label}, found {len(values)}")
    return values[0]


def run(args: argparse.Namespace) -> dict[str, object]:
    if not sys.platform.startswith("linux") or not os.environ.get("DISPLAY"):
        return {
            "schema": 1,
            "status": "skipped",
            "ok": False,
            "executed": False,
            "reason": "Linux X11 display is required",
        }
    if not 1 <= args.frames <= 120:
        raise ValueError("--frames must be in 1..=120")

    host_bin = secure.find_binary("latencydesk-host", args.host_bin)
    client_bin = secure.find_binary("latencydesk-client", args.client_bin)
    identity_bin = secure.find_binary("latencydesk-identity", args.identity_bin)
    listen = f"127.0.0.1:{free_port()}"

    with tempfile.TemporaryDirectory(prefix="ice-probe-") as temporary:
        temporary_root = Path(temporary)
        host_dir = temporary_root / "host"
        client_dir = temporary_root / "client"
        host_dir.mkdir()
        client_dir.mkdir()
        secure.generate_identity(identity_bin, "probe-host", host_dir, 30)
        secure.generate_identity(identity_bin, "probe-client", client_dir, 30)
        host_command, client_command = build_commands(
            host_bin,
            client_bin,
            listen,
            host_dir,
            client_dir,
            args.frames,
        )

        host: secure.TrackedProcess | None = None
        client: secure.TrackedProcess | None = None
        negative_host: secure.TrackedProcess | None = None
        negative_client: secure.TrackedProcess | None = None
        try:
            host = secure.TrackedProcess(host_command, ROOT)
            if not host.wait_for_text("Listening securely on", args.timeout):
                raise RuntimeError("Host did not become ready")
            client = secure.TrackedProcess(client_command, ROOT)
            deadline = time.monotonic() + args.timeout
            while time.monotonic() < deadline:
                if CLIENT_REPORT_RE.search(client.output()) and HOST_REPORT_RE.search(host.output()):
                    break
                time.sleep(0.05)

            client_code, client_timed_out = client.finish(5)
            host_code, host_timed_out = host.finish(5)
            client_output = client.output()
            host_output = host.output()
            client_report = parse_probe_output(client_output, role="client")
            host_report = parse_probe_output(host_output, role="host")
            client_active_local = _one_match(
                CLIENT_ACTIVE_LOCAL_RE, client_output, "Client active local address"
            )
            host_active_remote = _one_match(
                HOST_ACTIVE_REMOTE_RE, host_output, "Host active peer address"
            )

            checks = {
                "same_session_generation": (
                    host_report["session_id"],
                    host_report["generation"],
                )
                == (client_report["session_id"], client_report["generation"]),
                "mirrored_nominated_endpoints": host_report["local"]
                == client_report["remote"]
                and host_report["remote"] == client_report["local"],
                "probe_ports_fresh": client_report["local"] != client_active_local
                and host_report["local"] != listen,
                "active_route_unchanged": client_report["active_route"] == listen
                and host_report["active_route"] == client_active_local
                and host_active_remote == client_active_local,
                "host_streamed_frame": "streaming: frame " in host_output,
                "release_all": "input: ReleaseAll applied" in host_output,
                "clean_exits": client_code == 0
                and host_code == 0
                and not client_timed_out
                and not host_timed_out,
            }

            negative_listen = f"127.0.0.1:{free_port()}"
            negative_host_command, negative_client_command = build_commands(
                host_bin,
                client_bin,
                negative_listen,
                host_dir,
                client_dir,
                args.frames,
            )
            negative_host_command.remove("--ice-connectivity-probe")
            negative_host = secure.TrackedProcess(negative_host_command, ROOT)
            if not negative_host.wait_for_text("Listening securely on", args.timeout):
                raise RuntimeError("one-sided Host did not become ready")
            negative_client = secure.TrackedProcess(negative_client_command, ROOT)
            negative_client_code, negative_client_timed_out = negative_client.finish(5)
            negative_host_code, negative_host_timed_out = negative_host.finish(5)
            negative_client_output = negative_client.output()
            negative_host_output = negative_host.output()
            if SECRET_RE.search(negative_client_output + negative_host_output):
                raise ValueError("one-sided probe output contains a secret-like token")
            checks["one_sided_probe_isolated"] = (
                negative_client_code != 0
                and negative_host_code == 0
                and not negative_client_timed_out
                and not negative_host_timed_out
                and "success=false route_changed=false" in negative_client_output
                and "post_failure_frame=true release_all=true" in negative_client_output
                and "input: ReleaseAll applied" in negative_host_output
            )
            checks["ok"] = all(checks.values())
            return {
                "schema": 1,
                "status": "completed",
                "executed": True,
                "ok": checks["ok"],
                "checks": checks,
                "client_report": client_report,
                "host_report": host_report,
                "sha256": {
                    "client_output": hashlib.sha256(client_output.encode()).hexdigest(),
                    "host_output": hashlib.sha256(host_output.encode()).hexdigest(),
                    "one_sided_client_output": hashlib.sha256(
                        negative_client_output.encode()
                    ).hexdigest(),
                    "one_sided_host_output": hashlib.sha256(
                        negative_host_output.encode()
                    ).hexdigest(),
                },
            }
        finally:
            if client is not None:
                client.close()
            if host is not None:
                host.close()
            if negative_client is not None:
                negative_client.close()
            if negative_host is not None:
                negative_host.close()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host-bin", type=Path)
    parser.add_argument("--client-bin", type=Path)
    parser.add_argument("--identity-bin", type=Path)
    parser.add_argument("--frames", type=int, default=3)
    parser.add_argument("--timeout", type=int, default=45)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    report = run(args)
    report["generated_at"] = datetime.now(timezone.utc).isoformat()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if report.get("status") == "skipped":
        return 0
    return 0 if report.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
