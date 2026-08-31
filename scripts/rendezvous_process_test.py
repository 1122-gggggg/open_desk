#!/usr/bin/env python3
"""Process evidence for the bounded exact-mTLS rendezvous service."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import secrets
import socket
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import secure_connect_test as secure  # noqa: E402


SERVER_REPORT_RE = re.compile(
    r"^rendezvous:\s+registrations=(\d+)\s+matched=(\d+)\s+rejected=(\d+)\s+"
    r"desktop_payload=(true|false)\s+relay=(true|false)\s*$",
    re.I | re.M,
)
CLIENT_REPORT_RE = re.compile(
    r"^rendezvous-client:\s+matched=(true|false)\s+role=(Initiator|Responder)\s+"
    r"peer_candidates=(\d+)\s+exact_mtls=(true|false)\s+"
    r"desktop_payload=(true|false)\s+relay=(true|false)\s*$",
    re.I | re.M,
)
SECRET_RE = re.compile(r"(?:private[-_ ]?key|ice[-_ ]?(?:ufrag|password)|BEGIN .*PRIVATE)", re.I)


def free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def server_command(
    server_bin: Path,
    listen: str,
    server_dir: Path,
    client_a_dir: Path,
    client_b_dir: Path,
    timeout: int,
) -> list[str]:
    return [
        str(server_bin),
        "--listen",
        listen,
        "--identity-cert",
        str(server_dir / secure.CERTIFICATE_FILE),
        "--identity-key",
        str(server_dir / secure.PRIVATE_KEY_FILE),
        "--allowed-client-cert",
        str(client_a_dir / secure.CERTIFICATE_FILE),
        "--allowed-client-cert",
        str(client_b_dir / secure.CERTIFICATE_FILE),
        "--total-timeout",
        str(timeout),
        "--max-registrations",
        "2",
    ]


def client_command(
    client_bin: Path,
    server: str,
    identity_dir: Path,
    server_dir: Path,
    expected_peer_dir: Path,
    role: str,
    match_id: str,
    exchange_id: int,
    candidate_port: int,
    timeout: int,
) -> list[str]:
    return [
        str(client_bin),
        "--server",
        server,
        "--bind",
        "127.0.0.1:0",
        "--identity-cert",
        str(identity_dir / secure.CERTIFICATE_FILE),
        "--identity-key",
        str(identity_dir / secure.PRIVATE_KEY_FILE),
        "--server-cert",
        str(server_dir / secure.CERTIFICATE_FILE),
        "--expected-peer-cert",
        str(expected_peer_dir / secure.CERTIFICATE_FILE),
        "--role",
        role,
        "--match-id",
        match_id,
        "--exchange-id",
        str(exchange_id),
        "--candidate",
        f"127.0.0.1:{candidate_port}",
        "--timeout",
        str(timeout),
    ]


def parse_server(output: str) -> dict[str, object]:
    matches = SERVER_REPORT_RE.findall(output)
    if len(matches) != 1:
        raise ValueError("expected one rendezvous server report")
    registrations, matched, rejected, desktop, relay = matches[0]
    return {
        "registrations": int(registrations),
        "matched": int(matched),
        "rejected": int(rejected),
        "desktop_payload": desktop.lower() == "true",
        "relay": relay.lower() == "true",
    }


def parse_client(output: str, role: str) -> dict[str, object]:
    matches = CLIENT_REPORT_RE.findall(output)
    if len(matches) != 1:
        raise ValueError("expected one rendezvous client report")
    matched, actual_role, candidates, exact_mtls, desktop, relay = matches[0]
    if actual_role.lower() != role:
        raise ValueError("rendezvous role mismatch")
    return {
        "matched": matched.lower() == "true",
        "role": actual_role,
        "peer_candidates": int(candidates),
        "exact_mtls": exact_mtls.lower() == "true",
        "desktop_payload": desktop.lower() == "true",
        "relay": relay.lower() == "true",
    }


def run(args: argparse.Namespace) -> dict[str, object]:
    server_bin = secure.find_binary("latencydesk-rendezvousd", args.server_bin)
    client_bin = secure.find_binary("latencydesk-rendezvous-client", args.client_bin)
    identity_bin = secure.find_binary("latencydesk-identity", args.identity_bin)
    match_id = secrets.token_hex(16)
    exchange_id = int.from_bytes(secrets.token_bytes(8), "big") or 1
    listen = f"127.0.0.1:{free_udp_port()}"

    with tempfile.TemporaryDirectory(prefix="rendezvous-process-") as temporary:
        root = Path(temporary)
        directories = {
            name: root / name for name in ("server", "client-a", "client-b", "stranger")
        }
        for name, directory in directories.items():
            directory.mkdir()
            secure.generate_identity(identity_bin, name, directory, 30)

        server = client_a = client_b = stranger = None
        try:
            server = secure.TrackedProcess(
                server_command(
                    server_bin,
                    listen,
                    directories["server"],
                    directories["client-a"],
                    directories["client-b"],
                    args.timeout,
                ),
                ROOT,
            )
            if not server.wait_for_text("rendezvous: listening=", args.timeout):
                raise RuntimeError("rendezvous server did not become ready")

            stranger = secure.TrackedProcess(
                client_command(
                    client_bin,
                    listen,
                    directories["stranger"],
                    directories["server"],
                    directories["client-b"],
                    "initiator",
                    match_id,
                    exchange_id,
                    free_udp_port(),
                    args.timeout,
                ),
                ROOT,
            )
            stranger_code, stranger_timed_out = stranger.finish(5)

            client_a = secure.TrackedProcess(
                client_command(
                    client_bin,
                    listen,
                    directories["client-a"],
                    directories["server"],
                    directories["client-b"],
                    "initiator",
                    match_id,
                    exchange_id,
                    free_udp_port(),
                    args.timeout,
                ),
                ROOT,
            )
            client_b = secure.TrackedProcess(
                client_command(
                    client_bin,
                    listen,
                    directories["client-b"],
                    directories["server"],
                    directories["client-a"],
                    "responder",
                    match_id,
                    exchange_id,
                    free_udp_port(),
                    args.timeout,
                ),
                ROOT,
            )
            client_a_code, client_a_timed_out = client_a.finish(8)
            client_b_code, client_b_timed_out = client_b.finish(8)
            server_code, server_timed_out = server.finish(8)
            outputs = {
                "server": server.output(),
                "client_a": client_a.output(),
                "client_b": client_b.output(),
                "stranger": stranger.output(),
            }
            if any(SECRET_RE.search(output) for output in outputs.values()):
                raise ValueError("rendezvous process output contains secret-like material")
            server_report = parse_server(outputs["server"])
            client_a_report = parse_client(outputs["client_a"], "initiator")
            client_b_report = parse_client(outputs["client_b"], "responder")
            checks = {
                "stranger_rejected": stranger_code != 0 and not stranger_timed_out,
                "allowed_clients_clean": client_a_code == 0
                and client_b_code == 0
                and not client_a_timed_out
                and not client_b_timed_out,
                "server_clean": server_code == 0 and not server_timed_out,
                "one_match": server_report["registrations"] == 2
                and server_report["matched"] == 1,
                "rejection_recorded": server_report["rejected"] >= 1,
                "mutual_delivery": client_a_report["matched"]
                and client_b_report["matched"]
                and client_a_report["peer_candidates"] == 1
                and client_b_report["peer_candidates"] == 1,
                "exact_mtls": client_a_report["exact_mtls"]
                and client_b_report["exact_mtls"],
                "no_desktop_or_relay": not server_report["desktop_payload"]
                and not server_report["relay"]
                and not client_a_report["desktop_payload"]
                and not client_b_report["desktop_payload"],
            }
            checks["ok"] = all(checks.values())
            return {
                "schema": 1,
                "status": "completed",
                "ok": checks["ok"],
                "checks": checks,
                "server_report": server_report,
                "client_a_report": client_a_report,
                "client_b_report": client_b_report,
                "sha256": {
                    name: hashlib.sha256(output.encode()).hexdigest()
                    for name, output in outputs.items()
                },
            }
        finally:
            for process in (stranger, client_a, client_b, server):
                if process is not None:
                    process.close()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--server-bin", type=Path)
    parser.add_argument("--client-bin", type=Path)
    parser.add_argument("--identity-bin", type=Path)
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    report = run(args)
    report["generated_at"] = datetime.now(timezone.utc).isoformat()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0 if report.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
