#!/usr/bin/env python3
"""Process evidence for the bounded RFC 8656 UDP TURN relay profile."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import socket
import sys
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import secure_connect_test as secure  # noqa: E402


SERVER_RE = re.compile(
    r"^turn-relayd:\s+allocations=(\d+)\s+deallocations=(\d+)\s+rejected=(\d+)\s+"
    r"client_to_peer=(\d+)\s+peer_to_client=(\d+)\s+clean_shutdown=(true|false)\s+"
    r"opaque_payload=(true|false)\s+tcp_relay=(true|false)\s+desktop_payload=(true|false)$",
    re.M,
)
CLIENT_RE = re.compile(
    r"^turn-client:\s+challenge_authenticated=(true|false)\s+send_round_trip=(true|false)\s+"
    r"channel_round_trip=(true|false)\s+deallocated=(true|false)\s+relayed=([^\s]+)\s+"
    r"opaque_payload=(true|false)\s+exact_bytes=(true|false)\s+tcp_relay=(true|false)\s+"
    r"desktop_payload=(true|false)$",
    re.M,
)


def free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class EchoPeer:
    def __init__(self) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.settimeout(0.2)
        self.address = f"127.0.0.1:{self.socket.getsockname()[1]}"
        self.received = 0
        self.payload_hashes: list[str] = []
        self.error: str | None = None
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self._run, name="turn-echo-peer", daemon=True)

    def start(self) -> None:
        self.thread.start()

    def _run(self) -> None:
        try:
            while self.received < 2 and not self.stop_event.is_set():
                try:
                    payload, source = self.socket.recvfrom(4097)
                except TimeoutError:
                    continue
                if len(payload) > 4096:
                    raise RuntimeError("echo peer received oversized payload")
                self.received += 1
                self.payload_hashes.append(hashlib.sha256(payload).hexdigest())
                self.socket.sendto(payload, source)
        except Exception as error:  # noqa: BLE001
            self.error = type(error).__name__

    def close(self) -> None:
        self.stop_event.set()
        self.thread.join(timeout=2)
        self.socket.close()


def server_command(server_bin: Path, listen: str, password_file: Path, timeout: int) -> list[str]:
    return [
        str(server_bin),
        "--listen", listen,
        "--relay-ip", "127.0.0.1",
        "--realm", "turn.example",
        "--username", "process-client",
        "--password-file", str(password_file),
        "--max-allocations", "4",
        "--total-timeout", str(timeout),
        "--exit-after-deallocations", "1",
        "--allow-loopback-lab",
    ]


def client_command(
    client_bin: Path,
    server: str,
    password_file: Path,
    peer: str,
    timeout: int,
) -> list[str]:
    return [
        str(client_bin),
        "--server", server,
        "--bind", "127.0.0.1:0",
        "--username", "process-client",
        "--password-file", str(password_file),
        "--peer", peer,
        "--timeout", str(timeout),
        "--channel", "0x4000",
        "--allow-loopback-lab",
    ]


def parse_server(output: str) -> dict[str, object]:
    matches = SERVER_RE.findall(output)
    if len(matches) != 1:
        raise ValueError("expected exactly one TURN server report")
    allocations, deallocations, rejected, outbound, inbound, clean, opaque, tcp, desktop = matches[0]
    return {
        "allocations": int(allocations),
        "deallocations": int(deallocations),
        "rejected": int(rejected),
        "client_to_peer": int(outbound),
        "peer_to_client": int(inbound),
        "clean_shutdown": clean == "true",
        "opaque_payload": opaque == "true",
        "tcp_relay": tcp == "true",
        "desktop_payload": desktop == "true",
    }


def parse_client(output: str) -> dict[str, object]:
    matches = CLIENT_RE.findall(output)
    if len(matches) != 1:
        raise ValueError("expected exactly one TURN client report")
    challenge, send, channel, deallocated, relayed, opaque, exact, tcp, desktop = matches[0]
    return {
        "challenge_authenticated": challenge == "true",
        "send_round_trip": send == "true",
        "channel_round_trip": channel == "true",
        "deallocated": deallocated == "true",
        "relayed": relayed,
        "opaque_payload": opaque == "true",
        "exact_bytes": exact == "true",
        "tcp_relay": tcp == "true",
        "desktop_payload": desktop == "true",
    }


def run(args: argparse.Namespace) -> dict[str, object]:
    server_bin = secure.find_binary("latencydesk-turn-relayd", args.server_bin)
    client_bin = secure.find_binary("latencydesk-turn-client", args.client_bin)
    listen = f"127.0.0.1:{free_udp_port()}"
    password = (secrets.token_hex(32) + "\n").encode()
    echo = EchoPeer()
    server = client = None
    with tempfile.TemporaryDirectory(prefix="turn-relay-process-") as temporary:
        password_file = Path(temporary) / "turn.secret"
        password_file.write_bytes(password)
        os.chmod(password_file, 0o600)
        echo.start()
        try:
            server = secure.TrackedProcess(
                server_command(server_bin, listen, password_file, args.timeout), ROOT
            )
            if not server.wait_for_text("turn-relayd: listening=", args.timeout):
                raise RuntimeError("TURN server did not become ready")
            client = secure.TrackedProcess(
                client_command(client_bin, listen, password_file, echo.address, args.timeout), ROOT
            )
            client_code, client_timed_out = client.finish(args.timeout)
            server_code, server_timed_out = server.finish(args.timeout)
            client_output = client.output()
            server_output = server.output()
            if password.strip().decode() in client_output + server_output:
                raise ValueError("TURN process output exposed the password")
            server_report = parse_server(server_output)
            client_report = parse_client(client_output)
            checks = {
                "client_clean": client_code == 0 and not client_timed_out,
                "server_clean": server_code == 0 and not server_timed_out,
                "challenge_authenticated": client_report["challenge_authenticated"],
                "send_round_trip": client_report["send_round_trip"],
                "channel_round_trip": client_report["channel_round_trip"],
                "exact_bytes": client_report["exact_bytes"],
                "one_allocation_cleaned": server_report["allocations"] == 1
                and server_report["deallocations"] == 1
                and client_report["deallocated"],
                "two_way_relay": server_report["client_to_peer"] == 2
                and server_report["peer_to_client"] == 2
                and echo.received == 2,
                "opaque_no_desktop": server_report["opaque_payload"]
                and client_report["opaque_payload"]
                and not server_report["desktop_payload"]
                and not client_report["desktop_payload"],
                "udp_only": not server_report["tcp_relay"] and not client_report["tcp_relay"],
                "cleanup": server_report["clean_shutdown"] and echo.error is None,
            }
            checks["ok"] = all(checks.values())
            return {
                "schema": 1,
                "status": "completed",
                "ok": checks["ok"],
                "checks": checks,
                "server_report": server_report,
                "client_report": client_report,
                "echo": {"received": echo.received, "payload_sha256": echo.payload_hashes},
                "stdout_sha256": {
                    "server": hashlib.sha256(server_output.encode()).hexdigest(),
                    "client": hashlib.sha256(client_output.encode()).hexdigest(),
                },
            }
        finally:
            if client is not None:
                client.close()
            if server is not None:
                server.close()
            echo.close()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--server-bin", type=Path)
    parser.add_argument("--client-bin", type=Path)
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    report = run(args)
    report["generated_at"] = datetime.now(timezone.utc).isoformat()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
