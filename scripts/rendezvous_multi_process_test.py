#!/usr/bin/env python3
"""Two concurrent exact-mTLS rendezvous matches in separate processes."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import secrets
import subprocess
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

import rendezvous_process_test as single  # noqa: E402
from route_promotion_process_test import (  # noqa: E402
    process_udp_ports,
    validate_identity,
    verify_native_binary,
)
import secure_connect_test as secure  # noqa: E402


def server_command(
    server_bin: Path,
    listen: str,
    server_dir: Path,
    client_dirs: Sequence[Path],
    timeout: int,
) -> list[str]:
    command = [
        str(server_bin),
        "--listen",
        listen,
        "--identity-cert",
        str(server_dir / secure.CERTIFICATE_FILE),
        "--identity-key",
        str(server_dir / secure.PRIVATE_KEY_FILE),
    ]
    for client_dir in client_dirs:
        command.extend(
            ["--allowed-client-cert", str(client_dir / secure.CERTIFICATE_FILE)]
        )
    command.extend(
        [
            "--total-timeout",
            str(timeout),
            "--max-registrations",
            "4",
            "--max-matches",
            "2",
        ]
    )
    return command


def native_version(path: Path, name: str) -> str:
    """Validate and record the exact version identity of a production binary."""
    verify_native_binary(path, name)
    result = subprocess.run(
        [str(path.resolve(strict=True)), "--version"],
        text=True,
        capture_output=True,
        timeout=3,
        check=False,
    )
    version = result.stdout.strip()
    if result.returncode != 0 or not re.fullmatch(
        rf"{re.escape(name)} [0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?",
        version,
    ):
        raise ValueError(f"{name} version identity changed while recording")
    return version


def listen_port(endpoint: str) -> int:
    try:
        host, port = endpoint.rsplit(":", 1)
        if host != "127.0.0.1":
            raise ValueError
        value = int(port)
    except (ValueError, TypeError):
        raise ValueError(f"invalid rendezvous endpoint: {endpoint!r}") from None
    if not 1 <= value <= 65535:
        raise ValueError(f"invalid rendezvous UDP port: {value}")
    return value


def run(args: argparse.Namespace) -> dict[str, object]:
    server_bin = secure.find_binary("latencydesk-rendezvousd", args.server_bin)
    client_bin = secure.find_binary("latencydesk-rendezvous-client", args.client_bin)
    identity_bin = secure.find_binary("latencydesk-identity", args.identity_bin)
    versions = {
        "server": native_version(server_bin, "latencydesk-rendezvousd"),
        "client": native_version(client_bin, "latencydesk-rendezvous-client"),
        "identity": native_version(identity_bin, "latencydesk-identity"),
    }
    revision, worktree_dirty = secure.repository_state()
    listen = f"127.0.0.1:{single.free_udp_port()}"
    rendezvous_port = listen_port(listen)
    match_ids = [secrets.token_hex(16), secrets.token_hex(16)]
    exchange_ids = [
        int.from_bytes(secrets.token_bytes(8), "big") or 1,
        int.from_bytes(secrets.token_bytes(8), "big") or 2,
    ]

    with tempfile.TemporaryDirectory(prefix="rendezvous-multi-process-") as temporary:
        root = Path(temporary)
        directories = {
            name: root / name
            for name in (
                "server",
                "client-a",
                "client-b",
                "client-c",
                "client-d",
                "stranger",
            )
        }
        for name, directory in directories.items():
            directory.mkdir()
            secure.generate_identity(identity_bin, name, directory, 30)
            validate_identity(
                directory / secure.CERTIFICATE_FILE,
                directory / secure.PRIVATE_KEY_FILE,
            )
        valid_dirs = [directories[f"client-{letter}"] for letter in "abcd"]
        server = stranger = None
        clients: list[secure.TrackedProcess | None] = [None] * 4
        try:
            server = secure.TrackedProcess(
                server_command(
                    server_bin,
                    listen,
                    directories["server"],
                    valid_dirs,
                    args.timeout,
                ),
                ROOT,
            )
            if not server.wait_for_text("rendezvous: listening=", args.timeout):
                raise RuntimeError("multi rendezvous server did not become ready")
            server_udp_ports = process_udp_ports(server.proc.pid)
            server_socket_owned = rendezvous_port in server_udp_ports
            if not server_socket_owned:
                raise RuntimeError(
                    "rendezvous server readiness marker is not backed by its UDP socket"
                )
            stranger = secure.TrackedProcess(
                single.client_command(
                    client_bin,
                    listen,
                    directories["stranger"],
                    directories["server"],
                    directories["client-b"],
                    "initiator",
                    match_ids[0],
                    exchange_ids[0],
                    single.free_udp_port(),
                    args.timeout,
                ),
                ROOT,
            )
            stranger_code, stranger_timed_out = stranger.finish(5)

            specs = [
                (0, "initiator", 1, 0),
                (2, "initiator", 3, 1),
                (1, "responder", 0, 0),
                (3, "responder", 2, 1),
            ]
            # Start both waiters first. They must remain alive together before
            # either reciprocal responder exists.
            for client_index, role, peer_index, pair_index in specs[:2]:
                clients[client_index] = secure.TrackedProcess(
                    single.client_command(
                        client_bin,
                        listen,
                        valid_dirs[client_index],
                        directories["server"],
                        valid_dirs[peer_index],
                        role,
                        match_ids[pair_index],
                        exchange_ids[pair_index],
                        single.free_udp_port(),
                        args.timeout,
                    ),
                    ROOT,
                )
            time.sleep(0.1)
            if any(
                process is not None and process.poll() is not None
                for process in (clients[0], clients[2])
            ):
                raise RuntimeError(
                    "a rendezvous waiter exited before its responder started"
                )
            initiators_alive_before_responders = all(
                clients[index] is not None and clients[index].poll() is None
                for index in (0, 2)
            )
            waiting_udp_ports = {
                f"client_{index}": sorted(
                    process_udp_ports(clients[index].proc.pid)  # type: ignore[union-attr]
                )
                for index in (0, 2)
            }
            waiters_socket_owned = all(
                len(waiting_udp_ports[f"client_{index}"]) >= 2 for index in (0, 2)
            )
            if not waiters_socket_owned:
                raise RuntimeError(
                    "rendezvous initiator is not backed by candidate and QUIC UDP sockets"
                )
            for client_index, role, peer_index, pair_index in specs[2:]:
                clients[client_index] = secure.TrackedProcess(
                    single.client_command(
                        client_bin,
                        listen,
                        valid_dirs[client_index],
                        directories["server"],
                        valid_dirs[peer_index],
                        role,
                        match_ids[pair_index],
                        exchange_ids[pair_index],
                        single.free_udp_port(),
                        args.timeout,
                    ),
                    ROOT,
                )

            client_statuses = [process.finish(8) for process in clients if process]
            server_code, server_timed_out = server.finish(8)
            outputs = {
                "server": server.output(),
                "stranger": stranger.output(),
                **{
                    f"client_{index}": process.output()
                    for index, process in enumerate(clients)
                    if process is not None
                },
            }
            if any(single.SECRET_RE.search(output) for output in outputs.values()):
                raise ValueError(
                    "multi rendezvous output contains secret-like material"
                )
            server_report = single.parse_server(outputs["server"])
            client_reports = [
                single.parse_client(
                    outputs[f"client_{index}"],
                    "initiator" if index in (0, 2) else "responder",
                )
                for index in range(4)
            ]
            checks = {
                "stranger_rejected": stranger_code != 0 and not stranger_timed_out,
                "initiators_alive_before_responders": initiators_alive_before_responders,
                "server_owns_listen_socket": server_socket_owned,
                "waiting_initiators_own_candidate_and_quic_sockets": waiters_socket_owned,
                "four_clients_clean": len(client_statuses) == 4
                and all(
                    code == 0 and not timed_out for code, timed_out in client_statuses
                ),
                "server_clean": server_code == 0 and not server_timed_out,
                "two_matches": server_report["registrations"] == 4
                and server_report["matched"] == 2,
                "rejection_recorded": server_report["rejected"] >= 1,
                "all_exact_mtls_deliveries": all(
                    report["matched"]
                    and report["exact_mtls"]
                    and report["peer_candidates"] == 1
                    for report in client_reports
                ),
                "no_desktop_or_relay": not server_report["desktop_payload"]
                and not server_report["relay"]
                and all(
                    not report["desktop_payload"] and not report["relay"]
                    for report in client_reports
                ),
            }
            checks["ok"] = all(checks.values())
            return {
                "schema": 1,
                "status": "passed" if checks["ok"] else "failed",
                "ok": checks["ok"],
                "checks": checks,
                "server_report": server_report,
                "client_reports": client_reports,
                "versions": versions,
                "source": {
                    "repository_revision_at_test": revision,
                    "worktree_dirty_at_test": worktree_dirty,
                    "binary_sha256_proves_revision": False,
                },
                "socket_ownership": {
                    "server_pid": server.proc.pid,
                    "server_udp_ports": sorted(server_udp_ports),
                    "rendezvous_port": rendezvous_port,
                    "waiting_initiators": {
                        f"client_{index}": {
                            "pid": clients[index].proc.pid,  # type: ignore[union-attr]
                            "udp_ports": waiting_udp_ports[f"client_{index}"],
                        }
                        for index in (0, 2)
                    },
                },
                "identities": {
                    name: {
                        "certificate_sha256": secure.file_sha256(
                            directory / secure.CERTIFICATE_FILE
                        ),
                        "private_key_sha256": secure.file_sha256(
                            directory / secure.PRIVATE_KEY_FILE
                        ),
                        "der_pair_validated": True,
                    }
                    for name, directory in directories.items()
                },
                "sha256": {
                    "server_binary": secure.file_sha256(server_bin),
                    "client_binary": secure.file_sha256(client_bin),
                    "identity_binary": secure.file_sha256(identity_bin),
                    **{
                        name: hashlib.sha256(output.encode()).hexdigest()
                        for name, output in outputs.items()
                    },
                },
            }
        finally:
            for process in [*clients, stranger, server]:
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
    if not 5 <= args.timeout <= 60:
        parser.error("--timeout must be in 5..=60")
    try:
        report = run(args)
    except Exception as error:  # noqa: BLE001 - every gate failure enters the artifact.
        report = {"schema": 1, "status": "failed", "ok": False, "errors": [str(error)]}
    report["generated_at"] = datetime.now(timezone.utc).isoformat()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, sort_keys=True))
    return 0 if report.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
