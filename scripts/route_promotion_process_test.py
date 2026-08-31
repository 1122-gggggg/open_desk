#!/usr/bin/env python3
"""Two-process exact-mTLS promotion/rollback evidence on two UDP paths."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import socket
import stat
import subprocess
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

RESULT_RE = re.compile(
    r"^route-probe-result\s+role=(server|client)\s+exact_mtls=(true|false)\s+"
    r"paths=(\d+)\s+promoted_epoch=(\d+)\s+rollback_epoch=(\d+)\s+"
    r"active_index=(\d+)\s+active_failure=(true|false)\s+"
    r"input=(true|false)\s+media=(true|false)\s+"
    r"control=(true|false)\s+clean=(true|false)\s+"
    r"peer_challenge_sha256=([0-9a-f]{64})\s*$",
    re.IGNORECASE | re.MULTILINE,
)
SECRET_RE = re.compile(
    r"(?:private[-_ ]?key|BEGIN .*PRIVATE|ice[-_ ]?(?:ufrag|password))", re.I
)


def parse(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--identity-bin", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=15)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if not 3 <= args.timeout <= 60:
        parser.error("--timeout must be in 3..=60")
    return args


def free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def parse_result(output: str, expected_role: str) -> dict[str, object]:
    matches = RESULT_RE.findall(output)
    if len(matches) != 1:
        raise ValueError(
            f"expected one {expected_role} route result; log_tail={output[-1000:]!r}"
        )
    (
        role,
        exact_mtls,
        paths,
        promoted,
        rollback,
        active,
        active_failure,
        input_ok,
        media_ok,
        control_ok,
        clean,
        peer_challenge_sha256,
    ) = matches[0]
    if role.lower() != expected_role:
        raise ValueError("route result role mismatch")
    return {
        "role": role.lower(),
        "exact_mtls": exact_mtls.lower() == "true",
        "paths": int(paths),
        "promoted_epoch": int(promoted),
        "rollback_epoch": int(rollback),
        "active_index": int(active),
        "active_failure": active_failure.lower() == "true",
        "input": input_ok.lower() == "true",
        "media": media_ok.lower() == "true",
        "control": control_ok.lower() == "true",
        "clean": clean.lower() == "true",
        "peer_challenge_sha256": peer_challenge_sha256.lower(),
    }


def verify_native_binary(path: Path, name: str) -> None:
    resolved = path.resolve(strict=True)
    metadata = resolved.stat()
    with resolved.open("rb") as source:
        magic = source.read(4)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or not os.access(resolved, os.X_OK)
        or metadata.st_mode & 0o002
        or (magic != b"\x7fELF" and magic[:2] != b"MZ")
    ):
        raise ValueError(f"{name} is not a safe native executable")
    version = subprocess.run(
        [str(resolved), "--version"],
        text=True,
        capture_output=True,
        timeout=3,
        check=False,
    )
    if version.returncode != 0 or not re.fullmatch(
        rf"{re.escape(name)} [0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?\n?",
        version.stdout,
    ):
        raise ValueError(f"{name} version identity is invalid")


def validate_identity(certificate: Path, private_key: Path) -> None:
    openssl = Path("/usr/bin/openssl")
    if (
        not openssl.is_file()
        or openssl.stat().st_uid != 0
        or openssl.stat().st_mode & 0o022
    ):
        raise ValueError("trusted /usr/bin/openssl is unavailable")
    if (
        not certificate.is_file()
        or not private_key.is_file()
        or not 1 <= certificate.stat().st_size <= 64 * 1024
        or not 1 <= private_key.stat().st_size <= 64 * 1024
        or private_key.stat().st_mode & 0o077
    ):
        raise ValueError("identity DER files are missing, oversized, or insecure")
    certificate_key = subprocess.run(
        [
            str(openssl),
            "x509",
            "-inform",
            "DER",
            "-in",
            str(certificate),
            "-pubkey",
            "-noout",
        ],
        capture_output=True,
        timeout=3,
        check=False,
    )
    private_public = subprocess.run(
        [str(openssl), "pkey", "-inform", "DER", "-in", str(private_key), "-pubout"],
        capture_output=True,
        timeout=3,
        check=False,
    )
    if (
        certificate_key.returncode != 0
        or private_public.returncode != 0
        or certificate_key.stdout != private_public.stdout
    ):
        raise ValueError("certificate and private key are invalid or do not match")


def process_udp_ports(pid: int) -> set[int]:
    inodes: set[str] = set()
    for descriptor in Path(f"/proc/{pid}/fd").iterdir():
        try:
            target = os.readlink(descriptor)
        except OSError:
            continue
        match = re.fullmatch(r"socket:\[(\d+)\]", target)
        if match:
            inodes.add(match.group(1))
    ports: set[int] = set()
    for table in (Path("/proc/net/udp"), Path("/proc/net/udp6")):
        if not table.is_file():
            continue
        for line in table.read_text(encoding="ascii").splitlines()[1:]:
            fields = line.split()
            if len(fields) > 9 and fields[9] in inodes:
                ports.add(int(fields[1].rsplit(":", 1)[1], 16))
    return ports


def run(args: argparse.Namespace) -> dict[str, object]:
    binary = secure.find_binary("latencydesk-route-probe", args.binary)
    identity_bin = secure.find_binary("latencydesk-identity", args.identity_bin)
    verify_native_binary(binary, "latencydesk-route-probe")
    verify_native_binary(identity_bin, "latencydesk-identity")
    first_port = free_udp_port()
    second_port = free_udp_port()
    while second_port == first_port:
        second_port = free_udp_port()
    first = f"127.0.0.1:{first_port}"
    second = f"127.0.0.1:{second_port}"

    with tempfile.TemporaryDirectory(prefix="route-promotion-process-") as temporary:
        root = Path(temporary)
        server_dir = root / "server"
        client_dir = root / "client"
        secure.generate_identity(identity_bin, "route-server", server_dir, 30)
        secure.generate_identity(identity_bin, "route-client", client_dir, 30)
        validate_identity(
            server_dir / secure.CERTIFICATE_FILE,
            server_dir / secure.PRIVATE_KEY_FILE,
        )
        validate_identity(
            client_dir / secure.CERTIFICATE_FILE,
            client_dir / secure.PRIVATE_KEY_FILE,
        )
        server_challenge = secrets.token_hex(32)
        client_challenge = secrets.token_hex(32)
        common_timeout = ["--timeout", str(args.timeout)]
        server_command = [
            str(binary),
            "--role",
            "server",
            "--listen",
            first,
            "--listen2",
            second,
            "--cert",
            str(server_dir / secure.CERTIFICATE_FILE),
            "--key",
            str(server_dir / secure.PRIVATE_KEY_FILE),
            "--peer-cert",
            str(client_dir / secure.CERTIFICATE_FILE),
            *common_timeout,
            "--challenge",
            server_challenge,
        ]
        client_command = [
            str(binary),
            "--role",
            "client",
            "--host",
            first,
            "--host2",
            second,
            "--cert",
            str(client_dir / secure.CERTIFICATE_FILE),
            "--key",
            str(client_dir / secure.PRIVATE_KEY_FILE),
            "--peer-cert",
            str(server_dir / secure.CERTIFICATE_FILE),
            *common_timeout,
            "--challenge",
            client_challenge,
        ]
        server = client = None
        try:
            server = secure.TrackedProcess(server_command, ROOT)
            if not server.wait_for_text("route-probe-ready", args.timeout):
                raise RuntimeError("route probe server did not become ready")
            client = secure.TrackedProcess(client_command, ROOT)
            if not server.wait_for_text(
                "route-probe-connected role=server", args.timeout
            ):
                raise RuntimeError(
                    "route probe server did not establish two connections"
                )
            if not client.wait_for_text(
                "route-probe-connected role=client", args.timeout
            ):
                raise RuntimeError(
                    "route probe client did not establish two connections"
                )
            server_ports = process_udp_ports(server.proc.pid)
            client_ports = process_udp_ports(client.proc.pid)
            sockets_observed = {first_port, second_port} <= server_ports and len(
                client_ports
            ) >= 2
            client_code, client_timed_out = client.finish(args.timeout)
            server_code, server_timed_out = server.finish(args.timeout)
            outputs = {"server": server.output(), "client": client.output()}
            if any(SECRET_RE.search(output) for output in outputs.values()):
                raise ValueError("route process output contains secret-like material")
            try:
                server_report = parse_result(outputs["server"], "server")
                client_report = parse_result(outputs["client"], "client")
            except ValueError as error:
                raise ValueError(
                    f"{error}; server_tail={outputs['server'][-1000:]!r}; "
                    f"client_tail={outputs['client'][-1000:]!r}"
                ) from error
            required = {
                "exact_mtls": True,
                "paths": 2,
                "promoted_epoch": 2,
                "rollback_epoch": 3,
                "active_index": 0,
                "active_failure": True,
                "input": True,
                "media": True,
                "control": True,
                "clean": True,
            }
            checks = {
                "server_clean_exit": server_code == 0 and not server_timed_out,
                "client_clean_exit": client_code == 0 and not client_timed_out,
                "two_distinct_udp_paths": first != second,
                "live_process_udp_sockets": sockets_observed,
                "server_contract": all(
                    server_report.get(key) == value for key, value in required.items()
                ),
                "client_contract": all(
                    client_report.get(key) == value for key, value in required.items()
                ),
                "cross_process_challenge_exchange": server_report.get(
                    "peer_challenge_sha256"
                )
                == hashlib.sha256(bytes.fromhex(client_challenge)).hexdigest()
                and client_report.get("peer_challenge_sha256")
                == hashlib.sha256(bytes.fromhex(server_challenge)).hexdigest(),
                "no_unsafe_flag": all(
                    "--unsafe" not in item
                    for command in (server_command, client_command)
                    for item in command
                ),
            }
            checks["ok"] = all(checks.values())
            return {
                "schema": 1,
                "status": "passed" if checks["ok"] else "failed",
                "ok": checks["ok"],
                "checks": checks,
                "paths": [first, second],
                "server": server_report,
                "client": client_report,
                "sha256": {
                    "binary": secure.file_sha256(binary),
                    "identity_binary": secure.file_sha256(identity_bin),
                    "server_log": hashlib.sha256(
                        outputs["server"].encode()
                    ).hexdigest(),
                    "client_log": hashlib.sha256(
                        outputs["client"].encode()
                    ).hexdigest(),
                },
            }
        finally:
            for process in (client, server):
                if process is not None:
                    process.close()


def main(argv: Sequence[str] | None = None) -> int:
    args = parse(argv)
    try:
        report = run(args)
    except Exception as error:  # noqa: BLE001 - artifact must record every gate failure.
        report = {
            "schema": 1,
            "status": "failed",
            "ok": False,
            "errors": [str(error)],
        }
    report["generated_at"] = datetime.now(timezone.utc).isoformat()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, sort_keys=True))
    return 0 if report.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
