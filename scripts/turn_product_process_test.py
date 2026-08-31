#!/usr/bin/env python3
"""Forced TURN → exact-mTLS ProductSession process evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
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
import turn_relay_process_test as relay_gate  # noqa: E402
from route_promotion_process_test import (  # noqa: E402
    process_udp_ports,
    validate_identity,
    verify_native_binary,
)

PRODUCT_RE = re.compile(
    r"^product-probe-result\s+role=(host|client)\s+route=(direct|turn)\s+"
    r"exact_mtls=(true|false)\s+product=(true|false)\s+control=(true|false)\s+"
    r"input=(true|false)\s+media=(true|false)\s+clean=(true|false)\s+"
    r"session_id=(\d+)\s+route_epoch=(\d+)\s+"
    r"(peer_source|local_route)=([^\s]+)\s+peer_challenge_sha256=([0-9a-f]{64})\s*$",
    re.IGNORECASE | re.MULTILINE,
)
SECRET_RE = re.compile(
    r"(?:private[-_ ]?key|BEGIN .*PRIVATE|ice[-_ ]?(?:ufrag|password))", re.I
)


def native_version(path: Path, name: str) -> str:
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
        raise ValueError(f"{name} version identity is invalid")
    return version


def identity_file(directory: Path, filename: str) -> Path:
    return directory / filename


def relay_command(
    relay_bin: Path, listen: str, password_file: Path, timeout: int
) -> list[str]:
    return [
        str(relay_bin),
        "--listen",
        listen,
        "--relay-ip",
        "127.0.0.1",
        "--realm",
        "turn.product.test",
        "--username",
        "product-probe",
        "--password-file",
        str(password_file),
        "--max-allocations",
        "4",
        "--total-timeout",
        str(timeout),
        "--exit-after-deallocations",
        "1",
        "--allow-loopback-lab",
    ]


def host_command(
    probe_bin: Path,
    listen: str,
    host_dir: Path,
    client_dir: Path,
    challenge: str,
    timeout: int,
) -> list[str]:
    return [
        str(probe_bin),
        "--role",
        "host",
        "--bind",
        listen,
        "--cert",
        str(identity_file(host_dir, secure.CERTIFICATE_FILE)),
        "--key",
        str(identity_file(host_dir, secure.PRIVATE_KEY_FILE)),
        "--peer-cert",
        str(identity_file(client_dir, secure.CERTIFICATE_FILE)),
        "--timeout",
        str(timeout),
        "--challenge",
        challenge,
    ]


def client_command(
    probe_bin: Path,
    peer: str,
    relay: str,
    client_dir: Path,
    host_dir: Path,
    password_file: Path,
    challenge: str,
    timeout: int,
) -> list[str]:
    return [
        str(probe_bin),
        "--role",
        "client",
        "--bind",
        "127.0.0.1:0",
        "--peer",
        peer,
        "--cert",
        str(identity_file(client_dir, secure.CERTIFICATE_FILE)),
        "--key",
        str(identity_file(client_dir, secure.PRIVATE_KEY_FILE)),
        "--peer-cert",
        str(identity_file(host_dir, secure.CERTIFICATE_FILE)),
        "--timeout",
        str(timeout),
        "--challenge",
        challenge,
        "--turn-server",
        relay,
        "--turn-username",
        "product-probe",
        "--turn-password-file",
        str(password_file),
        "--turn-channel",
        "0x4000",
    ]


def parse_product_result(output: str, expected_role: str) -> dict[str, object]:
    matches = PRODUCT_RE.findall(output)
    if len(matches) != 1:
        raise ValueError(f"expected one complete {expected_role} product result")
    (
        role,
        route,
        exact_mtls,
        product,
        control,
        input_ok,
        media,
        clean,
        session_id,
        route_epoch,
        address_kind,
        address,
        challenge_hash,
    ) = matches[0]
    if role.lower() != expected_role:
        raise ValueError("product result role mismatch")
    return {
        "role": role.lower(),
        "route": route.lower(),
        "exact_mtls": exact_mtls.lower() == "true",
        "product": product.lower() == "true",
        "control": control.lower() == "true",
        "input": input_ok.lower() == "true",
        "media": media.lower() == "true",
        "clean": clean.lower() == "true",
        "session_id": int(session_id),
        "route_epoch": int(route_epoch),
        address_kind.lower(): address,
        "peer_challenge_sha256": challenge_hash.lower(),
    }


def run(args: argparse.Namespace) -> dict[str, object]:
    relay_bin = secure.find_binary("latencydesk-turn-relayd", args.relay_bin)
    probe_bin = secure.find_binary("latencydesk-product-probe", args.probe_bin)
    identity_bin = secure.find_binary("latencydesk-identity", args.identity_bin)
    versions = {
        "relay": native_version(relay_bin, "latencydesk-turn-relayd"),
        "probe": native_version(probe_bin, "latencydesk-product-probe"),
        "identity": native_version(identity_bin, "latencydesk-identity"),
    }
    relay_port = relay_gate.free_udp_port()
    host_port = relay_gate.free_udp_port()
    while host_port == relay_port:
        host_port = relay_gate.free_udp_port()
    relay_address = f"127.0.0.1:{relay_port}"
    host_address = f"127.0.0.1:{host_port}"
    host_challenge = secrets.token_hex(32)
    client_challenge = secrets.token_hex(32)
    password_text = secrets.token_hex(32)
    revision, worktree_dirty = secure.repository_state()

    with tempfile.TemporaryDirectory(prefix="turn-product-process-") as temporary:
        root = Path(temporary)
        host_dir = root / "host"
        client_dir = root / "client"
        host_dir.mkdir()
        client_dir.mkdir()
        password_file = root / "turn.secret"
        password_file.write_text(password_text + "\n", encoding="ascii")
        os.chmod(password_file, 0o600)
        secure.generate_identity(identity_bin, "turn-product-host", host_dir, args.timeout)
        secure.generate_identity(identity_bin, "turn-product-client", client_dir, args.timeout)
        validate_identity(
            identity_file(host_dir, secure.CERTIFICATE_FILE),
            identity_file(host_dir, secure.PRIVATE_KEY_FILE),
        )
        validate_identity(
            identity_file(client_dir, secure.CERTIFICATE_FILE),
            identity_file(client_dir, secure.PRIVATE_KEY_FILE),
        )

        relay = host = client = None
        try:
            relay = secure.TrackedProcess(
                relay_command(relay_bin, relay_address, password_file, args.timeout), ROOT
            )
            if not relay.wait_for_text("turn-relayd: listening=", args.timeout):
                raise RuntimeError("TURN relay did not become ready")
            initial_relay_ports = process_udp_ports(relay.proc.pid)
            if relay_port not in initial_relay_ports:
                raise RuntimeError("TURN readiness marker lacks owned control socket")

            host = secure.TrackedProcess(
                host_command(
                    probe_bin,
                    host_address,
                    host_dir,
                    client_dir,
                    host_challenge,
                    args.timeout,
                ),
                ROOT,
            )
            if not host.wait_for_text("product-probe-ready role=host", args.timeout):
                raise RuntimeError("Product Host did not become ready")
            host_ports = process_udp_ports(host.proc.pid)
            if host_port not in host_ports:
                raise RuntimeError("Product Host readiness lacks owned UDP socket")

            client = secure.TrackedProcess(
                client_command(
                    probe_bin,
                    host_address,
                    relay_address,
                    client_dir,
                    host_dir,
                    password_file,
                    client_challenge,
                    args.timeout,
                ),
                ROOT,
            )
            if not client.wait_for_text(
                "product-probe-connected role=client route=turn", args.timeout
            ):
                raise RuntimeError("Product Client did not establish TURN exact-mTLS")
            live_relay_ports = process_udp_ports(relay.proc.pid)
            live_host_ports = process_udp_ports(host.proc.pid)
            live_client_ports = process_udp_ports(client.proc.pid)
            if len(live_relay_ports) < 2 or not live_client_ports:
                raise RuntimeError("live TURN allocation socket ownership is incomplete")

            client_code, client_timed_out = client.finish(args.timeout)
            host_code, host_timed_out = host.finish(args.timeout)
            relay_code, relay_timed_out = relay.finish(args.timeout)
            outputs = {
                "relay": relay.output(),
                "host": host.output(),
                "client": client.output(),
            }
            if password_text in "".join(outputs.values()) or any(
                SECRET_RE.search(output) for output in outputs.values()
            ):
                raise ValueError("TURN product logs exposed secret-like material")
            relay_report = relay_gate.parse_server(outputs["relay"])
            host_report = parse_product_result(outputs["host"], "host")
            client_report = parse_product_result(outputs["client"], "client")
            expected_host_hash = hashlib.sha256(bytes.fromhex(host_challenge)).hexdigest()
            expected_client_hash = hashlib.sha256(bytes.fromhex(client_challenge)).hexdigest()
            product_contract = all(
                report[field]
                for report in (host_report, client_report)
                for field in ("exact_mtls", "product", "control", "input", "media", "clean")
            )
            checks = {
                "all_processes_clean": client_code == host_code == relay_code == 0
                and not client_timed_out
                and not host_timed_out
                and not relay_timed_out,
                "forced_turn_route": host_report["route"] == "direct"
                and client_report["route"] == "turn",
                "product_contract": product_contract,
                "session_and_epoch_match": host_report["session_id"]
                == client_report["session_id"]
                and int(host_report["session_id"]) > 0
                and host_report["route_epoch"] == client_report["route_epoch"] == 1,
                "cross_process_challenges": host_report["peer_challenge_sha256"]
                == expected_client_hash
                and client_report["peer_challenge_sha256"] == expected_host_hash,
                "host_observed_relay_source": host_report["peer_source"]
                == client_report["local_route"],
                "allocation_deallocated": relay_report["allocations"] == 1
                and relay_report["deallocations"] == 1
                and relay_report["clean_shutdown"],
                "bidirectional_encrypted_relay": relay_report["client_to_peer"] > 0
                and relay_report["peer_to_client"] > 0,
                "relay_opaque_no_desktop": relay_report["opaque_payload"]
                and not relay_report["desktop_payload"]
                and not relay_report["tcp_relay"],
                "live_socket_ownership": relay_port in live_relay_ports
                and host_port in live_host_ports
                and len(live_relay_ports) >= 2
                and bool(live_client_ports),
            }
            checks["ok"] = all(checks.values())
            return {
                "schema": 1,
                "status": "passed" if checks["ok"] else "failed",
                "ok": checks["ok"],
                "checks": checks,
                "relay_report": relay_report,
                "host_report": host_report,
                "client_report": client_report,
                "versions": versions,
                "source": {
                    "repository_revision_at_test": revision,
                    "worktree_dirty_at_test": worktree_dirty,
                    "binary_sha256_proves_revision": False,
                },
                "socket_ownership": {
                    "relay_pid": relay.proc.pid,
                    "relay_control_port": relay_port,
                    "relay_udp_ports": sorted(live_relay_ports),
                    "host_pid": host.proc.pid,
                    "host_udp_ports": sorted(live_host_ports),
                    "client_pid": client.proc.pid,
                    "client_udp_ports": sorted(live_client_ports),
                },
                "identities": {
                    "host_certificate_sha256": secure.file_sha256(
                        identity_file(host_dir, secure.CERTIFICATE_FILE)
                    ),
                    "client_certificate_sha256": secure.file_sha256(
                        identity_file(client_dir, secure.CERTIFICATE_FILE)
                    ),
                    "der_pairs_validated": True,
                    "private_key_exported": False,
                },
                "sha256": {
                    "relay_binary": secure.file_sha256(relay_bin),
                    "probe_binary": secure.file_sha256(probe_bin),
                    "identity_binary": secure.file_sha256(identity_bin),
                    **{
                        f"{name}_log": hashlib.sha256(output.encode()).hexdigest()
                        for name, output in outputs.items()
                    },
                },
                "evidence_scope": {
                    "network": "single-machine IPv4 loopback forced relay",
                    "payload": "exact-mTLS encrypted ProductSession control/input/media",
                    "competitive_claim": "not evidence of AnyDesk or RustDesk superiority",
                    "public_turn": False,
                },
            }
        finally:
            for process in (client, host, relay):
                if process is not None:
                    process.close()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--relay-bin", type=Path, required=True)
    parser.add_argument("--probe-bin", type=Path, required=True)
    parser.add_argument("--identity-bin", type=Path, required=True)
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if not 5 <= args.timeout <= 60:
        parser.error("--timeout must be in 5..=60")
    try:
        report = run(args)
    except Exception as error:  # noqa: BLE001 - every failure is retained.
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
