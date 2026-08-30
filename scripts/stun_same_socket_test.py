#!/usr/bin/env python3
"""Fail-closed fake-STUN and authenticated candidate-advertisement evidence.

This proves only that one explicitly configured RFC 8489 Binding transaction
and the following QUIC connection use the same local UDP socket, then exchange
a bounded candidate set inside the exact-mTLS product session without changing
the active route. It is not ICE, NAT traversal, nomination, or authorization.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import socket
import struct
import sys
import tempfile
import threading
import zlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import secure_connect_test as secure  # noqa: E402


ROOT = SCRIPT_DIR.parent
DEFAULT_OUTPUT = ROOT / "artifacts" / "stun-same-socket.json"
MAGIC_COOKIE = 0x2112A442
FINGERPRINT_XOR = 0x5354554E
BINDING_REQUEST = 0x0001
BINDING_SUCCESS = 0x0101
XOR_MAPPED_ADDRESS = 0x0020
FINGERPRINT = 0x8028
STUN_RE = re.compile(
    r"^stun:\s+server=(\S+)\s+local=(\S+)\s+reflexive=(\S+)\s+"
    r"requests=(\d+)\s+ignored=(\d+)\s+drained=(\d+)\s+elapsed_ms=(\d+)\s*$",
    re.IGNORECASE | re.MULTILINE,
)
LOCAL_RE = re.compile(r"^Local Binding Address:\s*(\S+)\s*$", re.I | re.M)
HOST_LISTEN_RE = re.compile(
    r"^Listening securely on\s+(127\.0\.0\.1):(\d+)\s*$", re.I | re.M
)
HOST_PEER_RE = re.compile(r"^quic-peer:\s+source=(\S+)\s*$", re.I | re.M)
CLIENT_LIFECYCLE_RE = re.compile(
    r"^handshake-lifecycle:\s*generation=(\d+)\s+authorization_epoch=(\d+)\s+"
    r"display_epoch=(\d+)\s+codec_epoch=(\d+)\s*$",
    re.I | re.M,
)
CANDIDATE_EXCHANGE_RE = re.compile(
    r"^candidate-exchange:\s+authenticated=(true|false)\s+session_id=(\d+)\s+"
    r"local_exchange_id=(\d+)\s+local_generation=(\d+)\s+local_candidates=(\d+)\s+"
    r"local_sha256=([0-9a-f]{64})\s+remote_exchange_id=(\d+)\s+"
    r"remote_generation=(\d+)\s+remote_candidates=(\d+)\s+"
    r"remote_sha256=([0-9a-f]{64})\s+transport_peer=(\S+)"
    r"(?:\s+active_route=(\S+))?\s+route_changed=(true|false)\s*$",
    re.IGNORECASE | re.MULTILINE,
)
SCOPE_MARKER = (
    "stun-scope: candidate discovery only; exact-certificate mTLS remains mandatory"
)
CANDIDATE_SCOPE_MARKER = (
    "candidate-exchange-scope: advertisement-only connectivity_checks=false "
    "nomination=false ice_complete=false"
)


def _fingerprint(message_before_attribute: bytes) -> int:
    return zlib.crc32(message_before_attribute) ^ FINGERPRINT_XOR


def encode_binding_request(transaction_id: bytes) -> bytes:
    if len(transaction_id) != 12:
        raise ValueError("STUN transaction ID must be 12 bytes")
    header = struct.pack(">HHI12s", BINDING_REQUEST, 8, MAGIC_COOKIE, transaction_id)
    return header + struct.pack(">HHI", FINGERPRINT, 4, _fingerprint(header))


def parse_binding_request(message: bytes) -> bytes:
    if len(message) != 28:
        raise ValueError("expected one fixed-size Binding request")
    message_type, length, cookie, transaction_id = struct.unpack(">HHI12s", message[:20])
    kind, attribute_length, fingerprint = struct.unpack(">HHI", message[20:28])
    if (
        message_type != BINDING_REQUEST
        or length != 8
        or cookie != MAGIC_COOKIE
        or kind != FINGERPRINT
        or attribute_length != 4
        or fingerprint != _fingerprint(message[:20])
    ):
        raise ValueError("invalid Binding request header or fingerprint")
    return transaction_id


def encode_binding_success(transaction_id: bytes, mapped: tuple[str, int]) -> bytes:
    if len(transaction_id) != 12:
        raise ValueError("STUN transaction ID must be 12 bytes")
    address, port = mapped
    packed_address = socket.inet_pton(socket.AF_INET, address)
    if not 1 <= port <= 65535:
        raise ValueError("mapped port must be nonzero")
    xor_port = port ^ (MAGIC_COOKIE >> 16)
    xor_address = bytes(
        plain ^ mask for plain, mask in zip(packed_address, MAGIC_COOKIE.to_bytes(4, "big"))
    )
    xor_attribute = struct.pack(">HHBBH4s", XOR_MAPPED_ADDRESS, 8, 0, 1, xor_port, xor_address)
    header = struct.pack(">HHI12s", BINDING_SUCCESS, 20, MAGIC_COOKIE, transaction_id)
    covered = header + xor_attribute
    return covered + struct.pack(">HHI", FINGERPRINT, 4, _fingerprint(covered))


def parse_binding_success(message: bytes, expected_transaction_id: bytes) -> tuple[str, int]:
    if len(message) != 40 or len(expected_transaction_id) != 12:
        raise ValueError("expected one fixed-size IPv4 Binding success")
    message_type, length, cookie, transaction_id = struct.unpack(">HHI12s", message[:20])
    kind, attribute_length, reserved, family, xor_port, xor_address = struct.unpack(
        ">HHBBH4s", message[20:32]
    )
    fingerprint_kind, fingerprint_length, fingerprint = struct.unpack(
        ">HHI", message[32:40]
    )
    if (
        message_type != BINDING_SUCCESS
        or length != 20
        or cookie != MAGIC_COOKIE
        or transaction_id != expected_transaction_id
        or kind != XOR_MAPPED_ADDRESS
        or attribute_length != 8
        or reserved != 0
        or family != 1
        or fingerprint_kind != FINGERPRINT
        or fingerprint_length != 4
        or fingerprint != _fingerprint(message[:32])
    ):
        raise ValueError("invalid Binding success")
    port = xor_port ^ (MAGIC_COOKIE >> 16)
    address = bytes(
        encoded ^ mask
        for encoded, mask in zip(xor_address, MAGIC_COOKIE.to_bytes(4, "big"))
    )
    if port == 0:
        raise ValueError("mapped port must be nonzero")
    return socket.inet_ntop(socket.AF_INET, address), port


def _render_address(address: tuple[str, int]) -> str:
    return f"{address[0]}:{address[1]}"


def canonical_host_candidate_exchange_sha256(session_id: int, address: str) -> str:
    host, raw_port = address.rsplit(":", 1)
    port = int(raw_port)
    packed_address = socket.inet_pton(socket.AF_INET, host)
    if session_id <= 0 or not 1 <= port <= 65535:
        raise ValueError("candidate evidence requires a nonzero session and IPv4 port")
    priority = (126 << 24) | (65535 << 8) | 255
    candidate = (
        (1).to_bytes(8, "big")
        + struct.pack(">BBBBIH", 1, 1, 1, 0, priority, port)
        + b"\x04"
        + packed_address
        + b"\x00"
    )
    exchange = (
        struct.pack(">BQIB", 1, session_id, 1, 1)
        + struct.pack(">H", len(candidate))
        + candidate
    )
    return hashlib.sha256(exchange).hexdigest()


def parse_client_stun(output: str) -> dict[str, object]:
    matches = STUN_RE.findall(output)
    local_matches = LOCAL_RE.findall(output)
    if len(matches) != 1 or len(local_matches) != 1 or output.count(SCOPE_MARKER) != 1:
        raise ValueError("expected one complete same-socket STUN log record")
    server, local, reflexive, requests, ignored, drained, elapsed_ms = matches[0]
    if local != local_matches[0]:
        raise ValueError("STUN local address does not match QUIC endpoint")
    return {
        "server": server,
        "local": local,
        "reflexive": reflexive,
        "requests": int(requests),
        "ignored": int(ignored),
        "drained": int(drained),
        "elapsed_ms": int(elapsed_ms),
    }


def parse_host_listen_address(output: str) -> str:
    matches = HOST_LISTEN_RE.findall(output)
    if len(matches) != 1:
        raise ValueError("expected one Host IPv4 loopback listen address")
    host, raw_port = matches[0]
    port = int(raw_port)
    if not 1 <= port <= 65535:
        raise ValueError("Host listen port must be nonzero")
    return f"{host}:{port}"


def parse_host_peer_source(output: str) -> str:
    matches = HOST_PEER_RE.findall(output)
    if len(matches) != 1:
        raise ValueError("expected one authenticated QUIC peer source address")
    return matches[0]


def parse_candidate_exchange(
    output: str, *, require_active_route: bool
) -> dict[str, object]:
    matches = CANDIDATE_EXCHANGE_RE.findall(output)
    if len(matches) != 1:
        raise ValueError("expected one complete authenticated candidate exchange record")
    (
        authenticated,
        session_id,
        local_exchange_id,
        local_generation,
        local_candidates,
        local_sha256,
        remote_exchange_id,
        remote_generation,
        remote_candidates,
        remote_sha256,
        transport_peer,
        active_route,
        route_changed,
    ) = matches[0]
    if authenticated.lower() != "true" or route_changed.lower() != "false":
        raise ValueError("candidate exchange must be authenticated and route preserving")
    if require_active_route != bool(active_route):
        raise ValueError("candidate exchange active-route field has the wrong role")
    return {
        "authenticated": True,
        "session_id": int(session_id),
        "local_exchange_id": int(local_exchange_id),
        "local_generation": int(local_generation),
        "local_candidates": int(local_candidates),
        "local_sha256": local_sha256,
        "remote_exchange_id": int(remote_exchange_id),
        "remote_generation": int(remote_generation),
        "remote_candidates": int(remote_candidates),
        "remote_sha256": remote_sha256,
        "transport_peer": transport_peer,
        "active_route": active_route or None,
        "route_changed": False,
    }


class FakeStunServer:
    def __init__(self) -> None:
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._socket.bind(("127.0.0.1", 0))
        self._socket.settimeout(15)
        self.address = _render_address(self._socket.getsockname())
        self.observation: dict[str, object] = {}
        self.error: str | None = None
        self._thread = threading.Thread(target=self._run, name="fake-stun", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def _run(self) -> None:
        try:
            request, source = self._socket.recvfrom(2049)
            transaction_id = parse_binding_request(request)
            response = encode_binding_success(transaction_id, source)
            sent = self._socket.sendto(response, source)
            if sent != len(response):
                raise RuntimeError("partial fake STUN response")
            self.observation = {
                "source": _render_address(source),
                "request_bytes": len(request),
                "response_bytes": len(response),
                "request_fingerprint_valid": True,
                "transaction_id_sha256": hashlib.sha256(transaction_id).hexdigest(),
            }
        except Exception as error:  # fail is surfaced by join()
            self.error = str(error)
        finally:
            self._socket.close()

    def join(self, timeout: float = 20) -> dict[str, object]:
        self._thread.join(timeout)
        if self._thread.is_alive():
            self._socket.close()
            raise RuntimeError("fake STUN server did not finish")
        if self.error:
            raise RuntimeError(f"fake STUN server failed: {self.error}")
        return self.observation


def build_commands(
    host_bin: Path,
    client_bin: Path,
    host_address: str,
    stun_address: str,
    host_dir: Path,
    client_dir: Path,
    frames: int,
) -> tuple[list[str], list[str]]:
    host = [
        str(host_bin),
        "--listen",
        host_address,
        "--identity-cert",
        str(host_dir / secure.CERTIFICATE_FILE),
        "--identity-key",
        str(host_dir / secure.PRIVATE_KEY_FILE),
        "--peer-cert",
        str(client_dir / secure.CERTIFICATE_FILE),
        "--pairing-timeout",
        "30",
        "--max-width",
        "320",
        "--max-height",
        "180",
        "--fps",
        "10",
        "--frames",
        str(max(frames * 2, frames + 8)),
        "--max-sessions",
        "1",
    ]
    client = [
        str(client_bin),
        "--connect",
        host_address,
        "--bind",
        "127.0.0.1:0",
        "--stun-server",
        stun_address,
        "--identity-cert",
        str(client_dir / secure.CERTIFICATE_FILE),
        "--identity-key",
        str(client_dir / secure.PRIVATE_KEY_FILE),
        "--peer-cert",
        str(host_dir / secure.CERTIFICATE_FILE),
        "--pairing-timeout",
        "30",
        "--candidate-exchange-probe",
    ]
    return host, client


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host-bin", type=Path)
    parser.add_argument("--client-bin", type=Path)
    parser.add_argument("--identity-bin", type=Path)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--frames", type=secure.bounded_int("frames", 2, 30), default=3)
    parser.add_argument("--timeout", type=secure.bounded_int("timeout", 10, 120), default=45)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    revision, dirty = secure.repository_state()
    report: dict[str, object] = {
        "schema_version": 1,
        "status": "pending",
        "ok": False,
        "executed": False,
        "scope": "single-machine IPv4 loopback fake-STUN to same-socket exact-mTLS QUIC and authenticated candidate advertisement",
        "honest_scope": (
            "server-reflexive discovery/socket handoff plus post-mTLS bounded candidate "
            "advertisement only; not ICE checks/nomination, NAT traversal, relay, "
            "cross-machine connectivity, or AnyDesk comparison"
        ),
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
    temporary = tempfile.TemporaryDirectory(prefix="open-desk-stun-same-socket-")
    temporary_root = Path(temporary.name)
    host_dir = temporary_root / "host"
    client_dir = temporary_root / "client"
    processes: list[secure.TrackedProcess] = []
    host_process: secure.TrackedProcess | None = None
    client_process: secure.TrackedProcess | None = None
    fake_stun: FakeStunServer | None = None
    host_output = client_output = ""
    host_exit = client_exit = None
    host_timed_out = client_timed_out = False
    identity_generation_ok = False
    binary_hashes: dict[str, str] = {}
    commands: tuple[list[str], list[str]] = ([], [])
    host_address: str | None = None
    stun_observation: dict[str, object] = {}
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
        secure.generate_identity(identity_bin, "stun-host", host_dir, 10)
        secure.generate_identity(identity_bin, "stun-client", client_dir, 10)
        identity_generation_ok = True
        fake_stun = FakeStunServer()
        host_command, _ = build_commands(
            host_bin,
            client_bin,
            "127.0.0.1:0",
            fake_stun.address,
            host_dir,
            client_dir,
            args.frames,
        )
        if secure.commands_contain_unsafe_flag((host_command,)):
            raise RuntimeError("unsafe transport flag present")

        fake_stun.start()
        host_process = secure.TrackedProcess(host_command, ROOT)
        processes.append(host_process)
        if not host_process.wait_for_text(secure.HOST_READY_MARKER, 15):
            raise RuntimeError("Host did not become ready")
        host_address = parse_host_listen_address(host_process.output())
        _, client_command = build_commands(
            host_bin,
            client_bin,
            host_address,
            fake_stun.address,
            host_dir,
            client_dir,
            args.frames,
        )
        commands = (host_command, client_command)
        if secure.commands_contain_unsafe_flag(commands):
            raise RuntimeError("unsafe transport flag present")
        client_process = secure.TrackedProcess(client_command, ROOT)
        processes.append(client_process)
        client_exit, client_timed_out = client_process.finish(args.timeout)
        client_output = client_process.output()
        stun_observation = fake_stun.join()
        host_exit, host_timed_out = host_process.finish(15)
        host_output = host_process.output()
    except Exception as error:
        runtime_error = secure.sanitize_log(str(error), temporary_root, 1_000)
    finally:
        for process in reversed(processes):
            process.close()
        if host_process is not None:
            host_output = host_process.output()
            host_exit = host_process.poll() if host_exit is None else host_exit
        if client_process is not None:
            client_output = client_process.output()
            client_exit = client_process.poll() if client_exit is None else client_exit
        if fake_stun is not None and not stun_observation and runtime_error is None:
            try:
                stun_observation = fake_stun.join(1)
            except Exception as error:
                runtime_error = secure.sanitize_log(str(error), temporary_root, 1_000)
        temporary.cleanup()

    parsed_stun: dict[str, object] = {}
    client_candidate_exchange: dict[str, object] = {}
    host_candidate_exchange: dict[str, object] = {}
    host_peer_source: str | None = None
    validation_errors: list[str] = []
    try:
        parsed_stun = parse_client_stun(client_output)
        host_peer_source = parse_host_peer_source(host_output)
        client_candidate_exchange = parse_candidate_exchange(
            client_output, require_active_route=True
        )
        host_candidate_exchange = parse_candidate_exchange(
            host_output, require_active_route=False
        )
    except ValueError as error:
        validation_errors.append(str(error))
    host_ids = secure.parse_host_session_ids(host_output)
    client_ids = secure.parse_client_session_ids(client_output)
    host_lifecycles = secure.parse_host_lifecycles(host_output)
    client_lifecycles = [
        tuple(int(value) for value in match)
        for match in CLIENT_LIFECYCLE_RE.findall(client_output)
    ]
    received = secure.parse_received_all(client_output)
    routes = secure.parse_client_routes(client_output)
    same_socket = bool(parsed_stun) and (
        parsed_stun.get("local")
        == parsed_stun.get("reflexive")
        == stun_observation.get("source")
        == host_peer_source
    )
    session_bound_candidate_exchange = len(host_ids) == 1 and all(
        value == host_ids[0]
        for value in (
            client_candidate_exchange.get("session_id"),
            client_candidate_exchange.get("local_exchange_id"),
            client_candidate_exchange.get("remote_exchange_id"),
            host_candidate_exchange.get("session_id"),
            host_candidate_exchange.get("local_exchange_id"),
            host_candidate_exchange.get("remote_exchange_id"),
        )
    )
    candidate_counts_match = (
        client_candidate_exchange.get("local_candidates")
        == host_candidate_exchange.get("remote_candidates")
        and client_candidate_exchange.get("remote_candidates")
        == host_candidate_exchange.get("local_candidates")
        and isinstance(client_candidate_exchange.get("local_candidates"), int)
        and client_candidate_exchange.get("local_candidates", 0) > 0
        and isinstance(client_candidate_exchange.get("remote_candidates"), int)
        and client_candidate_exchange.get("remote_candidates", 0) > 0
    )
    expected_client_digest = expected_host_digest = None
    if len(host_ids) == 1 and host_address is not None and parsed_stun.get("local"):
        try:
            expected_client_digest = canonical_host_candidate_exchange_sha256(
                host_ids[0], str(parsed_stun["local"])
            )
            expected_host_digest = canonical_host_candidate_exchange_sha256(
                host_ids[0], host_address
            )
        except (OSError, ValueError) as error:
            validation_errors.append(str(error))
    candidate_after_mtls = all(
        mtls_marker in output
        and marker in output
        and output.index(mtls_marker) < output.index(marker)
        for output, mtls_marker, marker in (
            (
                client_output,
                "mTLS: exact host certificate authenticated",
                "candidate-exchange: authenticated=true",
            ),
            (
                host_output,
                "mTLS: exact client certificate authenticated",
                "candidate-exchange: authenticated=true",
            ),
        )
    )
    checks = {
        "identity_generation_ok": identity_generation_ok,
        "host_exit_zero": host_exit == 0 and not host_timed_out,
        "client_exit_zero": client_exit == 0 and not client_timed_out,
        "fake_stun_request_valid": stun_observation.get("request_fingerprint_valid") is True
        and stun_observation.get("request_bytes") == 28
        and stun_observation.get("response_bytes") == 40,
        "same_socket_stun_and_quic_sources": same_socket,
        "single_bounded_transaction": parsed_stun.get("requests") == 1
        and parsed_stun.get("ignored") == 0
        and parsed_stun.get("drained") == 0,
        "candidate_only_scope_logged": client_output.count(SCOPE_MARKER) == 1,
        "candidate_exchange_scope_logged": client_output.count(CANDIDATE_SCOPE_MARKER)
        == 1
        and host_output.count(CANDIDATE_SCOPE_MARKER) == 1,
        "candidate_exchange_after_exact_mtls": candidate_after_mtls,
        "candidate_exchange_bound_to_active_session": session_bound_candidate_exchange,
        "candidate_exchange_generation_one": client_candidate_exchange.get(
            "local_generation"
        )
        == client_candidate_exchange.get("remote_generation")
        == host_candidate_exchange.get("local_generation")
        == host_candidate_exchange.get("remote_generation")
        == 1,
        "candidate_counts_match_both_directions": candidate_counts_match,
        "candidate_payloads_match_observed_sockets": expected_client_digest is not None
        and expected_host_digest is not None
        and client_candidate_exchange.get("local_sha256")
        == host_candidate_exchange.get("remote_sha256")
        == expected_client_digest
        and client_candidate_exchange.get("remote_sha256")
        == host_candidate_exchange.get("local_sha256")
        == expected_host_digest,
        "redundant_same_socket_srflx_eliminated": same_socket
        and client_candidate_exchange.get("local_candidates") == 1,
        "candidate_exchange_did_not_change_route": host_address is not None
        and client_candidate_exchange.get("active_route") == host_address
        and client_candidate_exchange.get("transport_peer") == host_address
        and host_candidate_exchange.get("transport_peer") == host_peer_source
        and client_candidate_exchange.get("route_changed") is False
        and host_candidate_exchange.get("route_changed") is False,
        "exact_mtls_both_sides": host_output.count(
            "mTLS: exact client certificate authenticated"
        )
        == 1
        and client_output.count("mTLS: exact host certificate authenticated") == 1,
        "exact_route_excludes_stun_server": host_address is not None
        and routes == [(host_address, 1)]
        and parsed_stun.get("server") != host_address,
        "one_matching_lifecycle": len(host_ids) == 1
        and host_ids == client_ids
        and len(host_lifecycles) == 1
        and host_lifecycles == client_lifecycles,
        "requested_frames_received": len(host_ids) == 1
        and len(received) == 1
        and received[0][0] == host_ids[0]
        and received[0][1] >= 1,
        "one_real_desktop_stream": secure.parse_host_desktop_streams(host_output) == 1,
        "release_all_completed": "input: ReleaseAll applied" in host_output,
        "binary_hashes_complete": len(binary_hashes) == 3
        and all(len(value) == 64 for value in binary_hashes.values()),
        "no_unsafe_transport_flag": not secure.commands_contain_unsafe_flag(commands),
        "temporary_credentials_removed": not temporary_root.exists(),
        "no_runtime_error": runtime_error is None,
    }
    errors = [name for name, passed in checks.items() if not passed]
    errors.extend(validation_errors)
    if runtime_error:
        errors.insert(0, runtime_error)
    passed = all(checks.values()) and not errors
    report.update(
        status="passed" if passed else "failed",
        ok=passed,
        checks=checks,
        errors=errors,
        stun={
            "client": parsed_stun,
            "server": stun_observation,
            "host_observed_quic_source": host_peer_source,
        },
        candidate_exchange={
            "client": client_candidate_exchange,
            "host": host_candidate_exchange,
        },
        results={
            "host_session_ids": host_ids,
            "client_session_ids": client_ids,
            "host_lifecycles": host_lifecycles,
            "client_lifecycles": client_lifecycles,
            "received": received,
            "routes": routes,
        },
        binaries=binary_hashes,
        logs={
            "host_tail": secure.sanitize_log(host_output, temporary_root),
            "client_tail": secure.sanitize_log(client_output, temporary_root),
        },
    )
    secure.write_report(args.output, report)
    print(f"Report: {args.output}")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
