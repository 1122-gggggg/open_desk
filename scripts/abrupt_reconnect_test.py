#!/usr/bin/env python3
"""Fail-closed loopback UDP blackhole test for abrupt ProductSession recovery.

This is deliberately narrow evidence: one Linux machine, IPv4 loopback, and a
four-second UDP drop window.  It does not establish Wi-Fi, cross-machine, or
AnyDesk superiority.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Sequence

from secure_connect_test import (  # type: ignore[import-not-found]
    CERTIFICATE_FILE,
    HOST_READY_MARKER,
    PRIVATE_KEY_FILE,
    TrackedProcess,
    bounded_int,
    find_binary,
    generate_identity,
    prerequisite_skip_reason,
    sanitize_log,
    write_report,
)

ROOT = Path(__file__).resolve().parents[1]
UNSAFE_FLAG = "--unsafe-udp-lab"
DROP_SECONDS = 4.0
RECOVERY_OBSERVATION_TIMEOUT = 15.0
LOOPBACK_RECOVERY_TARGET_MS = 2_000.0
STREAM_RE = re.compile(r"stream: .*over QUIC DATAGRAM", re.I)
SESSION_RE = re.compile(r"(?:session: active|handshake: active) session_id=(\d+)", re.I)
LIFE_RE = re.compile(
    r"session-lifecycle: generation=(\d+) authorization_epoch=(\d+) display_epoch=(\d+) codec_epoch=(\d+)",
    re.I,
)
CLIENT_LIFE_RE = re.compile(
    r"handshake-lifecycle: generation=(\d+) authorization_epoch=(\d+) display_epoch=(\d+) codec_epoch=(\d+)",
    re.I,
)
RECEIVED_RE = re.compile(r"received: session_id=(\d+) frames=(\d+)", re.I)


def bounded_float(name: str, minimum: float, maximum: float):
    def parse(value: str) -> float:
        try:
            parsed = float(value)
        except ValueError as error:
            raise argparse.ArgumentTypeError(f"{name} must be a number") from error
        if not minimum <= parsed <= maximum:
            raise argparse.ArgumentTypeError(
                f"{name} must be between {minimum} and {maximum}"
            )
        return parsed

    return parse


def lifecycles_strictly_advance(
    lifecycles: Sequence[tuple[int, int, int, int]],
) -> bool:
    return len(lifecycles) == 2 and all(
        current > previous
        for previous_lifecycle, current_lifecycle in zip(
            lifecycles, lifecycles[1:]
        )
        for previous, current in zip(previous_lifecycle, current_lifecycle)
    )


class UdpForwardProxy:
    """Bounded IPv4 UDP forwarder with an atomic, observable drop window."""

    def __init__(self, listen: tuple[str, int], target: tuple[str, int]) -> None:
        self.listen, self.target = listen, target
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(listen)
        self.sock.settimeout(0.1)
        self.client: tuple[str, int] | None = None
        self.running = False
        self.drop = False
        self.dropped = 0
        self.forwarded = 0
        self.forwarded_after_resume = 0
        self.resumed = False
        self._thread: threading.Thread | None = None

    @property
    def address(self) -> tuple[str, int]:
        return self.sock.getsockname()

    def start(self) -> None:
        self.running = True
        self._thread = threading.Thread(
            target=self._run, name="udp-blackhole", daemon=True
        )
        self._thread.start()

    def _run(self) -> None:
        while self.running:
            try:
                payload, source = self.sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            if source == self.target:
                if self.client is None:
                    continue
                destination = self.client
            else:
                self.client = source
                destination = self.target
            if self.drop:
                self.dropped += 1
                continue
            try:
                self.sock.sendto(payload, destination)
                self.forwarded += 1
                if self.resumed:
                    self.forwarded_after_resume += 1
            except OSError:
                pass

    def set_drop(self, enabled: bool) -> None:
        self.drop = enabled
        if not enabled:
            self.resumed = True

    def close(self) -> None:
        self.running = False
        try:
            self.sock.close()
        finally:
            if self._thread:
                self._thread.join(timeout=1)


def build_abrupt_commands(
    *,
    host_bin: Path,
    client_bin: Path,
    listen_addr: str,
    proxy_addr: str,
    host_dir: Path,
    client_dir: Path,
    frames: int = 3,
    reconnect_attempts: int = 3,
) -> tuple[list[str], list[str]]:
    host = [
        str(host_bin),
        "--listen",
        listen_addr,
        "--identity-cert",
        str(host_dir / CERTIFICATE_FILE),
        "--identity-key",
        str(host_dir / PRIVATE_KEY_FILE),
        "--peer-cert",
        str(client_dir / CERTIFICATE_FILE),
        "--pairing-timeout",
        "30",
        "--fps",
        "10",
        "--max-width",
        "320",
        "--max-height",
        "180",
        "--max-sessions",
        "2",
    ]
    client = [
        str(client_bin),
        "--connect",
        "127.0.0.1:1",
        "--fallback-address",
        proxy_addr,
        "--bind",
        "127.0.0.1:0",
        "--identity-cert",
        str(client_dir / CERTIFICATE_FILE),
        "--identity-key",
        str(client_dir / PRIVATE_KEY_FILE),
        "--peer-cert",
        str(host_dir / CERTIFICATE_FILE),
        "--pairing-timeout",
        "25",
        "--frames",
        str(frames),
        "--reconnect-attempts",
        str(reconnect_attempts),
    ]
    return host, client


def validate_abrupt_result(
    observation: dict[str, object],
) -> tuple[dict[str, bool], list[str]]:
    checks = {
        "proxy_dropped_and_resumed": bool(observation.get("proxy_dropped", 0))
        and bool(observation.get("proxy_resumed"))
        and int(observation.get("proxy_forwarded_after_resume", 0)) > 0,
        "drop_triggered_after_desktop_stream": bool(
            observation.get("drop_triggered_after_desktop_stream")
        ),
        "identity_generation_ok": bool(observation.get("identity_generation_ok")),
        "transport_loss_logged": bool(observation.get("transport_loss_logged")),
        "host_transport_loss_logged": bool(
            observation.get("host_transport_loss_logged")
        ),
        "reconnect_logged": bool(observation.get("reconnect_logged")),
        "recovered_logged": bool(observation.get("recovered_logged")),
        "post_resume_reconnect_within_target": isinstance(
            observation.get("post_resume_reconnect_ms"), (int, float)
        )
        and 0 <= float(observation["post_resume_reconnect_ms"])
        <= LOOPBACK_RECOVERY_TARGET_MS,
        "two_matching_sessions": observation.get("host_session_ids")
        == observation.get("client_session_ids")
        and len(observation.get("host_session_ids", [])) == 2,
        "lifecycle_advances": bool(observation.get("lifecycle_advances")),
        "release_all_between": bool(observation.get("release_all_between")),
        "successor_frames_only": bool(observation.get("successor_frames_only")),
        "two_streams": observation.get("desktop_streams") == 2,
        "exact_mtls_twice": observation.get("host_mtls", 0) >= 2
        and observation.get("client_mtls", 0) >= 2,
        "fallback_selected": bool(observation.get("fallback_selected")),
        "zero_exits": observation.get("host_exit") == 0
        and observation.get("client_exit") == 0,
        "no_process_timeout": not observation.get("host_timed_out", False)
        and not observation.get("client_timed_out", False),
        "credentials_removed": bool(observation.get("credentials_removed")),
        "no_unsafe_flag": observation.get("unsafe_flag") is False,
    }
    labels = {name: f"missing abrupt reconnect evidence: {name}" for name in checks}
    return checks, [labels[name] for name, passed in checks.items() if not passed]


def extract_evidence(
    host_output: str,
    client_output: str,
    proxy: UdpForwardProxy,
    host_exit: int | None,
    client_exit: int | None,
    credentials_removed: bool,
    commands: Sequence[Sequence[str]],
    requested_frames: int,
    identity_generation_ok: bool,
    post_resume_reconnect_ms: float | None = None,
) -> dict[str, object]:
    host_sessions = [int(x) for x in SESSION_RE.findall(host_output)]
    client_sessions = [int(x) for x in SESSION_RE.findall(client_output)]
    host_life = [tuple(int(x) for x in m) for m in LIFE_RE.findall(host_output)]
    client_life = [
        tuple(int(x) for x in match) for match in CLIENT_LIFE_RE.findall(client_output)
    ]
    received = [(int(a), int(b)) for a, b in RECEIVED_RE.findall(client_output)]
    release_positions = [
        m.start()
        for m in re.finditer(
            r"^input: ReleaseAll applied\s*$", host_output, re.I | re.M
        )
    ]
    stream_positions = [m.start() for m in STREAM_RE.finditer(host_output)]
    loss = "reconnect: recoverable transport loss" in client_output
    host_loss = bool(
        re.search(
            r"^session: authenticated peer transport lost(?: after ReleaseAll)?$",
            host_output,
            re.M,
        )
    )
    reconnect = bool(
        re.search(
            r"^reconnect: recoverable transport loss, attempt \d+/\d+ after ",
            client_output,
            re.M,
        )
    )
    recovered_marker = bool(
        re.search(
            r"^reconnect: recovered authenticated session after \d+ attempt\(s\)$",
            client_output,
            re.M,
        )
    )
    recovered = recovered_marker and (
        len(received) == 1
        and len(client_sessions) == 2
        and received[0][0] == client_sessions[1]
        and received[0][1] >= requested_frames
    )
    first_session = [
        m.start()
        for m in re.finditer(r"session: active session_id=", host_output, re.I)
    ]
    second_session = first_session[1] if len(first_session) > 1 else -1
    routes = re.findall(
        r"route: authenticated (\S+) after racing (\d+) candidate", client_output, re.I
    )
    proxy_text = f"127.0.0.1:{proxy.address[1]}"
    return {
        "proxy_dropped": proxy.dropped,
        "proxy_forwarded": proxy.forwarded,
        "proxy_forwarded_after_resume": proxy.forwarded_after_resume,
        "proxy_resumed": proxy.resumed
        and proxy.forwarded_after_resume > 0,
        "drop_triggered_after_desktop_stream": True,
        "identity_generation_ok": identity_generation_ok,
        "transport_loss_logged": loss,
        "host_transport_loss_logged": host_loss,
        "reconnect_logged": reconnect,
        "recovered_logged": recovered,
        "post_resume_reconnect_ms": post_resume_reconnect_ms,
        "host_session_ids": host_sessions,
        "client_session_ids": client_sessions,
        "host_lifecycles": host_life,
        "client_lifecycles": client_life,
        "lifecycle_advances": host_life == client_life
        and lifecycles_strictly_advance(host_life)
        and lifecycles_strictly_advance(client_life),
        "release_all_between": bool(
            release_positions
            and first_session
            and second_session > first_session[0]
            and any(first_session[0] < p < second_session for p in release_positions)
        ),
        "successor_frames_only": recovered,
        "desktop_streams": len(stream_positions),
        "host_mtls": host_output.count("mTLS: exact client certificate authenticated"),
        "client_mtls": client_output.count(
            "mTLS: exact host certificate authenticated"
        ),
        "fallback_selected": len(routes) == 2
        and all(
            route == proxy_text and int(attempts) >= 2 for route, attempts in routes
        ),
        "host_exit": host_exit,
        "client_exit": client_exit,
        "credentials_removed": credentials_removed,
        "unsafe_flag": any(UNSAFE_FLAG in command for command in commands),
    }


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frames", type=bounded_int("frames", 1, 120), default=3)
    parser.add_argument(
        "--drop-seconds",
        type=bounded_float("drop-seconds", 0.5, 30.0),
        default=DROP_SECONDS,
    )
    parser.add_argument("--host-bin", type=Path)
    parser.add_argument("--client-bin", type=Path)
    parser.add_argument("--identity-bin", type=Path)
    parser.add_argument(
        "--output", type=Path, default=ROOT / "artifacts" / "abrupt-reconnect.json"
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    report = {
        "schema_version": 1,
        "status": "pending",
        "ok": False,
        "scope": "single-machine IPv4 loopback UDP blackhole; not Wi-Fi/cross-machine/AnyDesk superiority",
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    skip_reason = prerequisite_skip_reason(
        platform=sys.platform, display=os.environ.get("DISPLAY")
    )
    if skip_reason:
        report.update(status="skipped", reason=skip_reason)
        write_report(args.output, report)
        print(f"SKIPPED: {skip_reason}")
        print(f"Report: {args.output}")
        return 0
    host_proc = client_proc = None
    proxy = None
    temp_root = Path(tempfile.mkdtemp(prefix="abrupt-reconnect-"))
    removed = False
    identity_generation_ok = False
    try:
        host_bin = find_binary("latencydesk-host", args.host_bin)
        client_bin = find_binary("latencydesk-client", args.client_bin)
        identity_bin = find_binary("latencydesk-identity", args.identity_bin)
        host_dir, client_dir = temp_root / "host", temp_root / "client"
        host_dir.mkdir()
        client_dir.mkdir()
        generate_identity(identity_bin, "host", host_dir, 10)
        generate_identity(identity_bin, "client", client_dir, 10)
        identity_generation_ok = True
        target_port = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        target_port.bind(("127.0.0.1", 0))
        host_port = target_port.getsockname()[1]
        target_port.close()
        proxy = UdpForwardProxy(("127.0.0.1", 0), ("127.0.0.1", host_port))
        proxy.start()
        host_cmd, client_cmd = build_abrupt_commands(
            host_bin=host_bin,
            client_bin=client_bin,
            listen_addr=f"127.0.0.1:{host_port}",
            proxy_addr=f"127.0.0.1:{proxy.address[1]}",
            host_dir=host_dir,
            client_dir=client_dir,
            frames=args.frames,
            reconnect_attempts=3,
        )
        host_proc = TrackedProcess(host_cmd, ROOT)
        if not host_proc.wait_for_text(HOST_READY_MARKER, 15):
            raise RuntimeError("host did not become ready")
        client_proc = TrackedProcess(client_cmd, ROOT)
        if not host_proc.wait_for_text("over QUIC DATAGRAM", 20):
            raise RuntimeError("first desktop stream was not announced")
        proxy.set_drop(True)
        time.sleep(args.drop_seconds)
        resumed_at = time.monotonic()
        proxy.set_drop(False)
        if not client_proc.wait_for_text(
            "reconnect: recovered authenticated session",
            RECOVERY_OBSERVATION_TIMEOUT,
        ):
            raise RuntimeError("client did not authenticate a successor after proxy resume")
        post_resume_reconnect_ms = (time.monotonic() - resumed_at) * 1_000
        client_exit, client_timeout = client_proc.finish(45)
        host_exit, host_timeout = host_proc.finish(15)
        observation = extract_evidence(
            host_proc.output(),
            client_proc.output(),
            proxy,
            host_exit,
            client_exit,
            False,
            (host_cmd, client_cmd),
            args.frames,
            identity_generation_ok,
            post_resume_reconnect_ms,
        )
        observation["client_timed_out"] = client_timeout
        observation["host_timed_out"] = host_timeout
    except Exception as error:  # retain complete fail-closed evidence
        observation = {
            "runtime_error": sanitize_log(str(error), temp_root, 1_000),
            "proxy_dropped": 0,
            "proxy_forwarded": 0,
            "proxy_forwarded_after_resume": 0,
            "proxy_resumed": False,
            "drop_triggered_after_desktop_stream": False,
            "identity_generation_ok": identity_generation_ok,
        }
    finally:
        if client_proc:
            client_proc.close()
        if host_proc:
            host_proc.close()
        if proxy:
            proxy.close()
        import shutil

        shutil.rmtree(temp_root, ignore_errors=True)
        removed = not temp_root.exists()
    observation["credentials_removed"] = removed
    checks, errors = validate_abrupt_result(observation)
    report.update(
        status="passed" if not errors else "failed",
        ok=not errors,
        checks=checks,
        errors=errors,
        observation={k: v for k, v in observation.items() if k != "runtime_error"},
    )
    report["runtime_error"] = observation.get("runtime_error")
    report["requested_frames"] = args.frames
    report["drop_seconds"] = args.drop_seconds
    report["loopback_recovery_target_ms"] = LOOPBACK_RECOVERY_TARGET_MS
    report["real_desktop_capture"] = bool(
        not errors
        and observation.get("desktop_streams") == 2
        and observation.get("successor_frames_only") is True
    )
    report["log_tails"] = {
        "host": sanitize_log(host_proc.output() if host_proc else "", temp_root),
        "client": sanitize_log(client_proc.output() if client_proc else "", temp_root),
    }
    write_report(args.output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    print(f"Report: {args.output}")
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
