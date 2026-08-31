#!/usr/bin/env python3
"""Fail-closed Linux X11 process smoke for LatencyDesk's secure QUIC path.

The test deliberately uses three short-lived identities. A client presenting
the rogue identity must be rejected without terminating the host; one pinned
Client process must then create two sequential connections with distinct,
monotonic product sessions and reassemble real X11 frames. ReleaseAll must occur
between the two sessions.
No identity material or command containing private-key paths is written to the
JSON artifact.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform as platform_module
import re
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "artifacts" / "secure-connect.json"
DEFAULT_FRAMES = 8
DEFAULT_FPS = 15
DEFAULT_MAX_WIDTH = 640
DEFAULT_MAX_HEIGHT = 360
DEFAULT_PAIRING_TIMEOUT = 30
TAIL_CHARS = 6_000

TRANSPORT = "quic_v1_tls13_exact_peer_mtls"
SCOPE = "x11_loopback"
VIEWER = "headless_reassembly_only"
UNSAFE_FLAG = "--unsafe-udp-lab"

HOST_READY_MARKER = "Listening securely on"
HOST_MTLS_MARKER = "mTLS: exact client certificate authenticated"
HOST_REJECTION_MARKER = "mTLS: rejected unauthenticated connection"
HOST_SHUTDOWN_MARKER = "shutdown: Ctrl-C requested"
HOST_PEER_COMPLETED_MARKER = "session: peer completed normally"
CLIENT_MTLS_MARKER = "mTLS: exact host certificate authenticated"
ROGUE_REJECTION_MARKER = "exact-peer mTLS connection failed"

HOST_SESSION_RE = re.compile(
    r"^session:\s*active\s+session_id=(\d+)\s*$", re.IGNORECASE | re.MULTILINE
)
HOST_LIFECYCLE_RE = re.compile(
    r"^session-lifecycle:\s*generation=(\d+)\s+authorization_epoch=(\d+)\s+display_epoch=(\d+)\s+codec_epoch=(\d+)\s+route_epoch=(\d+)\s*$",
    re.IGNORECASE | re.MULTILINE,
)
CLIENT_SESSION_RE = re.compile(
    r"^handshake:\s*active\s+session_id=(\d+)\s*$", re.IGNORECASE | re.MULTILINE
)
RECEIVED_RE = re.compile(
    r"^received:\s*session_id=(\d+)\s+frames=(\d+)\s*$",
    re.IGNORECASE | re.MULTILINE,
)
CLIENT_ROUTE_RE = re.compile(
    r"^route:\s*authenticated\s+(\S+)\s+after\s+racing\s+(\d+)\s+candidate\(s\)\s*$",
    re.IGNORECASE | re.MULTILINE,
)
HOST_DESKTOP_STREAM_RE = re.compile(
    r"^stream:\s+(?:H\.264 4:2:0|explicit Raw NV12)\s+\d+x\d+\s+over QUIC DATAGRAM\s*$",
    re.IGNORECASE | re.MULTILINE,
)

CERTIFICATE_FILE = "identity.cert.der"
PRIVATE_KEY_FILE = "identity.key.der"


class TrackedProcess:
    """A process whose combined output is drained continuously and bounded later."""

    def __init__(self, argv: Sequence[str], cwd: Path) -> None:
        self._chunks: list[str] = []
        creationflags = 0
        kwargs: dict[str, object] = {}
        if os.name == "nt":
            creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        else:
            kwargs["start_new_session"] = True

        self.proc = subprocess.Popen(
            list(argv),
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            creationflags=creationflags,
            **kwargs,
        )
        assert self.proc.stdout is not None
        self._thread = threading.Thread(
            target=self._drain,
            args=(self.proc.stdout,),
            name=f"secure-smoke-drain-{self.proc.pid}",
            daemon=True,
        )
        self._thread.start()

    def _drain(self, pipe) -> None:
        try:
            for line in pipe:
                self._chunks.append(line)
        except (OSError, ValueError):
            pass
        finally:
            try:
                pipe.close()
            except OSError:
                pass

    def output(self) -> str:
        return "".join(self._chunks)

    def poll(self) -> int | None:
        return self.proc.poll()

    def wait_for_text(self, marker: str, timeout: float) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if marker.lower() in self.output().lower():
                return True
            if self.poll() is not None:
                self._thread.join(timeout=1.0)
                return marker.lower() in self.output().lower()
            time.sleep(0.05)
        return marker.lower() in self.output().lower()

    def finish(self, timeout: float) -> tuple[int | None, bool]:
        timed_out = False
        try:
            self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            self.terminate()
        self._thread.join(timeout=2.0)
        return self.proc.poll(), timed_out

    def request_graceful_interrupt(self) -> bool:
        """Ask the host's Tokio Ctrl-C handler to perform a normal shutdown."""
        if self.proc.poll() is not None:
            return False
        try:
            if os.name == "nt":
                self.proc.send_signal(signal.CTRL_BREAK_EVENT)
            else:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGINT)
        except (OSError, ProcessLookupError):
            return False
        return True

    def terminate(self) -> None:
        if self.proc.poll() is not None:
            return
        try:
            if os.name != "nt":
                os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
            else:
                self.proc.terminate()
        except (OSError, ProcessLookupError):
            pass
        try:
            self.proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            try:
                if os.name != "nt":
                    os.killpg(os.getpgid(self.proc.pid), signal.SIGKILL)
                else:
                    self.proc.kill()
            except (OSError, ProcessLookupError):
                pass
            try:
                self.proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                pass

    def close(self) -> None:
        self.terminate()
        self._thread.join(timeout=2.0)


def prerequisite_skip_reason(
    platform: str | None = None, display: str | None = None
) -> str | None:
    """Return why the process E2E is inapplicable, without probing binaries."""
    platform = sys.platform if platform is None else platform
    display = os.environ.get("DISPLAY") if display is None else display
    if not platform.startswith("linux"):
        return "secure process smoke requires Linux X11; no processes were started"
    if not display or not display.strip():
        return (
            "secure process smoke requires a usable DISPLAY; no processes were started"
        )
    return None


def find_binary(name: str, explicit: Path | None = None) -> Path:
    candidates: list[Path]
    if explicit is not None:
        candidates = [explicit.expanduser()]
    else:
        suffix = ".exe" if os.name == "nt" else ""
        candidates = [
            ROOT / "target" / "debug" / f"{name}{suffix}",
            ROOT / "target" / "release" / f"{name}{suffix}",
        ]

    for candidate in candidates:
        resolved = candidate.resolve()
        if resolved.is_file() and os.access(resolved, os.X_OK):
            return resolved
    rendered = ", ".join(str(candidate) for candidate in candidates)
    raise FileNotFoundError(f"missing executable {name}; checked: {rendered}")


def pick_distinct_free_udp_ports() -> tuple[int, int]:
    with (
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as first,
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as second,
    ):
        first.bind(("127.0.0.1", 0))
        second.bind(("127.0.0.1", 0))
        first_port = int(first.getsockname()[1])
        second_port = int(second.getsockname()[1])
    if first_port <= 0 or second_port <= 0 or first_port == second_port:
        raise RuntimeError("operating system did not reserve two distinct UDP ports")
    return first_port, second_port


def parse_host_session_id(output: str) -> int | None:
    match = HOST_SESSION_RE.search(output)
    return int(match.group(1)) if match else None


def parse_host_session_ids(output: str) -> list[int]:
    return [int(value) for value in HOST_SESSION_RE.findall(output)]


def parse_host_lifecycles(output: str) -> list[tuple[int, int, int, int, int]]:
    return [
        tuple(int(value) for value in match)
        for match in HOST_LIFECYCLE_RE.findall(output)
    ]


def successor_lifecycle_is_fresh(
    previous: tuple[int, int, int, int, int],
    current: tuple[int, int, int, int, int],
) -> bool:
    """Validate a new independent session, whose route state starts at epoch one."""
    session_epochs_advanced = all(
        current_value > previous_value
        for previous_value, current_value in zip(previous[:4], current[:4])
    )
    return session_epochs_advanced and previous[4] == 1 and current[4] == 1


def parse_client_session_id(output: str) -> int | None:
    match = CLIENT_SESSION_RE.search(output)
    return int(match.group(1)) if match else None


def parse_client_session_ids(output: str) -> list[int]:
    return [int(value) for value in CLIENT_SESSION_RE.findall(output)]


def parse_received(output: str) -> tuple[int | None, int]:
    matches = RECEIVED_RE.findall(output)
    if not matches:
        return None, 0
    session, frames = matches[-1]
    return int(session), int(frames)


def parse_received_all(output: str) -> list[tuple[int, int]]:
    return [
        (int(session), int(frames)) for session, frames in RECEIVED_RE.findall(output)
    ]


def parse_client_route(output: str) -> tuple[str | None, int]:
    routes = parse_client_routes(output)
    if not routes:
        return None, 0
    return routes[0]


def parse_client_routes(output: str) -> list[tuple[str, int]]:
    return [(remote, int(count)) for remote, count in CLIENT_ROUTE_RE.findall(output)]


def parse_host_desktop_streams(output: str) -> int:
    return len(HOST_DESKTOP_STREAM_RE.findall(output))


def sanitize_log(text: str, sensitive_root: Path, limit: int = TAIL_CHARS) -> str:
    """Redact the owned credential directory before retaining a bounded tail."""
    variants = {
        str(sensitive_root),
        str(sensitive_root.resolve()),
        sensitive_root.as_posix(),
        str(sensitive_root).replace("\\", "/"),
    }
    redacted = text
    for variant in sorted(variants, key=len, reverse=True):
        if variant:
            redacted = re.sub(re.escape(variant), "[secure-temp]", redacted, flags=re.I)
    redacted = re.sub(
        re.escape(PRIVATE_KEY_FILE), "[private-key-file-redacted]", redacted, flags=re.I
    )
    return redacted if len(redacted) <= limit else redacted[-limit:]


def commands_contain_unsafe_flag(commands: Sequence[Sequence[str]]) -> bool:
    return any(UNSAFE_FLAG in command for command in commands)


def timeout_budgets(pairing_timeout: int) -> tuple[int, int, int]:
    """Reserve time for readiness, rogue rejection, and a valid connection."""
    ready = min(5, max(2, pairing_timeout // 6))
    rogue = min(5, max(2, pairing_timeout // 6))
    valid = pairing_timeout - ready - rogue - 5
    if valid < 5:
        raise ValueError(
            "pairing timeout is too small for rogue-then-valid verification"
        )
    return ready, rogue, valid


def host_frame_limit(client_frames: int) -> int:
    """Keep the sender alive while the client reassembles its requested frames."""
    return max(client_frames * 2, client_frames + 8)


def build_secure_commands(
    *,
    host_bin: Path,
    client_bin: Path,
    listen_addr: str,
    valid_primary_addr: str,
    host_dir: Path,
    client_dir: Path,
    rogue_dir: Path,
    host_frames: int,
    client_frames: int,
    fps: int,
    max_width: int,
    max_height: int,
    host_pairing_timeout: int,
    rogue_pairing_timeout: int,
    valid_pairing_timeout: int,
) -> tuple[list[str], list[str], list[str]]:
    host_cert = host_dir / CERTIFICATE_FILE
    client_cert = client_dir / CERTIFICATE_FILE
    rogue_cert = rogue_dir / CERTIFICATE_FILE
    host_command = [
        str(host_bin),
        "--listen",
        listen_addr,
        "--identity-cert",
        str(host_cert),
        "--identity-key",
        str(host_dir / PRIVATE_KEY_FILE),
        "--peer-cert",
        str(client_cert),
        "--pairing-timeout",
        str(host_pairing_timeout),
        "--max-width",
        str(max_width),
        "--max-height",
        str(max_height),
        "--fps",
        str(fps),
        "--frames",
        str(host_frames),
        "--max-sessions",
        "2",
    ]
    rogue_command = [
        str(client_bin),
        "--connect",
        listen_addr,
        "--bind",
        "127.0.0.1:0",
        "--identity-cert",
        str(rogue_cert),
        "--identity-key",
        str(rogue_dir / PRIVATE_KEY_FILE),
        "--peer-cert",
        str(host_cert),
        "--pairing-timeout",
        str(rogue_pairing_timeout),
        "--frames",
        "1",
    ]
    valid_command = [
        str(client_bin),
        "--connect",
        valid_primary_addr,
        "--fallback-address",
        listen_addr,
        "--bind",
        "127.0.0.1:0",
        "--identity-cert",
        str(client_cert),
        "--identity-key",
        str(client_dir / PRIVATE_KEY_FILE),
        "--peer-cert",
        str(host_cert),
        "--pairing-timeout",
        str(valid_pairing_timeout),
        "--frames",
        str(client_frames),
        "--session-count",
        "2",
    ]
    return host_command, rogue_command, valid_command


def validate_secure_result(
    *,
    identity_generation_ok: bool,
    host_ready: bool,
    rogue_exit: int | None,
    rogue_timed_out: bool,
    rogue_rejection_logged: bool,
    rogue_session_id: int | None,
    host_survived_rogue: bool,
    host_exit: int | None,
    host_timed_out: bool,
    client_exit: int | None,
    client_timed_out: bool,
    host_shutdown_requested: bool,
    host_graceful_shutdown_log: bool,
    host_peer_completed_log: bool,
    host_exact_mtls_log: bool,
    client_exact_mtls_log: bool,
    client_fallback_selected: bool,
    host_desktop_stream_log: bool,
    first_session_completed: bool,
    host_survived_first_session: bool,
    successor_session_distinct: bool,
    release_all_between_sessions: bool,
    host_session_id: int | None,
    client_session_id: int | None,
    received_session_id: int | None,
    received_frames: int,
    requested_frames: int,
    unsafe_flag_present: bool | None,
    temporary_credentials_removed: bool,
    runtime_error: str | None,
) -> tuple[dict[str, bool], list[str]]:
    """Evaluate every security and product signal; omissions always fail."""
    checks = {
        "identity_generation_ok": identity_generation_ok,
        "host_ready": host_ready,
        "rogue_client_rejected": (
            rogue_exit is not None
            and rogue_exit != 0
            and not rogue_timed_out
            and rogue_rejection_logged
            and rogue_session_id is None
        ),
        "host_survived_rogue": host_survived_rogue,
        "host_exit_zero": host_exit == 0 and not host_timed_out,
        "client_exit_zero": client_exit == 0 and not client_timed_out,
        "host_graceful_shutdown": (
            host_exit == 0
            and (
                host_peer_completed_log
                or (host_shutdown_requested and host_graceful_shutdown_log)
            )
        ),
        "host_exact_mtls_log": host_exact_mtls_log,
        "client_exact_mtls_log": client_exact_mtls_log,
        "client_fallback_selected": client_fallback_selected,
        "host_desktop_stream_log": host_desktop_stream_log,
        "first_session_completed": first_session_completed,
        "host_survived_first_session": host_survived_first_session,
        "successor_session_distinct": successor_session_distinct,
        "release_all_between_sessions": release_all_between_sessions,
        "product_session_nonzero": (
            host_session_id is not None
            and client_session_id is not None
            and host_session_id > 0
            and client_session_id > 0
        ),
        "product_session_ids_match": (
            host_session_id is not None
            and client_session_id is not None
            and host_session_id == client_session_id
        ),
        "received_session_matches": (
            received_session_id is not None
            and client_session_id is not None
            and received_session_id == client_session_id
        ),
        "requested_frames_received": received_frames >= requested_frames,
        "no_unsafe_transport_flag": unsafe_flag_present is False,
        "temporary_credentials_removed": temporary_credentials_removed,
    }

    errors: list[str] = []
    if runtime_error:
        errors.append(runtime_error)
    labels = {
        "identity_generation_ok": "temporary identities were not generated safely",
        "host_ready": "secure host did not reach its QUIC listening state",
        "rogue_client_rejected": "rogue client was not cleanly rejected before ProductSession",
        "host_survived_rogue": "host did not remain alive after rejecting the rogue certificate",
        "host_exit_zero": f"host exit was {host_exit!r} (timed_out={host_timed_out})",
        "client_exit_zero": f"valid client exit was {client_exit!r} (timed_out={client_timed_out})",
        "host_graceful_shutdown": (
            "host did not complete the harness-requested Ctrl-C shutdown cleanly"
        ),
        "host_exact_mtls_log": "host exact-certificate mTLS authentication log is missing",
        "client_exact_mtls_log": "client exact-certificate mTLS transport log is missing",
        "client_fallback_selected": (
            "valid client did not authenticate through the configured fallback address"
        ),
        "host_desktop_stream_log": (
            "host did not announce one authenticated desktop stream per valid session"
        ),
        "first_session_completed": "first valid session did not receive its requested frames",
        "host_survived_first_session": "host listener exited before the successor session",
        "successor_session_distinct": "successor session did not receive a fresh lifecycle identity",
        "release_all_between_sessions": "ReleaseAll was not completed before successor activation",
        "product_session_nonzero": "both ProductSession IDs must be present and nonzero",
        "product_session_ids_match": (
            f"ProductSession ID mismatch host={host_session_id!r} client={client_session_id!r}"
        ),
        "received_session_matches": (
            f"received-frame session {received_session_id!r} does not match client session {client_session_id!r}"
        ),
        "requested_frames_received": (
            f"received {received_frames} completed frames; requested {requested_frames}"
        ),
        "no_unsafe_transport_flag": "a process command contained --unsafe-udp-lab",
        "temporary_credentials_removed": "temporary identity directory was not removed",
    }
    errors.extend(labels[name] for name, passed in checks.items() if not passed)
    return checks, errors


def generate_identity(
    identity_bin: Path, name: str, directory: Path, timeout: int
) -> None:
    command = [
        str(identity_bin),
        "generate",
        "--name",
        name,
        "--out-dir",
        str(directory),
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(f"identity generation timed out for {name}") from error
    if completed.returncode != 0:
        # Do not retain stdout: it includes the private key's temporary path.
        raise RuntimeError(
            f"identity generation failed for {name} with exit {completed.returncode}"
        )

    certificate = directory / CERTIFICATE_FILE
    private_key = directory / PRIVATE_KEY_FILE
    if not certificate.is_file() or not private_key.is_file():
        raise RuntimeError(f"identity generator omitted required files for {name}")
    if os.name == "posix" and stat.S_IMODE(private_key.stat().st_mode) & 0o077:
        raise RuntimeError(
            f"identity generator created an overly permissive key for {name}"
        )


def repository_state() -> tuple[str | None, bool | None]:
    revision = None
    dirty = None
    try:
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=str(ROOT),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            timeout=5,
            check=True,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        dirty = bool(
            subprocess.run(
                ["git", "status", "--porcelain", "--untracked-files=no"],
                cwd=str(ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                encoding="utf-8",
                timeout=20,
                check=True,
            ).stdout
        )
    except (OSError, subprocess.SubprocessError):
        pass
    return revision or None, dirty


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def new_report(
    frames: int, fps: int, max_width: int, max_height: int
) -> dict[str, object]:
    revision, dirty = repository_state()
    return {
        "schema_version": 2,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "status": "pending",
        "ok": False,
        "executed": False,
        "transport": TRANSPORT,
        "scope": SCOPE,
        "real_desktop_capture": False,
        "viewer": VIEWER,
        "requested_frames": frames,
        "host_frame_limit": host_frame_limit(frames),
        "fps": fps,
        "geometry": {"max_width": max_width, "max_height": max_height},
        "environment": {
            "os": platform_module.platform(),
            "machine": platform_module.machine(),
            "python": platform_module.python_version(),
        },
        "source": {
            "repository_revision_at_test": revision,
            "worktree_dirty_at_test": dirty,
            "binary_sha256_proves_revision": False,
        },
        "evidence_scope": {
            "network": "single-machine IPv4 loopback only",
            "capture": "Linux X11 pixels; asserted only after completed client reassembly",
            "viewer": "headless frame reassembly only; no interactive rendering asserted",
            "input": "ReleaseAll transport/host handling only; no visible input effect asserted",
            "successor": "two sequential exact-pinned sessions on one Host endpoint; no abrupt-loss or interactive reconnect claim",
            "competitive_claim": "not evidence of superiority over AnyDesk or RustDesk",
        },
        "credentials": {
            "created": False,
            "ephemeral": True,
            "private_key_exported": False,
            "temporary_files_in_artifact": False,
            "removed": True,
        },
    }


def run_secure_smoke(
    args: argparse.Namespace,
    host_bin: Path,
    client_bin: Path,
    identity_bin: Path,
) -> dict[str, object]:
    report = new_report(args.frames, args.fps, args.max_width, args.max_height)
    report["executed"] = True
    report["listen_scope"] = "127.0.0.1"
    report["binaries"] = {
        "host_sha256": file_sha256(host_bin),
        "client_sha256": file_sha256(client_bin),
        "identity_sha256": file_sha256(identity_bin),
    }

    observation: dict[str, object] = {
        "identity_generation_ok": False,
        "host_ready": False,
        "rogue_exit": None,
        "rogue_timed_out": False,
        "rogue_rejection_logged": False,
        "rogue_session_id": None,
        "host_survived_rogue": False,
        "host_exit": None,
        "host_timed_out": False,
        "client_exit": None,
        "client_timed_out": False,
        "first_client_session_id": None,
        "first_client_received_frames": 0,
        "host_shutdown_requested": False,
        "host_graceful_shutdown_log": False,
        "host_peer_completed_log": False,
        "host_exact_mtls_log": False,
        "client_exact_mtls_log": False,
        "client_fallback_selected": False,
        "host_desktop_stream_log": False,
        "first_session_completed": False,
        "host_survived_first_session": False,
        "successor_session_distinct": False,
        "release_all_between_sessions": False,
        "host_session_id": None,
        "client_session_id": None,
        "received_session_id": None,
        "received_frames": 0,
        "unsafe_flag_present": None,
        "runtime_error": None,
    }
    processes: list[TrackedProcess] = []
    host_process: TrackedProcess | None = None
    rogue_process: TrackedProcess | None = None
    client_process: TrackedProcess | None = None
    host_output = ""
    rogue_output = ""
    client_output = ""
    listen_addr: str | None = None
    valid_primary_addr: str | None = None

    temporary = tempfile.TemporaryDirectory(prefix="latencydesk-secure-smoke-")
    temporary_root = Path(temporary.name)
    try:
        host_dir = temporary_root / "host"
        client_dir = temporary_root / "client"
        rogue_dir = temporary_root / "rogue"
        for name, directory in (
            ("secure-smoke-host", host_dir),
            ("secure-smoke-client", client_dir),
            ("secure-smoke-rogue", rogue_dir),
        ):
            generate_identity(identity_bin, name, directory, args.identity_timeout)
        observation["identity_generation_ok"] = True

        ready_timeout, rogue_pairing, valid_pairing = timeout_budgets(
            args.pairing_timeout
        )
        listen_port, valid_primary_port = pick_distinct_free_udp_ports()
        listen_addr = f"127.0.0.1:{listen_port}"
        valid_primary_addr = f"127.0.0.1:{valid_primary_port}"
        host_command, rogue_command, valid_command = build_secure_commands(
            host_bin=host_bin,
            client_bin=client_bin,
            listen_addr=listen_addr,
            valid_primary_addr=valid_primary_addr,
            host_dir=host_dir,
            client_dir=client_dir,
            rogue_dir=rogue_dir,
            host_frames=host_frame_limit(args.frames),
            client_frames=args.frames,
            fps=args.fps,
            max_width=args.max_width,
            max_height=args.max_height,
            host_pairing_timeout=args.pairing_timeout,
            rogue_pairing_timeout=rogue_pairing,
            valid_pairing_timeout=valid_pairing,
        )
        commands = (host_command, rogue_command, valid_command)
        observation["unsafe_flag_present"] = commands_contain_unsafe_flag(commands)
        if observation["unsafe_flag_present"]:
            raise RuntimeError(
                "refusing to execute a command containing --unsafe-udp-lab"
            )

        host_process = TrackedProcess(host_command, ROOT)
        processes.append(host_process)
        observation["host_ready"] = host_process.wait_for_text(
            HOST_READY_MARKER, ready_timeout
        )
        if not observation["host_ready"]:
            raise RuntimeError("host readiness timeout or early exit")

        rogue_process = TrackedProcess(rogue_command, ROOT)
        processes.append(rogue_process)
        rogue_exit, rogue_timed_out = rogue_process.finish(rogue_pairing + 3)
        observation["rogue_exit"] = rogue_exit
        observation["rogue_timed_out"] = rogue_timed_out
        rogue_output = rogue_process.output()
        observation["rogue_rejection_logged"] = (
            ROGUE_REJECTION_MARKER.lower() in rogue_output.lower()
        )
        observation["rogue_session_id"] = parse_client_session_id(rogue_output)
        observation["host_survived_rogue"] = host_process.poll() is None
        if not observation["host_survived_rogue"]:
            raise RuntimeError("host exited after the rogue certificate attempt")

        client_process = TrackedProcess(valid_command, ROOT)
        processes.append(client_process)
        valid_process_timeout = max(
            15.0,
            (valid_pairing * 2.0) + (args.frames / args.fps) + 5.0,
        )
        client_exit, client_timed_out = client_process.finish(valid_process_timeout)
        observation["client_exit"] = client_exit
        observation["client_timed_out"] = client_timed_out
        client_output = client_process.output()

        host_exit, host_timed_out = host_process.finish(
            max(10.0, (args.frames / args.fps) * 4.0 + 5.0)
        )
        observation["host_exit"] = host_exit
        observation["host_timed_out"] = host_timed_out
    except Exception as error:  # keep a complete fail-closed artifact
        observation["runtime_error"] = sanitize_log(str(error), temporary_root, 1_000)
    finally:
        for process in reversed(processes):
            process.close()
        if host_process is not None:
            host_output = host_process.output()
            if observation["host_exit"] is None:
                observation["host_exit"] = host_process.poll()
        if rogue_process is not None:
            rogue_output = rogue_process.output()
            if observation["rogue_exit"] is None:
                observation["rogue_exit"] = rogue_process.poll()
        if client_process is not None:
            client_output = client_process.output()
            if observation["client_exit"] is None:
                observation["client_exit"] = client_process.poll()
        try:
            temporary.cleanup()
        except OSError as error:
            cleanup_error = (
                f"temporary credential cleanup failed: {error.__class__.__name__}"
            )
            existing = observation.get("runtime_error")
            observation["runtime_error"] = (
                f"{existing}; {cleanup_error}" if existing else cleanup_error
            )

    credentials_removed = not temporary_root.exists()
    report["credentials"] = {
        "created": bool(observation["identity_generation_ok"]),
        "ephemeral": True,
        "private_key_exported": False,
        "temporary_files_in_artifact": False,
        "removed": credentials_removed,
    }

    observation["host_exact_mtls_log"] = (
        host_output.lower().count(HOST_MTLS_MARKER.lower()) >= 2
    )
    observation["rogue_rejection_logged"] = (
        bool(observation["rogue_rejection_logged"])
        or HOST_REJECTION_MARKER.lower() in host_output.lower()
    )
    observation["host_graceful_shutdown_log"] = (
        HOST_SHUTDOWN_MARKER.lower() in host_output.lower()
    )
    observation["host_peer_completed_log"] = (
        HOST_PEER_COMPLETED_MARKER.lower() in host_output.lower()
    )
    observation["client_exact_mtls_log"] = (
        client_output.lower().count(CLIENT_MTLS_MARKER.lower()) >= 2
    )
    host_desktop_streams = parse_host_desktop_streams(host_output)
    observation["host_desktop_stream_log"] = host_desktop_streams >= 2
    client_routes = parse_client_routes(client_output)
    selected_remote, candidate_attempts = (
        client_routes[-1] if client_routes else (None, 0)
    )
    observation["client_fallback_selected"] = (
        listen_addr is not None
        and len(client_routes) >= 2
        and all(
            remote == listen_addr and attempts >= 2
            for remote, attempts in client_routes[-2:]
        )
    )
    host_session_ids = parse_host_session_ids(host_output)
    host_lifecycles = parse_host_lifecycles(host_output)
    client_session_ids = parse_client_session_ids(client_output)
    received_sessions = parse_received_all(client_output)
    observation["host_session_id"] = host_session_ids[-1] if host_session_ids else None
    observation["client_session_id"] = (
        client_session_ids[-1] if client_session_ids else None
    )
    received_session, received_frames = (
        received_sessions[-1] if received_sessions else (None, 0)
    )
    observation["received_session_id"] = received_session
    observation["received_frames"] = received_frames
    first_client_session_id = (
        client_session_ids[-2] if len(client_session_ids) >= 2 else None
    )
    first_received_session, first_received_frames = (
        received_sessions[-2] if len(received_sessions) >= 2 else (None, 0)
    )
    observation["first_client_session_id"] = first_client_session_id
    observation["first_client_received_frames"] = first_received_frames
    observation["first_session_completed"] = (
        first_client_session_id is not None
        and first_received_session == first_client_session_id
        and first_received_frames >= args.frames
    )
    successor_client_session_id = observation["client_session_id"]
    lifecycle_advanced = len(host_lifecycles) >= 2 and successor_lifecycle_is_fresh(
        host_lifecycles[-2], host_lifecycles[-1]
    )
    observation["successor_session_distinct"] = (
        len(host_session_ids) >= 2
        and first_client_session_id is not None
        and successor_client_session_id is not None
        and host_session_ids[-2] == first_client_session_id
        and host_session_ids[-1] == successor_client_session_id
        and host_session_ids[-2] != host_session_ids[-1]
        and lifecycle_advanced
    )
    if len(host_session_ids) >= 2:
        first_marker = host_output.find(
            f"session: active session_id={host_session_ids[-2]}"
        )
        successor_marker = host_output.find(
            f"session: active session_id={host_session_ids[-1]}", first_marker + 1
        )
        release_marker = host_output.find("input: ReleaseAll applied", first_marker + 1)
        observation["release_all_between_sessions"] = (
            first_marker >= 0
            and release_marker > first_marker
            and successor_marker > release_marker
        )
        waiting_marker = host_output.find(
            "listener: waiting for authenticated successor session", first_marker + 1
        )
        observation["host_survived_first_session"] = (
            first_marker >= 0
            and waiting_marker > first_marker
            and successor_marker > waiting_marker
        )

    checks, errors = validate_secure_result(
        identity_generation_ok=bool(observation["identity_generation_ok"]),
        host_ready=bool(observation["host_ready"]),
        rogue_exit=observation["rogue_exit"],
        rogue_timed_out=bool(observation["rogue_timed_out"]),
        rogue_rejection_logged=bool(observation["rogue_rejection_logged"]),
        rogue_session_id=observation["rogue_session_id"],
        host_survived_rogue=bool(observation["host_survived_rogue"]),
        host_exit=observation["host_exit"],
        host_timed_out=bool(observation["host_timed_out"]),
        client_exit=observation["client_exit"],
        client_timed_out=bool(observation["client_timed_out"]),
        host_shutdown_requested=bool(observation["host_shutdown_requested"]),
        host_graceful_shutdown_log=bool(observation["host_graceful_shutdown_log"]),
        host_peer_completed_log=bool(observation["host_peer_completed_log"]),
        host_exact_mtls_log=bool(observation["host_exact_mtls_log"]),
        client_exact_mtls_log=bool(observation["client_exact_mtls_log"]),
        client_fallback_selected=bool(observation["client_fallback_selected"]),
        host_desktop_stream_log=bool(observation["host_desktop_stream_log"]),
        first_session_completed=bool(observation["first_session_completed"]),
        host_survived_first_session=bool(observation["host_survived_first_session"]),
        successor_session_distinct=bool(observation["successor_session_distinct"]),
        release_all_between_sessions=bool(observation["release_all_between_sessions"]),
        host_session_id=observation["host_session_id"],
        client_session_id=observation["client_session_id"],
        received_session_id=observation["received_session_id"],
        received_frames=int(observation["received_frames"]),
        requested_frames=args.frames,
        unsafe_flag_present=observation["unsafe_flag_present"],
        temporary_credentials_removed=credentials_removed,
        runtime_error=observation["runtime_error"],
    )

    report.update(
        {
            "status": "passed" if not errors else "failed",
            "ok": not errors,
            "checks": checks,
            "results": {
                "host_exit": observation["host_exit"],
                "rogue_client_exit": observation["rogue_exit"],
                "valid_client_successor_sequence_exit": observation["client_exit"],
                "host_session_id": observation["host_session_id"],
                "host_session_ids": host_session_ids,
                "host_lifecycles": host_lifecycles,
                "host_desktop_streams": host_desktop_streams,
                "first_client_session_id": observation["first_client_session_id"],
                "first_client_received_frames": observation[
                    "first_client_received_frames"
                ],
                "client_session_id": observation["client_session_id"],
                "client_session_ids": client_session_ids,
                "received_session_id": observation["received_session_id"],
                "received_frames": observation["received_frames"],
                "received_sessions": received_sessions,
                "selected_remote": selected_remote,
                "candidate_attempts": candidate_attempts,
                "client_routes": client_routes,
                "host_shutdown_mode": (
                    "peer_completed"
                    if observation["host_peer_completed_log"]
                    else "harness_ctrl_c"
                    if observation["host_graceful_shutdown_log"]
                    else None
                ),
            },
            "errors": errors,
            "logs": {
                "host_tail": sanitize_log(host_output, temporary_root),
                "rogue_client_tail": sanitize_log(rogue_output, temporary_root),
                "valid_client_tail": sanitize_log(client_output, temporary_root),
            },
        }
    )
    report["real_desktop_capture"] = bool(
        not errors
        and observation["host_desktop_stream_log"]
        and first_received_frames >= args.frames
        and received_frames >= args.frames
    )
    return report


def write_report(path: Path, report: dict[str, object]) -> None:
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary_path.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        os.replace(temporary_path, path)
    finally:
        try:
            temporary_path.unlink(missing_ok=True)
        except OSError:
            pass


def bounded_int(name: str, minimum: int, maximum: int):
    def parse(value: str) -> int:
        try:
            parsed = int(value)
        except ValueError as error:
            raise argparse.ArgumentTypeError(f"{name} must be an integer") from error
        if not minimum <= parsed <= maximum:
            raise argparse.ArgumentTypeError(
                f"{name} must be between {minimum} and {maximum}"
            )
        return parsed

    return parse


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify exact-peer mTLS rejection and real X11 frame transfer over QUIC"
    )
    parser.add_argument("--host-bin", type=Path, help="path to latencydesk-host")
    parser.add_argument("--client-bin", type=Path, help="path to latencydesk-client")
    parser.add_argument(
        "--identity-bin", type=Path, help="path to latencydesk-identity"
    )
    parser.add_argument(
        "--frames",
        type=bounded_int("frames", 1, 600),
        default=DEFAULT_FRAMES,
        help=f"completed frames required (default {DEFAULT_FRAMES})",
    )
    parser.add_argument(
        "--fps",
        type=bounded_int("fps", 1, 240),
        default=DEFAULT_FPS,
        help=f"host frame rate (default {DEFAULT_FPS})",
    )
    parser.add_argument(
        "--max-width",
        type=bounded_int("max-width", 2, 3840),
        default=DEFAULT_MAX_WIDTH,
    )
    parser.add_argument(
        "--max-height",
        type=bounded_int("max-height", 2, 2160),
        default=DEFAULT_MAX_HEIGHT,
    )
    parser.add_argument(
        "--pairing-timeout",
        type=bounded_int("pairing-timeout", 20, 3600),
        default=DEFAULT_PAIRING_TIMEOUT,
        help="host's total timeout, including rogue and valid attempts",
    )
    parser.add_argument(
        "--identity-timeout",
        type=bounded_int("identity-timeout", 1, 120),
        default=15,
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--output", type=Path, default=DEFAULT_OUTPUT, help="JSON result artifact"
    )
    args = parser.parse_args(argv)
    if args.max_width % 2 or args.max_height % 2:
        parser.error("--max-width and --max-height must be even for NV12")
    return args


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    skip_reason = prerequisite_skip_reason()
    if skip_reason:
        report = new_report(args.frames, args.fps, args.max_width, args.max_height)
        report.update(
            {
                "status": "skipped",
                "ok": False,
                "executed": False,
                "skip_reason": skip_reason,
            }
        )
        write_report(args.output, report)
        print(f"SKIPPED: {skip_reason}")
        print(f"Report: {args.output}")
        return 0

    try:
        host_bin = find_binary("latencydesk-host", args.host_bin)
        client_bin = find_binary("latencydesk-client", args.client_bin)
        identity_bin = find_binary("latencydesk-identity", args.identity_bin)
        report = run_secure_smoke(args, host_bin, client_bin, identity_bin)
    except Exception as error:
        report = new_report(args.frames, args.fps, args.max_width, args.max_height)
        report.update(
            {
                "status": "failed",
                "ok": False,
                "errors": [str(error)],
            }
        )

    write_report(args.output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    print(f"Report: {args.output}")
    return 0 if report.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
