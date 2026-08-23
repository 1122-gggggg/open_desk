#!/usr/bin/env python3
"""Autonomous localhost remote-connection test for LatencyDesk host/client."""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = ROOT / "artifacts" / "remote-connect.json"
DEFAULT_CLIENT_FRAMES = 8
DEFAULT_HOST_FRAMES = 16
DEFAULT_FPS = 30
TOTAL_TIMEOUT_S = 45.0
HOST_READY_WAIT_S = 2.0
TAIL_CHARS = 4000
TRANSPORT_MODE = "unsafe_udp_lab"
SECURITY_MODE = "plaintext"
NETWORK_SCOPE = "localhost_only"
WILDCARD_BIND_LOOPBACK = "wildcard-bind-loopback"
SCOPE_NOTE = (
    "All cases connect to 127.0.0.1. wildcard-bind-loopback only verifies a "
    "0.0.0.0 listener and is not a real LAN test."
)

HANDSHAKE_RE = re.compile(r"handshake:\s*active\s+session_id=(\S+)", re.IGNORECASE)
RECEIVED_FRAMES_RE = re.compile(r"received:\s*frames=(\d+)", re.IGNORECASE)
HOST_READY_MARKERS = (
    "host listening on udp",
    "listening on udp socket",
)



def find_binary(name: str) -> Path:
    debug = ROOT / "target" / "debug" / name
    release = ROOT / "target" / "release" / name
    if debug.is_file():
        return debug
    if release.is_file():
        return release
    raise FileNotFoundError(f"missing binary: {name} (looked in target/debug and target/release)")


def pick_free_udp_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("127.0.0.1", 0))
        port = int(sock.getsockname()[1])
        if port > 0:
            return port
    finally:
        sock.close()
    for port in range(19000, 19051):
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.bind(("127.0.0.1", port))
            return port
        except OSError:
            continue
        finally:
            probe.close()
    raise RuntimeError("no free UDP port on 127.0.0.1 (tried ephemeral + 19000-19050)")


def tail_text(text: str, limit: int = TAIL_CHARS) -> str:
    if len(text) <= limit:
        return text
    return text[-limit:]


def drain_pipe(pipe, chunks: list[str], stop: threading.Event) -> None:
    try:
        while not stop.is_set():
            data = pipe.read(4096)
            if not data:
                break
            chunks.append(data)
    except Exception:
        pass
    finally:
        try:
            pipe.close()
        except Exception:
            pass


class TrackedProcess:
    def __init__(self, argv: list[str], cwd: Path) -> None:
        self.argv = argv
        self.chunks: list[str] = []
        self.stop = threading.Event()
        creationflags = 0
        if os.name == "nt" and hasattr(subprocess, "CREATE_NEW_PROCESS_GROUP"):
            creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
        self.proc = subprocess.Popen(
            argv,
            cwd=str(cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
            creationflags=creationflags,
        )
        self.thread = threading.Thread(
            target=drain_pipe,
            args=(self.proc.stdout, self.chunks, self.stop),
            name=f"drain-{Path(argv[0]).name}",
            daemon=True,
        )
        self.thread.start()

    def output(self) -> str:
        return "".join(self.chunks)

    def poll(self) -> int | None:
        return self.proc.poll()

    def wait(self, timeout: float | None = None) -> int | None:
        try:
            return self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

    def kill(self) -> None:
        if self.proc.poll() is not None:
            return
        try:
            self.proc.terminate()
        except OSError:
            pass
        try:
            self.proc.wait(timeout=2.0)
        except subprocess.TimeoutExpired:
            try:
                self.proc.kill()
            except OSError:
                pass
            try:
                self.proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                pass

    def close(self) -> None:
        self.stop.set()
        self.kill()
        self.thread.join(timeout=1.0)


def host_ready(output: str) -> bool:
    lowered = output.lower()
    return any(marker in lowered for marker in HOST_READY_MARKERS)


def parse_handshake(output: str) -> str | None:
    match = HANDSHAKE_RE.search(output)
    return match.group(1) if match else None


def parse_client_frames(output: str) -> int:
    matches = RECEIVED_FRAMES_RE.findall(output)
    if not matches:
        return 0
    return max(int(value) for value in matches)


def canonical_mode(mode: str) -> str:
    """Map the former misleading mode name to its explicit localhost scope."""
    return WILDCARD_BIND_LOOPBACK if mode == "lan-bind" else mode


def validate_case_result(
    *,
    name: str,
    host_exit: int | None,
    client_exit: int | None,
    host_handshake: str | None,
    client_handshake: str | None,
    received_frames: int,
    requested_frames: int,
    killed: bool,
    runtime_error: str | None,
) -> str | None:
    """Return a complete failure summary, or ``None`` when the case passed."""
    failures: list[str] = []
    if runtime_error:
        failures.append(runtime_error)
    if host_exit is None:
        failures.append(f"{name}: host produced no exit code")
    if client_exit is None:
        failures.append(f"{name}: client produced no exit code")
    if host_exit not in (0,) or client_exit not in (0,):
        failures.append(f"{name}: nonzero exit host={host_exit} client={client_exit}")
    if not host_handshake:
        failures.append(f"{name}: missing host handshake: active session_id=")
    if not client_handshake:
        failures.append(f"{name}: missing client handshake: active session_id=")
    if host_handshake and client_handshake and host_handshake != client_handshake:
        failures.append(
            f"{name}: session id mismatch host={host_handshake} client={client_handshake}"
        )
    if received_frames < requested_frames:
        failures.append(
            f"{name}: client_frames={received_frames} < requested {requested_frames}"
        )
    if killed and not runtime_error:
        failures.append(f"{name}: leftover processes were killed")
    return "; ".join(failures) if failures else None


def finalize_report(report: dict[str, object], results: list[dict[str, object]]) -> bool:
    """Populate top-level status and require every selected case to pass."""
    report["transport_mode"] = TRANSPORT_MODE
    report["security"] = SECURITY_MODE
    report["network_scope"] = NETWORK_SCOPE
    report["real_lan"] = False
    report["scope_note"] = SCOPE_NOTE
    report["cases"] = results
    if not results:
        report["ok"] = False
        report["error"] = "no connection cases were selected"
        return False

    flatten_primary(report, results[0])
    failed = [result for result in results if result.get("ok") is not True]
    if failed:
        details = []
        for result in failed:
            detail = result.get("error")
            if detail:
                details.append(str(detail))
            else:
                details.append(
                    f"{result.get('name', 'unknown')}: failed without error details"
                )
        report["ok"] = False
        report["error"] = "; ".join(details)
        return False

    report["ok"] = True
    report["error"] = None
    return True


def build_case_commands(
    *,
    host_bin: Path,
    client_bin: Path,
    listen_addr: str,
    connect_addr: str,
    host_frames: int,
    client_frames: int,
    fps: int,
    shared_secret: str | None,
    extra_host: list[str],
    extra_client: list[str],
) -> tuple[list[str], list[str]]:
    """Build explicit legacy-lab commands; secure mode is never selected implicitly."""
    host_cmd = [
        str(host_bin),
        "--unsafe-udp-lab",
        "--listen",
        listen_addr,
        "--approve",
        "--frames",
        str(host_frames),
        "--fps",
        str(fps),
        *extra_host,
    ]
    client_cmd = [
        str(client_bin),
        "--unsafe-udp-lab",
        "--connect",
        connect_addr,
        "--approve",
        "--frames",
        str(client_frames),
        "--bind",
        "127.0.0.1:0",
        *extra_client,
    ]
    if shared_secret:
        host_cmd.extend(["--shared-secret", shared_secret])
        client_cmd.extend(["--shared-secret", shared_secret])
    return host_cmd, client_cmd


def run_case(
    *,
    name: str,
    host_bin: Path,
    client_bin: Path,
    listen_host: str,
    connect_host: str,
    host_frames: int,
    client_frames: int,
    fps: int,
    shared_secret: str | None,
    extra_host: list[str],
    extra_client: list[str],
) -> dict[str, object]:
    port = pick_free_udp_port()
    listen_addr = f"{listen_host}:{port}"
    connect_addr = f"{connect_host}:{port}"
    host_cmd, client_cmd = build_case_commands(
        host_bin=host_bin,
        client_bin=client_bin,
        listen_addr=listen_addr,
        connect_addr=connect_addr,
        host_frames=host_frames,
        client_frames=client_frames,
        fps=fps,
        shared_secret=shared_secret,
        extra_host=extra_host,
        extra_client=extra_client,
    )

    deadline = time.monotonic() + TOTAL_TIMEOUT_S
    host: TrackedProcess | None = None
    client: TrackedProcess | None = None
    error: str | None = None
    host_exit: int | None = None
    client_exit: int | None = None
    killed = False

    try:
        host = TrackedProcess(host_cmd, ROOT)
        ready_deadline = time.monotonic() + HOST_READY_WAIT_S
        while time.monotonic() < ready_deadline:
            if host.poll() is not None:
                break
            if host_ready(host.output()):
                break
            time.sleep(0.05)

        if host.poll() is not None:
            host_exit = host.poll()
            error = f"{name}: host exited before client start (exit={host_exit})"
        else:
            client = TrackedProcess(client_cmd, ROOT)
            while time.monotonic() < deadline:
                if host_exit is None:
                    host_exit = host.poll()
                if client_exit is None:
                    client_exit = client.poll()
                if host_exit is not None and client_exit is not None:
                    break
                time.sleep(0.05)
            if host_exit is None or client_exit is None:
                killed = True
                error = f"{name}: timed out after {TOTAL_TIMEOUT_S:.0f}s"
    except Exception as exc:
        error = f"{name}: {type(exc).__name__}: {exc}"
    finally:
        if host is not None:
            if host.poll() is None:
                killed = True
                host.kill()
            host_exit = host.poll() if host_exit is None else host_exit
        if client is not None:
            if client.poll() is None:
                killed = True
                client.kill()
            client_exit = client.poll() if client_exit is None else client_exit
        if host is not None:
            host.close()
        if client is not None:
            client.close()

    host_out = host.output() if host is not None else ""
    client_out = client.output() if client is not None else ""
    host_handshake = parse_handshake(host_out)
    client_handshake = parse_handshake(client_out)
    received = parse_client_frames(client_out)
    error = validate_case_result(
        name=name,
        host_exit=host_exit,
        client_exit=client_exit,
        host_handshake=host_handshake,
        client_handshake=client_handshake,
        received_frames=received,
        requested_frames=client_frames,
        killed=killed,
        runtime_error=error,
    )
    ok = error is None
    return {
        "name": name,
        "transport_mode": TRANSPORT_MODE,
        "security": SECURITY_MODE,
        "network_scope": NETWORK_SCOPE,
        "real_lan": False,
        "scope_note": SCOPE_NOTE,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host_bin": str(host_bin),
        "client_bin": str(client_bin),
        "listen_addr": listen_addr,
        "connect_addr": connect_addr,
        "host_cmd": host_cmd,
        "client_cmd": client_cmd,
        "host_exit": host_exit,
        "client_exit": client_exit,
        "host_handshake": host_handshake,
        "client_handshake": client_handshake,
        "client_frames": received,
        "requested_client_frames": client_frames,
        "requested_host_frames": host_frames,
        "host_stdout_tail": tail_text(host_out),
        "client_stdout_tail": tail_text(client_out),
        "ok": ok,
        "error": error,
    }


def flatten_primary(report: dict[str, object], primary: dict[str, object]) -> None:
    for key in (
        "host_bin",
        "client_bin",
        "listen_addr",
        "host_exit",
        "client_exit",
        "host_handshake",
        "client_handshake",
        "client_frames",
        "host_stdout_tail",
        "client_stdout_tail",
        "error",
    ):
        report[key] = primary.get(key)
    report["binary_paths"] = {
        "host": primary.get("host_bin"),
        "client": primary.get("client_bin"),
    }


def write_report(path: Path, report: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode",
        choices=("both", "loopback", WILDCARD_BIND_LOOPBACK, "lan-bind"),
        default="both",
        help=(
            "loopback=127.0.0.1 listen; wildcard-bind-loopback=0.0.0.0 listen "
            "with a 127.0.0.1 client (not a real LAN test); lan-bind is a legacy alias"
        ),
    )
    parser.add_argument("--frames", type=int, default=DEFAULT_CLIENT_FRAMES, dest="client_frames")
    parser.add_argument("--host-frames", type=int, default=DEFAULT_HOST_FRAMES)
    parser.add_argument("--fps", type=int, default=DEFAULT_FPS)
    parser.add_argument("--shared-secret", default=None)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    selected_mode = canonical_mode(args.mode)

    report: dict[str, object] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "requested_mode": args.mode,
        "mode": selected_mode,
        "transport_mode": TRANSPORT_MODE,
        "security": SECURITY_MODE,
        "network_scope": NETWORK_SCOPE,
        "real_lan": False,
        "scope_note": SCOPE_NOTE,
        "binary_paths": {},
        "listen_addr": None,
        "host_exit": None,
        "client_exit": None,
        "host_handshake": None,
        "client_handshake": None,
        "client_frames": 0,
        "host_stdout_tail": "",
        "client_stdout_tail": "",
        "ok": False,
        "error": None,
        "cases": [],
    }

    try:
        host_bin = find_binary("latencydesk-host.exe" if os.name == "nt" else "latencydesk-host")
        client_bin = find_binary(
            "latencydesk-client.exe" if os.name == "nt" else "latencydesk-client"
        )
    except FileNotFoundError as exc:
        report["error"] = str(exc)
        write_report(args.output, report)
        print(json.dumps(report, indent=2))
        return 1

    cases: list[tuple[str, str, str]] = []
    if selected_mode in ("both", "loopback"):
        cases.append(("loopback", "127.0.0.1", "127.0.0.1"))
    if selected_mode in ("both", WILDCARD_BIND_LOOPBACK):
        cases.append((WILDCARD_BIND_LOOPBACK, "0.0.0.0", "127.0.0.1"))

    results: list[dict[str, object]] = []
    for name, listen_host, connect_host in cases:
        result = run_case(
            name=name,
            host_bin=host_bin,
            client_bin=client_bin,
            listen_host=listen_host,
            connect_host=connect_host,
            host_frames=args.host_frames,
            client_frames=args.client_frames,
            fps=args.fps,
            shared_secret=args.shared_secret,
            extra_host=[],
            extra_client=[],
        )
        results.append(result)

    all_cases_ok = finalize_report(report, results)

    write_report(args.output, report)
    print(json.dumps(report, indent=2))
    return 0 if all_cases_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
