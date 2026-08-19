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
    host_cmd = [
        str(host_bin),
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

    if host_exit is None:
        error = error or f"{name}: host produced no exit code"
    if client_exit is None:
        error = error or f"{name}: client produced no exit code"
    if host_exit not in (0,) or client_exit not in (0,):
        error = error or f"{name}: nonzero exit host={host_exit} client={client_exit}"
    if not host_handshake:
        error = error or f"{name}: missing host handshake: active session_id="
    if not client_handshake:
        error = error or f"{name}: missing client handshake: active session_id="
    if received < client_frames:
        error = error or (
            f"{name}: client_frames={received} < requested {client_frames}"
        )
    if killed and error is None:
        error = f"{name}: leftover processes were killed"

    ok = error is None and host_exit == 0 and client_exit == 0
    return {
        "name": name,
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
        choices=("both", "loopback", "lan-bind"),
        default="both",
        help="loopback=127.0.0.1 listen; lan-bind=0.0.0.0 listen; both runs loopback then lan-bind",
    )
    parser.add_argument("--frames", type=int, default=DEFAULT_CLIENT_FRAMES, dest="client_frames")
    parser.add_argument("--host-frames", type=int, default=DEFAULT_HOST_FRAMES)
    parser.add_argument("--fps", type=int, default=DEFAULT_FPS)
    parser.add_argument("--shared-secret", default=None)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()

    report: dict[str, object] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
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
    if args.mode in ("both", "loopback"):
        cases.append(("loopback", "127.0.0.1", "127.0.0.1"))
    if args.mode in ("both", "lan-bind"):
        cases.append(("lan-bind", "0.0.0.0", "127.0.0.1"))

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

    report["cases"] = results
    primary = results[0]
    flatten_primary(report, primary)
    # Required case is loopback when both run; a lan-bind-only run uses that case.
    required_ok = bool(primary.get("ok"))
    lan = next((item for item in results if item.get("name") == "lan-bind"), None)
    if args.mode == "both" and lan is not None and not lan.get("ok"):
        extra = lan.get("error") or "lan-bind failed"
        if report["error"]:
            report["error"] = f"{report['error']}; {extra}"
        else:
            report["error"] = extra
            # Case 1 still decides process exit; keep top-level ok from loopback.
    report["ok"] = required_ok
    if required_ok and args.mode == "both" and lan is not None and not lan.get("ok"):
        report["ok"] = True
        report["error"] = f"loopback ok; {lan.get('error') or 'lan-bind failed'}"

    write_report(args.output, report)
    print(json.dumps(report, indent=2))
    return 0 if required_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
