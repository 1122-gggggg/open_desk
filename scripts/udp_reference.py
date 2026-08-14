#!/usr/bin/env python3
"""Real localhost UDP conformance run for the M2 lab-only socket boundary."""
from __future__ import annotations

import argparse
import json
import queue
import socket
import subprocess
import threading
import time
from pathlib import Path

from reference_lab import Reassembler, decode_exact, encode_exact, fake_frame, fragment, fnv1a

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUT = ROOT / "artifacts" / "udp-reference.json"
MAX_DATAGRAM = 1200


def git_commit() -> str | None:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, capture_output=True, check=False
    )
    return result.stdout.strip() if result.returncode == 0 else None


def run(frames: int, seed: int) -> dict[str, object]:
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1", 0))
    sender.bind(("127.0.0.1", 0))
    receiver.connect(sender.getsockname())
    sender.connect(receiver.getsockname())
    # This script validates conformance, not maximum localhost throughput. Give
    # the kernel enough buffering so scheduler jitter does not make the gate
    # flaky, while keeping datagram size and reassembly limits unchanged.
    receiver.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    sender.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4 * 1024 * 1024)
    receiver.settimeout(0.25)
    sender.settimeout(0.25)

    expected: dict[int, tuple[int, bytes]] = {}
    datagrams: list[bytes] = []
    for frame_id in range(frames):
        raw = fake_frame(160, 96, frame_id, seed)
        encoded = encode_exact(raw, 160, 96, frame_id)
        expected[frame_id] = (fnv1a(raw), raw)
        datagrams.extend(fragment(encoded, frame_id, MAX_DATAGRAM))

    result_queue: queue.Queue[dict[str, object]] = queue.Queue(maxsize=1)

    def receive() -> None:
        reassembler = Reassembler(max_frames=32, max_bytes=64 * 1024 * 1024)
        completed: dict[int, tuple[int, bytes]] = {}
        packets = 0
        timeouts = 0
        deadline = time.monotonic() + 5.0
        error: str | None = None
        while len(completed) < frames and time.monotonic() < deadline:
            try:
                datagram = receiver.recv(MAX_DATAGRAM)
            except socket.timeout:
                timeouts += 1
                continue
            try:
                output = reassembler.ingest(datagram)
                packets += 1
                if output is not None:
                    frame_id, access_unit = output
                    sequence, raw = decode_exact(access_unit)
                    completed[frame_id] = (sequence, raw)
            except Exception as exc:  # independent reference captures exact failure text
                error = f"{type(exc).__name__}: {exc}"
                break
        reassembler.discard_all()
        result_queue.put(
            {
                "completed": completed,
                "packets": packets,
                "timeouts": timeouts,
                "error": error,
                "reservation_after_cleanup": reassembler.reserved,
                "max_reserved": reassembler.max_reserved,
            }
        )

    thread = threading.Thread(target=receive, name="latencydesk-udp-reference", daemon=True)
    thread.start()
    # Let the receiver enter recv() before the burst starts.
    time.sleep(0.01)
    sent = 0
    send_error: str | None = None
    try:
        for datagram in datagrams:
            if not (0 < len(datagram) <= MAX_DATAGRAM):
                raise ValueError("datagram outside configured bound")
            sender.send(datagram)
            sent += 1
            if sent % 32 == 0:
                time.sleep(0.0005)
    except Exception as exc:
        send_error = f"{type(exc).__name__}: {exc}"
    thread.join(timeout=6.0)
    hung = thread.is_alive()
    received = result_queue.get_nowait() if not result_queue.empty() else {
        "completed": {}, "packets": 0, "timeouts": 0, "error": "receiver produced no result",
        "reservation_after_cleanup": -1, "max_reserved": 0,
    }
    completed = received.pop("completed")
    exact = 0
    silent_mismatch = 0
    for frame_id, (sequence, raw) in completed.items():
        expected_checksum, expected_raw = expected[frame_id]
        if sequence == frame_id and raw == expected_raw and fnv1a(raw) == expected_checksum:
            exact += 1
        else:
            silent_mismatch += 1
    sender.close()
    receiver.close()
    ok = (
        send_error is None
        and received["error"] is None
        and not hung
        and sent == len(datagrams)
        and exact == frames
        and silent_mismatch == 0
        and received["reservation_after_cleanup"] == 0
    )
    return {
        "schema": 1,
        "ok": ok,
        "commit": git_commit(),
        "transport": "IPv4 localhost UDP; insecure lab-only",
        "seed": seed,
        "frames": frames,
        "datagram_bound": MAX_DATAGRAM,
        "result": {
            "datagrams_expected": len(datagrams),
            "datagrams_sent": sent,
            "frames_exact": exact,
            "silent_mismatch": silent_mismatch,
            "send_error": send_error,
            "receiver_hung": hung,
            **received,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--frames", type=int, default=12)
    parser.add_argument("--seed", type=int, default=20260813)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    if not 1 <= args.frames <= 32:
        parser.error("--frames must be between 1 and 32")
    report = run(args.frames, args.seed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
