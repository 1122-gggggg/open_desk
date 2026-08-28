#!/usr/bin/env python3
"""Create paired identities and run a bounded secure host/client loopback."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def run(command: list[str], **kwargs) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=True, text=True, **kwargs)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--frames", type=int, default=8)
    parser.add_argument("--fps", type=int, default=30)
    parser.add_argument("--width", type=int, default=320)
    parser.add_argument("--height", type=int, default=180)
    parser.add_argument("--listen", default="127.0.0.1:9000")
    args = parser.parse_args()

    root = repo_root()
    cargo = ["cargo", "build", "--locked", "-p", "latencydesk-identity", "-p", "latencydesk-host", "-p", "latencydesk-client"]
    run(cargo, cwd=root)

    target = root / "target" / "debug"
    exe = ".exe" if os.name == "nt" else ""
    identity = target / f"latencydesk-identity{exe}"
    host = target / f"latencydesk-host{exe}"
    client = target / f"latencydesk-client{exe}"

    with tempfile.TemporaryDirectory(prefix="latencydesk-loopback-") as tmp:
        pair_dir = Path(tmp)
        run(
            [str(identity), "pair", "--out-dir", str(pair_dir)],
            cwd=root,
        )
        host_cert = pair_dir / "host" / "identity.cert.der"
        host_key = pair_dir / "host" / "identity.key.der"
        client_cert = pair_dir / "client" / "identity.cert.der"
        client_key = pair_dir / "client" / "identity.key.der"

        host_proc = subprocess.Popen(
            [
                str(host),
                "--listen",
                args.listen,
                "--identity-cert",
                str(host_cert),
                "--identity-key",
                str(host_key),
                "--peer-cert",
                str(client_cert),
                "--max-width",
                str(args.width),
                "--max-height",
                str(args.height),
                "--fps",
                str(args.fps),
                "--frames",
                str(args.frames),
                "--pairing-timeout",
                "30",
            ],
            cwd=root,
        )
        try:
            time.sleep(0.5)
            client_result = subprocess.run(
                [
                    str(client),
                    "--connect",
                    args.listen,
                    "--identity-cert",
                    str(client_cert),
                    "--identity-key",
                    str(client_key),
                    "--peer-cert",
                    str(host_cert),
                    "--frames",
                    str(args.frames),
                    "--pairing-timeout",
                    "30",
                ],
                cwd=root,
                check=False,
            )
        finally:
            host_proc.terminate()
            try:
                host_proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                host_proc.kill()
                host_proc.wait(timeout=5)

        if client_result.returncode != 0:
            print(f"client failed with exit {client_result.returncode}", file=sys.stderr)
            return client_result.returncode
        print("secure loopback received the requested frames")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
