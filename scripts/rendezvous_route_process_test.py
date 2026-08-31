#!/usr/bin/env python3
"""Fail-closed process evidence for rendezvous-derived two-path routing."""

from __future__ import annotations
import argparse
import hashlib
import json
import re
import secrets
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
import secure_connect_test as secure  # noqa: E402
from route_promotion_process_test import (  # noqa: E402
    free_udp_port,
    process_udp_ports,
    validate_identity,
    verify_native_binary,
)
from rendezvous_multi_process_test import native_version  # noqa: E402

RESULT_RE = re.compile(
    r"^route-rendezvous-result\s+role=(server|client)\s+rendezvous_committed=(true|false)\s+match_id=([0-9a-f]{32})\s+generation=(\d+)\s+exchange_id=(\d+)\s+delivered_host_candidates=(\d+)\s+path0_route_sha256=([0-9a-f]{64})\s+path1_route_sha256=([0-9a-f]{64})\s+candidate_sources_bound=(true|false)\s+exact_mtls=(true|false)\s+paths=(\d+)\s+promoted_epoch=(\d+)\s+rollback_epoch=(\d+)\s+active_index=(\d+)\s+active_failure=(true|false)\s+input=(true|false)\s+media=(true|false)\s+control=(true|false)\s+clean=(true|false)\s+peer_challenge_sha256=([0-9a-f]{64})$",
    re.I | re.M,
)
COMMITTED_RE = re.compile(
    r"^route-rendezvous-committed\s+role=(server|client)\s+match_id=([0-9a-f]{32})\s+generation=(\d+)\s+exchange_id=(\d+)\s+delivered_host_candidates=(\d+)\s+product0_port=(\d+)\s+product1_port=(\d+)\s+rendezvous_local_port=(\d+)$",
    re.I | re.M,
)
SECRET_RE = re.compile(
    r"(?:private[-_ ]?key|BEGIN .*PRIVATE|ice[-_ ]?(?:ufrag|password))", re.I
)
EVIDENCE_SCOPE = {
    "network": "single-machine IPv4 loopback committed rendezvous to two direct product paths",
    "type_state_token": "same-process and not durable attestation",
    "competitive_claim": "not evidence of AnyDesk or RustDesk superiority",
    "automatic_desktop_integration": False,
}


def parse(argv: Sequence[str] | None = None):
    p = argparse.ArgumentParser()
    p.add_argument("--binary", type=Path, required=True)
    p.add_argument("--rendezvous-bin", type=Path, required=True)
    p.add_argument("--identity-bin", type=Path, required=True)
    p.add_argument("--timeout", type=int, default=20)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args(argv)
    if not 5 <= a.timeout <= 60:
        p.error("--timeout must be in 5..=60")
    return a


def command(
    binary: Path,
    role: str,
    listen: str,
    listen2: str,
    ident: Path,
    peer: Path,
    challenge: str,
    timeout: int,
    rv: str,
    rv_cert: Path,
    match: str,
    exchange: str,
):
    c = [
        str(binary),
        "--role",
        role,
        "--cert",
        str(ident / secure.CERTIFICATE_FILE),
        "--key",
        str(ident / secure.PRIVATE_KEY_FILE),
        "--peer-cert",
        str(peer / secure.CERTIFICATE_FILE),
        "--challenge",
        challenge,
        "--timeout",
        str(timeout),
        "--rendezvous",
        rv,
        "--rendezvous-cert",
        str(rv_cert),
        "--match-id",
        match,
        "--exchange-id",
        exchange,
    ]
    if role == "server":
        c[3:3] = ["--listen", listen, "--listen2", listen2]
    return c


def parse_result(output: str, role: str):
    m = RESULT_RE.findall(output)
    if len(m) != 1:
        raise ValueError(f"expected one route-rendezvous result for {role}")
    (
        actual,
        committed,
        match,
        generation,
        exchange,
        candidates,
        d0,
        d1,
        sources_bound,
        mtls,
        paths,
        promoted,
        rollback,
        active,
        failure,
        inp,
        media,
        control,
        clean,
        challenge,
    ) = m[0]
    if actual.lower() != role or d0 == d1 or d0 == "0" * 64 or d1 == "0" * 64:
        raise ValueError("invalid role or path digest")
    return {
        "role": actual.lower(),
        "committed": committed.lower() == "true",
        "match": match.lower(),
        "generation": int(generation),
        "exchange": int(exchange),
        "delivered_host_candidates": int(candidates),
        "path0_digest": d0.lower(),
        "path1_digest": d1.lower(),
        "candidate_sources_bound": sources_bound.lower() == "true",
        "exact_mtls": mtls.lower() == "true",
        "paths": int(paths),
        "promoted_epoch": int(promoted),
        "rollback_epoch": int(rollback),
        "active_index": int(active),
        "active_failure": failure.lower() == "true",
        "input": inp.lower() == "true",
        "media": media.lower() == "true",
        "control": control.lower() == "true",
        "clean": clean.lower() == "true",
        "peer_challenge_sha256": challenge.lower(),
    }


def parse_committed(output: str, role: str):
    matches = COMMITTED_RE.findall(output)
    if len(matches) != 1:
        raise ValueError(f"expected one committed marker for {role}")
    actual, match, generation, exchange, candidates, product0, product1, rendezvous = (
        matches[0]
    )
    ports = [int(product0), int(product1), int(rendezvous)]
    if (
        actual.lower() != role
        or len(set(ports)) != 3
        or any(not 1 <= port <= 65535 for port in ports)
    ):
        raise ValueError("invalid committed socket marker")
    return {
        "role": actual.lower(),
        "match": match.lower(),
        "generation": int(generation),
        "exchange": int(exchange),
        "candidates": int(candidates),
        "product_ports": ports[:2],
        "rendezvous_port": ports[2],
    }


def run(a):
    binary = secure.find_binary("latencydesk-route-probe", a.binary)
    rvbin = secure.find_binary("latencydesk-rendezvousd", a.rendezvous_bin)
    identbin = secure.find_binary("latencydesk-identity", a.identity_bin)
    for p, n in (
        (binary, "latencydesk-route-probe"),
        (rvbin, "latencydesk-rendezvousd"),
        (identbin, "latencydesk-identity"),
    ):
        verify_native_binary(p, n)
    versions = {
        "probe": native_version(binary, "latencydesk-route-probe"),
        "rendezvous": native_version(rvbin, "latencydesk-rendezvousd"),
        "identity": native_version(identbin, "latencydesk-identity"),
    }
    revision, worktree_dirty = secure.repository_state()
    match = secrets.token_hex(16)
    exchange = str(int.from_bytes(secrets.token_bytes(8), "big") or 1)
    ports = []
    while len(ports) < 3:
        port = free_udp_port()
        if port not in ports:
            ports.append(port)
    rvlisten = f"127.0.0.1:{ports[0]}"
    p0 = f"127.0.0.1:{ports[1]}"
    p1 = f"127.0.0.1:{ports[2]}"
    with tempfile.TemporaryDirectory(prefix="rendezvous-route-process-") as t:
        root = Path(t)
        dirs = {n: root / n for n in ("rendezvous", "server", "client")}
        for n, d in dirs.items():
            d.mkdir()
            secure.generate_identity(identbin, n, d, 30)
            validate_identity(d / secure.CERTIFICATE_FILE, d / secure.PRIVATE_KEY_FILE)
        rv = None
        server = None
        client = None
        try:
            rv = secure.TrackedProcess(
                [
                    str(rvbin),
                    "--listen",
                    rvlisten,
                    "--identity-cert",
                    str(dirs["rendezvous"] / secure.CERTIFICATE_FILE),
                    "--identity-key",
                    str(dirs["rendezvous"] / secure.PRIVATE_KEY_FILE),
                    "--allowed-client-cert",
                    str(dirs["server"] / secure.CERTIFICATE_FILE),
                    "--allowed-client-cert",
                    str(dirs["client"] / secure.CERTIFICATE_FILE),
                    "--total-timeout",
                    str(a.timeout),
                    "--max-registrations",
                    "2",
                    "--max-matches",
                    "1",
                ],
                ROOT,
            )
            if not rv.wait_for_text("rendezvous: listening=", a.timeout):
                raise RuntimeError("rendezvous daemon not ready")
            daemon_ports = process_udp_ports(rv.proc.pid)
            live_daemon = int(rvlisten.rsplit(":", 1)[1]) in daemon_ports
            sch = secrets.token_hex(32)
            cch = secrets.token_hex(32)
            rv_cert = dirs["rendezvous"] / secure.CERTIFICATE_FILE
            server = secure.TrackedProcess(
                command(
                    binary,
                    "server",
                    p0,
                    p1,
                    dirs["server"],
                    dirs["client"],
                    sch,
                    a.timeout,
                    rvlisten,
                    rv_cert,
                    match,
                    exchange,
                ),
                ROOT,
            )
            if not server.wait_for_text("route-probe-ready", a.timeout):
                raise RuntimeError("route server not ready")
            client = secure.TrackedProcess(
                command(
                    binary,
                    "client",
                    p0,
                    p1,
                    dirs["client"],
                    dirs["server"],
                    cch,
                    a.timeout,
                    rvlisten,
                    rv_cert,
                    match,
                    exchange,
                ),
                ROOT,
            )
            if not server.wait_for_text(
                "route-rendezvous-committed", a.timeout
            ) or not client.wait_for_text("route-rendezvous-committed", a.timeout):
                raise RuntimeError("rendezvous commit marker missing")
            server_marker = parse_committed(server.output(), "server")
            client_marker = parse_committed(client.output(), "client")
            server_ports = process_udp_ports(server.proc.pid)
            client_ports = process_udp_ports(client.proc.pid)
            live_server = set(
                server_marker["product_ports"] + [server_marker["rendezvous_port"]]
            ).issubset(server_ports) and server_marker["product_ports"] == [
                int(p0.rsplit(":", 1)[1]),
                int(p1.rsplit(":", 1)[1]),
            ]
            live_client = set(
                client_marker["product_ports"] + [client_marker["rendezvous_port"]]
            ).issubset(client_ports)
            finish_deadline = time.monotonic() + a.timeout
            sc, st = server.finish(max(0.1, finish_deadline - time.monotonic()))
            cc, ct = client.finish(max(0.1, finish_deadline - time.monotonic()))
            rc, rt = rv.finish(max(0.1, finish_deadline - time.monotonic()))
            outs = {
                "server": server.output(),
                "client": client.output(),
                "rendezvous": rv.output(),
            }
            if any(SECRET_RE.search(v) for v in outs.values()):
                raise ValueError("secret-like output")
            sr = parse_result(outs["server"], "server")
            cr = parse_result(outs["client"], "client")
            required = {
                "committed": True,
                "generation": 1,
                "exchange": int(exchange),
                "delivered_host_candidates": 2,
                "candidate_sources_bound": True,
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
            server_command = command(
                binary,
                "server",
                p0,
                p1,
                dirs["server"],
                dirs["client"],
                sch,
                a.timeout,
                rvlisten,
                rv_cert,
                match,
                exchange,
            )
            client_command = command(
                binary,
                "client",
                p0,
                p1,
                dirs["client"],
                dirs["server"],
                cch,
                a.timeout,
                rvlisten,
                rv_cert,
                match,
                exchange,
            )
            checks = {
                "same_machine_loopback": True,
                "clean_exits": sc == cc == rc == 0 and not (st or ct or rt),
                "daemon_socket_live": live_daemon,
                "server_product_paths_live": live_server,
                "client_product_and_rendezvous_sockets_live": live_client,
                "contract": all(
                    sr.get(k) == v and cr.get(k) == v for k, v in required.items()
                ),
                "same_match_generation": sr["match"] == cr["match"] == match
                and sr["generation"] == cr["generation"],
                "committed_markers_match": server_marker["match"]
                == client_marker["match"]
                == match
                and server_marker["generation"] == client_marker["generation"] == 1
                and server_marker["exchange"]
                == client_marker["exchange"]
                == int(exchange)
                and server_marker["candidates"] == client_marker["candidates"] == 2,
                "same_path_digests": sr["path0_digest"] == cr["path0_digest"]
                and sr["path1_digest"] == cr["path1_digest"]
                and sr["path0_digest"] != sr["path1_digest"],
                "cross_process_challenge": sr["peer_challenge_sha256"]
                == hashlib.sha256(bytes.fromhex(cch)).hexdigest()
                and cr["peer_challenge_sha256"]
                == hashlib.sha256(bytes.fromhex(sch)).hexdigest(),
                "client_has_no_cli_product_destination": all(
                    flag not in client_command
                    for flag in ("--host", "--host2", "--listen", "--listen2")
                ),
                "no_unsafe_flag": all(
                    "--unsafe" not in item for item in server_command + client_command
                ),
            }
            checks["ok"] = all(checks.values())
            return {
                "schema": 1,
                "status": "passed" if checks["ok"] else "failed",
                "ok": checks["ok"],
                "checks": checks,
                "scope": dict(EVIDENCE_SCOPE),
                "server": sr,
                "client": cr,
                "versions": versions,
                "source": {
                    "repository_revision_at_test": revision,
                    "worktree_dirty_at_test": worktree_dirty,
                    "binary_sha256_proves_revision": False,
                },
                "socket_ownership": {
                    "rendezvous_pid": rv.proc.pid,
                    "rendezvous_udp_ports": sorted(daemon_ports),
                    "server_pid": server.proc.pid,
                    "server_udp_ports": sorted(server_ports),
                    "server_declared": server_marker,
                    "client_pid": client.proc.pid,
                    "client_udp_ports": sorted(client_ports),
                    "client_declared": client_marker,
                },
                "identities": {
                    name: {
                        "certificate_sha256": secure.file_sha256(
                            directory / secure.CERTIFICATE_FILE
                        ),
                        "der_pair_validated": True,
                    }
                    for name, directory in dirs.items()
                },
                "sha256": {
                    "probe_binary": secure.file_sha256(binary),
                    "rendezvous_binary": secure.file_sha256(rvbin),
                    "identity_binary": secure.file_sha256(identbin),
                    **{
                        f"{name}_log": hashlib.sha256(output.encode()).hexdigest()
                        for name, output in outs.items()
                    },
                },
            }
        finally:
            for p in (client, server, rv):
                if p is not None:
                    p.close()


def main(argv=None):
    a = parse(argv)
    try:
        report = run(a)
    except Exception as e:
        report = {
            "schema": 1,
            "status": "failed",
            "ok": False,
            "errors": [str(e)],
            "scope": dict(EVIDENCE_SCOPE),
        }
    report["generated_at"] = datetime.now(timezone.utc).isoformat()
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    return 0 if report.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
