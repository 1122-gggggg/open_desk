#!/usr/bin/env python3
"""Run exact-mTLS ProductSession control/input/media through isolated netns profiles."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import select
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Mapping, Sequence

SCRIPT = Path(__file__).resolve()
SCRIPT_DIR = SCRIPT.parent
ROOT = SCRIPT_DIR.parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

import nat_netns_matrix as matrix  # noqa: E402
import secure_connect_test as secure  # noqa: E402
import turn_product_process_test as product_gate  # noqa: E402
from route_promotion_process_test import (  # noqa: E402
    validate_identity,
    verify_native_binary,
)

SCHEMA = 1
PORT = matrix.UDP_PORT
PROFILES = ("lan-v4", "eim-eif", "double-nat", "cgnat", "native-v6")
PROFILE_DEADLINE_SECONDS = 30


def endpoint(address: str, port: int = PORT) -> str:
    return f"[{address}]:{port}" if ":" in address else f"{address}:{port}"


def expected_source(profile: str) -> str:
    if profile == "lan-v4":
        return endpoint("10.77.1.2")
    if profile == "eim-eif":
        addresses = matrix.nat_addresses(matrix.profile_by_name(profile))
        return endpoint(addresses["public"], 40000)
    if profile in {"double-nat", "cgnat"}:
        return endpoint("198.18.40.1", 42000)
    if profile == "native-v6":
        return endpoint("fd77:1::2")
    raise ValueError(f"unsupported product profile: {profile}")


def is_safe_internal_context(
    uid: int, pid: int, parent_net: int, self_net: int
) -> bool:
    return (
        uid == 0
        and pid == 1
        and parent_net > 0
        and self_net > 0
        and parent_net != self_net
    )


def native_version(path: Path, name: str) -> str:
    verify_native_binary(path, name)
    completed = subprocess.run(
        [str(path.resolve(strict=True)), "--version"],
        text=True,
        capture_output=True,
        timeout=3,
        check=False,
    )
    version = completed.stdout.strip()
    if completed.returncode != 0 or not re.fullmatch(
        rf"{re.escape(name)} [0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?",
        version,
    ):
        raise ValueError(f"{name} version identity is invalid")
    return version


def probe_command(
    probe: Path,
    identity: Path,
    role: str,
    bind: str,
    peer: str | None,
    peer_identity: Path,
    challenge: str,
    timeout: int,
) -> list[str]:
    command = [
        str(probe),
        "--role",
        role,
        "--bind",
        bind,
    ]
    if peer is not None:
        command.extend(["--peer", peer])
    command.extend(
        [
            "--cert",
            str(identity / secure.CERTIFICATE_FILE),
            "--key",
            str(identity / secure.PRIVATE_KEY_FILE),
            "--peer-cert",
            str(peer_identity / secure.CERTIFICATE_FILE),
            "--timeout",
            str(timeout),
            "--challenge",
            challenge,
        ]
    )
    return command


def build_plan(profiles: Sequence[str]) -> dict[str, Any]:
    if not profiles or len(set(profiles)) != len(profiles):
        raise ValueError("profiles must be non-empty and unique")
    if any(profile not in PROFILES for profile in profiles):
        raise ValueError(
            "product profiles must be selected from the fixed supported set"
        )
    return {
        "schema": SCHEMA,
        "profile_deadline_seconds": PROFILE_DEADLINE_SECONDS,
        "port": PORT,
        "profiles": [
            {"name": profile, "expected_peer_source": expected_source(profile)}
            for profile in profiles
        ],
    }


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
    for table in (Path(f"/proc/{pid}/net/udp"), Path(f"/proc/{pid}/net/udp6")):
        if not table.is_file():
            continue
        for line in table.read_text(encoding="ascii").splitlines()[1:]:
            fields = line.split()
            if len(fields) > 9 and fields[9] in inodes:
                ports.add(int(fields[1].rsplit(":", 1)[1], 16))
    return ports


def netns_inode(pid: int) -> int:
    return os.stat(f"/proc/{pid}/ns/net").st_ino


def exact_executable(pid: int, expected: Path) -> bool:
    try:
        return Path(os.readlink(f"/proc/{pid}/exe")).resolve() == expected.resolve()
    except OSError:
        return False


def wait_for_marker(
    process: subprocess.Popen[str], marker: str, deadline: float
) -> str:
    if process.stdout is None:
        raise matrix.MatrixError("product process stdout pipe is unavailable")
    output: list[str] = []
    while time.monotonic() < deadline:
        rendered = "".join(output)
        if marker in rendered:
            return rendered
        if process.poll() is not None:
            output.append(process.stdout.read())
            break
        ready, _, _ = select.select(
            [process.stdout], [], [], min(0.05, max(0.0, deadline - time.monotonic()))
        )
        if ready:
            line = process.stdout.readline()
            if line:
                output.append(line)
    if marker not in "".join(output):
        raise matrix.MatrixError(f"product process omitted marker {marker!r}")
    return "".join(output)


def finish_process(
    process: subprocess.Popen[str], prefix: str, deadline: float
) -> tuple[int, str, str]:
    try:
        stdout, stderr = process.communicate(
            timeout=max(0.05, deadline - time.monotonic())
        )
    except subprocess.TimeoutExpired as exc:
        raise matrix.DeadlineExpired(
            "product process exceeded profile deadline"
        ) from exc
    return process.returncode, prefix + stdout, stderr


def setup_profile(
    topology: matrix.Topology, profile: matrix.Profile
) -> tuple[matrix.Node, matrix.Node, dict[str, str]]:
    if profile.name in {"lan-v4", "native-v6"}:
        client, server, _observer, _client, _server, _unused, addresses = (
            matrix._setup_direct(topology, profile.family)
        )
        return client, server, addresses
    if profile.name == "eim-eif":
        client, server, _observer, addresses = matrix._setup_nat(topology, profile)
        return client, server, addresses
    if profile.name in {"double-nat", "cgnat"}:
        client, server, _observer, addresses = matrix._setup_two_router_profile(
            topology, profile
        )
        return client, server, addresses
    raise matrix.MatrixError(f"unsupported product topology {profile.name}")


def expected_profile_contract() -> dict[str, Any]:
    return {
        "product_session": "passed",
        "exact_mtls": True,
        "control": True,
        "input": True,
        "media": True,
        "clean": True,
        "session_match": True,
        "challenge_match": True,
        "route_epoch": 1,
        "client_route": "direct",
        "source_match": True,
        "socket_ownership": True,
        "netns_isolation": True,
    }


def run_product_pair(
    topology: matrix.Topology,
    profile: matrix.Profile,
    probe: Path,
    host_identity: Path,
    client_identity: Path,
) -> dict[str, Any]:
    client_node, host_node, addresses = setup_profile(topology, profile)
    client_address = addresses["client"]
    host_address = addresses["server"]
    host_endpoint = endpoint(host_address)
    client_endpoint = endpoint(client_address)
    if profile.name == "native-v6":
        diagnostic_port = PORT + 10
        server_code = """import socket,sys,time
s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM)
s.bind((sys.argv[1],int(sys.argv[2])))
s.settimeout(0.2)
print('READY',flush=True)
end=time.monotonic()+3
while time.monotonic()<end:
    try:
        data,address=s.recvfrom(2048)
    except TimeoutError:
        continue
    if data==b'STOP':
        break
    s.sendto(data,address)
"""
        client_code = """import socket,sys,time
s=socket.socket(socket.AF_INET6,socket.SOCK_DGRAM)
s.bind((sys.argv[1],0))
s.settimeout(0.12)
payload=b'x'*1200
destination=(sys.argv[2],int(sys.argv[3]))
end=time.monotonic()+3
while time.monotonic()<end:
    s.sendto(payload,destination)
    try:
        if s.recv(2048)==payload:
            s.sendto(b'STOP',destination)
            raise SystemExit(0)
    except TimeoutError:
        pass
raise SystemExit(1)
"""
        diagnostic_server = topology.spawn_workload(
            host_node,
            [
                sys.executable,
                "-c",
                server_code,
                host_address,
                str(diagnostic_port),
            ],
        )
        wait_for_marker(diagnostic_server, "READY", topology.deadline)
        diagnostic = topology.node_command(
            "probe",
            client_node,
            [
                sys.executable,
                "-c",
                client_code,
                client_address,
                host_address,
                str(diagnostic_port),
            ],
            check=False,
        )
        if diagnostic.returncode != 0:
            server_output, server_error = diagnostic_server.communicate(timeout=1)
            raise matrix.MatrixError(
                "bounded native IPv6 1200-byte path preflight failed: "
                f"client={diagnostic.stderr[-500:]} server={server_error[-500:]} "
                f"output={server_output[-100:]}"
            )
        _diagnostic_output, diagnostic_error = diagnostic_server.communicate(timeout=2)
        if diagnostic_server.returncode != 0:
            raise matrix.MatrixError(
                f"native IPv6 preflight server failed: {diagnostic_error[-500:]}"
            )
    timeout = max(5, min(15, int(matrix._remaining(topology.deadline)) - 2))
    host_challenge = secrets.token_hex(32)
    client_challenge = secrets.token_hex(32)
    host = topology.spawn_workload(
        host_node,
        probe_command(
            probe,
            host_identity,
            "host",
            host_endpoint,
            None,
            client_identity,
            host_challenge,
            timeout,
        ),
    )
    host_prefix = wait_for_marker(
        host, "product-probe-ready role=host", topology.deadline
    )
    client = topology.spawn_workload(
        client_node,
        probe_command(
            probe,
            client_identity,
            "client",
            client_endpoint,
            host_endpoint,
            host_identity,
            client_challenge,
            timeout,
        ),
    )
    client_prefix = wait_for_marker(
        client,
        "product-probe-connected role=client route=direct",
        topology.deadline,
    )
    host_ports = process_udp_ports(host.pid)
    client_ports = process_udp_ports(client.pid)
    host_inode = netns_inode(host.pid)
    client_inode = netns_inode(client.pid)
    host_node_inode = netns_inode(host_node.process.pid)
    client_node_inode = netns_inode(client_node.process.pid)
    native_processes = exact_executable(host.pid, probe) and exact_executable(
        client.pid, probe
    )
    client_code, client_output, client_stderr = finish_process(
        client, client_prefix, topology.deadline
    )
    host_code, host_output, host_stderr = finish_process(
        host, host_prefix, topology.deadline
    )
    matrix.append_stderr(topology.evidence, client_stderr)
    matrix.append_stderr(topology.evidence, host_stderr)
    if client_code != 0 or host_code != 0:
        raise matrix.MatrixError(
            f"product pair failed host={host_code} client={client_code}"
        )
    host_report = product_gate.parse_product_result(host_output, "host")
    client_report = product_gate.parse_product_result(client_output, "client")
    expected_host_hash = hashlib.sha256(bytes.fromhex(host_challenge)).hexdigest()
    expected_client_hash = hashlib.sha256(bytes.fromhex(client_challenge)).hexdigest()
    source = expected_source(profile.name)
    session_match = (
        host_report["session_id"] == client_report["session_id"]
        and int(host_report["session_id"]) > 0
    )
    challenge_match = (
        host_report["peer_challenge_sha256"] == expected_client_hash
        and client_report["peer_challenge_sha256"] == expected_host_hash
    )
    product_ok = bool(host_report["product"] and client_report["product"])
    clean = bool(host_report["clean"] and client_report["clean"])
    netns_ok = (
        host_inode == host_node_inode
        and client_inode == client_node_inode
        and host_inode != client_inode
        and host_inode != topology.outer_inode
        and client_inode != topology.outer_inode
    )
    observed: dict[str, Any] = {
        "product_session": "passed" if product_ok else "failed",
        "exact_mtls": bool(host_report["exact_mtls"] and client_report["exact_mtls"]),
        "control": bool(host_report["control"] and client_report["control"]),
        "input": bool(host_report["input"] and client_report["input"]),
        "media": bool(host_report["media"] and client_report["media"]),
        "clean": clean,
        "source_match": host_report["peer_source"] == source,
        "socket_ownership": PORT in host_ports
        and PORT in client_ports
        and native_processes,
        "netns_isolation": netns_ok,
        "expected_peer_source": source,
        "observed_peer_source": host_report["peer_source"],
        "session_id": host_report["session_id"],
        "route_epoch": host_report["route_epoch"],
        "session_match": session_match,
        "client_route": client_report["route"],
        "challenge_match": challenge_match,
        "host_udp_ports": sorted(host_ports),
        "client_udp_ports": sorted(client_ports),
        "host_netns_inode": host_inode,
        "client_netns_inode": client_inode,
        "host_node_netns_inode": host_node_inode,
        "client_node_netns_inode": client_node_inode,
        "executor_profile_netns_inode": topology.outer_inode,
        "host_process_pid": host.pid,
        "client_process_pid": client.pid,
        "host_node_pid": host_node.process.pid,
        "client_node_pid": client_node.process.pid,
        "native_process_executables": native_processes,
        "host_output_sha256": hashlib.sha256(host_output.encode()).hexdigest(),
        "client_output_sha256": hashlib.sha256(client_output.encode()).hexdigest(),
    }
    if profile.name == "eim-eif":
        observed["nat_public_source_observed"] = host_report["peer_source"] == source
    elif profile.name == "native-v6":
        observed["ipv6_1200_byte_path_preflight"] = True
    elif profile.name in {"double-nat", "cgnat"}:
        inner_packets = matrix._nat_counter(
            topology,
            topology.nodes["inner-router"],
            f"{profile.table}_n1",
        )
        outer_packets = matrix._nat_counter(
            topology,
            topology.nodes["outer-router"],
            f"{profile.table}_n2",
        )
        observed["inner_nat_packets"] = inner_packets
        observed["outer_nat_packets"] = outer_packets
        if inner_packets <= 0 or outer_packets <= 0:
            observed["source_match"] = False
    return observed


def execute_profile(
    profile: matrix.Profile,
    probe: Path,
    host_identity: Path,
    client_identity: Path,
) -> dict[str, Any]:
    started = time.monotonic()
    evidence = matrix.new_evidence(profile.name, expected_profile_contract(), started)
    topology = matrix.Topology(profile, evidence, started + PROFILE_DEADLINE_SECONDS)
    observed: dict[str, Any] = {}
    forced_status = None
    reason = None
    try:
        observed = run_product_pair(
            topology, profile, probe, host_identity, client_identity
        )
    except matrix.CapabilityBlocked as exc:
        forced_status, reason = "blocked", str(exc)
    except (
        matrix.DeadlineExpired,
        matrix.CommandFailed,
        matrix.MatrixError,
        OSError,
        ValueError,
    ) as exc:
        forced_status, reason = "failed", str(exc)
    finally:
        cleaned = topology.cleanup()
        if not cleaned and forced_status is None:
            forced_status, reason = "failed", "topology cleanup did not complete"
    evidence["elapsed_seconds"] = round(time.monotonic() - started, 6)
    finalized = matrix.finalize_evidence(
        evidence, observed, status=forced_status, reason=reason
    )
    finalized["command_counts"] = {
        phase: len(commands)
        for phase, commands in finalized.pop("commands", {}).items()
    }
    finalized["evidence_scope"] = (
        "ProductSession connectivity only; mapping/filter classification remains in nat_netns_matrix"
    )
    return finalized


def internal(args: argparse.Namespace) -> int:
    parent_inode, executor_inode = matrix.enter_executor_network_namespace()
    if not is_safe_internal_context(
        os.getuid(), os.getpid(), parent_inode, executor_inode
    ):
        raise RuntimeError("product executor safety gate failed")
    probe = Path(args.probe_bin).resolve(strict=True)
    report = {
        "schema": SCHEMA,
        "isolated": True,
        "outer_netns_inode": parent_inode,
        "executor_netns_inode": executor_inode,
        "results": [
            execute_profile(
                matrix.profile_by_name(profile),
                probe,
                Path(args.host_identity),
                Path(args.client_identity),
            )
            for profile in args.profiles
        ],
    }
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return 0


def blocked_report(plan: Mapping[str, Any], reason: str) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "status": "blocked",
        "isolated": False,
        "plan": plan,
        "results": [
            {"name": entry["name"], "status": "blocked", "reason": reason}
            for entry in plan["profiles"]
        ],
    }


def result_exit_code(results: Sequence[Mapping[str, Any]]) -> int:
    statuses = {result.get("status") for result in results}
    if "failed" in statuses:
        return 1
    if "blocked" in statuses:
        return 2
    return 0


def run(args: argparse.Namespace) -> int:
    plan = build_plan(args.profiles)
    inventory = matrix.inventory()
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    if not args.allow_netns:
        report = blocked_report(plan, "requires explicit --allow-netns")
        output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        return 2
    if not inventory["rootless_user_netns"] or not all(inventory["commands"].values()):
        report = blocked_report(plan, "rootless namespace capability or tool missing")
        report["inventory"] = inventory
        output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        return 2

    probe = Path(args.probe_bin).resolve(strict=True)
    identity_bin = Path(args.identity_bin).resolve(strict=True)
    versions = {
        "probe": native_version(probe, "latencydesk-product-probe"),
        "identity": native_version(identity_bin, "latencydesk-identity"),
    }
    revision, dirty = secure.repository_state()
    host_inode = os.stat("/proc/self/ns/net").st_ino
    with tempfile.TemporaryDirectory(prefix="nat-product-identities-") as temporary:
        identity_root = Path(temporary)
        host_identity = identity_root / "host"
        client_identity = identity_root / "client"
        host_identity.mkdir()
        client_identity.mkdir()
        secure.generate_identity(
            identity_bin, "nat-product-host", host_identity, PROFILE_DEADLINE_SECONDS
        )
        secure.generate_identity(
            identity_bin,
            "nat-product-client",
            client_identity,
            PROFILE_DEADLINE_SECONDS,
        )
        validate_identity(
            host_identity / secure.CERTIFICATE_FILE,
            host_identity / secure.PRIVATE_KEY_FILE,
        )
        validate_identity(
            client_identity / secure.CERTIFICATE_FILE,
            client_identity / secure.PRIVATE_KEY_FILE,
        )
        internal_output = identity_root / "internal.json"
        command = [
            "unshare",
            "--user",
            "--map-root-user",
            "--mount",
            "--net",
            "--pid",
            "--fork",
            "--mount-proc",
            sys.executable,
            str(SCRIPT),
            "__internal",
            "--output",
            str(internal_output),
            "--probe-bin",
            str(probe),
            "--host-identity",
            str(host_identity),
            "--client-identity",
            str(client_identity),
            "--profiles",
            *args.profiles,
        ]
        timeout = len(args.profiles) * (PROFILE_DEADLINE_SECONDS + 5) + 20
        completed = subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        if completed.returncode != 0 or not internal_output.is_file():
            report = {
                **blocked_report(plan, "isolated product executor failed"),
                "inventory": inventory,
                "outer_stderr_sha256": hashlib.sha256(
                    completed.stderr.encode()
                ).hexdigest(),
            }
            for result in report["results"]:
                result["status"] = "failed"
            report["status"] = "failed"
            output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
            return 1
        internal_report = json.loads(internal_output.read_text())
        inodes = {
            host_inode,
            internal_report.get("outer_netns_inode"),
            internal_report.get("executor_netns_inode"),
        }
        if (
            internal_report.get("schema") != SCHEMA
            or internal_report.get("isolated") is not True
            or len(inodes) != 3
            or not all(isinstance(inode, int) and inode > 0 for inode in inodes)
        ):
            raise ValueError("product executor namespace provenance is invalid")
        report = {
            **internal_report,
            "plan": plan,
            "inventory": inventory,
            "host_netns_inode": host_inode,
            "outer_command_sha256": hashlib.sha256(
                "\x1f".join(command).encode()
            ).hexdigest(),
            "outer_stderr_sha256": hashlib.sha256(
                completed.stderr.encode()
            ).hexdigest(),
            "versions": versions,
            "source": {
                "repository_revision_at_test": revision,
                "worktree_dirty_at_test": dirty,
                "binary_sha256_proves_revision": False,
            },
            "sha256": {
                "probe_binary": secure.file_sha256(probe),
                "identity_binary": secure.file_sha256(identity_bin),
                "host_certificate": secure.file_sha256(
                    host_identity / secure.CERTIFICATE_FILE
                ),
                "client_certificate": secure.file_sha256(
                    client_identity / secure.CERTIFICATE_FILE
                ),
            },
            "identities": {
                "der_pairs_validated": True,
                "private_key_exported": False,
            },
            "competitive_claim": "not evidence of AnyDesk or RustDesk superiority",
        }
        report["status"] = (
            "passed" if result_exit_code(report["results"]) == 0 else "failed"
        )
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    return result_exit_code(report["results"])


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "__internal":
        parser = argparse.ArgumentParser(add_help=False)
        parser.add_argument("--probe-bin", required=True)
        parser.add_argument("--host-identity", required=True)
        parser.add_argument("--client-identity", required=True)
        parser.add_argument("--profiles", nargs="+", required=True)
        parser.add_argument("--output", required=True)
        return internal(parser.parse_args(argv[1:]))
    parser = argparse.ArgumentParser()
    parser.add_argument("--probe-bin", type=Path, required=True)
    parser.add_argument("--identity-bin", type=Path, required=True)
    parser.add_argument("--profiles", nargs="+", default=list(PROFILES))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--allow-netns", action="store_true")
    return run(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
