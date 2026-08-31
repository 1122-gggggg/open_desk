#!/usr/bin/env python3
"""Actual, rootless Linux network-namespace NAT/IPv6 matrix evidence.

The public ``run`` command never invokes ``ip`` or ``nft`` in its caller's
namespace.  It starts one user/mount/network/PID namespace and the internal
executor then creates short-lived child network namespaces for every endpoint.
That makes this a topology test rather than a loopback or a planning stub.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import select
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence


SCHEMA = 2
DEADLINE_SECONDS = 30
UDP_PORT = 38765
PRIVATE_CONTROL_SPACE = "10.77.0.0/24"
CGNAT_SPACE = "100.64.0.0/10"
DOCUMENTATION_SPACE = "198.18.0.0/15"
SCRIPT = Path(__file__).resolve()
REQUIRED_TOOLS = ("ip", "nft", "nsenter", "sysctl", "unshare")


@dataclass(frozen=True)
class Profile:
    """A stable test profile, including only assertions we can observe."""

    name: str
    token: str
    kind: str
    family: int
    expected: Mapping[str, Any]

    @property
    def table(self) -> str:
        return f"ldnm_{self.token}"

    @property
    def node_names(self) -> Mapping[str, str]:
        roles = ("client", "router", "server", "observer")
        if self.kind in {"double", "cgnat"}:
            roles = ("client", "inner-router", "outer-router", "server", "observer")
        return {role: f"ldnm-{self.token}-{role}" for role in roles}


PROFILES = (
    Profile("lan-v4", "lan4", "direct", socket.AF_INET, {"reachability": "reachable"}),
    Profile(
        "eim-eif",
        "eimeif",
        "nat",
        socket.AF_INET,
        {
            "reachability": "reachable",
            "mapping": "same",
            "filter_same_ip_alt_port": "delivered",
            "filter_alt_ip": "delivered",
        },
    ),
    Profile(
        "eim-adf",
        "eimadf",
        "nat",
        socket.AF_INET,
        {
            "reachability": "reachable",
            "mapping": "same",
            "filter_same_ip_alt_port": "delivered",
            "filter_alt_ip": "blocked",
        },
    ),
    Profile(
        "eim-apdf",
        "eimapdf",
        "nat",
        socket.AF_INET,
        {
            "reachability": "reachable",
            "mapping": "same",
            "filter_same_ip_alt_port": "blocked",
            "filter_alt_ip": "blocked",
        },
    ),
    Profile(
        "apdm-mapping",
        "symnat",
        "nat",
        socket.AF_INET,
        {
            "reachability": "reachable",
            "mapping": "different",
            "mapping_dependency": "destination-address-and-port",
            "same_address_alt_port_mapping": "different",
            "filter_observer_to_server_mapping": "blocked",
        },
    ),
    Profile(
        "double-nat",
        "doublenat",
        "double",
        socket.AF_INET,
        {
            "reachability": "reachable",
            "layers": "two",
            "inner_nat": "observed",
            "outer_nat": "observed",
        },
    ),
    Profile(
        "cgnat",
        "cgnat",
        "cgnat",
        socket.AF_INET,
        {
            "reachability": "reachable",
            "layers": "two",
            "address_path": "private-cgnat-public",
            "actual_address_path": [
                "10.77.40.2",
                "100.64.1.2",
                "198.18.40.1",
            ],
            "inner_nat": "observed",
            "outer_nat": "observed",
        },
    ),
    Profile(
        "native-v6", "native6", "direct", socket.AF_INET6, {"reachability": "reachable"}
    ),
    Profile(
        "broken-v6",
        "broken6",
        "broken-v6",
        socket.AF_INET6,
        {"reachability": "blocked"},
    ),
    Profile(
        "udp-blocked",
        "udpblock",
        "udp-blocked",
        socket.AF_INET,
        {"reachability": "blocked"},
    ),
)
OPTIONAL = {
    "nat64": "requires an explicit NAT64 gateway; it is intentionally not synthesized"
}
PROFILE_INDEX = {profile.name: profile for profile in PROFILES}


class MatrixError(RuntimeError):
    """A failed lab assertion or command, never silently converted to pass."""


class CapabilityBlocked(MatrixError):
    """A required kernel/user-namespace capability is absent."""


class DeadlineExpired(MatrixError):
    """A profile exceeded its hard thirty-second wall-clock budget."""


class CommandFailed(MatrixError):
    def __init__(self, argv: Sequence[str], returncode: int, stderr: str):
        self.argv = list(argv)
        self.returncode = returncode
        self.stderr = stderr
        super().__init__(f"command failed ({returncode}): {' '.join(argv[:4])}")


def link_names(profile: Profile, role: str, slot: int) -> tuple[str, str]:
    """Return unique, deterministic veth endpoint names within IFNAMSIZ."""

    role_codes = {
        "client": "c",
        "server": "s",
        "observer": "v",
        "inner-router": "i",
        "outer-router": "o",
    }
    try:
        code = role_codes[role]
    except KeyError as exc:
        raise ValueError(f"unknown topology role: {role}") from exc
    stem = f"ld{profile.token[:7]}{code}{slot}"
    return stem, f"n{stem[1:]}"


def profile_by_name(name: str) -> Profile:
    if name == "symmetric-nat":
        name = "apdm-mapping"
    try:
        return PROFILE_INDEX[name]
    except KeyError as exc:
        raise ValueError(f"unknown NAT matrix profile: {name}") from exc


def _profile_plan(profile: Profile) -> dict[str, Any]:
    return {
        "name": profile.name,
        "status": "planned",
        "kind": profile.kind,
        "family": "ipv6" if profile.family == socket.AF_INET6 else "ipv4",
        "table": profile.table,
        "node_names": dict(profile.node_names),
        "expected": dict(profile.expected),
    }


def build_plan(names: Sequence[str]) -> dict[str, Any]:
    """Return a deterministic plan; duplicate names hide evidence and are rejected."""

    if len(set(names)) != len(names):
        raise ValueError("profile names must be unique")
    profiles: list[dict[str, Any]] = []
    for name in names:
        if name in OPTIONAL:
            profiles.append(
                {"name": name, "status": "optional", "reason": OPTIONAL[name]}
            )
        else:
            profiles.append(_profile_plan(profile_by_name(name)))
    return {
        "schema": SCHEMA,
        "deadline_seconds": DEADLINE_SECONDS,
        "port": UDP_PORT,
        "private_control_space": PRIVATE_CONTROL_SPACE,
        "cgnat_space": CGNAT_SPACE,
        "address_space": DOCUMENTATION_SPACE,
        "profiles": profiles,
    }


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _digest_commands(commands: Iterable[Sequence[str]]) -> str:
    canonical = "\n".join("\x1f".join(map(str, argv)) for argv in commands).encode()
    return _digest(canonical)


def new_evidence(
    name: str, expected: Mapping[str, str], started: float
) -> dict[str, Any]:
    """Create one evidence item with explicit command and stderr accounting."""

    return {
        "schema": SCHEMA,
        "name": name,
        "status": "running",
        "expected": dict(expected),
        "observed": {},
        "started_monotonic": round(started, 6),
        "deadline_seconds": DEADLINE_SECONDS,
        "commands": {"setup": [], "probe": [], "cleanup": []},
        "_stderr": [],
    }


def record_command(evidence: dict[str, Any], phase: str, argv: Sequence[str]) -> None:
    if phase not in evidence["commands"]:
        raise ValueError(f"invalid command evidence phase: {phase}")
    evidence["commands"][phase].append([str(part) for part in argv])


def append_stderr(evidence: dict[str, Any], stderr: str) -> None:
    if stderr:
        evidence["_stderr"].append(stderr)


def finish_evidence(
    expected: Mapping[str, str], observed: Mapping[str, Any]
) -> dict[str, Any]:
    mismatches: dict[str, Any] = {}
    for key, value in expected.items():
        actual = observed.get(key)
        if actual != value:
            mismatches[key] = {"expected": value, "observed": actual}
    return {"status": "pass" if not mismatches else "failed", "mismatches": mismatches}


def finalize_evidence(
    evidence: dict[str, Any],
    observed: Mapping[str, Any],
    *,
    status: str | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    """Finalize only after cleanup; no observed result can bypass the contract."""

    evidence["observed"] = dict(observed)
    verdict = finish_evidence(evidence["expected"], evidence["observed"])
    evidence["mismatches"] = verdict["mismatches"]
    evidence["status"] = status or verdict["status"]
    if reason:
        evidence["reason"] = reason
    evidence["command_hashes"] = {
        phase: _digest_commands(commands)
        for phase, commands in evidence["commands"].items()
    }
    evidence["command_hashes"]["all"] = _digest_commands(
        command
        for phase in ("setup", "probe", "cleanup")
        for command in evidence["commands"][phase]
    )
    evidence["stderr_hash"] = _digest("\n".join(evidence.pop("_stderr", [])).encode())
    return evidence


def is_safe_internal_context(
    uid: int,
    parent_netns_inode: int,
    executor_netns_inode: int,
    process_id: int,
) -> bool:
    """Require a mapped-root PID-1 executor after a self-created net namespace."""

    return (
        uid == 0
        and parent_netns_inode > 0
        and executor_netns_inode > 0
        and parent_netns_inode != executor_netns_inode
        and process_id == 1
    )


def enter_executor_network_namespace() -> tuple[int, int]:
    """Create the namespace used by every mutating command in this process.

    The executor itself makes this syscall. Safety does not depend on a
    caller-provided marker or inode: a direct invocation of the hidden command
    either fails before mutation or enters a fresh network namespace first.
    """

    if os.getuid() != 0 or os.getpid() != 1:
        raise RuntimeError("executor requires mapped UID 0 and PID 1")
    parent_inode = os.stat("/proc/self/ns/net").st_ino
    try:
        os.unshare(os.CLONE_NEWNET)
    except OSError as exc:
        raise RuntimeError(
            "executor could not create its own network namespace"
        ) from exc
    executor_inode = os.stat("/proc/self/ns/net").st_ino
    if not is_safe_internal_context(
        os.getuid(), parent_inode, executor_inode, os.getpid()
    ):
        raise RuntimeError("executor did not enter a fresh network namespace")
    return parent_inode, executor_inode


def isolated_command(output: Path, profiles: Sequence[str]) -> list[str]:
    """The sole host-side operation: enter a fresh user/mount/net/PID namespace."""

    return [
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
        str(output),
        "--profiles",
        *profiles,
    ]


def inventory() -> dict[str, Any]:
    commands = {name: shutil.which(name) is not None for name in REQUIRED_TOOLS}
    rootless = False
    diagnostic = ""
    if commands["unshare"]:
        try:
            result = subprocess.run(
                ["unshare", "--user", "--map-root-user", "--net", "true"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            rootless = result.returncode == 0
            diagnostic = result.stderr
        except (OSError, subprocess.TimeoutExpired) as exc:
            diagnostic = str(exc)
    return {
        "uid": os.getuid(),
        "commands": commands,
        "rootless_user_netns": rootless,
        "inventory_stderr_hash": _digest(diagnostic.encode()),
    }


def _remaining(deadline: float) -> float:
    value = deadline - time.monotonic()
    if value <= 0:
        raise DeadlineExpired("profile exceeded its 30-second absolute deadline")
    return value


def _command(
    evidence: dict[str, Any],
    phase: str,
    argv: Sequence[str],
    deadline: float,
    *,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    """Run a non-shell command under the profile deadline and retain stderr evidence."""

    record_command(evidence, phase, argv)
    try:
        result = subprocess.run(
            list(argv),
            text=True,
            capture_output=True,
            timeout=max(0.05, _remaining(deadline)),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        append_stderr(evidence, str(exc))
        raise DeadlineExpired(f"command timed out: {argv[0]}") from exc
    except OSError as exc:
        append_stderr(evidence, str(exc))
        raise CapabilityBlocked(f"cannot execute {argv[0]}: {exc}") from exc
    append_stderr(evidence, result.stderr)
    if check and result.returncode != 0:
        raise CommandFailed(argv, result.returncode, result.stderr)
    return result


@dataclass
class Node:
    role: str
    process: subprocess.Popen[str]


class Topology:
    """Resource-owned namespace graph, with deterministic veth and nft cleanup."""

    def __init__(self, profile: Profile, evidence: dict[str, Any], deadline: float):
        self.profile = profile
        self.evidence = evidence
        self.deadline = deadline
        self.nodes: dict[str, Node] = {}
        self.workloads: list[subprocess.Popen[str]] = []
        self.cleanup_actions: list[list[str]] = []
        self.cleanup_ok = True
        self.outer_inode = os.stat("/proc/self/ns/net").st_ino

    def command(
        self, phase: str, argv: Sequence[str], *, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        return _command(self.evidence, phase, argv, self.deadline, check=check)

    def start_node(self, role: str) -> Node:
        if role in self.nodes:
            raise MatrixError(f"duplicate topology node: {role}")
        argv = [
            "unshare",
            "--net",
            "sleep",
            "40",
        ]
        record_command(self.evidence, "setup", argv)
        try:
            process = subprocess.Popen(
                argv, text=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
            )
        except OSError as exc:
            append_stderr(self.evidence, str(exc))
            raise CapabilityBlocked(
                f"cannot create {role} network namespace: {exc}"
            ) from exc
        time.sleep(0.03)
        if process.poll() is not None:
            stderr = process.stderr.read() if process.stderr else ""
            append_stderr(self.evidence, stderr)
            raise CapabilityBlocked(f"{role} network namespace exited during setup")
        try:
            inode = os.stat(f"/proc/{process.pid}/ns/net").st_ino
        except OSError as exc:
            raise CapabilityBlocked(
                f"cannot inspect {role} network namespace: {exc}"
            ) from exc
        if inode == self.outer_inode:
            raise CapabilityBlocked(
                f"{role} did not enter a distinct network namespace"
            )
        node = Node(role, process)
        self.nodes[role] = node
        self.node_command("setup", node, ["ip", "link", "set", "lo", "up"])
        return node

    def node_argv(self, node: Node, argv: Sequence[str]) -> list[str]:
        return ["nsenter", "-t", str(node.process.pid), "-n", "--", *argv]

    def node_command(
        self, phase: str, node: Node, argv: Sequence[str], *, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        return self.command(phase, self.node_argv(node, argv), check=check)

    def attach(
        self, node: Node, ifname: str, slot: int, *, bridge: str | None = None
    ) -> str:
        outer, child = link_names(self.profile, node.role, slot)
        self.command(
            "setup",
            ["ip", "link", "add", "name", outer, "type", "veth", "peer", "name", child],
        )
        self.cleanup_actions.append(["ip", "link", "del", "dev", outer])
        self.command(
            "setup", ["ip", "link", "set", "dev", child, "netns", str(node.process.pid)]
        )
        if bridge:
            self.command("setup", ["ip", "link", "set", "dev", outer, "master", bridge])
        self.command("setup", ["ip", "link", "set", "dev", outer, "up"])
        self.node_command(
            "setup", node, ["ip", "link", "set", "dev", child, "name", ifname]
        )
        self.node_command("setup", node, ["ip", "link", "set", "dev", ifname, "up"])
        return outer

    def bridge(self, label: str) -> str:
        name = f"ld{self.profile.token[:7]}{label}"[:15]
        self.command("setup", ["ip", "link", "add", "name", name, "type", "bridge"])
        self.cleanup_actions.append(["ip", "link", "del", "dev", name])
        self.command("setup", ["ip", "link", "set", "dev", name, "up"])
        return name

    def spawn_workload(self, node: Node, argv: Sequence[str]) -> subprocess.Popen[str]:
        command = self.node_argv(node, argv)
        record_command(self.evidence, "probe", command)
        try:
            process = subprocess.Popen(
                command, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
        except OSError as exc:
            append_stderr(self.evidence, str(exc))
            raise CapabilityBlocked(f"cannot start node workload: {exc}") from exc
        self.workloads.append(process)
        time.sleep(0.04)
        if process.poll() is not None:
            _, stderr = process.communicate()
            append_stderr(self.evidence, stderr)
            raise MatrixError(
                f"node workload exited during startup: {' '.join(argv[:2])}"
            )
        return process

    def cleanup(self) -> bool:
        """Always delete named resources, then terminate and reap child namespaces."""

        cleanup_deadline = time.monotonic() + 8.0

        for workload in self.workloads:
            if workload.poll() is None:
                record_command(
                    self.evidence, "cleanup", ["signal", "TERM", str(workload.pid)]
                )
                workload.terminate()
            try:
                _, stderr = workload.communicate(timeout=1)
                append_stderr(self.evidence, stderr)
            except subprocess.TimeoutExpired:
                self.cleanup_ok = False
                record_command(
                    self.evidence, "cleanup", ["signal", "KILL", str(workload.pid)]
                )
                workload.kill()
                _, stderr = workload.communicate()
                append_stderr(self.evidence, stderr)

        for action in reversed(self.cleanup_actions):
            record_command(self.evidence, "cleanup", action)
            try:
                result = subprocess.run(
                    action,
                    capture_output=True,
                    text=True,
                    timeout=max(0.05, min(1.0, cleanup_deadline - time.monotonic())),
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                self.cleanup_ok = False
                append_stderr(self.evidence, str(exc))
                continue
            append_stderr(self.evidence, result.stderr)
            if (
                result.returncode != 0
                and "Cannot find device" not in result.stderr
                and "No such file" not in result.stderr
            ):
                self.cleanup_ok = False

        for node in self.nodes.values():
            process = node.process
            if process.poll() is None:
                record_command(
                    self.evidence, "cleanup", ["signal", "TERM", str(process.pid)]
                )
                process.terminate()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                self.cleanup_ok = False
                record_command(
                    self.evidence, "cleanup", ["signal", "KILL", str(process.pid)]
                )
                process.kill()
                process.wait()
            if process.stderr:
                append_stderr(self.evidence, process.stderr.read())
        return self.cleanup_ok


def _address(
    argv: list[str], family: int, value: str, ifname: str, *, alias: bool = False
) -> list[str]:
    prefix = "64" if family == socket.AF_INET6 else "24"
    command = ["ip"]
    if family == socket.AF_INET6:
        command.append("-6")
    command.extend(["addr", "add", f"{value}/{prefix}", "dev", ifname])
    if family == socket.AF_INET6:
        command.append("nodad")
    return command


def _configure_endpoint(
    topology: Topology,
    node: Node,
    family: int,
    address: str,
    gateway: str,
    *,
    ifname: str = "eth0",
    aliases: Sequence[str] = (),
) -> None:
    topology.node_command("setup", node, _address([], family, address, ifname))
    for alias in aliases:
        topology.node_command(
            "setup", node, _address([], family, alias, ifname, alias=True)
        )
    route = ["ip"]
    if family == socket.AF_INET6:
        route.append("-6")
    route.extend(["route", "replace", "default", "via", gateway, "dev", ifname])
    topology.node_command("setup", node, route)


def _configure_outer_interface(
    topology: Topology, family: int, ifname: str, address: str
) -> None:
    command = ["ip"]
    if family == socket.AF_INET6:
        command.append("-6")
    prefix = "64" if family == socket.AF_INET6 else "24"
    command.extend(["addr", "add", f"{address}/{prefix}", "dev", ifname])
    if family == socket.AF_INET6:
        command.append("nodad")
    topology.command("setup", command)


def _configure_public_loopback(topology: Topology, address: str) -> None:
    """Own the NAT public tuple for exactly one profile and remove it afterwards."""

    topology.command("setup", ["ip", "addr", "add", f"{address}/32", "dev", "lo"])
    topology.cleanup_actions.append(["ip", "addr", "del", f"{address}/32", "dev", "lo"])


def _set_forwarding(
    topology: Topology, family: int, *, node: Node | None = None
) -> None:
    key = (
        "net.ipv6.conf.all.forwarding=1"
        if family == socket.AF_INET6
        else "net.ipv4.ip_forward=1"
    )
    if node:
        topology.node_command("setup", node, ["sysctl", "-w", key])
    else:
        topology.command("setup", ["sysctl", "-w", key])


def _start_echo(
    topology: Topology, node: Node, bind: str, *, port: int = UDP_PORT
) -> None:
    seconds = max(2.0, min(8.0, _remaining(topology.deadline)))
    topology.spawn_workload(
        node,
        [
            sys.executable,
            str(SCRIPT),
            "__node",
            "echo",
            "--bind",
            bind,
            "--port",
            str(port),
            "--timeout",
            f"{seconds:.2f}",
        ],
    )


def _json_from_completed(result: subprocess.CompletedProcess[str]) -> dict[str, Any]:
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    if not lines:
        raise MatrixError("node probe produced no JSON observation")
    try:
        value = json.loads(lines[-1])
    except json.JSONDecodeError as exc:
        raise MatrixError("node probe produced malformed JSON") from exc
    if not isinstance(value, dict):
        raise MatrixError("node probe JSON must be an object")
    return value


def _map_client(
    topology: Topology,
    client: Node,
    bind: str,
    destinations: Sequence[tuple[str, str]],
    *,
    destination_ports: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    seconds = max(0.75, min(3.0, _remaining(topology.deadline)))
    args = [
        sys.executable,
        str(SCRIPT),
        "__node",
        "map",
        "--bind",
        bind,
        "--port",
        str(UDP_PORT),
        "--timeout",
        f"{seconds:.2f}",
    ]
    for label, address in destinations:
        port = (destination_ports or {}).get(label, UDP_PORT)
        args.extend(["--destination", f"{label}|{address}|{port}"])
    return _json_from_completed(topology.node_command("probe", client, args))


def _filter_probe(
    topology: Topology,
    observer: Node,
    source: str,
    source_port: int,
    destination: str,
    destination_port: int,
    label: str,
) -> str:
    seconds = max(0.35, min(1.1, _remaining(topology.deadline)))
    result = topology.node_command(
        "probe",
        observer,
        [
            sys.executable,
            str(SCRIPT),
            "__node",
            "filter",
            "--source",
            source,
            "--source-port",
            str(source_port),
            "--destination",
            destination,
            "--destination-port",
            str(destination_port),
            "--label",
            label,
            "--timeout",
            f"{seconds:.2f}",
        ],
    )
    return (
        "delivered"
        if _json_from_completed(result).get("delivered") is True
        else "blocked"
    )


def _start_listener(topology: Topology, client: Node, bind: str) -> None:
    seconds = max(2.0, min(6.0, _remaining(topology.deadline)))
    topology.spawn_workload(
        client,
        [
            sys.executable,
            str(SCRIPT),
            "__node",
            "listener",
            "--bind",
            bind,
            "--port",
            str(UDP_PORT),
            "--timeout",
            f"{seconds:.2f}",
        ],
    )


def _setup_direct(
    topology: Topology, family: int
) -> tuple[Node, Node, Node, str, str, str, dict[str, str]]:
    client = topology.start_node("client")
    server = topology.start_node("server")
    observer = topology.start_node("observer")
    outer_client = topology.attach(client, "eth0", 0)
    outer_server = topology.attach(server, "eth0", 0)
    outer_observer = topology.attach(observer, "eth0", 0)
    _set_forwarding(topology, family)
    if family == socket.AF_INET:
        addresses = {
            "client": "10.77.1.2",
            "router_client": "10.77.1.1",
            "server": "10.77.2.2",
            "router_server": "10.77.2.1",
            "observer": "10.77.3.2",
            "router_observer": "10.77.3.1",
        }
    else:
        addresses = {
            "client": "fd77:1::2",
            "router_client": "fd77:1::1",
            "server": "fd77:2::2",
            "router_server": "fd77:2::1",
            "observer": "fd77:3::2",
            "router_observer": "fd77:3::1",
        }
    _configure_outer_interface(
        topology, family, outer_client, addresses["router_client"]
    )
    _configure_outer_interface(
        topology, family, outer_server, addresses["router_server"]
    )
    _configure_outer_interface(
        topology, family, outer_observer, addresses["router_observer"]
    )
    _configure_endpoint(
        topology, client, family, addresses["client"], addresses["router_client"]
    )
    _configure_endpoint(
        topology, server, family, addresses["server"], addresses["router_server"]
    )
    _configure_endpoint(
        topology, observer, family, addresses["observer"], addresses["router_observer"]
    )
    return (
        client,
        server,
        observer,
        addresses["client"],
        addresses["server"],
        addresses["observer"],
        addresses,
    )


def _add_table_chain(
    topology: Topology, family: str, table: str, chain: str, declaration: str
) -> None:
    topology.command(
        "setup", ["nft", "add", "chain", family, table, chain, declaration]
    )


def _add_nat_rules(
    topology: Topology,
    *,
    table: str,
    client_if: str,
    server_if: str,
    observer_if: str,
    client: str,
    server: str,
    observer: str,
    public: str,
    server_port: int,
    observer_port: int,
    profile: Profile,
) -> None:
    topology.command("setup", ["nft", "add", "table", "ip", table])
    topology.cleanup_actions.append(["nft", "delete", "table", "ip", table])
    _add_table_chain(
        topology,
        "ip",
        table,
        "prerouting",
        "{ type nat hook prerouting priority dstnat; policy accept; }",
    )
    _add_table_chain(
        topology,
        "ip",
        table,
        "postrouting",
        "{ type nat hook postrouting priority srcnat; policy accept; }",
    )
    _add_table_chain(
        topology,
        "ip",
        table,
        "forward",
        "{ type filter hook forward priority filter; policy drop; }",
    )

    # Endpoint-independent mapping uses the same explicit public tuple on both
    # egress links. APDM uses distinct tuples for the same destination address
    # at two ports as well as for the observer address.
    mapping_rules = (
        (server_if, server, UDP_PORT, server_port),
        (observer_if, observer, UDP_PORT, observer_port),
    )
    if profile.name == "apdm-mapping":
        mapping_rules = (
            (server_if, server, UDP_PORT, server_port),
            (server_if, server, UDP_PORT + 1, server_port + 1),
            (observer_if, observer, UDP_PORT, observer_port),
        )
    for interface, destination, destination_port, port in mapping_rules:
        match = [
            "oifname",
            interface,
            "ip",
            "saddr",
            client,
            "udp",
            "sport",
            str(UDP_PORT),
        ]
        if profile.name == "apdm-mapping":
            match.extend(
                ["ip", "daddr", destination, "udp", "dport", str(destination_port)]
            )
        topology.command(
            "setup",
            [
                "nft",
                "add",
                "rule",
                "ip",
                table,
                "postrouting",
                *match,
                "snat",
                "to",
                f"{public}:{port}",
            ],
        )
        topology.command(
            "setup",
            [
                "nft",
                "add",
                "rule",
                "ip",
                table,
                "prerouting",
                "ip",
                "daddr",
                public,
                "udp",
                "dport",
                str(port),
                "dnat",
                "to",
                f"{client}:{UDP_PORT}",
            ],
        )
    topology.command(
        "setup",
        [
            "nft",
            "add",
            "rule",
            "ip",
            table,
            "forward",
            "iifname",
            client_if,
            "meta",
            "l4proto",
            "udp",
            "accept",
        ],
    )
    if profile.name == "apdm-mapping":
        topology.command(
            "setup",
            [
                "nft",
                "add",
                "rule",
                "ip",
                table,
                "forward",
                "iifname",
                server_if,
                "oifname",
                client_if,
                "ip",
                "saddr",
                server,
                "udp",
                "sport",
                str(UDP_PORT + 1),
                "accept",
            ],
        )
    topology.command(
        "setup",
        [
            "nft",
            "add",
            "rule",
            "ip",
            table,
            "forward",
            "iifname",
            server_if,
            "oifname",
            client_if,
            "ip",
            "saddr",
            server,
            "udp",
            "sport",
            str(UDP_PORT),
            "accept",
        ],
    )
    observer_prefix = f"{observer.rsplit('.', 1)[0]}.0/24"
    if profile.name == "eim-eif":
        rule = [
            "iifname",
            observer_if,
            "oifname",
            client_if,
            "ip",
            "saddr",
            observer_prefix,
            "meta",
            "l4proto",
            "udp",
            "accept",
        ]
    elif profile.name == "eim-adf":
        rule = [
            "iifname",
            observer_if,
            "oifname",
            client_if,
            "ip",
            "saddr",
            observer,
            "meta",
            "l4proto",
            "udp",
            "accept",
        ]
    else:
        # APDF and APDM permit only the peer tuple used by the original
        # client mapping request; the later observer probe changes its port.
        rule = [
            "iifname",
            observer_if,
            "oifname",
            client_if,
            "ip",
            "saddr",
            observer,
            "udp",
            "sport",
            str(UDP_PORT),
            "accept",
        ]
    topology.command("setup", ["nft", "add", "rule", "ip", table, "forward", *rule])


def nat_addresses(profile: Profile) -> dict[str, str]:
    """Give each NAT profile unique deterministic tuples.

    conntrack entries are scoped to the outer router namespace and can outlive
    a veth.  Distinct profile tuples prevent a prior NAT decision from being
    reused as evidence for the next profile.
    """

    slots = {"eim-eif": 10, "eim-adf": 20, "eim-apdf": 30, "apdm-mapping": 40}
    try:
        slot = slots[profile.name]
    except KeyError as exc:
        raise ValueError(f"not a single-router NAT profile: {profile.name}") from exc
    return {
        "client": f"10.77.{slot}.2",
        "router_client": f"10.77.{slot}.1",
        "server": f"198.18.{slot}.2",
        "router_server": f"198.18.{slot}.1",
        "observer": f"198.18.{slot + 50}.2",
        "observer_alias": f"198.18.{slot + 50}.3",
        "router_observer": f"198.18.{slot + 50}.1",
        "public": f"198.18.{slot + 100}.1",
    }


def _setup_nat(
    topology: Topology, profile: Profile
) -> tuple[Node, Node, Node, dict[str, str]]:
    client = topology.start_node("client")
    server = topology.start_node("server")
    observer = topology.start_node("observer")
    client_if = topology.attach(client, "eth0", 0)
    server_if = topology.attach(server, "eth0", 0)
    observer_if = topology.attach(observer, "eth0", 0)
    _set_forwarding(topology, socket.AF_INET)
    addresses = nat_addresses(profile)
    _configure_outer_interface(
        topology, socket.AF_INET, client_if, addresses["router_client"]
    )
    _configure_outer_interface(
        topology, socket.AF_INET, server_if, addresses["router_server"]
    )
    _configure_outer_interface(
        topology, socket.AF_INET, observer_if, addresses["router_observer"]
    )
    _configure_public_loopback(topology, addresses["public"])
    _configure_endpoint(
        topology,
        client,
        socket.AF_INET,
        addresses["client"],
        addresses["router_client"],
    )
    _configure_endpoint(
        topology,
        server,
        socket.AF_INET,
        addresses["server"],
        addresses["router_server"],
    )
    _configure_endpoint(
        topology,
        observer,
        socket.AF_INET,
        addresses["observer"],
        addresses["router_observer"],
        aliases=(addresses["observer_alias"],),
    )
    if profile.name == "apdm-mapping":
        # server_port + 1 is reserved for the same server address at UDP_PORT+1.
        server_port, observer_port = 40001, 40003
    else:
        server_port = observer_port = 40000
    _add_nat_rules(
        topology,
        table=profile.table,
        client_if=client_if,
        server_if=server_if,
        observer_if=observer_if,
        client=addresses["client"],
        server=addresses["server"],
        observer=addresses["observer"],
        public=addresses["public"],
        server_port=server_port,
        observer_port=observer_port,
        profile=profile,
    )
    addresses["server_port"] = str(server_port)
    addresses["observer_port"] = str(observer_port)
    return client, server, observer, addresses


def _add_udp_drop(topology: Topology) -> None:
    table = topology.profile.table
    topology.command("setup", ["nft", "add", "table", "inet", table])
    topology.cleanup_actions.append(["nft", "delete", "table", "inet", table])
    _add_table_chain(
        topology,
        "inet",
        table,
        "input",
        "{ type filter hook input priority filter; policy accept; }",
    )
    _add_table_chain(
        topology,
        "inet",
        table,
        "forward",
        "{ type filter hook forward priority filter; policy accept; }",
    )
    topology.command(
        "setup",
        [
            "nft",
            "add",
            "rule",
            "inet",
            table,
            "input",
            "meta",
            "l4proto",
            "udp",
            "drop",
        ],
    )
    topology.command(
        "setup",
        [
            "nft",
            "add",
            "rule",
            "inet",
            table,
            "forward",
            "meta",
            "l4proto",
            "udp",
            "drop",
        ],
    )


def _add_broken_v6_route(topology: Topology, server: str) -> None:
    topology.command(
        "setup", ["ip", "-6", "route", "add", "blackhole", f"{server}/128"]
    )


def _node_nft(
    topology: Topology, node: Node, table: str, command: Sequence[str]
) -> None:
    topology.node_command("setup", node, ["nft", *command])


def _setup_two_router_profile(
    topology: Topology, profile: Profile
) -> tuple[Node, Node, Node, dict[str, str]]:
    """Build client -> NAT1 -> CGNAT/NAT2 -> public LAN on three isolated bridges."""

    client = topology.start_node("client")
    inner = topology.start_node("inner-router")
    outer = topology.start_node("outer-router")
    server = topology.start_node("server")
    observer = topology.start_node("observer")
    bridge_a, bridge_b, bridge_c = (
        topology.bridge("a"),
        topology.bridge("b"),
        topology.bridge("c"),
    )
    topology.attach(client, "eth0", 0, bridge=bridge_a)
    topology.attach(inner, "eth0", 0, bridge=bridge_a)
    topology.attach(inner, "eth1", 1, bridge=bridge_b)
    topology.attach(outer, "eth0", 0, bridge=bridge_b)
    topology.attach(outer, "eth1", 1, bridge=bridge_c)
    topology.attach(server, "eth0", 0, bridge=bridge_c)
    topology.attach(observer, "eth0", 0, bridge=bridge_c)
    addresses = {
        "client": "10.77.40.2",
        "inner_client": "10.77.40.1",
        "inner_cgnat": "100.64.1.2",
        "outer_cgnat": "100.64.1.1",
        "outer_public": "198.18.40.1",
        "server": "198.18.40.2",
        "observer": "198.18.40.3",
        "observer_alias": "198.18.40.4",
    }
    _configure_endpoint(
        topology, client, socket.AF_INET, addresses["client"], addresses["inner_client"]
    )
    _configure_endpoint(
        topology, server, socket.AF_INET, addresses["server"], addresses["outer_public"]
    )
    _configure_endpoint(
        topology,
        observer,
        socket.AF_INET,
        addresses["observer"],
        addresses["outer_public"],
        aliases=(addresses["observer_alias"],),
    )
    topology.node_command(
        "setup",
        inner,
        ["ip", "addr", "add", f"{addresses['inner_client']}/24", "dev", "eth0"],
    )
    topology.node_command(
        "setup",
        inner,
        ["ip", "addr", "add", f"{addresses['inner_cgnat']}/24", "dev", "eth1"],
    )
    topology.node_command(
        "setup",
        inner,
        [
            "ip",
            "route",
            "replace",
            "default",
            "via",
            addresses["outer_cgnat"],
            "dev",
            "eth1",
        ],
    )
    topology.node_command(
        "setup",
        outer,
        ["ip", "addr", "add", f"{addresses['outer_cgnat']}/24", "dev", "eth0"],
    )
    topology.node_command(
        "setup",
        outer,
        ["ip", "addr", "add", f"{addresses['outer_public']}/24", "dev", "eth1"],
    )
    _set_forwarding(topology, socket.AF_INET, node=inner)
    _set_forwarding(topology, socket.AF_INET, node=outer)
    inner_table, outer_table = f"{profile.table}_n1", f"{profile.table}_n2"
    for node, table in ((inner, inner_table), (outer, outer_table)):
        _node_nft(topology, node, table, ["add", "table", "ip", table])
        topology.cleanup_actions.append(
            topology.node_argv(node, ["nft", "delete", "table", "ip", table])
        )
        _node_nft(
            topology,
            node,
            table,
            [
                "add",
                "chain",
                "ip",
                table,
                "prerouting",
                "{ type nat hook prerouting priority dstnat; policy accept; }",
            ],
        )
        _node_nft(
            topology,
            node,
            table,
            [
                "add",
                "chain",
                "ip",
                table,
                "postrouting",
                "{ type nat hook postrouting priority srcnat; policy accept; }",
            ],
        )
        _node_nft(
            topology,
            node,
            table,
            [
                "add",
                "chain",
                "ip",
                table,
                "forward",
                "{ type filter hook forward priority filter; policy accept; }",
            ],
        )
    _node_nft(
        topology,
        inner,
        inner_table,
        [
            "add",
            "rule",
            "ip",
            inner_table,
            "postrouting",
            "oifname",
            "eth1",
            "ip",
            "saddr",
            addresses["client"],
            "udp",
            "sport",
            str(UDP_PORT),
            "counter",
            "snat",
            "to",
            f"{addresses['inner_cgnat']}:41000",
        ],
    )
    _node_nft(
        topology,
        inner,
        inner_table,
        [
            "add",
            "rule",
            "ip",
            inner_table,
            "prerouting",
            "ip",
            "daddr",
            addresses["inner_cgnat"],
            "udp",
            "dport",
            "41000",
            "dnat",
            "to",
            f"{addresses['client']}:{UDP_PORT}",
        ],
    )
    _node_nft(
        topology,
        outer,
        outer_table,
        [
            "add",
            "rule",
            "ip",
            outer_table,
            "postrouting",
            "oifname",
            "eth1",
            "ip",
            "saddr",
            addresses["inner_cgnat"],
            "udp",
            "sport",
            "41000",
            "counter",
            "snat",
            "to",
            f"{addresses['outer_public']}:42000",
        ],
    )
    _node_nft(
        topology,
        outer,
        outer_table,
        [
            "add",
            "rule",
            "ip",
            outer_table,
            "prerouting",
            "ip",
            "daddr",
            addresses["outer_public"],
            "udp",
            "dport",
            "42000",
            "dnat",
            "to",
            f"{addresses['inner_cgnat']}:41000",
        ],
    )
    return client, server, observer, addresses


def _nat_counter(topology: Topology, node: Node, table: str) -> int:
    result = topology.node_command(
        "probe", node, ["nft", "list", "chain", "ip", table, "postrouting"]
    )
    counters = [
        int(value) for value in re.findall(r"counter packets ([0-9]+)", result.stdout)
    ]
    return sum(counters)


def _observe_direct(topology: Topology, profile: Profile) -> dict[str, Any]:
    client, server, _observer, client_address, server_address, _unused, addresses = (
        _setup_direct(topology, profile.family)
    )
    _start_echo(topology, server, server_address)
    if profile.kind == "udp-blocked":
        _add_udp_drop(topology)
    if profile.kind == "broken-v6":
        _add_broken_v6_route(topology, server_address)
    report = _map_client(
        topology, client, client_address, (("server", server_address),)
    )
    reachable = "reachable" if "server" in report.get("responses", {}) else "blocked"
    return {
        "reachability": reachable,
        "client": client_address,
        "server": server_address,
        "response_count": len(report.get("responses", {})),
    }


def _observe_nat(topology: Topology, profile: Profile) -> dict[str, Any]:
    client, server, observer, addresses = _setup_nat(topology, profile)
    _start_echo(topology, server, addresses["server"])
    if profile.name == "apdm-mapping":
        _start_echo(topology, server, addresses["server"], port=UDP_PORT + 1)
    _start_echo(topology, observer, addresses["observer"])
    destinations = [
        ("server", addresses["server"]),
        ("observer", addresses["observer"]),
    ]
    destination_ports: dict[str, int] = {}
    if profile.name == "apdm-mapping":
        destinations.insert(1, ("server-alt-port", addresses["server"]))
        destination_ports["server-alt-port"] = UDP_PORT + 1
    report = _map_client(
        topology,
        client,
        addresses["client"],
        destinations,
        destination_ports=destination_ports,
    )
    responses = report.get("responses", {})
    server_map = responses.get("server", {}).get("seen_source")
    server_alt_map = responses.get("server-alt-port", {}).get("seen_source")
    observer_map = responses.get("observer", {}).get("seen_source")
    required_maps = [server_map, observer_map]
    if profile.name == "apdm-mapping":
        required_maps.append(server_alt_map)
    observed: dict[str, Any] = {
        "reachability": "reachable" if all(required_maps) else "blocked",
        "mapping": "same" if server_map and server_map == observer_map else "different",
        "mappings": {
            "server": server_map,
            "server_alt_port": server_alt_map,
            "observer": observer_map,
        },
    }
    _start_listener(topology, client, addresses["client"])
    # Give the listener a scheduling turn in its distinct namespace before the
    # observer injects a non-loopback packet through the router.
    time.sleep(0.06)
    if profile.name == "apdm-mapping":
        observed["mapping_dependency"] = (
            "destination-address-and-port"
            if server_map and server_alt_map and server_map != server_alt_map
            else "not-observed"
        )
        observed["same_address_alt_port_mapping"] = (
            "different"
            if server_map and server_alt_map and server_map != server_alt_map
            else "same-or-missing"
        )
        observed["filter_observer_to_server_mapping"] = _filter_probe(
            topology,
            observer,
            addresses["observer"],
            UDP_PORT + 1,
            addresses["public"],
            int(addresses["server_port"]),
            "observer-to-server-map",
        )
    else:
        public_port = int(addresses["server_port"])
        observed["filter_same_ip_alt_port"] = _filter_probe(
            topology,
            observer,
            addresses["observer"],
            UDP_PORT + 1,
            addresses["public"],
            public_port,
            "same-ip-alt-port",
        )
        observed["filter_alt_ip"] = _filter_probe(
            topology,
            observer,
            addresses["observer_alias"],
            UDP_PORT + 2,
            addresses["public"],
            public_port,
            "alt-ip",
        )
    return observed


def _observe_two_router(topology: Topology, profile: Profile) -> dict[str, Any]:
    client, server, observer, addresses = _setup_two_router_profile(topology, profile)
    _start_echo(topology, server, addresses["server"])
    _start_echo(topology, observer, addresses["observer"])
    report = _map_client(
        topology,
        client,
        addresses["client"],
        (("server", addresses["server"]), ("observer", addresses["observer"])),
    )
    responses = report.get("responses", {})
    server_map = responses.get("server", {}).get("seen_source")
    observer_map = responses.get("observer", {}).get("seen_source")
    inner_packets = _nat_counter(
        topology, topology.nodes["inner-router"], f"{profile.table}_n1"
    )
    outer_packets = _nat_counter(
        topology, topology.nodes["outer-router"], f"{profile.table}_n2"
    )
    observed: dict[str, Any] = {
        "reachability": "reachable" if server_map and observer_map else "blocked",
        "layers": "two",
        "mappings": {"server": server_map, "observer": observer_map},
        "router_processes": 2,
        "inner_nat": "observed" if inner_packets > 0 else "missing",
        "outer_nat": "observed" if outer_packets > 0 else "missing",
        "inner_nat_packets": inner_packets,
        "outer_nat_packets": outer_packets,
    }
    if profile.kind == "cgnat":
        actual_path = [
            addresses["client"],
            addresses["inner_cgnat"],
            addresses["outer_public"],
        ]
        observed["actual_address_path"] = actual_path
        observed["address_path"] = (
            "private-cgnat-public"
            if ipaddress.ip_address(actual_path[0])
            in ipaddress.ip_network("10.0.0.0/8")
            and ipaddress.ip_address(actual_path[1])
            in ipaddress.ip_network(CGNAT_SPACE)
            and ipaddress.ip_address(actual_path[2])
            in ipaddress.ip_network(DOCUMENTATION_SPACE)
            else "unexpected"
        )
    return observed


def _execute_profile(profile: Profile) -> dict[str, Any]:
    started = time.monotonic()
    evidence = new_evidence(profile.name, profile.expected, started)
    topology = Topology(profile, evidence, started + DEADLINE_SECONDS)
    observed: dict[str, Any] = {}
    forced_status: str | None = None
    reason: str | None = None
    try:
        if profile.kind in {"direct", "udp-blocked", "broken-v6"}:
            observed = _observe_direct(topology, profile)
        elif profile.kind == "nat":
            observed = _observe_nat(topology, profile)
        elif profile.kind in {"double", "cgnat"}:
            observed = _observe_two_router(topology, profile)
        else:
            raise MatrixError(f"unsupported profile executor: {profile.kind}")
    except CapabilityBlocked as exc:
        forced_status, reason = "blocked", str(exc)
    except (DeadlineExpired, CommandFailed, MatrixError) as exc:
        forced_status, reason = "failed", str(exc)
    finally:
        cleaned = topology.cleanup()
        if not cleaned and forced_status is None:
            forced_status, reason = "failed", "topology cleanup/reap did not complete"
    evidence["elapsed_seconds"] = round(time.monotonic() - started, 6)
    return finalize_evidence(evidence, observed, status=forced_status, reason=reason)


def _internal(args: argparse.Namespace) -> int:
    outer_inode, executor_inode = enter_executor_network_namespace()
    report = {
        "schema": SCHEMA,
        "isolated": True,
        "outer_netns_inode": outer_inode,
        "executor_netns_inode": executor_inode,
        "results": [],
    }
    for entry in build_plan(args.profiles)["profiles"]:
        if entry["status"] == "optional":
            report["results"].append(entry)
        else:
            report["results"].append(_execute_profile(profile_by_name(entry["name"])))
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return 0


def _blocked_result(profile: Profile, reason: str, stderr: str) -> dict[str, Any]:
    evidence = new_evidence(profile.name, profile.expected, time.monotonic())
    append_stderr(evidence, stderr)
    return finalize_evidence(evidence, {}, status="blocked", reason=reason)


def result_exit_code(results: Sequence[Mapping[str, Any]]) -> int:
    statuses = {item.get("status") for item in results}
    if "failed" in statuses:
        return 1
    if "blocked" in statuses:
        return 2
    return 0


def valid_executor_report_provenance(
    host_inode: int, internal: Mapping[str, Any]
) -> bool:
    """Accept only a schema-valid report with three distinct namespace inodes."""

    outer_inode = internal.get("outer_netns_inode")
    executor_inode = internal.get("executor_netns_inode")
    inodes = (host_inode, outer_inode, executor_inode)
    return (
        internal.get("schema") == SCHEMA
        and internal.get("isolated") is True
        and all(
            isinstance(inode, int) and not isinstance(inode, bool) and inode > 0
            for inode in inodes
        )
        and len(set(inodes)) == 3
    )


def run(args: argparse.Namespace) -> int:
    plan = build_plan(args.profiles)
    inv = inventory()
    output = Path(args.output).resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    report: dict[str, Any] = {
        "schema": SCHEMA,
        "plan": plan,
        "inventory": inv,
        "isolated": False,
        "results": [],
    }
    concrete_profiles = [
        profile_by_name(entry["name"])
        for entry in plan["profiles"]
        if entry["status"] == "planned"
    ]
    optional = [entry for entry in plan["profiles"] if entry["status"] == "optional"]
    if not args.allow_netns:
        report["results"] = [
            *optional,
            *[
                _blocked_result(
                    profile, "requires explicit --allow-netns isolated executor", ""
                )
                for profile in concrete_profiles
            ],
        ]
    elif not inv["rootless_user_netns"] or not all(inv["commands"].values()):
        missing = [name for name, available in inv["commands"].items() if not available]
        reason = (
            "rootless user network namespaces unavailable"
            if not inv["rootless_user_netns"]
            else f"missing required tools: {', '.join(missing)}"
        )
        report["results"] = [
            *optional,
            *[_blocked_result(profile, reason, "") for profile in concrete_profiles],
        ]
    else:
        host_inode = os.stat("/proc/self/ns/net").st_ino
        command = isolated_command(output, args.profiles)
        timeout = max(45, len(concrete_profiles) * (DEADLINE_SECONDS + 5) + 15)
        executor_failure_status = "failed"
        try:
            child = subprocess.run(
                command,
                text=True,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            stderr = str(exc)
            child = None
            executor_failure_status = (
                "blocked" if isinstance(exc, OSError) else "failed"
            )
        if child is not None and child.returncode == 0 and output.exists():
            try:
                internal = json.loads(output.read_text())
                if not isinstance(
                    internal, dict
                ) or not valid_executor_report_provenance(host_inode, internal):
                    raise ValueError("isolated executor provenance is invalid")
                report.update(internal)
                report["host_netns_inode"] = host_inode
                report["outer_command_hash"] = _digest_commands([command])
                report["outer_stderr_hash"] = _digest(child.stderr.encode())
            except (OSError, TypeError, ValueError, json.JSONDecodeError) as exc:
                stderr = str(exc)
                child = None
        if child is None or child.returncode != 0 or not output.exists():
            stderr = stderr if child is None else child.stderr
            report["results"] = [
                *optional,
                *[
                    finalize_evidence(
                        new_evidence(profile.name, profile.expected, time.monotonic()),
                        {},
                        status=executor_failure_status,
                        reason="isolated executor failed or produced invalid evidence",
                    )
                    for profile in concrete_profiles
                ],
            ]
            report["outer_stderr_hash"] = _digest(stderr.encode())
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    return result_exit_code(report["results"])


def _non_loopback(address: str) -> None:
    parsed = ipaddress.ip_address(address)
    if parsed.is_loopback or parsed.is_unspecified:
        raise ValueError(
            "matrix node probes reject loopback and unspecified destinations"
        )


def _node_echo(args: argparse.Namespace) -> int:
    _non_loopback(args.bind)
    family = socket.AF_INET6 if ":" in args.bind else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.bind, args.port))
    sock.setblocking(False)
    deadline = time.monotonic() + args.timeout
    events = 0
    while time.monotonic() < deadline:
        ready, _, _ = select.select(
            [sock], [], [], min(0.15, max(0.0, deadline - time.monotonic()))
        )
        if not ready:
            continue
        payload, source = sock.recvfrom(512)
        try:
            text = payload.decode("ascii")
        except UnicodeDecodeError:
            continue
        if not text.startswith("MAP|"):
            continue
        label = text.split("|", 1)[1]
        host, port = source[0], source[1]
        sock.sendto(f"ECHO|{label}|{host}|{port}".encode("ascii"), source)
        events += 1
    print(json.dumps({"events": events}, sort_keys=True))
    return 0


def _node_map(args: argparse.Namespace) -> int:
    _non_loopback(args.bind)
    family = socket.AF_INET6 if ":" in args.bind else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.bind, args.port))
    destinations: dict[str, tuple[str, int]] = {}
    for raw in args.destination:
        try:
            label, address, port_string = raw.split("|", 2)
            _non_loopback(address)
            destinations[label] = (address, int(port_string))
        except (ValueError, ipaddress.AddressValueError) as exc:
            raise ValueError(f"invalid non-loopback destination: {raw}") from exc
    for label, destination in destinations.items():
        sock.sendto(f"MAP|{label}".encode("ascii"), destination)
    sock.setblocking(False)
    responses: dict[str, Any] = {}
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline and len(responses) < len(destinations):
        ready, _, _ = select.select(
            [sock], [], [], min(0.12, max(0.0, deadline - time.monotonic()))
        )
        if not ready:
            continue
        payload, source = sock.recvfrom(512)
        try:
            marker, label, seen_address, seen_port = payload.decode("ascii").split(
                "|", 3
            )
        except (UnicodeDecodeError, ValueError):
            continue
        if marker != "ECHO" or label not in destinations:
            continue
        responses[label] = {
            "echo_source": f"{source[0]}:{source[1]}",
            "seen_source": f"{seen_address}:{seen_port}",
        }
    print(json.dumps({"responses": responses}, sort_keys=True))
    return 0


def _node_listener(args: argparse.Namespace) -> int:
    _non_loopback(args.bind)
    family = socket.AF_INET6 if ":" in args.bind else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.bind, args.port))
    sock.setblocking(False)
    acknowledgements = 0
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        ready, _, _ = select.select(
            [sock], [], [], min(0.15, max(0.0, deadline - time.monotonic()))
        )
        if not ready:
            continue
        payload, source = sock.recvfrom(512)
        try:
            marker, label = payload.decode("ascii").split("|", 1)
        except (UnicodeDecodeError, ValueError):
            continue
        if marker != "FILTER":
            continue
        sock.sendto(f"ACK|{label}".encode("ascii"), source)
        acknowledgements += 1
    print(json.dumps({"acknowledgements": acknowledgements}, sort_keys=True))
    return 0


def _node_filter(args: argparse.Namespace) -> int:
    _non_loopback(args.source)
    _non_loopback(args.destination)
    family = socket.AF_INET6 if ":" in args.source else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.source, args.source_port))
    sock.sendto(
        f"FILTER|{args.label}".encode("ascii"),
        (args.destination, args.destination_port),
    )
    sock.setblocking(False)
    deadline = time.monotonic() + args.timeout
    delivered = False
    while time.monotonic() < deadline:
        ready, _, _ = select.select(
            [sock], [], [], min(0.12, max(0.0, deadline - time.monotonic()))
        )
        if not ready:
            continue
        payload, _source = sock.recvfrom(512)
        if payload == f"ACK|{args.label}".encode("ascii"):
            delivered = True
            break
    print(json.dumps({"delivered": delivered}, sort_keys=True))
    return 0


def _node_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog="nat_netns_matrix.py __node")
    subparsers = parser.add_subparsers(dest="node_mode", required=True)
    echo = subparsers.add_parser("echo")
    echo.add_argument("--bind", required=True)
    echo.add_argument("--port", type=int, required=True)
    echo.add_argument("--timeout", type=float, required=True)
    mapping = subparsers.add_parser("map")
    mapping.add_argument("--bind", required=True)
    mapping.add_argument("--port", type=int, required=True)
    mapping.add_argument("--timeout", type=float, required=True)
    mapping.add_argument("--destination", action="append", required=True)
    listener = subparsers.add_parser("listener")
    listener.add_argument("--bind", required=True)
    listener.add_argument("--port", type=int, required=True)
    listener.add_argument("--timeout", type=float, required=True)
    filtered = subparsers.add_parser("filter")
    filtered.add_argument("--source", required=True)
    filtered.add_argument("--source-port", type=int, required=True)
    filtered.add_argument("--destination", required=True)
    filtered.add_argument("--destination-port", type=int, required=True)
    filtered.add_argument("--label", required=True)
    filtered.add_argument("--timeout", type=float, required=True)
    args = parser.parse_args(argv)
    return {
        "echo": _node_echo,
        "map": _node_map,
        "listener": _node_listener,
        "filter": _node_filter,
    }[args.node_mode](args)


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "__node":
        return _node_main(argv[1:])
    if argv and argv[0] == "__internal":
        internal = argparse.ArgumentParser(add_help=False)
        internal.add_argument("--profiles", nargs="+", required=True)
        internal.add_argument("--output", required=True)
        return _internal(internal.parse_args(argv[1:]))
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("inventory", "plan", "run"))
    parser.add_argument(
        "--profiles", nargs="+", default=[profile.name for profile in PROFILES]
    )
    parser.add_argument("--output", default="artifacts/nat-matrix.json")
    parser.add_argument("--allow-netns", action="store_true")
    args = parser.parse_args(argv)
    if args.mode == "inventory":
        print(json.dumps(inventory(), sort_keys=True))
        return 0
    if args.mode == "plan":
        print(json.dumps(build_plan(args.profiles), indent=2, sort_keys=True))
        return 0
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
