"""Unit contract for the isolated namespace NAT matrix.

These tests deliberately exercise only pure planning and evidence decisions.
The separate ``run --allow-netns`` invocation is the integration proof: it
creates real network namespaces and sends UDP packets between them.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).parents[2]
SPEC = importlib.util.spec_from_file_location(
    "nat_matrix", ROOT / "scripts" / "nat_netns_matrix.py"
)
assert SPEC and SPEC.loader
mod = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = mod
SPEC.loader.exec_module(mod)


class NatMatrixPlanTests(unittest.TestCase):
    def test_required_profiles_have_fixed_topology_and_expected_observation(
        self,
    ) -> None:
        names = [profile.name for profile in mod.PROFILES]
        self.assertEqual(
            names,
            [
                "lan-v4",
                "eim-eif",
                "eim-adf",
                "eim-apdf",
                "apdm-mapping",
                "double-nat",
                "cgnat",
                "native-v6",
                "broken-v6",
                "udp-blocked",
            ],
        )
        plan = mod.build_plan(names)
        self.assertEqual(plan["schema"], 2)
        self.assertEqual(plan["deadline_seconds"], 30)
        self.assertEqual(plan["address_space"], "198.18.0.0/15")
        self.assertEqual(plan["cgnat_space"], "100.64.0.0/10")
        self.assertEqual(plan["private_control_space"], "10.77.0.0/24")
        for entry in plan["profiles"]:
            self.assertEqual(entry["status"], "planned")
            self.assertTrue(entry["table"].startswith("ldnm_"))
            self.assertTrue(entry["node_names"]["client"].startswith("ldnm-"))
            self.assertIn("expected", entry)

    def test_plan_rejects_duplicate_unknown_and_optional_profiles_explicitly(
        self,
    ) -> None:
        with self.assertRaises(ValueError):
            mod.build_plan(["lan-v4", "lan-v4"])
        with self.assertRaises(ValueError):
            mod.build_plan(["not-a-profile"])
        optional = mod.build_plan(["nat64"])["profiles"][0]
        self.assertEqual(optional["status"], "optional")
        self.assertIn("gateway", optional["reason"])

    def test_expected_observation_is_the_only_path_to_pass(self) -> None:
        expected = {"reachability": "reachable", "mapping": "same"}
        good = mod.finish_evidence(
            expected, {"reachability": "reachable", "mapping": "same"}
        )
        bad = mod.finish_evidence(
            expected, {"reachability": "reachable", "mapping": "different"}
        )
        missing = mod.finish_evidence(expected, {"reachability": "reachable"})
        self.assertEqual(good["status"], "pass")
        self.assertEqual(bad["status"], "failed")
        self.assertEqual(missing["status"], "failed")
        self.assertEqual(
            bad["mismatches"],
            {"mapping": {"expected": "same", "observed": "different"}},
        )
        self.assertEqual(mod.result_exit_code([good]), 0)
        self.assertEqual(mod.result_exit_code([{"status": "blocked"}]), 2)
        self.assertEqual(mod.result_exit_code([{"status": "failed"}]), 1)

    def test_evidence_hashes_every_command_group_and_stderr(self) -> None:
        evidence = mod.new_evidence("lan-v4", {"reachability": "reachable"}, 12.5)
        mod.record_command(evidence, "setup", ["ip", "link", "add", "ldnm-x"])
        mod.record_command(
            evidence, "probe", ["nsenter", "-t", "123", "-n", "--", "python3"]
        )
        mod.record_command(evidence, "cleanup", ["ip", "link", "del", "ldnm-x"])
        mod.append_stderr(evidence, "a harmless diagnostic")
        final = mod.finalize_evidence(evidence, {"reachability": "reachable"})
        self.assertEqual(final["status"], "pass")
        self.assertEqual(
            set(final["command_hashes"]), {"setup", "probe", "cleanup", "all"}
        )
        self.assertEqual(len(final["stderr_hash"]), 64)
        self.assertEqual(final["commands"]["setup"][0][0], "ip")
        json.dumps(final, sort_keys=True)

    def test_internal_context_requires_root_pid1_and_self_created_network(self) -> None:
        self.assertTrue(mod.is_safe_internal_context(0, 12, 13, 1))
        self.assertFalse(mod.is_safe_internal_context(1000, 12, 13, 1))
        self.assertFalse(mod.is_safe_internal_context(0, 12, 12, 1))
        self.assertFalse(mod.is_safe_internal_context(0, 12, 13, 99))

    def test_internal_executor_self_unshares_before_any_network_mutation(self) -> None:
        with (
            mock.patch.object(mod.os, "getuid", return_value=0),
            mock.patch.object(mod.os, "getpid", return_value=1),
            mock.patch.object(
                mod.os,
                "stat",
                side_effect=[SimpleNamespace(st_ino=12), SimpleNamespace(st_ino=13)],
            ),
            mock.patch.object(mod.os, "unshare") as unshare,
        ):
            self.assertEqual(mod.enter_executor_network_namespace(), (12, 13))
            unshare.assert_called_once_with(mod.os.CLONE_NEWNET)

        with (
            mock.patch.object(mod.os, "getuid", return_value=0),
            mock.patch.object(mod.os, "getpid", return_value=99),
            mock.patch.object(mod.os, "unshare") as unshare,
        ):
            with self.assertRaises(RuntimeError):
                mod.enter_executor_network_namespace()
            unshare.assert_not_called()

    def test_outer_executor_is_isolated_and_never_invokes_host_network_tools(
        self,
    ) -> None:
        command = mod.isolated_command(Path("artifact.json"), ["lan-v4"])
        self.assertEqual(
            command[:7],
            [
                "unshare",
                "--user",
                "--map-root-user",
                "--mount",
                "--net",
                "--pid",
                "--fork",
            ],
        )
        self.assertIn("__internal", command)
        self.assertNotIn("ip", command)
        self.assertNotIn("nft", command)

    def test_public_runner_requires_three_distinct_namespace_inodes(self) -> None:
        valid = {
            "schema": mod.SCHEMA,
            "isolated": True,
            "outer_netns_inode": 12,
            "executor_netns_inode": 13,
        }
        self.assertTrue(mod.valid_executor_report_provenance(11, valid))
        for field, value in (
            ("outer_netns_inode", 11),
            ("executor_netns_inode", 11),
            ("executor_netns_inode", 12),
            ("executor_netns_inode", True),
            ("executor_netns_inode", 0),
        ):
            invalid = dict(valid)
            invalid[field] = value
            self.assertFalse(mod.valid_executor_report_provenance(11, invalid))

    def test_invalid_executor_provenance_becomes_failed_artifact(self) -> None:
        host_inode = mod.os.stat("/proc/self/ns/net").st_ino
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "matrix.json"
            output.write_text(
                json.dumps(
                    {
                        "schema": mod.SCHEMA,
                        "isolated": True,
                        "outer_netns_inode": host_inode + 1,
                        "executor_netns_inode": host_inode,
                        "results": [],
                    }
                ),
                encoding="utf-8",
            )
            args = SimpleNamespace(
                profiles=["lan-v4"], output=str(output), allow_netns=True
            )
            inv = {
                "rootless_user_netns": True,
                "commands": {tool: True for tool in mod.REQUIRED_TOOLS},
            }
            child = subprocess.CompletedProcess(["unshare"], 0, "", "")
            with (
                mock.patch.object(mod, "inventory", return_value=inv),
                mock.patch.object(mod.subprocess, "run", return_value=child),
                mock.patch("builtins.print"),
            ):
                self.assertEqual(mod.run(args), 1)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["results"][0]["status"], "failed")
            self.assertIn("invalid evidence", report["results"][0]["reason"])

    def test_nat_observer_contract_distinguishes_mapping_and_filtering(self) -> None:
        self.assertEqual(
            mod.profile_by_name("eim-eif").expected,
            {
                "reachability": "reachable",
                "mapping": "same",
                "filter_same_ip_alt_port": "delivered",
                "filter_alt_ip": "delivered",
            },
        )
        self.assertEqual(
            mod.profile_by_name("eim-adf").expected["filter_alt_ip"], "blocked"
        )
        self.assertEqual(
            mod.profile_by_name("eim-apdf").expected["filter_same_ip_alt_port"],
            "blocked",
        )
        symmetric = mod.profile_by_name("apdm-mapping").expected
        self.assertEqual(symmetric["mapping"], "different")
        self.assertEqual(
            symmetric["mapping_dependency"], "destination-address-and-port"
        )
        self.assertEqual(symmetric["same_address_alt_port_mapping"], "different")
        self.assertEqual(symmetric["filter_observer_to_server_mapping"], "blocked")

        cgnat = mod.profile_by_name("cgnat").expected
        self.assertEqual(
            cgnat["actual_address_path"],
            ["10.77.40.2", "100.64.1.2", "198.18.40.1"],
        )

    def test_generated_nft_filter_rules_use_a_valid_udp_protocol_predicate(
        self,
    ) -> None:
        class RecordingTopology:
            def __init__(self) -> None:
                self.cleanup_actions = []
                self.commands = []

            def command(self, phase, argv):
                self.commands.append((phase, list(argv)))

        topology = RecordingTopology()
        mod._add_nat_rules(
            topology,
            table="ldnm_test",
            client_if="client0",
            server_if="server0",
            observer_if="observer0",
            client="10.77.10.2",
            server="198.18.20.2",
            observer="198.18.30.2",
            public="198.18.0.1",
            server_port=40000,
            observer_port=40000,
            profile=mod.profile_by_name("eim-eif"),
        )
        rules = [argv for _phase, argv in topology.commands if "forward" in argv]
        self.assertTrue(any("meta" in rule and "l4proto" in rule for rule in rules))
        for rule in rules:
            for index, token in enumerate(rule[:-1]):
                if token == "udp" and rule[index + 1] == "accept":
                    self.assertGreaterEqual(index, 1)
                    self.assertEqual(rule[index - 1], "l4proto")

    def test_apdm_rules_distinguish_same_address_at_two_ports(self) -> None:
        class RecordingTopology:
            def __init__(self) -> None:
                self.cleanup_actions = []
                self.commands = []

            def command(self, phase, argv):
                self.commands.append((phase, list(argv)))

        topology = RecordingTopology()
        mod._add_nat_rules(
            topology,
            table="ldnm_apdm",
            client_if="client0",
            server_if="server0",
            observer_if="observer0",
            client="10.77.40.2",
            server="198.18.40.2",
            observer="198.18.90.2",
            public="198.18.140.1",
            server_port=40001,
            observer_port=40003,
            profile=mod.profile_by_name("apdm-mapping"),
        )
        postrouting = [
            argv
            for _phase, argv in topology.commands
            if "postrouting" in argv and "snat" in argv
        ]
        server_rules = [rule for rule in postrouting if "198.18.40.2" in rule]
        self.assertEqual(len(server_rules), 2)
        self.assertEqual(
            {rule[rule.index("dport") + 1] for rule in server_rules},
            {str(mod.UDP_PORT), str(mod.UDP_PORT + 1)},
        )
        self.assertEqual(
            {rule[-1] for rule in server_rules},
            {"198.18.140.1:40001", "198.18.140.1:40002"},
        )

    def test_cleanup_uses_an_independent_deadline_after_profile_expiry(self) -> None:
        evidence = mod.new_evidence("lan-v4", {}, 0.0)
        topology = mod.Topology.__new__(mod.Topology)
        topology.evidence = evidence
        topology.deadline = -1.0
        topology.workloads = []
        topology.cleanup_actions = [["ip", "link", "del", "test-only"]]
        topology.nodes = {}
        topology.cleanup_ok = True
        completed = subprocess.CompletedProcess(
            topology.cleanup_actions[0], 1, "", "Cannot find device"
        )
        with mock.patch.object(mod.subprocess, "run", return_value=completed) as run:
            self.assertTrue(topology.cleanup())
        self.assertGreater(run.call_args.kwargs["timeout"], 0)

    def test_public_nat_loopback_is_explicitly_removed_between_profiles(self) -> None:
        class RecordingTopology:
            def __init__(self) -> None:
                self.cleanup_actions = []
                self.commands = []

            def command(self, phase, argv):
                self.commands.append((phase, list(argv)))

        topology = RecordingTopology()
        mod._configure_public_loopback(topology, "198.18.0.1")
        self.assertEqual(
            topology.commands,
            [("setup", ["ip", "addr", "add", "198.18.0.1/32", "dev", "lo"])],
        )
        self.assertEqual(
            topology.cleanup_actions,
            [["ip", "addr", "del", "198.18.0.1/32", "dev", "lo"]],
        )

    def test_nat_profiles_use_disjoint_tuples_to_avoid_stale_conntrack_state(
        self,
    ) -> None:
        independent = mod.nat_addresses(mod.profile_by_name("eim-eif"))
        symmetric = mod.nat_addresses(mod.profile_by_name("apdm-mapping"))
        self.assertNotEqual(independent["client"], symmetric["client"])
        self.assertNotEqual(independent["server"], symmetric["server"])
        self.assertNotEqual(independent["observer"], symmetric["observer"])
        self.assertNotEqual(independent["public"], symmetric["public"])
        self.assertTrue(independent["client"].startswith("10.77."))
        self.assertTrue(symmetric["public"].startswith("198.18."))

    def test_two_router_profile_veth_names_do_not_collide_with_observer(self) -> None:
        profile = mod.profile_by_name("double-nat")
        names = {
            mod.link_names(profile, role, slot)[0]
            for role, slot in (
                ("client", 0),
                ("inner-router", 0),
                ("inner-router", 1),
                ("outer-router", 0),
                ("outer-router", 1),
                ("server", 0),
                ("observer", 0),
            )
        }
        self.assertEqual(len(names), 7)
        self.assertTrue(all(len(name) <= 15 for name in names))


if __name__ == "__main__":
    unittest.main()
