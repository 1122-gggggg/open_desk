import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).parents[2]
spec = importlib.util.spec_from_file_location(
    "nat_product", ROOT / "scripts/nat_product_netns_test.py"
)
assert spec and spec.loader
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


class ProductNatTests(unittest.TestCase):
    def test_profiles_and_sources(self):
        plan = mod.build_plan(mod.PROFILES)
        self.assertEqual(plan["port"], 38765)
        self.assertEqual(mod.expected_source("eim-eif"), "198.18.110.1:40000")
        self.assertEqual(mod.expected_source("double-nat"), "198.18.40.1:42000")
        self.assertEqual(mod.expected_source("cgnat"), "198.18.40.1:42000")
        contract = mod.expected_profile_contract()
        self.assertTrue(contract["session_match"])
        self.assertTrue(contract["challenge_match"])
        self.assertEqual(contract["route_epoch"], 1)
        with self.assertRaises(ValueError):
            mod.expected_source("apdm-mapping")

    def test_probe_command_has_product_identity_and_fixed_bind(self):
        cmd = mod.probe_command(
            Path("probe"),
            Path("client"),
            "client",
            "10.77.1.2:38765",
            "10.77.2.2:38765",
            Path("host"),
            "ab" * 32,
            10,
        )
        self.assertIn("--key", cmd)
        self.assertIn("10.77.1.2:38765", cmd)
        self.assertIn("--peer-cert", cmd)

    def test_hidden_internal_requires_mapped_root_pid1_and_distinct_netns(self):
        self.assertTrue(mod.is_safe_internal_context(0, 1, 10, 11))
        self.assertFalse(mod.is_safe_internal_context(1000, 1, 10, 11))
        self.assertFalse(mod.is_safe_internal_context(0, 99, 10, 11))
        self.assertFalse(mod.is_safe_internal_context(0, 1, 10, 10))

    def test_artifact_is_fail_closed_and_no_secret(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "report.json"
            self.assertEqual(
                mod.main(
                    [
                        "--probe-bin",
                        "p",
                        "--identity-bin",
                        "i",
                        "--profiles",
                        "lan-v4",
                        "--output",
                        str(out),
                    ]
                ),
                2,
            )
            report = json.loads(out.read_text())
            self.assertEqual(report["status"], "blocked")
            self.assertNotIn("private-key", json.dumps(report))


if __name__ == "__main__":
    unittest.main()
