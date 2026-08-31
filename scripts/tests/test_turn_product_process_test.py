import unittest
from pathlib import Path

from scripts import turn_product_process_test as gate


class TurnProductProcessGateTests(unittest.TestCase):
    def test_commands_use_exact_mtls_and_forced_turn_without_plaintext_password(self):
        relay = gate.relay_command(
            Path("relay"), "127.0.0.1:3478", Path("secret"), 20
        )
        host = gate.host_command(
            Path("probe"),
            "127.0.0.1:5000",
            Path("host"),
            Path("client"),
            "aa" * 32,
            20,
        )
        client = gate.client_command(
            Path("probe"),
            "127.0.0.1:5000",
            "127.0.0.1:3478",
            Path("client"),
            Path("host"),
            Path("secret"),
            "bb" * 32,
            20,
        )
        combined = relay + host + client
        self.assertIn("--turn-server", client)
        self.assertIn("--peer-cert", host + client)
        self.assertIn("--password-file", relay)
        self.assertIn("--turn-password-file", client)
        self.assertNotIn("--password", combined)
        self.assertNotIn("--unsafe-udp-lab", combined)

    def test_result_parser_rejects_marker_only_or_incomplete_contract(self):
        valid = (
            "product-probe-result role=client route=turn exact_mtls=true product=true "
            "control=true input=true media=true clean=true session_id=9 route_epoch=1 "
            "local_route=127.0.0.1:49000 peer_challenge_sha256=" + "ab" * 32
        )
        parsed = gate.parse_product_result(valid, "client")
        self.assertEqual(parsed["route"], "turn")
        self.assertEqual(parsed["session_id"], 9)
        with self.assertRaises(ValueError):
            gate.parse_product_result("product-probe-result role=client", "client")


if __name__ == "__main__":
    unittest.main()
