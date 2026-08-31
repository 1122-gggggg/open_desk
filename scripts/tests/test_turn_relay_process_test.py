import importlib.util
import sys
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "turn_relay_process_test.py"
SPEC = importlib.util.spec_from_file_location("turn_relay_process_test", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class TurnRelayProcessTests(unittest.TestCase):
    def test_commands_use_password_files_udp_and_explicit_lab_scope(self):
        server = MODULE.server_command(
            Path("server"), "127.0.0.1:9", Path("secret"), 20
        )
        client = MODULE.client_command(
            Path("client"), "127.0.0.1:9", Path("secret"), "127.0.0.1:10", 20
        )
        self.assertIn("--password-file", server + client)
        self.assertNotIn("--password", server + client)
        self.assertIn("--allow-loopback-lab", server)
        self.assertIn("--allow-loopback-lab", client)

    def test_report_parsers_require_explicit_udp_opaque_scope(self):
        server = MODULE.parse_server(
            "turn-relayd: allocations=1 deallocations=1 rejected=0 client_to_peer=2 "
            "peer_to_client=2 clean_shutdown=true opaque_payload=true tcp_relay=false "
            "desktop_payload=false\n"
        )
        client = MODULE.parse_client(
            "turn-client: challenge_authenticated=true send_round_trip=true channel_round_trip=true "
            "deallocated=true relayed=127.0.0.1:50000 opaque_payload=true exact_bytes=true "
            "tcp_relay=false desktop_payload=false\n"
        )
        self.assertTrue(server["clean_shutdown"])
        self.assertTrue(client["exact_bytes"])
        self.assertFalse(server["tcp_relay"])
        self.assertFalse(client["desktop_payload"])


if __name__ == "__main__":
    unittest.main()
