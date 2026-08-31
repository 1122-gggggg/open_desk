import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "rendezvous_process_test.py"
SPEC = importlib.util.spec_from_file_location("rendezvous_process_test", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class RendezvousProcessTests(unittest.TestCase):
    def test_report_parsers_require_exact_security_scope(self):
        server = MODULE.parse_server(
            "rendezvous: registrations=2 matched=1 rejected=1 "
            "desktop_payload=false relay=false\n"
        )
        client = MODULE.parse_client(
            "rendezvous-client: matched=true role=Initiator peer_candidates=1 "
            "exact_mtls=true desktop_payload=false relay=false\n",
            "initiator",
        )
        self.assertEqual(server["matched"], 1)
        self.assertTrue(client["exact_mtls"])
        with self.assertRaises(ValueError):
            MODULE.parse_client(
                "rendezvous-client: matched=true role=Responder peer_candidates=1 "
                "exact_mtls=true desktop_payload=false relay=false\n",
                "initiator",
            )

    def test_commands_pin_exact_certificates_and_roles(self):
        server = MODULE.server_command(
            Path("server"),
            "127.0.0.1:9",
            Path("s"),
            Path("a"),
            Path("b"),
            20,
        )
        client = MODULE.client_command(
            Path("client"),
            "127.0.0.1:9",
            Path("a"),
            Path("s"),
            Path("b"),
            "initiator",
            "01" * 16,
            7,
            5001,
            20,
        )
        self.assertEqual(server.count("--allowed-client-cert"), 2)
        self.assertIn("--max-registrations", server)
        self.assertNotIn("--max-connections", server)
        self.assertIn("--expected-peer-cert", client)
        self.assertNotIn("--unsafe-udp-lab", server + client)


if __name__ == "__main__":
    unittest.main()
