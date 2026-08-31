import unittest
from pathlib import Path
from scripts import rendezvous_route_process_test as gate


class RendezvousRouteGateTests(unittest.TestCase):
    def test_client_command_has_no_host_and_no_secret(self):
        cmd = gate.command(
            Path("probe"),
            "client",
            "127.0.0.1:1",
            "127.0.0.1:2",
            Path("c"),
            Path("s"),
            "a" * 64,
            10,
            "127.0.0.1:3",
            Path("r/cert.der"),
            "b" * 32,
            "123",
        )
        self.assertNotIn("--host", cmd)
        self.assertNotIn("--host2", cmd)
        self.assertNotIn("--listen", cmd)
        self.assertNotIn("secret", " ".join(cmd).lower())
        self.assertEqual(cmd[cmd.index("--rendezvous-cert") + 1], "r/cert.der")

    def test_server_command_preserves_role_and_listeners(self):
        cmd = gate.command(
            Path("probe"),
            "server",
            "127.0.0.1:1",
            "127.0.0.1:2",
            Path("s"),
            Path("c"),
            "a" * 64,
            10,
            "127.0.0.1:3",
            Path("r/cert.der"),
            "b" * 32,
            "123",
        )
        self.assertEqual(cmd[cmd.index("--role") + 1], "server")
        self.assertEqual(cmd[cmd.index("--listen") + 1], "127.0.0.1:1")
        self.assertEqual(cmd[cmd.index("--listen2") + 1], "127.0.0.1:2")

    def test_parse_rejects_digest_mismatch(self):
        line = (
            "route-rendezvous-result role=client rendezvous_committed=true match_id="
            + "a" * 32
            + " generation=1 exchange_id=123 delivered_host_candidates=2 path0_route_sha256="
            + "c" * 64
            + " path1_route_sha256="
            + "c" * 64
            + " candidate_sources_bound=true exact_mtls=true paths=2 promoted_epoch=2 rollback_epoch=3 active_index=0 active_failure=true input=true media=true control=true clean=true peer_challenge_sha256="
            + "d" * 64
        )
        with self.assertRaises(ValueError):
            gate.parse_result(line, "client")

    def test_scope_is_explicit(self):
        self.assertFalse(gate.SECRET_RE.search("normal output"))
        self.assertFalse(gate.EVIDENCE_SCOPE["automatic_desktop_integration"])
        self.assertIn("not evidence", gate.EVIDENCE_SCOPE["competitive_claim"])
        self.assertIn("not durable", gate.EVIDENCE_SCOPE["type_state_token"])

    def test_committed_marker_requires_three_distinct_ports(self):
        marker = (
            "route-rendezvous-committed role=client match_id="
            + "a" * 32
            + " generation=1 exchange_id=123 delivered_host_candidates=2 product0_port=4000 product1_port=4001 rendezvous_local_port=4000"
        )
        with self.assertRaises(ValueError):
            gate.parse_committed(marker, "client")


if __name__ == "__main__":
    unittest.main()
