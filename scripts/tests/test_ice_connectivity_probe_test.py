import importlib.util
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "ice_connectivity_probe_test.py"
SPEC = importlib.util.spec_from_file_location("ice_connectivity_probe_test", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def report_line(
    *,
    role: str = "client",
    local: str = "127.0.0.1:41001",
    remote: str = "127.0.0.1:41002",
) -> str:
    prefix = "ice-connectivity-probe" if role == "client" else "ice-connectivity-probe-host"
    ice_role = "controlling" if role == "client" else "controlled"
    suffix = " frames_after_probe=1" if role == "client" else ""
    return (
        f"{prefix}: authenticated=true success=true role={ice_role} session_id=7 "
        f"generation=1 local={local} remote={remote} requests_sent=1 "
        "successes_received=1 requests_received=1 nominations_sent=1 "
        "ice_elapsed_ms=2 quic_echo_elapsed_ms=3 exact_mtls=true "
        "full_stamp_bound=true control_nonces_bound=true route_changed=false "
        f"active_route=127.0.0.1:40002{suffix}\n"
    )


CLIENT_SCOPE = (
    "ice-connectivity-probe-scope: fresh_socket=true same_socket_handoff=true "
    "client_nonce_nonzero=true host_nonce_nonzero=true connectivity_checks=true "
    "nomination=true route_promotion=false nat_traversal_claim=false internet_claim=false\n"
)


class ProbeEvidenceTests(unittest.TestCase):
    def test_parser_accepts_complete_actual_reports(self):
        client = MODULE.parse_probe_output(report_line() + CLIENT_SCOPE, role="client")
        host = MODULE.parse_probe_output(report_line(role="host"), role="host")
        self.assertEqual(client["session_id"], 7)
        self.assertEqual(client["role"], "controlling")
        self.assertEqual(host["role"], "controlled")

    def test_parser_rejects_duplicate_scope_and_security_mismatch(self):
        with self.assertRaises(ValueError):
            MODULE.parse_probe_output(report_line() * 2 + CLIENT_SCOPE, role="client")
        with self.assertRaises(ValueError):
            MODULE.parse_probe_output(
                report_line().replace("route_changed=false", "route_changed=true")
                + CLIENT_SCOPE,
                role="client",
            )
        with self.assertRaises(ValueError):
            MODULE.parse_probe_output(
                report_line() + CLIENT_SCOPE + "ice-password=leaked\n", role="client"
            )
        with self.assertRaises(ValueError):
            MODULE.parse_probe_output(report_line() + CLIENT_SCOPE * 2, role="client")

    def test_commands_pin_probe_flags_frames_and_no_lab_bypass(self):
        host, client = MODULE.build_commands(
            Path("host"),
            Path("client"),
            "127.0.0.1:9",
            Path("h"),
            Path("c"),
            7,
        )
        self.assertIn("--ice-connectivity-probe", host)
        self.assertIn("--ice-connectivity-probe", client)
        self.assertEqual(host[host.index("--frames") + 1], "7")
        self.assertEqual(client[client.index("--bind") + 1], "127.0.0.1:0")
        self.assertNotIn("--unsafe-udp-lab", host + client)


if __name__ == "__main__":
    unittest.main()
