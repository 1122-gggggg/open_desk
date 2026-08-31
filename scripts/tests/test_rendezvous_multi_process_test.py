import tempfile
import unittest
from pathlib import Path

from scripts.rendezvous_multi_process_test import (
    listen_port,
    native_version,
    server_command,
)
from scripts.route_promotion_process_test import validate_identity, verify_native_binary


class MultiRendezvousCommandTests(unittest.TestCase):
    def test_server_command_binds_four_exact_clients_and_two_matches(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            command = server_command(
                Path("rendezvousd"),
                "127.0.0.1:9443",
                root / "server",
                [root / f"client-{index}" for index in range(4)],
                20,
            )
        self.assertEqual(command.count("--allowed-client-cert"), 4)
        self.assertEqual(command[command.index("--max-registrations") + 1], "4")
        self.assertEqual(command[command.index("--max-matches") + 1], "2")
        self.assertNotIn("--unsafe", " ".join(command))

    def test_marker_only_shell_falsifier_is_rejected_as_non_native(self):
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "latencydesk-rendezvousd"
            marker.write_text(
                "#!/bin/sh\n"
                "echo 'rendezvous: listening=127.0.0.1:9443'\n",
                encoding="utf-8",
            )
            marker.chmod(0o755)
            with self.assertRaises(ValueError):
                verify_native_binary(marker, "latencydesk-rendezvousd")

    def test_endpoint_parser_only_accepts_loopback_udp_endpoint(self):
        self.assertEqual(listen_port("127.0.0.1:9443"), 9443)
        for endpoint in ("0.0.0.0:9443", "127.0.0.1:0", "not-an-endpoint"):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                listen_port(endpoint)

    def test_native_version_rejects_marker_only_version_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            marker = Path(temporary) / "latencydesk-rendezvousd"
            marker.write_text(
                "#!/bin/sh\n"
                "if [ \"$1\" = \"--version\" ]; then\n"
                "  echo 'latencydesk-rendezvousd 0.1.0'\n"
                "fi\n",
                encoding="utf-8",
            )
            marker.chmod(0o755)
            with self.assertRaises(ValueError):
                native_version(marker, "latencydesk-rendezvousd")

    def test_empty_identity_pair_is_rejected_before_any_process_starts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            certificate = root / "identity.cert.der"
            private_key = root / "identity.key.der"
            certificate.touch()
            private_key.touch(mode=0o600)
            with self.assertRaises(ValueError):
                validate_identity(certificate, private_key)


if __name__ == "__main__":
    unittest.main()
