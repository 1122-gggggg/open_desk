import io
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path

from scripts.route_promotion_process_test import (
    parse,
    parse_result,
    validate_identity,
    verify_native_binary,
)


class RoutePromotionParserTests(unittest.TestCase):
    def args(self, *extra: str):
        return parse(
            [
                "--binary",
                "probe",
                "--identity-bin",
                "identity",
                "--output",
                "artifact.json",
                *extra,
            ]
        )

    def test_bounded_defaults(self):
        self.assertEqual(self.args().timeout, 15)

    def test_timeout_override_and_bounds(self):
        self.assertEqual(self.args("--timeout", "3").timeout, 3)
        with redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                self.args("--timeout", "2")

    def test_result_requires_exact_role_and_fields(self):
        line = (
            "route-probe-result role=server exact_mtls=true paths=2 "
            "promoted_epoch=2 rollback_epoch=3 active_index=0 active_failure=true input=true "
            f"media=true control=true clean=true peer_challenge_sha256={'a' * 64}"
        )
        parsed = parse_result(line, "server")
        self.assertEqual(parsed["rollback_epoch"], 3)
        self.assertTrue(parsed["exact_mtls"])
        with self.assertRaises(ValueError):
            parse_result(line, "client")
        with self.assertRaises(ValueError):
            parse_result(line + "\n" + line, "server")

    def test_marker_only_shell_and_empty_identity_are_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fake = root / "latencydesk-route-probe"
            fake.write_text("#!/bin/sh\necho marker-only\n", encoding="utf-8")
            fake.chmod(0o755)
            with self.assertRaises(ValueError):
                verify_native_binary(fake, "latencydesk-route-probe")
            certificate = root / "identity.cert.der"
            private_key = root / "identity.key.der"
            certificate.touch()
            private_key.touch(mode=0o600)
            with self.assertRaises(ValueError):
                validate_identity(certificate, private_key)


if __name__ == "__main__":
    unittest.main()
