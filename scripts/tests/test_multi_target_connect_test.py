import importlib.util
import unittest
from pathlib import Path
from unittest import mock

SCRIPT = Path(__file__).resolve().parents[1] / "multi_target_connect_test.py"
spec = importlib.util.spec_from_file_location("multi_target_connect_test", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class MultiTargetParsingTests(unittest.TestCase):
    def test_extracts_each_target_evidence(self):
        output = """mTLS: exact host certificate authenticated
route: authenticated 127.0.0.1:32001 after racing 1 candidate(s)
handshake: active session_id=11
received: session_id=11 frames=5
stream: explicit Raw NV12 320x180 over QUIC DATAGRAM
session: active session_id=11
"""
        evidence = module.parse_evidence(output)
        self.assertEqual(evidence["host_session_ids"], [11])
        self.assertEqual(evidence["received"], [(11, 5)])
        self.assertEqual(evidence["routes"], [("127.0.0.1:32001", 1)])
        self.assertEqual(evidence["desktop_streams"], 1)

    def test_concurrency_requires_both_alive_and_authenticated_markers(self):
        text = "mTLS: exact client certificate authenticated\nsession: active session_id=1\n"
        self.assertTrue(module.concurrent_markers([text, text], [True, True], True))
        self.assertFalse(module.concurrent_markers([text, text], [True, True], False))
        self.assertFalse(module.concurrent_markers([text, text], [True, False], True))
        self.assertFalse(module.concurrent_markers([text, ""], [True, True], True))


class MultiTargetValidationTests(unittest.TestCase):
    def test_phase_one_requires_exact_two_host_identity_sets(self):
        host1 = (
            "Host certificate: "
            + "a" * 64
            + "\nmTLS: exact client certificate authenticated\n"
            "session: active session_id=11\n"
            "stream: explicit Raw NV12 320x180 over QUIC DATAGRAM\n"
        )
        host2 = (
            "Host certificate: "
            + "b" * 64
            + "\nmTLS: exact client certificate authenticated\n"
            "session: active session_id=22\n"
            "stream: H.264 4:2:0 320x180 over QUIC DATAGRAM\n"
        )
        client = """mTLS: exact host certificate authenticated
route: authenticated 127.0.0.1:1 after racing 1 candidate(s)
handshake: active session_id=11
received: session_id=11 frames=5
mTLS: exact host certificate authenticated
route: authenticated 127.0.0.1:2 after racing 1 candidate(s)
handshake: active session_id=22
received: session_id=22 frames=5
"""
        checks, errors = module.validate_phase1(
            [host1, host2],
            client,
            [0, 0],
            [False, False],
            0,
            False,
            5,
            True,
            {"127.0.0.1:1", "127.0.0.1:2"},
            {"a" * 64, "b" * 64},
        )
        self.assertEqual(errors, [])
        self.assertTrue(all(checks.values()))

    def test_phase_one_fails_when_one_target_has_no_frames(self):
        host = "Host certificate: " + "a" * 64 + "\nmTLS: exact client certificate authenticated\nsession: active session_id=1\nstream: explicit Raw NV12 320x180 over QUIC DATAGRAM\n"
        checks, errors = module.validate_phase1(
            [host, host],
            "",
            [0, 0],
            [False, False],
            0,
            False,
            5,
            True,
            {"127.0.0.1:1", "127.0.0.1:2"},
            {"a" * 64, "b" * 64},
        )
        self.assertFalse(checks["both_requested_frames"])
        self.assertIn("both_requested_frames", errors)

    def test_phase_two_requires_failure_isolation_signals(self):
        output = "route: authenticated 127.0.0.1:1 after racing 1 candidate(s)\nhandshake: active session_id=2\nexact host certificate authenticated\nreceived: session_id=2 frames=5\n"
        host = "Host certificate: " + "a" * 64 + "\nmTLS: exact client certificate authenticated\nsession: active session_id=2\nstream: H.264 4:2:0 320x180 over QUIC DATAGRAM\n"
        output += "Error: target children failed: 127.0.0.1:1 exited with exit status: 1\n"
        checks, errors = module.validate_phase2(
            host,
            output,
            1,
            False,
            0,
            False,
            5,
            "127.0.0.1:1",
            "127.0.0.1:1",
            "a" * 64,
        )
        self.assertEqual(errors, [])
        self.assertTrue(all(checks.values()))
        checks, errors = module.validate_phase2(
            "",
            "",
            0,
            False,
            0,
            False,
            5,
            "127.0.0.1:2",
            "127.0.0.1:1",
            "a" * 64,
        )
        self.assertTrue(errors)


class MultiTargetCliTests(unittest.TestCase):
    def test_commands_use_distinct_pins_and_short_bounded_failure_phase(self):
        dirs = {
            "client": Path("private/client"),
            "host1": Path("private/host1"),
            "host2": Path("private/host2"),
        }
        host1, host2, valid, bad = module.build_commands(
            Path("host"), Path("client"), (4001, 4002), dirs, 5, 10, 320, 180
        )
        self.assertNotEqual(
            valid[valid.index("--target") + 1],
            valid[valid.index("--target", valid.index("--target") + 1) + 1],
        )
        self.assertEqual(bad[bad.index("--pairing-timeout") + 1], "8")
        self.assertNotIn(module.secure.UNSAFE_FLAG, host1 + host2 + valid + bad)

    def test_accepts_explicit_binaries_and_output(self):
        args = module.parse_args(["--host-binary", "/h", "--client-binary", "/c", "--identity-binary", "/i", "--output", "/o", "--frames", "5"])
        self.assertEqual(args.host_binary, Path("/h"))
        self.assertEqual(args.frames, 5)

    def test_platform_skip_is_fail_safe(self):
        self.assertIsNotNone(module.secure.prerequisite_skip_reason("darwin", ":0"))
        with (
            mock.patch.object(
                module.secure,
                "prerequisite_skip_reason",
                return_value="Linux X11 required",
            ),
            mock.patch.object(module.secure, "write_report") as write_report,
            mock.patch("builtins.print"),
        ):
            self.assertEqual(module.main(["--output", "ignored.json"]), 0)
        report = write_report.call_args.args[1]
        self.assertEqual(report["status"], "skipped")
        self.assertFalse(report["ok"])


if __name__ == "__main__":
    unittest.main()
