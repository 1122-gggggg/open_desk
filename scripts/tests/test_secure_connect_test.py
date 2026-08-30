from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "secure_connect_test.py"
SPEC = importlib.util.spec_from_file_location("secure_connect_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
secure_connect_test = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(secure_connect_test)


def valid_result(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "identity_generation_ok": True,
        "host_ready": True,
        "rogue_exit": 1,
        "rogue_timed_out": False,
        "rogue_rejection_logged": True,
        "rogue_session_id": None,
        "host_survived_rogue": True,
        "host_exit": 0,
        "host_timed_out": False,
        "client_exit": 0,
        "client_timed_out": False,
        "host_shutdown_requested": True,
        "host_graceful_shutdown_log": True,
        "host_peer_completed_log": False,
        "host_exact_mtls_log": True,
        "client_exact_mtls_log": True,
        "client_fallback_selected": True,
        "host_desktop_stream_log": True,
        "first_session_completed": True,
        "host_survived_first_session": True,
        "successor_session_distinct": True,
        "release_all_between_sessions": True,
        "host_session_id": 73,
        "client_session_id": 73,
        "received_session_id": 73,
        "received_frames": 8,
        "requested_frames": 8,
        "unsafe_flag_present": False,
        "temporary_credentials_removed": True,
        "runtime_error": None,
    }
    values.update(overrides)
    return values


class OutputParsingTests(unittest.TestCase):
    def test_parses_role_specific_product_session_logs(self) -> None:
        host = "prefix\nsession: active session_id=9123\n"
        client = "handshake: active session_id=9123\n"

        self.assertEqual(secure_connect_test.parse_host_session_id(host), 9123)
        self.assertEqual(secure_connect_test.parse_client_session_id(client), 9123)

    def test_parses_successor_session_ids_and_monotonic_lifecycle(self) -> None:
        output = """session: active session_id=41
session-lifecycle: generation=1 authorization_epoch=1 display_epoch=1 codec_epoch=1
session: active session_id=42
session-lifecycle: generation=2 authorization_epoch=2 display_epoch=2 codec_epoch=2
"""
        self.assertEqual(secure_connect_test.parse_host_session_ids(output), [41, 42])
        self.assertEqual(
            secure_connect_test.parse_host_lifecycles(output),
            [(1, 1, 1, 1), (2, 2, 2, 2)],
        )
        client_output = """handshake: active session_id=41
received: session_id=41 frames=3
handshake: active session_id=42
received: session_id=42 frames=3
"""
        self.assertEqual(
            secure_connect_test.parse_client_session_ids(client_output), [41, 42]
        )
        self.assertEqual(
            secure_connect_test.parse_received_all(client_output), [(41, 3), (42, 3)]
        )

    def test_counts_only_explicit_linux_desktop_stream_announcements(self) -> None:
        output = """stream: H.264 4:2:0 224x180 over QUIC DATAGRAM
stream: explicit Raw NV12 320x180 over QUIC DATAGRAM
stream: unverified 320x180 over QUIC DATAGRAM
"""
        self.assertEqual(secure_connect_test.parse_host_desktop_streams(output), 2)

    def test_does_not_accept_legacy_or_malformed_session_logs(self) -> None:
        self.assertIsNone(
            secure_connect_test.parse_host_session_id(
                "handshake: active session_id=legacy-session"
            )
        )
        self.assertIsNone(
            secure_connect_test.parse_client_session_id(
                "session: active session_id=9"
            )
        )

    def test_parses_completed_frames_and_their_session(self) -> None:
        self.assertEqual(
            secure_connect_test.parse_received(
                "received: session_id=44 frames=1\nreceived: session_id=44 frames=8\n"
            ),
            (44, 8),
        )
        self.assertEqual(secure_connect_test.parse_received("no summary"), (None, 0))

    def test_parses_authenticated_fallback_route(self) -> None:
        self.assertEqual(
            secure_connect_test.parse_client_route(
                "route: authenticated 127.0.0.1:34567 after racing 2 candidate(s)\n"
            ),
            ("127.0.0.1:34567", 2),
        )
        self.assertEqual(secure_connect_test.parse_client_route("no route"), (None, 0))

    def test_sensitive_temporary_path_is_redacted(self) -> None:
        root = Path("/tmp/private-smoke")
        text = f"failed reading {root}/host/{secure_connect_test.PRIVATE_KEY_FILE}"
        sanitized = secure_connect_test.sanitize_log(text, root)

        self.assertNotIn(str(root), sanitized)
        self.assertNotIn("/host/identity.key.der", sanitized)
        self.assertIn("[secure-temp]", sanitized)


class FailClosedValidationTests(unittest.TestCase):
    def validate(self, **overrides: object):
        return secure_connect_test.validate_secure_result(**valid_result(**overrides))

    def test_complete_secure_result_passes(self) -> None:
        checks, errors = self.validate()

        self.assertEqual(errors, [])
        self.assertTrue(all(checks.values()))

    def test_missing_mtls_logs_fail_even_with_zero_exits(self) -> None:
        checks, errors = self.validate(
            host_exact_mtls_log=False, client_exact_mtls_log=False
        )

        self.assertFalse(checks["host_exact_mtls_log"])
        self.assertFalse(checks["client_exact_mtls_log"])
        self.assertTrue(any("host exact-certificate" in error for error in errors))
        self.assertTrue(any("client exact-certificate" in error for error in errors))

    def test_valid_client_must_win_through_the_authenticated_fallback(self) -> None:
        checks, errors = self.validate(client_fallback_selected=False)

        self.assertFalse(checks["client_fallback_selected"])
        self.assertTrue(any("fallback" in error for error in errors))

    def test_two_real_desktop_stream_announcements_are_required(self) -> None:
        checks, errors = self.validate(host_desktop_stream_log=False)

        self.assertFalse(checks["host_desktop_stream_log"])
        self.assertTrue(any("desktop stream" in error for error in errors))

    def test_successor_requires_first_cleanup_and_distinct_session(self) -> None:
        checks, errors = self.validate(
            first_session_completed=False,
            host_survived_first_session=False,
            successor_session_distinct=False,
            release_all_between_sessions=False,
        )
        for name in (
            "first_session_completed",
            "host_survived_first_session",
            "successor_session_distinct",
            "release_all_between_sessions",
        ):
            self.assertFalse(checks[name])
        self.assertGreaterEqual(len(errors), 4)

    def test_rogue_must_exit_itself_before_product_session(self) -> None:
        checks, errors = self.validate(rogue_timed_out=True, rogue_session_id=73)

        self.assertFalse(checks["rogue_client_rejected"])
        self.assertTrue(any("rogue client" in error for error in errors))

    def test_host_must_survive_rogue_attempt(self) -> None:
        checks, errors = self.validate(host_survived_rogue=False)

        self.assertFalse(checks["host_survived_rogue"])
        self.assertTrue(any("remain alive" in error for error in errors))

    def test_normal_peer_completion_wins_shutdown_race_cleanly(self) -> None:
        checks, errors = self.validate(
            host_shutdown_requested=False,
            host_graceful_shutdown_log=False,
            host_peer_completed_log=True,
        )

        self.assertTrue(checks["host_graceful_shutdown"])
        self.assertEqual(errors, [])

    def test_missing_both_clean_shutdown_paths_fails(self) -> None:
        checks, errors = self.validate(
            host_shutdown_requested=False,
            host_graceful_shutdown_log=False,
            host_peer_completed_log=False,
        )

        self.assertFalse(checks["host_graceful_shutdown"])
        self.assertTrue(any("Ctrl-C shutdown" in error for error in errors))

    def test_session_mismatch_and_zero_are_rejected(self) -> None:
        checks, errors = self.validate(client_session_id=0, received_session_id=0)

        self.assertFalse(checks["product_session_nonzero"])
        self.assertFalse(checks["product_session_ids_match"])
        self.assertTrue(any("ProductSession ID mismatch" in error for error in errors))

    def test_missing_frames_fail(self) -> None:
        checks, errors = self.validate(received_frames=7)

        self.assertFalse(checks["requested_frames_received"])
        self.assertTrue(any("received 7" in error for error in errors))

    def test_unsafe_flag_or_uncleaned_credentials_fail(self) -> None:
        checks, errors = self.validate(
            unsafe_flag_present=True, temporary_credentials_removed=False
        )

        self.assertFalse(checks["no_unsafe_transport_flag"])
        self.assertFalse(checks["temporary_credentials_removed"])
        self.assertGreaterEqual(len(errors), 2)


class CommandConstructionTests(unittest.TestCase):
    def test_secure_commands_have_required_flags_and_never_unsafe_flag(self) -> None:
        host, rogue, client = secure_connect_test.build_secure_commands(
            host_bin=Path("latencydesk-host"),
            client_bin=Path("latencydesk-client"),
            listen_addr="127.0.0.1:34567",
            valid_primary_addr="127.0.0.1:34568",
            host_dir=Path("identities/host"),
            client_dir=Path("identities/client"),
            rogue_dir=Path("identities/rogue"),
            host_frames=16,
            client_frames=8,
            fps=15,
            max_width=640,
            max_height=360,
            host_pairing_timeout=30,
            rogue_pairing_timeout=5,
            valid_pairing_timeout=15,
        )

        self.assertFalse(
            secure_connect_test.commands_contain_unsafe_flag((host, rogue, client))
        )
        for command in (host, rogue, client):
            self.assertIn("--identity-cert", command)
            self.assertIn("--identity-key", command)
            self.assertIn("--peer-cert", command)
            self.assertIn("--pairing-timeout", command)
        self.assertIn("--max-width", host)
        self.assertIn("--max-height", host)
        self.assertIn("--fps", host)
        self.assertEqual(host[host.index("--frames") + 1], "16")
        self.assertEqual(host[host.index("--max-sessions") + 1], "2")
        self.assertEqual(rogue.count("--frames"), 1)
        self.assertEqual(rogue[rogue.index("--frames") + 1], "1")
        self.assertEqual(client[client.index("--frames") + 1], "8")
        self.assertEqual(client[client.index("--session-count") + 1], "2")
        self.assertEqual(client[client.index("--connect") + 1], "127.0.0.1:34568")
        self.assertEqual(
            client[client.index("--fallback-address") + 1], "127.0.0.1:34567"
        )

    def test_rogue_uses_rogue_identity_but_correct_host_pin(self) -> None:
        _, rogue, _ = secure_connect_test.build_secure_commands(
            host_bin=Path("host"),
            client_bin=Path("client"),
            listen_addr="127.0.0.1:9",
            valid_primary_addr="127.0.0.1:10",
            host_dir=Path("host-id"),
            client_dir=Path("client-id"),
            rogue_dir=Path("rogue-id"),
            host_frames=9,
            client_frames=1,
            fps=1,
            max_width=2,
            max_height=2,
            host_pairing_timeout=30,
            rogue_pairing_timeout=5,
            valid_pairing_timeout=15,
        )

        self.assertEqual(
            rogue[rogue.index("--identity-cert") + 1],
            str(Path("rogue-id") / secure_connect_test.CERTIFICATE_FILE),
        )
        self.assertEqual(
            rogue[rogue.index("--peer-cert") + 1],
            str(Path("host-id") / secure_connect_test.CERTIFICATE_FILE),
        )

    def test_timeout_budget_keeps_valid_attempt_inside_host_total(self) -> None:
        ready, rogue, valid = secure_connect_test.timeout_budgets(30)

        self.assertLessEqual(ready + rogue + valid + 5, 30)
        self.assertGreaterEqual(valid, 5)

    def test_host_frame_limit_is_larger_than_client_requirement(self) -> None:
        self.assertEqual(secure_connect_test.host_frame_limit(3), 11)
        self.assertEqual(secure_connect_test.host_frame_limit(20), 40)

    def test_fallback_smoke_reserves_two_distinct_udp_ports(self) -> None:
        first, second = secure_connect_test.pick_distinct_free_udp_ports()
        self.assertNotEqual(first, second)
        self.assertGreater(first, 0)
        self.assertGreater(second, 0)


class PlatformGateTests(unittest.TestCase):
    def test_windows_main_skips_without_finding_binaries_or_running_e2e(self) -> None:
        with (
            mock.patch.object(secure_connect_test.sys, "platform", "win32"),
            mock.patch.object(secure_connect_test, "find_binary") as find_binary,
            mock.patch.object(secure_connect_test, "run_secure_smoke") as run_e2e,
            mock.patch.object(secure_connect_test, "write_report") as write_report,
            mock.patch("builtins.print"),
        ):
            exit_code = secure_connect_test.main(["--output", "ignored.json"])

        self.assertEqual(exit_code, 0)
        find_binary.assert_not_called()
        run_e2e.assert_not_called()
        report = write_report.call_args.args[1]
        self.assertEqual(report["status"], "skipped")
        self.assertIs(report["ok"], False)
        self.assertIs(report["executed"], False)
        self.assertIs(report["real_desktop_capture"], False)
        self.assertEqual(report["source"]["binary_sha256_proves_revision"], False)

    def test_linux_without_display_is_explicitly_skipped(self) -> None:
        self.assertIsNotNone(
            secure_connect_test.prerequisite_skip_reason("linux", "")
        )
        self.assertIsNone(
            secure_connect_test.prerequisite_skip_reason("linux", ":99")
        )


if __name__ == "__main__":
    unittest.main()
