from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "remote_connect_test.py"
SPEC = importlib.util.spec_from_file_location("remote_connect_test", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
remote_connect_test = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(remote_connect_test)


def successful_case(name: str, session_id: str = "session-1") -> dict[str, object]:
    return {
        "name": name,
        "transport_mode": "unsafe_udp_lab",
        "security": "plaintext",
        "network_scope": "localhost_only",
        "real_lan": False,
        "host_exit": 0,
        "client_exit": 0,
        "host_handshake": session_id,
        "client_handshake": session_id,
        "client_frames": 8,
        "ok": True,
        "error": None,
    }


class ValidateCaseResultTests(unittest.TestCase):
    def validate(self, **overrides: object) -> str | None:
        values: dict[str, object] = {
            "name": "loopback",
            "host_exit": 0,
            "client_exit": 0,
            "host_handshake": "session-1",
            "client_handshake": "session-1",
            "received_frames": 8,
            "requested_frames": 8,
            "killed": False,
            "runtime_error": None,
        }
        values.update(overrides)
        return remote_connect_test.validate_case_result(**values)

    def test_matching_session_ids_pass(self) -> None:
        self.assertIsNone(self.validate())

    def test_missing_session_id_fails(self) -> None:
        error = self.validate(client_handshake=None)
        self.assertIsNotNone(error)
        self.assertIn("missing client handshake", error)

    def test_mismatched_session_ids_fail_with_both_values(self) -> None:
        error = self.validate(client_handshake="session-2")
        self.assertIsNotNone(error)
        self.assertIn("session id mismatch host=session-1 client=session-2", error)

    def test_multiple_failures_are_reported_together(self) -> None:
        error = self.validate(client_exit=3, received_frames=2)
        self.assertIsNotNone(error)
        self.assertIn("nonzero exit host=0 client=3", error)
        self.assertIn("client_frames=2 < requested 8", error)


class FinalizeReportTests(unittest.TestCase):
    def test_all_selected_cases_must_pass(self) -> None:
        loopback = successful_case("loopback")
        wildcard = successful_case("wildcard-bind-loopback")
        wildcard.update(
            {
                "ok": False,
                "error": "wildcard-bind-loopback: connection failed",
            }
        )
        report: dict[str, object] = {}

        ok = remote_connect_test.finalize_report(report, [loopback, wildcard])

        self.assertFalse(ok)
        self.assertIs(report["ok"], False)
        self.assertEqual(
            report["error"], "wildcard-bind-loopback: connection failed"
        )
        self.assertEqual(report["transport_mode"], "unsafe_udp_lab")
        self.assertEqual(report["security"], "plaintext")
        self.assertIs(report["real_lan"], False)

    def test_all_selected_cases_success_clears_error(self) -> None:
        report: dict[str, object] = {"error": "stale error"}

        ok = remote_connect_test.finalize_report(
            report,
            [
                successful_case("loopback"),
                successful_case("wildcard-bind-loopback"),
            ],
        )

        self.assertTrue(ok)
        self.assertIs(report["ok"], True)
        self.assertIsNone(report["error"])

    def test_no_cases_is_a_clear_failure(self) -> None:
        report: dict[str, object] = {}

        ok = remote_connect_test.finalize_report(report, [])

        self.assertFalse(ok)
        self.assertIs(report["ok"], False)
        self.assertEqual(report["error"], "no connection cases were selected")


class CommandConstructionTests(unittest.TestCase):
    def test_commands_explicitly_select_plaintext_lab_transport(self) -> None:
        host_cmd, client_cmd = remote_connect_test.build_case_commands(
            host_bin=Path("host.exe"),
            client_bin=Path("client.exe"),
            listen_addr="0.0.0.0:9000",
            connect_addr="127.0.0.1:9000",
            host_frames=4,
            client_frames=4,
            fps=30,
            shared_secret=None,
            extra_host=[],
            extra_client=[],
        )

        self.assertIn("--unsafe-udp-lab", host_cmd)
        self.assertIn("--unsafe-udp-lab", client_cmd)
        self.assertEqual(
            client_cmd[client_cmd.index("--connect") + 1], "127.0.0.1:9000"
        )


class ModeNamingTests(unittest.TestCase):
    def test_legacy_lan_bind_alias_maps_to_explicit_loopback_name(self) -> None:
        self.assertEqual(
            remote_connect_test.canonical_mode("lan-bind"),
            "wildcard-bind-loopback",
        )

    def test_explicit_mode_name_is_stable(self) -> None:
        self.assertEqual(
            remote_connect_test.canonical_mode("wildcard-bind-loopback"),
            "wildcard-bind-loopback",
        )


class MainExitTests(unittest.TestCase):
    def run_main_with(
        self, results: list[dict[str, object]]
    ) -> tuple[int, dict[str, object]]:
        with (
            mock.patch.object(
                remote_connect_test, "find_binary", return_value=Path("binary")
            ),
            mock.patch.object(remote_connect_test, "run_case", side_effect=results),
            mock.patch.object(remote_connect_test, "write_report") as write_report,
            mock.patch.object(sys, "argv", [str(SCRIPT), "--mode", "both"]),
            mock.patch("builtins.print"),
        ):
            exit_code = remote_connect_test.main()
        report = write_report.call_args.args[1]
        return exit_code, report

    def test_wildcard_bind_loopback_failure_exits_nonzero(self) -> None:
        wildcard = successful_case("wildcard-bind-loopback")
        wildcard.update(
            {
                "ok": False,
                "error": "wildcard-bind-loopback: connection failed",
            }
        )

        exit_code, report = self.run_main_with(
            [successful_case("loopback"), wildcard]
        )

        self.assertEqual(exit_code, 1)
        self.assertIs(report["ok"], False)
        self.assertEqual(
            report["error"], "wildcard-bind-loopback: connection failed"
        )

    def test_all_cases_success_exits_zero(self) -> None:
        exit_code, report = self.run_main_with(
            [
                successful_case("loopback"),
                successful_case("wildcard-bind-loopback"),
            ]
        )

        self.assertEqual(exit_code, 0)
        self.assertIs(report["ok"], True)
        self.assertIsNone(report["error"])


if __name__ == "__main__":
    unittest.main()
