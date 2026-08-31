from __future__ import annotations

import importlib.util
import socket
import sys
import time
import types
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "abrupt_reconnect_test.py"
sys.path.insert(0, str(SCRIPT.parent))
SPEC = importlib.util.spec_from_file_location("abrupt_reconnect_test", SCRIPT)
assert SPEC and SPEC.loader
mod = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)


class ProxyTests(unittest.TestCase):
    def test_proxy_forwards_then_drops_both_directions_and_resumes(self) -> None:
        target = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        target.bind(("127.0.0.1", 0))
        target.settimeout(1)
        proxy = mod.UdpForwardProxy(("127.0.0.1", 0), target.getsockname())
        client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        client.settimeout(1)
        proxy.start()
        try:
            client.sendto(b"one", proxy.address)
            self.assertEqual(target.recvfrom(32)[0], b"one")
            target.sendto(b"reply", proxy.address)
            self.assertEqual(client.recvfrom(32)[0], b"reply")
            proxy.set_drop(True)
            client.sendto(b"lost", proxy.address)
            time.sleep(0.15)
            self.assertGreater(proxy.dropped, 0)
            proxy.set_drop(False)
            client.sendto(b"again", proxy.address)
            self.assertEqual(target.recvfrom(32)[0], b"again")
            self.assertTrue(proxy.resumed)
            deadline = time.monotonic() + 1
            while proxy.forwarded_after_resume == 0 and time.monotonic() < deadline:
                time.sleep(0.005)
            self.assertGreater(proxy.forwarded_after_resume, 0)
        finally:
            client.close()
            proxy.close()
            target.close()


class ValidationTests(unittest.TestCase):
    def good(self) -> dict[str, object]:
        return {
            "proxy_dropped": 2,
            "proxy_forwarded_after_resume": 2,
            "proxy_resumed": True,
            "drop_triggered_after_desktop_stream": True,
            "identity_generation_ok": True,
            "transport_loss_logged": True,
            "host_transport_loss_logged": True,
            "reconnect_logged": True,
            "recovered_logged": True,
            "post_resume_reconnect_ms": 25.0,
            "host_session_ids": [1, 2],
            "client_session_ids": [1, 2],
            "lifecycle_advances": True,
            "release_all_between": True,
            "successor_frames_only": True,
            "desktop_streams": 2,
            "host_mtls": 2,
            "client_mtls": 2,
            "fallback_selected": True,
            "host_exit": 0,
            "client_exit": 0,
            "credentials_removed": True,
            "unsafe_flag": False,
        }

    def test_complete_evidence_passes(self) -> None:
        checks, errors = mod.validate_abrupt_result(self.good())
        self.assertFalse(errors)
        self.assertTrue(all(checks.values()))

    def test_missing_any_critical_marker_fails_closed(self) -> None:
        for key in (
            "proxy_dropped",
            "recovered_logged",
            "release_all_between",
            "fallback_selected",
        ):
            observation = self.good()
            observation[key] = 0 if key == "proxy_dropped" else False
            _, errors = mod.validate_abrupt_result(observation)
            self.assertTrue(errors, key)

    def test_matching_sessions_and_monotonic_epochs_are_required(self) -> None:
        observation = self.good()
        observation["client_session_ids"] = [1, 3]
        checks, _ = mod.validate_abrupt_result(observation)
        self.assertFalse(checks["two_matching_sessions"])

        observation = self.good()
        observation["post_resume_reconnect_ms"] = 2_001.0
        checks, _ = mod.validate_abrupt_result(observation)
        self.assertFalse(checks["post_resume_reconnect_within_target"])


class CommandTests(unittest.TestCase):
    def test_commands_use_proxy_fallback_and_safe_reconnect_flags(self) -> None:
        host, client = mod.build_abrupt_commands(
            host_bin=Path("host"),
            client_bin=Path("client"),
            listen_addr="127.0.0.1:4000",
            proxy_addr="127.0.0.1:4001",
            host_dir=Path("h"),
            client_dir=Path("c"),
        )
        self.assertIn("--max-sessions", host)
        self.assertIn("2", host)
        self.assertIn("--fallback-address", client)
        self.assertIn("--reconnect-attempts", client)
        self.assertEqual(host[host.index("--fps") + 1], "10")
        self.assertEqual(host[host.index("--max-width") + 1], "320")
        self.assertEqual(host[host.index("--max-height") + 1], "180")
        self.assertNotIn(mod.UNSAFE_FLAG, host + client)


class EvidenceExtractionTests(unittest.TestCase):
    def logs(self) -> tuple[str, str]:
        host = """mTLS: exact client certificate authenticated
session: active session_id=101
session-lifecycle: generation=1 authorization_epoch=1 display_epoch=1 codec_epoch=1 route_epoch=1
stream: H.264 4:2:0 320x180 over QUIC DATAGRAM
session: authenticated peer transport lost
input: ReleaseAll applied
listener: waiting for authenticated successor session
mTLS: exact client certificate authenticated
session: active session_id=202
session-lifecycle: generation=2 authorization_epoch=2 display_epoch=2 codec_epoch=2 route_epoch=1
stream: H.264 4:2:0 320x180 over QUIC DATAGRAM
input: ReleaseAll applied
"""
        client = """mTLS: exact host certificate authenticated
route: authenticated 127.0.0.1:4001 after racing 2 candidate(s)
handshake: active session_id=101
handshake-lifecycle: generation=1 authorization_epoch=1 display_epoch=1 codec_epoch=1 route_epoch=1
reconnect: recoverable transport loss, attempt 1/3 after 100ms
mTLS: exact host certificate authenticated
route: authenticated 127.0.0.1:4001 after racing 2 candidate(s)
handshake: active session_id=202
handshake-lifecycle: generation=2 authorization_epoch=2 display_epoch=2 codec_epoch=2 route_epoch=1
reconnect: recovered authenticated session after 1 attempt(s)
received: session_id=202 frames=3
"""
        return host, client

    def proxy(self):
        return types.SimpleNamespace(
            address=("127.0.0.1", 4001),
            dropped=20,
            forwarded=40,
            forwarded_after_resume=10,
            resumed=True,
        )

    def test_realistic_abrupt_logs_require_only_the_successor_frame_summary(
        self,
    ) -> None:
        host, client = self.logs()
        observation = mod.extract_evidence(
            host,
            client,
            self.proxy(),
            0,
            0,
            True,
            (["host"], ["client"]),
            3,
            True,
            25.0,
        )
        checks, errors = mod.validate_abrupt_result(observation)
        self.assertEqual(errors, [])
        self.assertTrue(all(checks.values()))
        self.assertEqual(observation["host_session_ids"], [101, 202])
        self.assertEqual(observation["client_session_ids"], [101, 202])

    def test_epoch_field_regression_wrong_route_and_late_release_fail(self) -> None:
        self.assertFalse(
            mod.lifecycles_strictly_advance([(1, 5, 5, 5, 1), (2, 6, 4, 6, 1)])
        )
        host, client = self.logs()
        host = host.replace(
            "input: ReleaseAll applied\nlistener: waiting",
            "listener: waiting",
            1,
        )
        client = client.replace("127.0.0.1:4001", "127.0.0.1:4999", 1)
        client = client.replace(
            "generation=2 authorization_epoch=2 display_epoch=2 codec_epoch=2",
            "generation=2 authorization_epoch=2 display_epoch=1 codec_epoch=2",
        )
        observation = mod.extract_evidence(
            host,
            client,
            self.proxy(),
            0,
            0,
            True,
            (["host"], ["client"]),
            3,
            True,
            25.0,
        )
        self.assertFalse(observation["release_all_between"])
        self.assertFalse(observation["fallback_selected"])
        self.assertFalse(observation["lifecycle_advances"])


if __name__ == "__main__":
    unittest.main()
