import importlib.util
import io
import unittest
from contextlib import redirect_stderr
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "multi_target_cancel_test.py"
spec = importlib.util.spec_from_file_location("multi_target_cancel_test", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def valid_output() -> str:
    lines = []
    for index in range(1, 5):
        lines.append(
            f"multi-target: spawned target=127.0.0.1:{9000 + index} pid={100 + index}"
        )
    for index in range(1, 5):
        lines.append(
            "input-latency-start: "
            f"target=127.0.0.1:{9000 + index} session_id={index} "
            "generation=1 authorization_epoch=1 display_epoch=1 codec_epoch=1 "
            "route_epoch=1 samples=1024"
        )
    lines.extend(
        [
            "multi-target: cancellation requested targets=4",
            "multi-target: completed reaped=4 forwarders_joined=8",
            "Error: target children failed: multi-target supervisor cancelled "
            "reaped=4 forwarders_joined=8",
        ]
    )
    return "\n".join(lines) + "\n"


class MultiTargetCancelParsingTests(unittest.TestCase):
    def setUp(self):
        self.targets = {f"127.0.0.1:{9000 + index}" for index in range(1, 5)}

    def test_precancel_and_final_records_are_exact(self):
        output = valid_output()
        prefix = output.split("multi-target: cancellation requested", 1)[0]
        spawned, starts = module.parse_precancel_state(prefix, self.targets)
        self.assertEqual(len(spawned), 4)
        self.assertEqual(len(starts), 4)
        _, _, result = module.parse_final_events(output, self.targets)
        self.assertEqual(
            result,
            {"cancelled_targets": 4, "reaped": 4, "forwarders_joined": 8},
        )

    def test_spawn_records_reject_malformed_duplicates_and_target_mismatch(self):
        output = valid_output()
        malformed = output.replace("pid=101", "pid=bad")
        duplicate = output.replace(
            "target=127.0.0.1:9004 pid=104",
            "target=127.0.0.1:9003 pid=103",
        )
        for candidate in (malformed, duplicate):
            with self.assertRaises(ValueError):
                module.parse_spawn_events(candidate)
        with self.assertRaises(ValueError):
            module.parse_precancel_state(output, {"127.0.0.1:1"})

    def test_precancel_rejects_stop_result_or_nonpositive_stamp(self):
        base = valid_output().split("multi-target: cancellation requested", 1)[0]
        cases = [
            base + "input-latency-stop: target=127.0.0.1:9001\n",
            base + "input-latency: target=127.0.0.1:9001 raw_us=1:1\n",
            base.replace("session_id=1 ", "session_id=0 ", 1),
        ]
        for candidate in cases:
            with self.assertRaises(ValueError):
                module.parse_precancel_state(candidate, self.targets)

    def test_final_rejects_missing_duplicate_or_wrong_counters(self):
        base = valid_output()
        cases = [
            base.replace("cancellation requested targets=4\n", ""),
            base.replace(
                "multi-target: cancellation requested targets=4\n",
                "multi-target: cancellation requested targets=4\n" * 2,
            ),
            base.replace("targets=4", "targets=3", 1),
            base.replace("reaped=4", "reaped=3", 1),
            base.replace("forwarders_joined=8", "forwarders_joined=7", 1),
            base.replace(module.CANCELLATION_ERROR_MARKER, "cancelled"),
        ]
        for candidate in cases:
            with self.assertRaises(ValueError):
                module.parse_final_events(candidate, self.targets)

    def test_timeout_is_bounded(self):
        args = module.parse_args(["--timeout", "120"])
        self.assertEqual(args.timeout, 120)
        with self.assertRaises(SystemExit), redirect_stderr(io.StringIO()):
            module.parse_args(["--timeout", "121"])


if __name__ == "__main__":
    unittest.main()
