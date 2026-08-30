import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "multi_target_input_latency_test.py"
spec = importlib.util.spec_from_file_location("multi_target_input_latency_test", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def latency_line(target: str, session_id: int, latency_offset: int = 0) -> str:
    values = [10 + latency_offset, 20 + latency_offset, 30 + latency_offset, 40 + latency_offset]
    return (
        f"input-latency: target={target} session_id={session_id} generation=1 "
        "authorization_epoch=1 display_epoch=1 codec_epoch=1 samples=4 "
        f"min_us={values[0]} p50_us={values[1]} p95_us={values[3]} "
        f"p99_us={values[3]} max_us={values[3]} "
        f"mean_us={sum(values) // len(values)} raw_us="
        + ",".join(f"{index}:{value}" for index, value in enumerate(values, 1))
    )


def start_line(target: str, session_id: int) -> str:
    return (
        f"input-latency-start: target={target} session_id={session_id} generation=1 "
        "authorization_epoch=1 display_epoch=1 codec_epoch=1 samples=4"
    )


def stop_line(target: str, session_id: int) -> str:
    return (
        f"input-latency-stop: target={target} session_id={session_id} generation=1 "
        "authorization_epoch=1 display_epoch=1 codec_epoch=1 samples=4"
    )


class MultiTargetInputParsingTests(unittest.TestCase):
    def test_records_bind_target_full_lifecycle_and_raw_samples(self):
        output = "\n".join(
            [
                latency_line("127.0.0.1:4001", 11),
                latency_line("127.0.0.1:4002", 22, 5),
            ]
        )
        records = module.parse_probe_records(output)
        self.assertEqual([item["target"] for item in records], ["127.0.0.1:4001", "127.0.0.1:4002"])
        self.assertEqual(records[0]["stamp"], (11, 1, 1, 1, 1))
        self.assertEqual(len(records[1]["samples"]), 4)

    def test_duplicate_target_or_session_fails_closed(self):
        duplicate_target = "\n".join(
            [latency_line("127.0.0.1:4001", 11), latency_line("127.0.0.1:4001", 22)]
        )
        duplicate_session = "\n".join(
            [latency_line("127.0.0.1:4001", 11), latency_line("127.0.0.1:4002", 11)]
        )
        with self.assertRaises(ValueError):
            module.parse_probe_records(duplicate_target)
        with self.assertRaises(ValueError):
            module.parse_probe_records(duplicate_session)

    def test_overlap_requires_both_started_before_either_completed(self):
        expected = {"127.0.0.1:4001", "127.0.0.1:4002"}
        starts = "\n".join(
            [start_line("127.0.0.1:4001", 11), start_line("127.0.0.1:4002", 22)]
        )
        self.assertTrue(
            module.concurrent_probe_overlap(starts, expected, 4, True, [True, True])
        )
        self.assertFalse(
            module.concurrent_probe_overlap(
                starts + "\n" + stop_line("127.0.0.1:4001", 11),
                expected,
                4,
                True,
                [True, True],
            )
        )
        self.assertFalse(
            module.concurrent_probe_overlap(starts, expected, 4, False, [True, True])
        )


class MultiTargetInputValidationTests(unittest.TestCase):
    def test_target_requires_exact_host_stamp_certificate_stream_and_release(self):
        address = "127.0.0.1:4001"
        certificate = "a" * 64
        record = module.parse_probe_records(latency_line(address, 11))[0]
        start = module.parse_probe_starts(start_line(address, 11))[0]
        stop = module.parse_probe_stops(stop_line(address, 11))[0]
        host = (
            f"Host certificate: {certificate}\n"
            "mTLS: exact client certificate authenticated\n"
            "session: active session_id=11\n"
            "session-lifecycle: generation=1 authorization_epoch=1 "
            "display_epoch=1 codec_epoch=1\n"
            "stream: explicit Raw NV12 320x180 over QUIC DATAGRAM\n"
            "input: ReleaseAll applied\n"
        )
        checks, errors = module.validate_target_evidence(
            address,
            certificate,
            host,
            record,
            start,
            stop,
            0,
            False,
            4,
            100_000,
        )
        self.assertEqual(errors, [])
        self.assertTrue(all(checks.values()))

        wrong = dict(record)
        wrong["stamp"] = (11, 2, 1, 1, 1)
        checks, errors = module.validate_target_evidence(
            address,
            certificate,
            host,
            wrong,
            start,
            stop,
            0,
            False,
            4,
            100_000,
        )
        self.assertFalse(checks["full_stamp_matches_host"])
        self.assertTrue(errors)

    def test_global_evidence_requires_exact_sets_and_parent_success(self):
        addresses = {"127.0.0.1:4001", "127.0.0.1:4002"}
        output = "\n".join(
            [
                "mTLS: exact host certificate authenticated",
                "route: authenticated 127.0.0.1:4001 after racing 1 candidate(s)",
                "handshake: active session_id=11",
                "handshake-lifecycle: generation=1 authorization_epoch=1 display_epoch=1 codec_epoch=1",
                "mTLS: exact host certificate authenticated",
                "route: authenticated 127.0.0.1:4002 after racing 1 candidate(s)",
                "handshake: active session_id=22",
                "handshake-lifecycle: generation=1 authorization_epoch=1 display_epoch=1 codec_epoch=1",
                start_line("127.0.0.1:4001", 11),
                start_line("127.0.0.1:4002", 22),
                stop_line("127.0.0.1:4001", 11),
                stop_line("127.0.0.1:4002", 22),
                latency_line("127.0.0.1:4001", 11),
                latency_line("127.0.0.1:4002", 22, 5),
            ]
        )
        records = module.parse_probe_records(output)
        starts = module.parse_probe_starts(output)
        stops = module.parse_probe_stops(output)
        checks, errors = module.validate_global_evidence(
            output, records, starts, stops, addresses, 0, False, True, 4
        )
        self.assertEqual(errors, [])
        self.assertTrue(all(checks.values()))

        checks, errors = module.validate_global_evidence(
            output.replace("127.0.0.1:4002 after", "127.0.0.1:4999 after"),
            records,
            starts,
            stops,
            addresses,
            0,
            False,
            True,
            4,
        )
        self.assertFalse(checks["exact_routes"])
        self.assertTrue(errors)


class MultiTargetInputCliTests(unittest.TestCase):
    def test_commands_use_one_supervisor_and_two_distinct_pins(self):
        dirs = {
            "client": Path("private/client"),
            "host1": Path("private/host1"),
            "host2": Path("private/host2"),
        }
        hosts, parent = module.build_commands(
            Path("host"), Path("client"), (4001, 4002), dirs, 128
        )
        self.assertEqual(len(hosts), 2)
        self.assertEqual(parent.count("--target"), 2)
        self.assertEqual(parent[parent.index("--input-latency-probes") + 1], "128")
        targets = [parent[index + 1] for index, item in enumerate(parent) if item == "--target"]
        self.assertEqual(len(set(targets)), 2)
        self.assertFalse(module.secure.commands_contain_unsafe_flag([*hosts, parent]))


if __name__ == "__main__":
    unittest.main()
