import importlib.util
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "stun_same_socket_test.py"
spec = importlib.util.spec_from_file_location("stun_same_socket_test", SCRIPT)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class StunWireTests(unittest.TestCase):
    def test_binding_request_fingerprint_and_success_xor_mapping(self):
        transaction = bytes(range(1, 13))
        request = module.encode_binding_request(transaction)
        self.assertEqual(module.parse_binding_request(request), transaction)
        tampered = bytearray(request)
        tampered[8] ^= 1
        with self.assertRaises(ValueError):
            module.parse_binding_request(bytes(tampered))

        response = module.encode_binding_success(
            transaction, ("203.0.113.7", 54321)
        )
        parsed = module.parse_binding_success(response, transaction)
        self.assertEqual(parsed, ("203.0.113.7", 54321))

    def test_wire_parser_rejects_wrong_cookie_type_length_and_transaction(self):
        transaction = b"t" * 12
        valid = module.encode_binding_request(transaction)
        for mutation in ("cookie", "type", "length"):
            message = bytearray(valid)
            if mutation == "cookie":
                message[4] ^= 1
            elif mutation == "type":
                message[1] ^= 1
            else:
                message[3] ^= 4
            with self.assertRaises(ValueError):
                module.parse_binding_request(bytes(message))
        response = module.encode_binding_success(transaction, ("127.0.0.1", 4000))
        with self.assertRaises(ValueError):
            module.parse_binding_success(response, b"x" * 12)


class StunEvidenceParsingTests(unittest.TestCase):
    def test_host_listen_address_must_be_one_real_loopback_port(self):
        self.assertEqual(
            module.parse_host_listen_address("Listening securely on 127.0.0.1:41234\n"),
            "127.0.0.1:41234",
        )
        for invalid in ("", "Listening securely on 127.0.0.1:0\n"):
            with self.assertRaises(ValueError):
                module.parse_host_listen_address(invalid)
        self.assertEqual(
            module.parse_host_peer_source("quic-peer: source=127.0.0.1:45678\n"),
            "127.0.0.1:45678",
        )

    def test_client_log_requires_one_exact_same_socket_record(self):
        output = (
            "Local Binding Address: 127.0.0.1:45678\n"
            "stun: server=127.0.0.1:3478 local=127.0.0.1:45678 "
            "reflexive=127.0.0.1:45678 requests=1 ignored=0 drained=0 elapsed_ms=2\n"
            "stun-scope: candidate discovery only; exact-certificate mTLS remains mandatory\n"
        )
        parsed = module.parse_client_stun(output)
        self.assertEqual(parsed["local"], "127.0.0.1:45678")
        self.assertEqual(parsed["reflexive"], parsed["local"])
        self.assertEqual(parsed["requests"], 1)

        with self.assertRaises(ValueError):
            module.parse_client_stun(output + output)

    def test_commands_are_secure_and_use_one_explicit_stun_server(self):
        host, client = module.build_commands(
            Path("host"),
            Path("client"),
            "127.0.0.1:9000",
            "127.0.0.1:3478",
            Path("ids/host"),
            Path("ids/client"),
            3,
        )
        self.assertEqual(client.count("--stun-server"), 1)
        self.assertEqual(client[client.index("--stun-server") + 1], "127.0.0.1:3478")
        self.assertNotIn(module.secure.UNSAFE_FLAG, host + client)


if __name__ == "__main__":
    unittest.main()
