from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "source_sanity.py"
SPEC = importlib.util.spec_from_file_location("source_sanity", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
source_sanity = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = source_sanity
SPEC.loader.exec_module(source_sanity)


class SourceSanityTests(unittest.TestCase):
    def test_target_specific_path_dependency_is_discovered(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Cargo.toml").write_text(
                '[workspace]\nmembers = ["apps/client", "crates/platform-windows"]\n',
                encoding="utf-8",
            )
            client = root / "apps" / "client"
            client.joinpath("src").mkdir(parents=True)
            client.joinpath("Cargo.toml").write_text(
                """[package]
name = "example-client"
version = "0.1.0"

[target.'cfg(windows)'.dependencies]
latencydesk-platform-windows = { path = "../../crates/platform-windows" }
""",
                encoding="utf-8",
            )
            client.joinpath("src", "lib.rs").write_text(
                "use latencydesk_platform_windows::NativeProvider;\n",
                encoding="utf-8",
            )

            platform = root / "crates" / "platform-windows"
            platform.joinpath("src").mkdir(parents=True)
            platform.joinpath("Cargo.toml").write_text(
                """[package]
name = "latencydesk-platform-windows"
version = "0.1.0"
""",
                encoding="utf-8",
            )
            platform.joinpath("src", "lib.rs").write_text(
                "pub struct NativeProvider;\n", encoding="utf-8"
            )

            with mock.patch.object(source_sanity, "ROOT", root):
                packages, failures = source_sanity.load_workspace()

            self.assertEqual(failures, [])
            client_package = next(
                package for package in packages if package.name == "example-client"
            )
            self.assertIn(
                "latencydesk-platform-windows", client_package.dependencies
            )
            self.assertEqual(
                client_package.path_dependencies,
                (("latencydesk-platform-windows", platform.resolve()),),
            )

    def test_fallback_parser_preserves_target_dependency_tables(self) -> None:
        parsed = source_sanity.parse_simple_manifest(
            """[package]
name = "fallback-client"

[target.'cfg(target_os = "linux")'.dependencies]
latencydesk-platform-linux = { path = "../../crates/platform-linux" }
"""
        )

        tables = source_sanity.dependency_tables(parsed)
        self.assertTrue(
            any("latencydesk-platform-linux" in table for table in tables), tables
        )


if __name__ == "__main__":
    unittest.main()
