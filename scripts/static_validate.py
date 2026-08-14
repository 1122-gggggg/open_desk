#!/usr/bin/env python3
"""Dependency-free structural validation for the LatencyDesk repository."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import re
try:
    import tomllib
except ModuleNotFoundError:
    try:
        import tomli as tomllib
    except ModuleNotFoundError:
        tomllib = None
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts" / "static-validation.json"

REQUIRED = [
    "Cargo.toml",
    "README.md",
    "README.zh-TW.md",
    "SECURITY.md",
    "LICENSE-APACHE",
    "LICENSE-MIT",
    "docs/TECHNICAL_AUDIT.md",
    "docs/ROADMAP.md",
    "docs/PROTOCOL.md",
    "docs/BENCHMARKING.md",
    "docs/THREAT_MODEL.md",
    "docs/M1_LOOPBACK_LAB.md",
    "docs/adr/0001-surface-ownership.md",
    "docs/status/M2_FOUNDATION.md",
    "crates/protocol/src/lib.rs",
    "crates/frame/src/lib.rs",
    "crates/codec/src/lib.rs",
    "crates/input/src/lib.rs",
    "crates/transport/src/lib.rs",
    "crates/test-codec/src/lib.rs",
    "crates/testkit/src/lib.rs",
    "crates/session/src/lib.rs",
    "crates/media/src/lib.rs",
    "crates/scheduler/src/lib.rs",
    "crates/telemetry/src/lib.rs",
    "apps/lab/src/main.rs",
    "apps/stress/src/main.rs",
    "scripts/reference_lab.py",
    "scripts/udp_reference.py",
    "scripts/surface_reference.py",
    "scripts/source_sanity.py",
    "docs/status/M2.md",
    "crates/surface/src/lib.rs",
    "crates/platform/src/lib.rs",
    "crates/socket-transport/src/lib.rs",
    "crates/h264/src/lib.rs",
    "crates/platform-windows/src/lib.rs",
    "crates/platform-linux/src/lib.rs",
    "native/common/media_wire.hpp",
    "native/tests/protocol_conformance.cpp",
    "scripts/ffmpeg_h264_probe.py",
]

REQUIRED_PHRASES = {
    "docs/TECHNICAL_AUDIT.md": [
        "capture lease",
        "copy fallback",
        "decoder continuity",
        "Wayland",
        "unattended",
        "protected content",
    ],
    "docs/PROTOCOL.md": [
        "QUIC DATAGRAM",
        "codec_epoch",
        "dependency_frame_id",
        "bounded",
    ],
    "docs/BENCHMARKING.md": [
        "p50",
        "p95",
        "p99",
        "optical",
        "clock domain",
    ],
    "docs/M1_LOOPBACK_LAB.md": [
        "reassembly",
        "input reconciliation",
        "reference_lab.py",
        "cargo test",
    ],
}

SOURCE_GUARDS = {
    "crates/protocol/src/lib.rs": [
        "MAX_FRAME_BYTES",
        "checked_add",
        "ReservedBits",
        "KeyframeHasDependency",
        "ControlPacket",
    ],
    "crates/transport/src/lib.rs": [
        "max_fragment_entries",
        "reserved_bytes",
        "FragmentOverlap",
        "deadline_ns",
        "NetworkSimulator",
    ],
    "crates/input/src/lib.rs": [
        "InputReconciler",
        "pub fn disconnect",
        "Snapshot",
        "IgnoredStaleSequence",
        "IgnoredStaleEpoch",
    ],
    "crates/media/src/lib.rs": [
        "CopyLedger",
        "DirectAlias",
        "ProfilerVerifiedNoApplicationCopy",
        "validate_capture_source",
    ],
    "crates/test-codec/src/lib.rs": [
        "MAX_ENCODED_BYTES",
        "Checksum",
        "DecodedLength",
    ],
    "crates/surface/src/lib.rs": [
        "SurfacePool",
        "CaptureLease",
        "OwnedSurface",
        "PoolExhausted",
        "CopyLedger",
        "validate_capture_source",
    ],
    "crates/socket-transport/src/lib.rs": [
        "UdpEndpoint",
        "DEFAULT_MAX_SOCKET_DATAGRAM",
        "receive",
    ],
    "crates/h264/src/lib.rs": [
        "inspect_annex_b",
        "BFrameDetected",
        "continuity_meta",
        "LowDelayPolicy",
    ],
    "crates/platform-windows/src/lib.rs": [
        "DesktopDuplication",
        "WindowsGraphicsCapture",
        "DenySecureDesktop",
        "PerUserAgentBroker",
        "LedgerEpoch",
        "copy_ledger",
    ],
    "crates/platform-linux/src/lib.rs": [
        "LinuxPortalSession",
        "PipeWireReconfigured",
        "ReleaseAllAndReconfigure",
        "DmaBufModifierUnknown",
        "resume_after_reconfigure",
    ],


}

PRESENTATION_CONTRACT_TOKENS = [
    "PresentationSubmissionGuard",
    "PresentSubmission",
    "NativePresentationCompletion",
    "HandoffInProgress",
    "PresentationRecoveryRequired",
]

CORE_UNSAFE_CONSTRUCT_RE = re.compile(r"\bunsafe\s+(?:trait|impl|fn)\b|\bunsafe\s*\{")

def run(cmd: list[str]) -> dict[str, object]:
    result = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, check=False)
    return {
        "command": cmd,
        "returncode": result.returncode,
        "stdout": result.stdout[-8000:],
        "stderr": result.stderr[-8000:],
    }


def main() -> int:
    checks: list[dict[str, object]] = []
    failures: list[str] = []

    for relative in REQUIRED:
        path = ROOT / relative
        ok = path.is_file()
        checks.append({"check": "required_file", "path": relative, "ok": ok})
        if not ok:
            failures.append(f"missing required file: {relative}")

    for relative, phrases in REQUIRED_PHRASES.items():
        path = ROOT / relative
        text = path.read_text(encoding="utf-8") if path.is_file() else ""
        for phrase in phrases:
            ok = phrase.lower() in text.lower()
            checks.append({"check": "required_phrase", "path": relative, "phrase": phrase, "ok": ok})
            if not ok:
                failures.append(f"{relative} missing phrase: {phrase}")

    for relative, tokens in SOURCE_GUARDS.items():
        path = ROOT / relative
        text = path.read_text(encoding="utf-8") if path.is_file() else ""
        for token in tokens:
            ok = token in text
            checks.append({"check": "source_guard", "path": relative, "token": token, "ok": ok})
            if not ok:
                failures.append(f"source guard missing in {relative}: {token}")


    presentation_path = ROOT / "crates/platform/src/lib.rs"
    presentation_text = presentation_path.read_text(encoding="utf-8") if presentation_path.is_file() else ""
    for token in PRESENTATION_CONTRACT_TOKENS:
        ok = token in presentation_text
        checks.append({"check": "presentation_contract", "token": token, "ok": ok})
        if not ok:
            failures.append(f"presentation contract missing token: {token}")
    for match in CORE_UNSAFE_CONSTRUCT_RE.finditer(presentation_text):
        construct = match.group()
        checks.append(
            {
                "check": "core_unsafe_construct",
                "path": "crates/platform/src/lib.rs",
                "construct": construct,
                "ok": False,
            }
        )
        failures.append(f"core unsafe construct: {construct}")
    cargo_path = ROOT / "Cargo.toml"
    try:
        content = cargo_path.read_text(encoding="utf-8")
        if tomllib is not None:
            workspace = tomllib.loads(content)["workspace"]
            members = workspace["members"]
        else:
            match = re.search(r'members\s*=\s*\[(.*?)\]', content, re.DOTALL)
            if match:
                members = re.findall(r'"([^"]+)"', match.group(1))
            else:
                members = []
    except Exception as error:
        failures.append(f"workspace manifest invalid: {error}")
        members = []
    duplicates = sorted({member for member in members if members.count(member) > 1})
    if duplicates:
        failures.append(f"duplicate workspace members: {duplicates}")
    checks.append({"check": "unique_workspace_members", "ok": not duplicates, "duplicates": duplicates})
    for member in members:
        manifest = ROOT / member / "Cargo.toml"
        source = ROOT / member / "src"
        ok = manifest.is_file() and source.is_dir()
        checks.append({"check": "workspace_member", "member": member, "ok": ok})
        if not ok:
            failures.append(f"workspace member incomplete: {member}")

    reference_result = run([sys.executable, "scripts/reference_lab.py", "--fuzz-iterations", "5000"])
    if reference_result["returncode"] != 0:
        failures.append("independent reference lab failed")

    cargo_result = None
    if shutil.which("cargo"):
        cargo_result = run(["cargo", "metadata", "--format-version", "1", "--no-deps"])
        if cargo_result["returncode"] != 0:
            failures.append("cargo metadata failed")

    report = {
        "root": str(ROOT),
        "ok": not failures,
        "failures": failures,
        "checks": checks,
        "reference_lab": reference_result,
        "cargo_metadata": cargo_result,
        "cargo_available": bool(shutil.which("cargo")),
        "note": "Reference/static checks are bootstrap gates. cargo fmt/clippy/test remain authoritative Rust gates.",
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"ok": report["ok"], "failures": failures, "report": str(OUT)}, ensure_ascii=False))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
