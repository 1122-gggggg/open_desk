#!/usr/bin/env python3
"""Dependency-free structural validation for the LatencyDesk repository."""
from __future__ import annotations

import concurrent.futures
import functools
import json
import os
import shutil
import subprocess
import sys
import re

# --- __pycache__ 加速：確保位元組碼快取啟用以加速後續啟動 ---
if getattr(sys, "dont_write_bytecode", False):
    sys.dont_write_bytecode = False

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
# --- 快取正則編譯 ---
_MEMBERS_RE = re.compile(r'members\s*=\s*\[(.*?)\]', re.DOTALL)
_QUOTED_RE = re.compile(r'"([^"]+)"')

@functools.lru_cache(maxsize=512)
def _cached_text(path_str: str) -> str:
    try:
        return Path(path_str).read_text(encoding="utf-8")
    except OSError:
        return ""


@functools.lru_cache(maxsize=512)
def _cached_lower(path_str: str) -> str:
    return _cached_text(path_str).lower()


@functools.lru_cache(maxsize=512)
def _file_exists(path_str: str) -> bool:
    return Path(path_str).is_file()

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
        path_str = str(ROOT / relative)
        ok = _file_exists(path_str)
        checks.append({"check": "required_file", "path": relative, "ok": ok})
        if not ok:
            failures.append(f"missing required file: {relative}")

    # --- 並行檢查 REQUIRED_PHRASES 與 SOURCE_GUARDS（減少重複 read、快取 lower）---
    def _check_phrase_entry(item: tuple[str, list[str]]) -> list[tuple[str, str, bool]]:
        relative, phrases = item
        pstr = str(ROOT / relative)
        # 提早退出：檔案不存在直接全部標記失敗，免去 read/lower
        if not _file_exists(pstr):
            return [(relative, ph, False) for ph in phrases]
        lower = _cached_lower(pstr)
        # 提早退出：空檔直接失敗
        if not lower:
            return [(relative, ph, False) for ph in phrases]
        return [(relative, ph, ph.lower() in lower) for ph in phrases]

    def _check_guard_entry(item: tuple[str, list[str]]) -> list[tuple[str, str, bool]]:
        relative, tokens = item
        pstr = str(ROOT / relative)
        if not _file_exists(pstr):
            return [(relative, tok, False) for tok in tokens]
        text = _cached_text(pstr)
        if not text:
            return [(relative, tok, False) for tok in tokens]
        # token in text 為 C 層級搜尋，已具早退特性
        return [(relative, tok, tok in text) for tok in tokens]

    phrase_items = list(REQUIRED_PHRASES.items())
    guard_items = list(SOURCE_GUARDS.items())
    # 使用 ThreadPool 並行 I/O；map 保持原始順序以確保輸出一致
    max_workers = min(32, (os.cpu_count() or 4) * 4)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        phrase_results = list(executor.map(_check_phrase_entry, phrase_items))
        guard_results = list(executor.map(_check_guard_entry, guard_items))

    for results in phrase_results:
        for relative, phrase, ok in results:
            checks.append({"check": "required_phrase", "path": relative, "phrase": phrase, "ok": ok})
            if not ok:
                failures.append(f"{relative} missing phrase: {phrase}")

    for results in guard_results:
        for relative, token, ok in results:
            checks.append({"check": "source_guard", "path": relative, "token": token, "ok": ok})
            if not ok:
                failures.append(f"source guard missing in {relative}: {token}")


    presentation_path = ROOT / "crates/platform/src/lib.rs"
    presentation_text = _cached_text(str(presentation_path))
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
        content = _cached_text(str(cargo_path))
        if tomllib is not None:
            workspace = tomllib.loads(content)["workspace"]
            members = workspace["members"]
        else:
            m = _MEMBERS_RE.search(content)
            if m:
                members = _QUOTED_RE.findall(m.group(1))
            else:
                members = []
    except Exception as error:
        failures.append(f"workspace manifest invalid: {error}")
        members = []
    # 使用 Counter 避免 O(n^2) 的 list.count，並保持排序輸出一致
    from collections import Counter
    counts = Counter(members)
    duplicates = sorted([member for member, c in counts.items() if c > 1])
    if duplicates:
        failures.append(f"duplicate workspace members: {duplicates}")
    checks.append({"check": "unique_workspace_members", "ok": not duplicates, "duplicates": duplicates})

    # workspace_member 檢查並行化（保留原始順序）
    def _check_member(member: str) -> tuple[str, bool]:
        manifest = ROOT / member / "Cargo.toml"
        source = ROOT / member / "src"
        # is_file / is_dir 為系統呼叫，適合並行
        ok = manifest.is_file() and source.is_dir()
        return member, ok

    if members:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
            member_results = list(executor.map(_check_member, members))
    else:
        member_results = []
    for member, ok in member_results:
        checks.append({"check": "workspace_member", "member": member, "ok": ok})
        if not ok:
            failures.append(f"workspace member incomplete: {member}")

    # --- 並行執行獨立子進程（提早退出：兩者獨立，無需序列等待）---
    reference_result: dict[str, object] | None = None
    cargo_result: dict[str, object] | None = None
    cargo_available = bool(shutil.which("cargo"))
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        fut_ref = executor.submit(run, [sys.executable, "scripts/reference_lab.py", "--fuzz-iterations", "5000"])
        fut_cargo = None
        if cargo_available:
            fut_cargo = executor.submit(run, ["cargo", "metadata", "--format-version", "1", "--no-deps"])
        reference_result = fut_ref.result()  # type: ignore[assignment]
        if fut_cargo is not None:
            cargo_result = fut_cargo.result()  # type: ignore[assignment]

    # 保底：若未透過執行緒池（理論不發生）
    if reference_result is None:
        reference_result = run([sys.executable, "scripts/reference_lab.py", "--fuzz-iterations", "5000"])
    if reference_result["returncode"] != 0:
        failures.append("independent reference lab failed")

    if cargo_result is not None and cargo_result["returncode"] != 0:
        failures.append("cargo metadata failed")

    report = {
        "root": str(ROOT),
        "ok": not failures,
        "failures": failures,
        "checks": checks,
        "reference_lab": reference_result,
        "cargo_metadata": cargo_result,
        "cargo_available": cargo_available,
        "note": "Reference/static checks are bootstrap gates. cargo fmt/clippy/test remain authoritative Rust gates.",
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"ok": report["ok"], "failures": failures, "report": str(OUT)}, ensure_ascii=False))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
