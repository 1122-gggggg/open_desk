#!/usr/bin/env python3
"""Dependency-free Rust workspace sanity checks.

Cargo remains authoritative. This script catches common bootstrap mistakes before
CI is available: missing direct dependencies, invalid path dependencies, cycles,
workspace duplication, and obvious unfinished production code.
"""
from __future__ import annotations

import concurrent.futures
import functools
import json
import os
import re
import sys

# --- __pycache__ 加速：確保位元組碼快取啟用 ---
if getattr(sys, "dont_write_bytecode", False):
    sys.dont_write_bytecode = False

try:
    import tomllib
except ModuleNotFoundError:
    try:
        import tomli as tomllib
    except ModuleNotFoundError:
        tomllib = None
from dataclasses import dataclass
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "artifacts" / "source-sanity.json"

USE_RE = re.compile(r"(?m)^\s*(?:pub\s+)?use\s+(latencydesk_[A-Za-z0-9_]+)(?::|\s*;)")
EXTERN_RE = re.compile(r"(?m)^\s*extern\s+crate\s+(latencydesk_[A-Za-z0-9_]+)\s*;")
UNFINISHED_RE = re.compile(r"\b(?:todo!|unimplemented!)\s*\(")

# --- 快取正則編譯（避免在熱迴圈內重複編譯）---
_TARGET_SECTION_RE = re.compile(
    r"target\.(?:'([^']+)'|\"([^\"]+)\")\.(dependencies|dev-dependencies|build-dependencies)"
)
_PATH_RE = re.compile(r'path\s*=\s*["\']([^"\']+)["\']')
_PACKAGE_RE = re.compile(r'package\s*=\s*["\']([^"\']+)["\']')
_MEMBERS_RE = re.compile(r'members\s*=\s*\[(.*?)\]', re.DOTALL)
_QUOTED_RE = re.compile(r'"([^"]+)"')


@functools.lru_cache(maxsize=512)
def _cached_text(path_str: str) -> str:
    try:
        return Path(path_str).read_text(encoding="utf-8")
    except OSError:
        return ""


@functools.lru_cache(maxsize=128)
def _cached_rs_files(dir_str: str) -> tuple[Path, ...]:
    try:
        return tuple(sorted(Path(dir_str).rglob("*.rs")))
    except OSError:
        return ()


@dataclass(frozen=True)
class Package:
    member: str
    name: str
    manifest: Path
    source_dir: Path
    dependencies: frozenset[str]
    path_dependencies: tuple[tuple[str, Path], ...]


def crate_token(package_name: str) -> str:
    return package_name.replace("-", "_")


def parse_simple_manifest(text: str) -> dict[str, object]:
    data: dict[str, object] = {
        "package": {},
        "dependencies": {},
        "dev-dependencies": {},
        "build-dependencies": {},
        "target": {},
    }
    current_section = ""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current_section = line[1:-1].strip()
            continue
        if "=" in line:
            key, val = [part.strip() for part in line.split("=", 1)]
            val_clean = val.strip("\"'")
            if current_section == "package" and key == "name":
                data["package"]["name"] = val_clean
            dependency_section = None
            destination = None
            if current_section in ("dependencies", "dev-dependencies", "build-dependencies"):
                dependency_section = current_section
                destination = data[current_section]
            else:
                target_match = _TARGET_SECTION_RE.fullmatch(current_section)
                if target_match:
                    target_name = target_match.group(1) or target_match.group(2)
                    dependency_section = target_match.group(3)
                    target_table = data["target"].setdefault(target_name, {})
                    destination = target_table.setdefault(dependency_section, {})
            if dependency_section is not None:
                if val.startswith("{") and "path" in val:
                    path_match = _PATH_RE.search(val)
                    pkg_match = _PACKAGE_RE.search(val)
                    spec = {"path": path_match.group(1) if path_match else ""}
                    if pkg_match:
                        spec["package"] = pkg_match.group(1)
                    destination[key] = spec
                else:
                    destination[key] = val_clean
    return data


def dependency_tables(data: dict[str, object]) -> list[dict[str, object]]:
    """Return every Cargo dependency table, including target-specific ones."""
    tables: list[dict[str, object]] = []
    section_names = ("dependencies", "dev-dependencies", "build-dependencies")
    for section in section_names:
        values = data.get(section, {})
        if isinstance(values, dict):
            tables.append(values)

    targets = data.get("target", {})
    if isinstance(targets, dict):
        for target in targets.values():
            if not isinstance(target, dict):
                continue
            for section in section_names:
                values = target.get(section, {})
                if isinstance(values, dict):
                    tables.append(values)
    return tables


def load_workspace() -> tuple[list[Package], list[str]]:
    failures: list[str] = []
    cargo_content = _cached_text(str(ROOT / "Cargo.toml"))
    if tomllib is not None:
        root = tomllib.loads(cargo_content)
        members = root.get("workspace", {}).get("members", [])
    else:
        m = _MEMBERS_RE.search(cargo_content)
        members = _QUOTED_RE.findall(m.group(1)) if m else []
    if not isinstance(members, list):
        return [], ["workspace.members must be an array"]
    if len(members) != len(set(members)):
        failures.append("workspace contains duplicate members")

    packages: list[Package] = []
    names: set[str] = set()
    for member in members:
        base = (ROOT / member).resolve()
        manifest = base / "Cargo.toml"
        source = base / "src"
        if not manifest.is_file():
            failures.append(f"{member}: missing Cargo.toml")
            continue
        if not source.is_dir():
            failures.append(f"{member}: missing src directory")
        try:
            text = _cached_text(str(manifest))
            if tomllib is not None:
                data = tomllib.loads(text)
            else:
                data = parse_simple_manifest(text)
            name = data["package"]["name"]
        except Exception as error:
            failures.append(f"{member}: invalid manifest: {error}")
            continue
        if name in names:
            failures.append(f"duplicate package name: {name}")
        names.add(name)
        dependencies: set[str] = set()
        path_dependencies: list[tuple[str, Path]] = []
        for values in dependency_tables(data):
            for dependency_name, spec in values.items():
                actual_name = dependency_name
                if isinstance(spec, dict):
                    actual_name = spec.get("package", dependency_name)
                    if "path" in spec:
                        target = (manifest.parent / spec["path"]).resolve()
                        path_dependencies.append((actual_name, target))
                dependencies.add(actual_name)
        packages.append(
            Package(
                member=member,
                name=name,
                manifest=manifest,
                source_dir=source,
                dependencies=frozenset(dependencies),
                path_dependencies=tuple(path_dependencies),
            )
        )
    return packages, failures


def cycle_failures(graph: dict[str, set[str]]) -> list[str]:
    failures: list[str] = []
    visiting: set[str] = set()
    visited: set[str] = set()
    path: list[str] = []

    def visit(node: str) -> None:
        if node in visited:
            return
        if node in visiting:
            start = path.index(node)
            failures.append("dependency cycle: " + " -> ".join(path[start:] + [node]))
            return
        visiting.add(node)
        path.append(node)
        for target in sorted(graph.get(node, set())):
            visit(target)
        path.pop()
        visiting.remove(node)
        visited.add(node)

    for node in sorted(graph):
        visit(node)
    return failures


def main() -> int:
    packages, failures = load_workspace()
    by_name = {package.name: package for package in packages}
    by_path = {package.manifest.parent.resolve(): package.name for package in packages}
    token_to_package = {crate_token(package.name): package.name for package in packages}
    graph: dict[str, set[str]] = {package.name: set() for package in packages}
    checks: list[dict[str, object]] = []

    # --- 並行掃描：提早提交所有 package 的原始檔掃描任務，減少重複 glob/read ---
    def _scan_package(pkg: Package) -> tuple[set[str], list[str]]:
        imported_tokens: set[str] = set()
        unfinished: list[str] = []
        sources = _cached_rs_files(str(pkg.source_dir))
        # 提早退出：無來源檔直接回空
        if not sources:
            return imported_tokens, unfinished
        for source in sources:
            text = _cached_text(str(source))
            if not text:
                continue
            # 快取正則已編譯；提早退出：若不含 latencydesk_ 前綴則用快速檢查避免正則
            if "latencydesk_" in text:
                imported_tokens.update(USE_RE.findall(text))
                imported_tokens.update(EXTERN_RE.findall(text))
            # 若文本不含 latencydesk_ 但仍含 use / extern，仍需保底掃描（極少）
            elif "use " in text or "extern crate" in text:
                # 只有極少數檔案會走此分支，保留語意一致性
                imported_tokens.update(USE_RE.findall(text))
                imported_tokens.update(EXTERN_RE.findall(text))
            # 提早退出：tests 目錄下跳過 unfinished 檢查
            if "tests" in source.parts:
                continue
            if "todo!" in text or "unimplemented!" in text:
                if UNFINISHED_RE.search(text):
                    unfinished.append(str(source.relative_to(ROOT)))
        return imported_tokens, unfinished

    max_workers = min(32, (os.cpu_count() or 4) * 4)
    # 預先提交所有掃描，真正並行執行 I/O 與正則
    scan_futures: dict[str, concurrent.futures.Future[tuple[set[str], list[str]]]] = {}
    executor: concurrent.futures.ThreadPoolExecutor | None = None
    if packages:
        executor = concurrent.futures.ThreadPoolExecutor(max_workers=max_workers)
        for pkg in packages:
            scan_futures[pkg.name] = executor.submit(_scan_package, pkg)

    try:
        for package in packages:
            for dependency_name, target_path in package.path_dependencies:
                actual = by_path.get(target_path)
                ok = actual == dependency_name
                checks.append(
                    {
                        "check": "path_dependency",
                        "package": package.name,
                        "dependency": dependency_name,
                        "path": str(target_path.relative_to(ROOT)) if target_path.is_relative_to(ROOT) else str(target_path),
                        "actual_package": actual,
                        "ok": ok,
                    }
                )
                if not ok:
                    failures.append(
                        f"{package.name}: path dependency {dependency_name} points to {actual or 'no workspace package'}"
                    )
                if dependency_name in by_name:
                    graph[package.name].add(dependency_name)

            # 取得並行掃描結果（保持原始套件順序以確保輸出一致）
            imported_tokens: set[str] = set()
            unfinished: list[str] = []
            if package.name in scan_futures:
                imported_tokens, unfinished = scan_futures[package.name].result()
            else:
                imported_tokens, unfinished = _scan_package(package)

            for token in sorted(imported_tokens):
                dependency_name = token_to_package.get(token)
                if dependency_name is None or dependency_name == package.name:
                    continue
                ok = dependency_name in package.dependencies
                checks.append(
                    {
                        "check": "direct_dependency",
                        "package": package.name,
                        "import": token,
                        "dependency": dependency_name,
                        "ok": ok,
                    }
                )
                if not ok:
                    failures.append(
                        f"{package.name}: imports {token} but does not declare direct dependency {dependency_name}"
                    )
            if unfinished:
                failures.append(f"{package.name}: unfinished macros in {', '.join(unfinished)}")
    finally:
        if executor is not None:
            executor.shutdown(wait=True)

    failures.extend(cycle_failures(graph))
    report = {
        "schema": 1,
        "ok": not failures,
        "workspace_packages": len(packages),
        "dependency_graph": {key: sorted(value) for key, value in sorted(graph.items())},
        "checks": checks,
        "failures": failures,
        "note": "Bootstrap sanity only; cargo metadata/check/clippy/test are authoritative.",
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"ok": report["ok"], "failures": failures, "report": str(OUT)}, ensure_ascii=False))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
