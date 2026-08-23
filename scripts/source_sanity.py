#!/usr/bin/env python3
"""Dependency-free Rust workspace sanity checks.

Cargo remains authoritative. This script catches common bootstrap mistakes before
CI is available: missing direct dependencies, invalid path dependencies, cycles,
workspace duplication, and obvious unfinished production code.
"""
from __future__ import annotations

import json
import re
import sys
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
                target_match = re.fullmatch(
                    r"target\.(?:'([^']+)'|\"([^\"]+)\")\."
                    r"(dependencies|dev-dependencies|build-dependencies)",
                    current_section,
                )
                if target_match:
                    target_name = target_match.group(1) or target_match.group(2)
                    dependency_section = target_match.group(3)
                    target_table = data["target"].setdefault(target_name, {})
                    destination = target_table.setdefault(dependency_section, {})
            if dependency_section is not None:
                if val.startswith("{") and "path" in val:
                    path_match = re.search(r'path\s*=\s*["\']([^"\']+)["\']', val)
                    pkg_match = re.search(r'package\s*=\s*["\']([^"\']+)["\']', val)
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
    cargo_content = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
    if tomllib is not None:
        root = tomllib.loads(cargo_content)
        members = root.get("workspace", {}).get("members", [])
    else:
        match = re.search(r'members\s*=\s*\[(.*?)\]', cargo_content, re.DOTALL)
        members = re.findall(r'"([^"]+)"', match.group(1)) if match else []
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
            text = manifest.read_text(encoding="utf-8")
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

        imported_tokens: set[str] = set()
        unfinished: list[str] = []
        for source in sorted(package.source_dir.rglob("*.rs")):
            text = source.read_text(encoding="utf-8")
            imported_tokens.update(USE_RE.findall(text))
            imported_tokens.update(EXTERN_RE.findall(text))
            if UNFINISHED_RE.search(text) and "tests" not in source.parts:
                unfinished.append(str(source.relative_to(ROOT)))
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
