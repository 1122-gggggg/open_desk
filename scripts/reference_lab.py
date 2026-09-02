#!/usr/bin/env python3
"""Independent executable reference for LatencyDesk M1 wire and lab invariants.

This does not replace cargo test. It mirrors the fixed-width protocol, exact test
codec, fragment reassembly, and input reconciliation so the repository has an
executable gate even in bootstrap environments without a Rust toolchain.
"""
from __future__ import annotations

import functools
import os
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "artifacts" / "reference-lab.json"
MEDIA = struct.Struct(">4sBBHIIQQIIH2s")
CODEC = struct.Struct(">4sBBHIIIIIQQ")
NO_DEP = (1 << 64) - 1
KEYFRAME = 1
LOSSLESS = 4
MAX_FRAME = 16 * 1024 * 1024

# --- cached regex / lazy import helpers (avoid recompile and import cost) ---
_RE_MEMBERS: object = None
_RE_QUOTED: object = None


def _get_member_patterns():
    global _RE_MEMBERS, _RE_QUOTED
    if _RE_MEMBERS is None:
        import re

        _RE_MEMBERS = re.compile(r'members\s*=\s*\[(.*?)\]', re.DOTALL)
        _RE_QUOTED = re.compile(r'"([^"]+)"')
    return _RE_MEMBERS, _RE_QUOTED  # type: ignore[return-value]


@functools.lru_cache(maxsize=1)
def _cargo_text() -> str:
    return (ROOT / "Cargo.toml").read_text()


def _default_fuzz_iterations() -> int:
    raw = os.environ.get("REFERENCE_LAB_FUZZ_ITERATIONS", "25000")
    try:
        value = int(raw)
        return value if value >= 0 else 25000
    except (ValueError, TypeError):
        return 25000


@functools.lru_cache(maxsize=256)
def fnv1a(data: bytes) -> int:
    value = 0xCBF29CE484222325
    for byte in data:
        value ^= byte
        value = (value * 0x100000001B3) & NO_DEP
    return value


@functools.lru_cache(maxsize=128)
def fake_frame(width: int, height: int, sequence: int, seed: int) -> bytes:
    out = bytearray(width * height * 4)
    caret_x = (sequence * 5) % width
    for y in range(height):
        row, stroke = divmod(y, 12)
        for x in range(width):
            glyph = (x // 7 + row + seed) % 11
            if caret_x <= x < caret_x + 2 and 1 < stroke < 11:
                b = g = r = 255
            elif stroke in (3, 8) or glyph == 0:
                b, g, r = 210, 220, 225
            else:
                b, g, r = 20, 23, 27
            offset = (y * width + x) * 4
            out[offset : offset + 4] = bytes((b, g, r, 255))
    return bytes(out)


def encode_packbits(data: bytes) -> bytes:
    out = bytearray()
    cursor = 0
    while cursor < len(data):
        run = 1
        while cursor + run < len(data) and data[cursor + run] == data[cursor] and run < 130:
            run += 1
        if run >= 3:
            out.extend((0x80 | (run - 3), data[cursor]))
            cursor += run
            continue
        start = cursor
        cursor += max(run, 1)
        while cursor < len(data) and cursor - start < 128:
            next_run = 1
            while (
                cursor + next_run < len(data)
                and data[cursor + next_run] == data[cursor]
                and next_run < 130
            ):
                next_run += 1
            if next_run >= 3:
                break
            cursor += max(next_run, 1)
        literal = data[start:cursor]
        out.append(len(literal) - 1)
        out.extend(literal)
    return bytes(out)


def decode_packbits(payload: bytes, expected: int) -> bytes:
    out = bytearray()
    cursor = 0
    while cursor < len(payload):
        control = payload[cursor]
        cursor += 1
        if control & 0x80:
            count = (control & 0x7F) + 3
            if cursor >= len(payload):
                raise ValueError("malformed run")
            if len(out) + count > expected:
                raise ValueError("decompression bound")
            out.extend(bytes((payload[cursor],)) * count)
            cursor += 1
        else:
            count = control + 1
            end = cursor + count
            if end > len(payload) or len(out) + count > expected:
                raise ValueError("malformed literal")
            out.extend(payload[cursor:end])
            cursor = end
    if len(out) != expected:
        raise ValueError("decoded length")
    return bytes(out)


def encode_exact(raw: bytes, width: int, height: int, sequence: int) -> bytes:
    payload = encode_packbits(raw)
    header = CODEC.pack(
        b"LDTC",
        1,
        1,
        1,
        width,
        height,
        width * 4,
        len(raw),
        len(payload),
        sequence,
        fnv1a(raw),
    )
    assert len(header) == 44
    return header + payload


def decode_exact(encoded: bytes) -> tuple[int, bytes]:
    if len(encoded) < CODEC.size:
        raise ValueError("truncated exact frame")
    magic, version, fmt, flags, width, height, stride, raw_len, payload_len, sequence, checksum = CODEC.unpack_from(encoded)
    if (magic, version, fmt, flags) != (b"LDTC", 1, 1, 1):
        raise ValueError("exact header")
    if width <= 0 or height <= 0 or stride != width * 4 or raw_len != stride * height:
        raise ValueError("exact geometry")
    if CODEC.size + payload_len != len(encoded):
        raise ValueError("exact payload")
    raw = decode_packbits(encoded[CODEC.size :], raw_len)
    if fnv1a(raw) != checksum:
        raise ValueError("checksum")
    return sequence, raw


def media_packet(*, frame: bytes, frame_id: int, offset: int, payload: bytes) -> bytes:
    header = MEDIA.pack(
        b"LDSK",
        1,
        1,
        KEYFRAME | LOSSLESS,
        1,
        1,
        frame_id,
        NO_DEP,
        len(frame),
        offset,
        len(payload),
        b"\0\0",
    )
    return header + payload


def fragment(frame: bytes, frame_id: int, mtu: int = 1200) -> list[bytes]:
    cap = mtu - MEDIA.size
    if not frame or len(frame) > MAX_FRAME or cap <= 0 or cap > 16 * 1024:
        raise ValueError("fragment bounds")
    return [
        media_packet(frame=frame, frame_id=frame_id, offset=offset, payload=frame[offset : offset + cap])
        for offset in range(0, len(frame), cap)
    ]


def parse_media(datagram: bytes) -> tuple[tuple[int, int, int, int], int, int, bytes]:
    if len(datagram) < MEDIA.size:
        raise ValueError("truncated media")
    magic, version, kind, flags, stream, epoch, frame_id, dependency, frame_len, offset, frag_len, reserved = MEDIA.unpack_from(datagram)
    if magic != b"LDSK" or version != 1 or kind not in (1, 2, 3, 4) or reserved != b"\0\0":
        raise ValueError("media header")
    if flags & ~0xF or frame_len <= 0 or frame_len > MAX_FRAME or frag_len <= 0 or frag_len > 16 * 1024:
        raise ValueError("media bounds")
    if offset >= frame_len or offset + frag_len > frame_len or len(datagram) != MEDIA.size + frag_len:
        raise ValueError("media range")
    if flags & KEYFRAME and dependency != NO_DEP:
        raise ValueError("keyframe dependency")
    if dependency != NO_DEP and dependency >= frame_id:
        raise ValueError("forward dependency")
    return (stream, epoch, frame_id, kind), frame_len, offset, datagram[MEDIA.size :]


@dataclass
class Partial:
    frame_len: int
    fragments: dict[int, bytes] = field(default_factory=dict)


class Reassembler:
    def __init__(self, max_frames: int = 32, max_bytes: int = 64 * 1024 * 1024):
        self.max_frames = max_frames
        self.max_bytes = max_bytes
        self.frames: dict[tuple[int, int, int, int], Partial] = {}
        self.reserved = 0
        self.max_reserved = 0

    def ingest(self, datagram: bytes) -> tuple[int, bytes] | None:
        key, frame_len, offset, payload = parse_media(datagram)
        if frame_len > self.max_bytes:
            raise ValueError("frame budget")
        partial = self.frames.get(key)
        if partial is None:
            while self.frames and (len(self.frames) >= self.max_frames or self.reserved + frame_len > self.max_bytes):
                victim = min(self.frames)
                self.reserved -= self.frames[victim].frame_len
                del self.frames[victim]
            if len(self.frames) >= self.max_frames or self.reserved + frame_len > self.max_bytes:
                raise ValueError("capacity")
            partial = self.frames[key] = Partial(frame_len)
            self.reserved += frame_len
            self.max_reserved = max(self.max_reserved, self.reserved)
        elif partial.frame_len != frame_len:
            self._drop(key)
            raise ValueError("metadata conflict")
        if offset in partial.fragments:
            if partial.fragments[offset] == payload:
                return None
            self._drop(key)
            raise ValueError("fragment conflict")
        end = offset + len(payload)
        for other_offset, other in partial.fragments.items():
            other_end = other_offset + len(other)
            if max(offset, other_offset) < min(end, other_end):
                self._drop(key)
                raise ValueError("fragment overlap")
        partial.fragments[offset] = payload
        if sum(map(len, partial.fragments.values())) != frame_len:
            return None
        cursor = 0
        output = bytearray(frame_len)
        for position in sorted(partial.fragments):
            payload = partial.fragments[position]
            if position != cursor:
                self._drop(key)
                raise ValueError("gap")
            output[position : position + len(payload)] = payload
            cursor += len(payload)
        self._drop(key)
        return key[2], bytes(output)

    def discard_all(self) -> None:
        self.frames.clear()
        self.reserved = 0

    def _drop(self, key: tuple[int, int, int, int]) -> None:
        partial = self.frames.pop(key, None)
        if partial:
            self.reserved -= partial.frame_len


class XorShift:
    def __init__(self, seed: int):
        self.state = seed or 0x9E3779B97F4A7C15

    def next(self) -> int:
        value = self.state
        value ^= (value << 13) & NO_DEP
        value ^= value >> 7
        value ^= (value << 17) & NO_DEP
        self.state = value & NO_DEP
        return self.state


def run_loopback(
    frames: int,
    loss_ppm: int,
    duplicate_ppm: int,
    reorder_ppm: int,
    corrupt_ppm: int,
    seed: int,
) -> dict[str, int | bool]:
    rng = XorShift(seed)
    expected: dict[int, int] = {}
    transmitted: list[bytes] = []
    lost = duplicated = corrupted = 0
    for sequence in range(frames):
        raw = fake_frame(96, 64, sequence, seed & 0xFFFF)
        expected[sequence] = fnv1a(raw)
        for packet in fragment(encode_exact(raw, 96, 64, sequence), sequence):
            if rng.next() % 1_000_000 < loss_ppm:
                lost += 1
                continue
            copies = [packet]
            if rng.next() % 1_000_000 < duplicate_ppm:
                copies.append(packet)
                duplicated += 1
            for copy in copies:
                if rng.next() % 1_000_000 < corrupt_ppm:
                    mutable = bytearray(copy)
                    index = rng.next() % len(mutable)
                    mutable[index] ^= 1 << (rng.next() % 8)
                    copy = bytes(mutable)
                    corrupted += 1
                transmitted.append(copy)
                if rng.next() % 1_000_000 < reorder_ppm and len(transmitted) >= 2:
                    transmitted[-1], transmitted[-2] = transmitted[-2], transmitted[-1]
    reassembler = Reassembler()
    completed = exact = rejected_access_units = 0
    errors = 0
    for packet in transmitted:
        try:
            result = reassembler.ingest(packet)
        except ValueError:
            # Malformed/corrupt datagrams are expected to be rejected.
            continue
        if not result:
            continue
        completed += 1
        sequence, encoded = result
        try:
            decoded_sequence, raw = decode_exact(encoded)
        except ValueError:
            rejected_access_units += 1
            continue
        if decoded_sequence != sequence or expected.get(sequence) != fnv1a(raw):
            errors += 1
        else:
            exact += 1
    residual_before_cleanup = reassembler.reserved
    max_reserved = reassembler.max_reserved
    reassembler.discard_all()
    return {
        "configured_frames": frames,
        "completed_frames": completed,
        "exact_frames": exact,
        "rejected_access_units": rejected_access_units,
        "lost_datagrams": lost,
        "duplicate_datagrams": duplicated,
        "corrupted_datagrams": corrupted,
        "silent_corruption_errors": errors,
        "residual_before_cleanup": residual_before_cleanup,
        "reserved_bytes_after_cleanup": reassembler.reserved,
        "max_reserved_bytes": max_reserved,
        "passed": (
            errors == 0
            and exact + rejected_access_units == completed
            and reassembler.reserved == 0
            and max_reserved <= reassembler.max_bytes
            and len(reassembler.frames) <= reassembler.max_frames
        ),
    }


def input_probe() -> dict[str, object]:
    state: set[int] = set()
    last = -1
    stale = 0
    messages = [(1, "event", {4}), (3, "snapshot", set()), (1, "event", {4})]
    for sequence, kind, value in messages:
        if sequence <= last:
            stale += 1
            continue
        state = set(value) if kind == "snapshot" else state | set(value)
        last = sequence
    release_plan = sorted(state)
    state.clear()
    return {"repaired": not release_plan, "stale": stale, "release_plan": release_plan}


def rust_structure() -> dict[str, object]:
    # lazy tomllib import (heavy, only needed here)
    try:
        import tomllib  # type: ignore
    except ModuleNotFoundError:
        try:
            import tomli as tomllib  # type: ignore
        except ModuleNotFoundError:
            tomllib = None  # type: ignore[assignment]

    content = _cargo_text()
    if tomllib is not None:
        try:
            cargo = tomllib.loads(content)  # type: ignore[attr-defined]
            members = cargo["workspace"]["members"]
        except Exception:
            members_re, quoted_re = _get_member_patterns()
            match = members_re.search(content)  # type: ignore[attr-defined]
            members = quoted_re.findall(match.group(1)) if match else []  # type: ignore[attr-defined]
    else:
        members_re, quoted_re = _get_member_patterns()
        match = members_re.search(content)  # type: ignore[attr-defined]
        members = quoted_re.findall(match.group(1)) if match else []  # type: ignore[attr-defined]
    missing = [member for member in members if not (ROOT / member / "Cargo.toml").is_file()]
    source_missing = [member for member in members if not (ROOT / member / "src").exists()]
    delimiter_failures: list[str] = []
    for path in sorted(ROOT.glob("**/*.rs")):
        if ".git" in path.parts:
            continue
        text = path.read_text()
        # Lightweight lexical pass: ignore comments and strings, then ensure all
        # structural delimiters are balanced. Cargo remains the authoritative gate.
        stack: list[str] = []
        pairs = {')': '(', ']': '[', '}': '{'}
        in_string = False
        escaped = False
        in_line_comment = False
        in_block_comment = 0
        i = 0
        while i < len(text):
            ch = text[i]
            nxt = text[i + 1] if i + 1 < len(text) else ""
            if in_line_comment:
                if ch == "\n":
                    in_line_comment = False
                i += 1
                continue
            if in_block_comment:
                if ch == '/' and nxt == '*':
                    in_block_comment += 1
                    i += 2
                    continue
                if ch == '*' and nxt == '/':
                    in_block_comment -= 1
                    i += 2
                    continue
                i += 1
                continue
            if in_string:
                if escaped:
                    escaped = False
                elif ch == '\\':
                    escaped = True
                elif ch == '"':
                    in_string = False
                i += 1
                continue
            if ch == '/' and nxt == '/':
                in_line_comment = True
                i += 2
                continue
            if ch == '/' and nxt == '*':
                in_block_comment = 1
                i += 2
                continue
            if ch == '"':
                in_string = True
                i += 1
                continue
            if ch == "'":
                # Skip a Rust character literal without confusing lifetimes such
                # as `'a` or `'static`. Escaped characters occupy two bytes.
                end = i + 2
                if i + 1 < len(text) and text[i + 1] == "\\":
                    end = i + 3
                if end < len(text) and text[end] == "'":
                    i = end + 1
                    continue
            if ch in "([{":
                stack.append(ch)
            elif ch in ")]}":
                if not stack or stack.pop() != pairs[ch]:
                    delimiter_failures.append(str(path.relative_to(ROOT)))
                    break
            i += 1
        else:
            if stack or in_string or in_block_comment:
                delimiter_failures.append(str(path.relative_to(ROOT)))
    return {
        "workspace_members": len(members),
        "missing_members": missing,
        "missing_src": source_missing,
        "delimiter_failures": delimiter_failures,
        "passed": not missing and not source_missing and not delimiter_failures,
    }


def parser_fuzz(iterations: int, seed: int) -> dict[str, int | bool]:
    import random

    rng = random.Random(seed)
    unexpected = accepted_random = accepted_mutations = 0
    valid = fragment(encode_exact(fake_frame(32, 24, 1, seed), 32, 24, 1), 1)[0]
    valid_exact = encode_exact(fake_frame(32, 24, 2, seed), 32, 24, 2)
    for index in range(iterations):
        if index % 2 == 0:
            data = rng.randbytes(rng.randrange(0, 2049))
            try:
                parse_media(data)
                accepted_random += 1
            except (ValueError, struct.error, OverflowError):
                pass
            except Exception:
                unexpected += 1
        else:
            data = bytearray(valid)
            operation = rng.randrange(4)
            if operation == 0 and data:
                for _ in range(rng.randrange(1, 5)):
                    position = rng.randrange(len(data))
                    data[position] ^= 1 << rng.randrange(8)
            elif operation == 1:
                del data[rng.randrange(len(data) + 1) :]
            elif operation == 2:
                data.extend(rng.randbytes(rng.randrange(1, 17)))
            else:
                data = bytearray(rng.randbytes(rng.randrange(0, MEDIA.size + 32)))
            try:
                parse_media(bytes(data))
                accepted_mutations += 1
            except (ValueError, struct.error, OverflowError):
                pass
            except Exception:
                unexpected += 1

        exact = bytearray(valid_exact)
        if exact:
            exact[rng.randrange(len(exact))] ^= 1 << rng.randrange(8)
        try:
            decode_exact(bytes(exact))
        except (ValueError, struct.error, OverflowError):
            pass
        except Exception:
            unexpected += 1
    return {
        "iterations": iterations,
        "accepted_random": accepted_random,
        "accepted_valid_mutations": accepted_mutations,
        "unexpected_exceptions": unexpected,
        "passed": unexpected == 0,
    }


@functools.lru_cache(maxsize=1)
def git_commit() -> str | None:
    import subprocess

    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True, capture_output=True, check=False
    )
    return result.stdout.strip() or None if result.returncode == 0 else None


def main() -> int:
    import argparse
    import json

    parser = argparse.ArgumentParser()
    parser.add_argument("--fuzz-iterations", type=int, default=_default_fuzz_iterations())
    parser.add_argument("--frames", type=int, default=20)
    parser.add_argument("--hostile-frames", type=int, default=50)
    parser.add_argument("--seed", type=int, default=12345)
    parser.add_argument("--loss-ppm", type=int, default=20_000)
    parser.add_argument("--duplicate-ppm", type=int, default=50_000)
    parser.add_argument("--reorder-ppm", type=int, default=100_000)
    parser.add_argument("--corrupt-ppm", type=int, default=10_000)
    parser.add_argument("--output", type=Path, default=ARTIFACT)
    args = parser.parse_args()
    probability_values = (
        args.loss_ppm,
        args.duplicate_ppm,
        args.reorder_ppm,
        args.corrupt_ppm,
    )
    if (
        args.fuzz_iterations < 0
        or args.frames <= 0
        or args.hostile_frames <= 0
        or any(value < 0 or value > 1_000_000 for value in probability_values)
    ):
        parser.error("counts must be positive and probabilities must be in 0..=1_000_000")

    clean = run_loopback(args.frames, 0, 0, 0, 0, args.seed)
    hostile = run_loopback(
        args.hostile_frames,
        args.loss_ppm,
        args.duplicate_ppm,
        args.reorder_ppm,
        args.corrupt_ppm,
        args.seed ^ 0xA5A55A5A,
    )
    report = {
        "schema": 2,
        "commit": git_commit(),
        "parameters": {
            "seed": args.seed,
            "fuzz_iterations": args.fuzz_iterations,
            "clean_frames": args.frames,
            "hostile_frames": args.hostile_frames,
            "loss_ppm": args.loss_ppm,
            "duplicate_ppm": args.duplicate_ppm,
            "reorder_ppm": args.reorder_ppm,
            "corrupt_ppm": args.corrupt_ppm,
        },
        "note": "Independent Python reference; cargo test remains authoritative for Rust compilation.",
        "wire_sizes": {"media": MEDIA.size, "test_codec": CODEC.size},
        "clean_loopback": clean,
        "hostile_loopback": hostile,
        "input": input_probe(),
        "parser_fuzz": parser_fuzz(args.fuzz_iterations, args.seed ^ 0xC0DEC0DE),
        "rust_structure": rust_structure(),
    }
    report["passed"] = all(
        (
            MEDIA.size == 44,
            CODEC.size == 44,
            clean["passed"] and clean["exact_frames"] == clean["configured_frames"],
            hostile["passed"],
            report["input"]["repaired"],
            report["parser_fuzz"]["passed"],
            report["rust_structure"]["passed"],
        )
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n")
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
