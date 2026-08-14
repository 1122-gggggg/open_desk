#!/usr/bin/env python3
"""Run EXP-03 without implementing a desktop refinement protocol."""
from __future__ import annotations

import argparse
import json
import math
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "artifacts" / "exp-03-codec-quality.json"
WORKLOADS = ("ide", "terminal", "browser")


@dataclass(frozen=True)
class Variant:
    name: str
    pixel_format: str


VARIANTS = {
    "base420": Variant("base420", "yuv420p"),
    "444": Variant("444", "yuv444p"),
}


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, check=False)


def encoder_available(name: str) -> bool:
    result = run(["ffmpeg", "-hide_banner", "-encoders"])
    return any(
        fields[1:2] == [name]
        for line in result.stdout.splitlines()
        if (fields := line.split())
    )


def is_hardware_encoder(name: str) -> bool:
    return any(token in name for token in ("_nvenc", "_qsv", "_vaapi", "_amf"))


def ffmpeg_version() -> str | None:
    result = run(["ffmpeg", "-version"])
    return result.stdout.splitlines()[0] if result.returncode == 0 and result.stdout else None


def pixel_offset(width: int, x: int, y: int) -> int:
    return (y * width + x) * 4


def put_pixel(frame: bytearray, width: int, x: int, y: int, color: tuple[int, int, int]) -> None:
    offset = pixel_offset(width, x, y)
    frame[offset : offset + 4] = bytes((*color, 255))


def fill_rect(
    frame: bytearray,
    width: int,
    height: int,
    left: int,
    top: int,
    right: int,
    bottom: int,
    color: tuple[int, int, int],
) -> None:
    left = max(0, left)
    top = max(0, top)
    right = min(width, right)
    bottom = min(height, bottom)
    for y in range(top, bottom):
        row = pixel_offset(width, left, y)
        for x in range(left, right):
            frame[row : row + 4] = bytes((*color, 255))
            row += 4


def glyph_bit(character: int, x: int, y: int) -> bool:
    if x in (0, 5) or y in (0, 8):
        return True
    return ((character * 13 + x * 7 + y * 3) & 7) < 2


def draw_text_row(
    frame: bytearray,
    mask: bytearray,
    width: int,
    height: int,
    left: int,
    top: int,
    glyphs: int,
    color: tuple[int, int, int],
    seed: int,
) -> None:
    for glyph in range(glyphs):
        origin_x = left + glyph * 8
        if origin_x + 6 >= width:
            break
        character = (glyph + seed) % 95
        for glyph_y in range(9):
            y = top + glyph_y
            if y >= height:
                return
            for glyph_x in range(6):
                x = origin_x + glyph_x
                if glyph_bit(character, glyph_x, glyph_y):
                    put_pixel(frame, width, x, y, color)
                    mask[y * width + x] = 1


def generate_frame(width: int, height: int, index: int) -> tuple[bytes, bytes, str]:
    workload = WORKLOADS[index % len(WORKLOADS)]
    if workload == "browser":
        background = (245, 245, 245)
        primary = (24, 24, 24)
        accent = (190, 80, 25)
    elif workload == "terminal":
        background = (20, 23, 27)
        primary = (205, 230, 145)
        accent = (100, 220, 80)
    else:
        background = (28, 30, 36)
        primary = (205, 220, 235)
        accent = (220, 150, 90)

    frame = bytearray(bytes((*background, 255)) * (width * height))
    mask = bytearray(width * height)
    top_bar = max(12, height // 12)
    fill_rect(frame, width, height, 0, 0, width, top_bar, (45, 48, 55))
    if workload == "ide":
        fill_rect(frame, width, height, 0, top_bar, max(24, width // 5), height, (35, 38, 45))
        left = max(30, width // 5 + 8)
    else:
        left = 12

    row_height = 14
    rows = max(1, (height - top_bar - 12) // row_height)
    for row in range(rows):
        color = accent if row % 7 == 2 else primary
        draw_text_row(
            frame,
            mask,
            width,
            height,
            left,
            top_bar + 6 + row * row_height,
            max(1, (width - left - 16) // 8),
            color,
            index * 17 + row * 11,
        )

    caret_x = left + ((index * 5) % max(1, width - left - 8))
    caret_top = top_bar + 6 + ((index // 3) % rows) * row_height
    for y in range(caret_top, min(height, caret_top + 10)):
        put_pixel(frame, width, caret_x, y, (255, 255, 255))
        mask[y * width + caret_x] = 1
    return bytes(frame), bytes(mask), workload


def write_corpus(path: Path, width: int, height: int, frames: int) -> dict[str, int]:
    workloads = {name: 0 for name in WORKLOADS}
    with path.open("wb") as stream:
        for index in range(frames):
            frame, _, workload = generate_frame(width, height, index)
            stream.write(frame)
            workloads[workload] += 1
    return workloads


def encoder_arguments(encoder: str, variant: Variant, bitrate: str, fps: int) -> list[str]:
    common = [
        "-bf",
        "0",
        "-g",
        str(fps),
        "-keyint_min",
        str(fps),
        "-sc_threshold",
        "0",
        "-b:v",
        bitrate,
        "-maxrate",
        bitrate,
        "-bufsize",
        bitrate,
    ]
    if encoder == "libx264":
        profile = "high444" if variant.pixel_format == "yuv444p" else "high"
        return [
            "-c:v",
            encoder,
            "-preset",
            "ultrafast",
            "-tune",
            "zerolatency",
            "-x264-params",
            "rc-lookahead=0:sync-lookahead=0",
            "-profile:v",
            profile,
            *common,
        ]
    if encoder == "h264_nvenc":
        return [
            "-c:v",
            encoder,
            "-preset",
            "p1",
            "-tune",
            "ull",
            "-rc",
            "cbr",
            "-zerolatency",
            "1",
            "-delay",
            "0",
            "-forced-idr",
            "1",
            *common,
        ]
    if encoder == "h264_qsv":
        return ["-c:v", encoder, "-look_ahead", "0", *common]
    return ["-c:v", encoder, *common]


def inspect_stream(path: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    stream_result = run(
        [
            "ffprobe",
            "-v",
            "error",
            "-count_frames",
            "-select_streams",
            "v:0",
            "-show_entries",
            "stream=codec_name,pix_fmt,width,height,nb_read_frames",
            "-of",
            "json",
            str(path),
        ]
    )
    if stream_result.returncode != 0:
        raise RuntimeError(stream_result.stderr[-4000:])
    streams = json.loads(stream_result.stdout).get("streams", [])
    if len(streams) != 1:
        raise RuntimeError("expected exactly one video stream")
    frames_result = run(
        [
            "ffprobe",
            "-v",
            "error",
            "-select_streams",
            "v:0",
            "-show_entries",
            "frame=pict_type,key_frame",
            "-of",
            "json",
            str(path),
        ]
    )
    if frames_result.returncode != 0:
        raise RuntimeError(frames_result.stderr[-4000:])
    return streams[0], json.loads(frames_result.stdout).get("frames", [])


def score_decoded(
    decoded: bytes,
    width: int,
    height: int,
    frames: int,
) -> dict[str, Any]:
    frame_bytes = width * height * 4
    expected_size = frame_bytes * frames
    if len(decoded) != expected_size:
        raise RuntimeError(f"decoded size {len(decoded)} does not equal {expected_size}")

    total_squared = total_absolute = total_samples = 0
    text_squared = text_absolute = text_samples = 0
    for index in range(frames):
        original, mask, _ = generate_frame(width, height, index)
        offset = index * frame_bytes
        output = decoded[offset : offset + frame_bytes]
        for pixel in range(width * height):
            source_offset = pixel * 4
            for channel in range(3):
                delta = int(original[source_offset + channel]) - int(output[source_offset + channel])
                magnitude = abs(delta)
                total_squared += delta * delta
                total_absolute += magnitude
                total_samples += 1
                if mask[pixel]:
                    text_squared += delta * delta
                    text_absolute += magnitude
                    text_samples += 1

    def summarize(squared: int, absolute: int, samples: int) -> dict[str, Any]:
        if samples == 0:
            return {"samples": 0, "mean_absolute_error": None, "psnr_db": None, "exact": False}
        mse = squared / samples
        return {
            "samples": samples,
            "mean_absolute_error": absolute / samples,
            "psnr_db": None if mse == 0 else 10 * math.log10((255 * 255) / mse),
            "exact": mse == 0,
        }

    return {"full_frame": summarize(total_squared, total_absolute, total_samples), "text_pixels": summarize(text_squared, text_absolute, text_samples)}


def run_variant(
    directory: Path,
    raw: Path,
    encoder: str,
    variant: Variant,
    width: int,
    height: int,
    frames: int,
    fps: int,
    bitrate: str,
) -> dict[str, Any]:
    encoded = directory / f"{variant.name}.h264"
    decoded = directory / f"{variant.name}.bgra"
    command = [
        "ffmpeg",
        "-hide_banner",
        "-loglevel",
        "error",
        "-y",
        "-f",
        "rawvideo",
        "-pixel_format",
        "bgra",
        "-video_size",
        f"{width}x{height}",
        "-framerate",
        str(fps),
        "-i",
        str(raw),
        "-an",
        *encoder_arguments(encoder, variant, bitrate, fps),
        "-pix_fmt",
        variant.pixel_format,
        "-f",
        "h264",
        str(encoded),
    ]
    started = time.perf_counter_ns()
    encode = run(command)
    encode_elapsed_ns = time.perf_counter_ns() - started
    result: dict[str, Any] = {
        "name": variant.name,
        "requested_pixel_format": variant.pixel_format,
        "command": command,
        "encode_total_ms": encode_elapsed_ns / 1_000_000,
        "encode_wall_ms_per_frame": encode_elapsed_ns / frames / 1_000_000,
        "p95_encode_latency_ms": None,
        "latency_measurement": "batch wall-clock only; it is not per-frame encode latency",
    }
    if encode.returncode != 0:
        result.update(
            {
                "available": False,
                "passed": False,
                "encode_returncode": encode.returncode,
                "stderr": encode.stderr[-4000:],
            }
        )
        return result

    started = time.perf_counter_ns()
    decode = run(
        [
            "ffmpeg",
            "-hide_banner",
            "-loglevel",
            "error",
            "-y",
            "-flags",
            "low_delay",
            "-i",
            str(encoded),
            "-vframes",
            str(frames),
            "-f",
            "rawvideo",
            "-pix_fmt",
            "bgra",
            str(decoded),
        ]
    )
    decode_elapsed_ns = time.perf_counter_ns() - started
    if decode.returncode != 0:
        result.update(
            {
                "available": True,
                "passed": False,
                "decode_returncode": decode.returncode,
                "stderr": decode.stderr[-4000:],
            }
        )
        return result

    try:
        stream, frame_records = inspect_stream(encoded)
        decoded_bytes = decoded.read_bytes()
        score = score_decoded(decoded_bytes, width, height, frames)
    except (OSError, RuntimeError, json.JSONDecodeError) as error:
        result.update({"available": True, "passed": False, "error": str(error)})
        return result

    picture_types = [record.get("pict_type") for record in frame_records]
    b_frames = sum(picture_type == "B" for picture_type in picture_types)
    decoded_frames = len(decoded_bytes) // (width * height * 4)
    result.update(
        {
            "available": True,
            "passed": (
                stream.get("codec_name") == "h264"
                and int(stream.get("width", 0)) == width
                and int(stream.get("height", 0)) == height
                and int(stream.get("nb_read_frames", 0)) == frames
                and len(frame_records) == frames
                and decoded_frames == frames
                and b_frames == 0
            ),
            "stream": stream,
            "encoded_bytes": encoded.stat().st_size,
            "bytes_per_pixel_frame": encoded.stat().st_size / (width * height * frames),
            "decoded_frames": decoded_frames,
            "decode_total_ms": decode_elapsed_ns / 1_000_000,
            "decode_wall_ms_per_frame": decode_elapsed_ns / frames / 1_000_000,
            "picture_type_counts": {
                picture_type: picture_types.count(picture_type)
                for picture_type in sorted(set(picture_types))
                if picture_type is not None
            },
            "b_frames": b_frames,
            "quality": score,
        }
    )
    return result


def compare_to_baseline(results: list[dict[str, Any]]) -> dict[str, Any]:
    baseline = next((result for result in results if result["name"] == "base420"), None)
    alternate = next((result for result in results if result["name"] == "444"), None)
    if baseline is None or alternate is None or not baseline.get("passed") or not alternate.get("passed"):
        return {"comparison_available": False, "promotion_eligible": False, "reason": "both base420 and 444 must pass"}
    base_quality = baseline["quality"]["text_pixels"]["psnr_db"]
    alternate_quality = alternate["quality"]["text_pixels"]["psnr_db"]
    quality_delta = None if base_quality is None or alternate_quality is None else alternate_quality - base_quality
    return {
        "comparison_available": True,
        "text_psnr_delta_db": quality_delta,
        "byte_delta": alternate["encoded_bytes"] - baseline["encoded_bytes"],
        "p95_latency_comparable": False,
        "promotion_eligible": False,
        "reason": "synthetic corpus and batch timing cannot satisfy EXP-03's text/byte and P95-latency promotion gate",
    }


def self_test() -> int:
    frame, mask, workload = generate_frame(64, 48, 0)
    if workload != "ide" or len(frame) != 64 * 48 * 4 or len(mask) != 64 * 48 or not any(mask):
        raise AssertionError("synthetic corpus shape is invalid")
    exact = score_decoded(frame, 64, 48, 1)
    if not exact["full_frame"]["exact"] or exact["full_frame"]["mean_absolute_error"] != 0:
        raise AssertionError("exact score must be lossless")
    corrupted = bytearray(frame)
    corrupted[pixel_offset(64, 0, 0)] ^= 1
    score = score_decoded(bytes(corrupted), 64, 48, 1)
    if score["full_frame"]["exact"] or score["full_frame"]["mean_absolute_error"] <= 0:
        raise AssertionError("corruption must change the score")
    comparison = compare_to_baseline([])
    if comparison["promotion_eligible"]:
        raise AssertionError("an incomplete comparison must not promote")
    print(json.dumps({"self_test": "passed", "workload": workload}))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--encoder", default="libx264")
    parser.add_argument("--variants", default="base420,444")
    parser.add_argument("--width", type=int, default=640)
    parser.add_argument("--height", type=int, default=360)
    parser.add_argument("--frames", type=int, default=30)
    parser.add_argument("--fps", type=int, default=60)
    parser.add_argument("--bitrate", default="8M")
    parser.add_argument("--allow-unavailable", action="store_true")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()

    if args.self_test:
        return self_test()
    if any(value <= 0 for value in (args.width, args.height, args.frames, args.fps)):
        parser.error("width, height, frames, and fps must be positive")
    requested = tuple(part.strip() for part in args.variants.split(",") if part.strip())
    unknown = sorted(set(requested).difference(VARIANTS))
    if not requested or unknown:
        parser.error(f"variants must be drawn from {', '.join(VARIANTS)}")
    if not shutil.which("ffmpeg") or not shutil.which("ffprobe"):
        parser.error("ffmpeg and ffprobe are required")

    available = encoder_available(args.encoder)
    report: dict[str, Any] = {
        "experiment": "EXP-03",
        "question": "Does 4:4:4 improve synthetic desktop text quality or delivered bytes without a base H.264 4:2:0 latency regression?",
        "environment": {
            "ffmpeg": ffmpeg_version(),
            "encoder": args.encoder,
            "encoder_available": available,
            "hardware_encoder_name": is_hardware_encoder(args.encoder),
        },
        "configuration": {
            "width": args.width,
            "height": args.height,
            "frames": args.frames,
            "fps": args.fps,
            "bitrate": args.bitrate,
            "variants": requested,
            "corpus": "deterministic synthetic IDE, terminal, and browser text-like frames",
        },
        "roi": {"implemented": False, "reason": "provider-specific ROI side-data is intentionally outside this neutral probe"},
        "static_refinement": {"implemented": False, "reason": "v0.1 forbids building a refinement protocol before EXP-03 promotes it"},
        "promotion": {
            "eligible": False,
            "reason": "this probe uses synthetic input and batch timing; it cannot establish the required hardware P95 latency gate",
        },
    }
    if not available:
        report["results"] = []
        report["passed"] = bool(args.allow_unavailable)
        report["error"] = f"encoder {args.encoder!r} is unavailable"
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(json.dumps(report, indent=2))
        return 0 if args.allow_unavailable else 2

    with tempfile.TemporaryDirectory(prefix="latencydesk-exp03-") as temporary:
        directory = Path(temporary)
        raw = directory / "desktop-corpus.bgra"
        workloads = write_corpus(raw, args.width, args.height, args.frames)
        results = [
            run_variant(
                directory,
                raw,
                args.encoder,
                VARIANTS[name],
                args.width,
                args.height,
                args.frames,
                args.fps,
                args.bitrate,
            )
            for name in requested
        ]
    report["configuration"]["workload_frames"] = workloads
    report["results"] = results
    report["comparison"] = compare_to_baseline(results)
    report["passed"] = all(result.get("passed", False) for result in results if result["name"] == "base420")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0 if report["passed"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
