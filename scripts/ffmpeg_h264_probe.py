#!/usr/bin/env python3
"""Execute a real low-delay H.264 encode/decode conformance probe.

The default software encoder is an executable fallback gate. Pass
`--encoder h264_nvenc` on supported NVIDIA hosts to exercise the hardware path.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARTIFACT = ROOT / "artifacts" / "ffmpeg-h264-probe.json"


def run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, text=True, capture_output=True, check=check)


def encoder_available(name: str) -> bool:
    result = run(["ffmpeg", "-hide_banner", "-encoders"], check=False)
    return any(line.split()[1:2] == [name] for line in result.stdout.splitlines() if line.strip())


def write_bgra(path: Path, width: int, height: int, frames: int) -> None:
    with path.open("wb") as stream:
        for frame in range(frames):
            caret = (frame * 5) % width
            data = bytearray(width * height * 4)
            for y in range(height):
                row, stroke = divmod(y, 12)
                for x in range(width):
                    glyph = (x // 7 + row + 17) % 11
                    if caret <= x < caret + 2 and 1 < stroke < 11:
                        b = g = r = 255
                    elif stroke in (3, 8) or glyph == 0:
                        b, g, r = 210, 220, 225
                    else:
                        b, g, r = 20, 23, 27
                    offset = (y * width + x) * 4
                    data[offset : offset + 4] = bytes((b, g, r, 255))
            stream.write(data)


def encoder_arguments(name: str, bitrate: str, fps: int) -> list[str]:
    common = ["-bf", "0", "-g", str(fps), "-pix_fmt", "yuv420p"]
    if name == "libx264":
        return ["-c:v", name, "-preset", "ultrafast", "-tune", "zerolatency", "-sc_threshold", "0", *common]
    if name == "h264_nvenc":
        return [
            "-c:v", name,
            "-preset", "p1",
            "-tune", "ull",
            "-rc", "cbr",
            "-b:v", bitrate,
            "-maxrate", bitrate,
            "-bufsize", bitrate,
            "-delay", "0",
            "-forced-idr", "1",
            *common,
        ]
    if name == "h264_qsv":
        return ["-c:v", name, "-preset", "veryfast", "-look_ahead", "0", "-b:v", bitrate, *common]
    if name == "h264_vaapi":
        return ["-c:v", name, "-rc_mode", "CBR", "-b:v", bitrate, *common]
    return ["-c:v", name, *common]



def annex_b_nal_types(data: bytes) -> list[int]:
    starts: list[tuple[int, int]] = []
    cursor = 0
    while cursor + 3 <= len(data):
        if data[cursor:cursor + 4] == b"\x00\x00\x00\x01":
            starts.append((cursor, 4))
            cursor += 4
        elif data[cursor:cursor + 3] == b"\x00\x00\x01":
            starts.append((cursor, 3))
            cursor += 3
        else:
            cursor += 1
    result: list[int] = []
    for index, (start, prefix) in enumerate(starts):
        nal_start = start + prefix
        nal_end = starts[index + 1][0] if index + 1 < len(starts) else len(data)
        if nal_start < nal_end:
            header = data[nal_start]
            if header & 0x80:
                raise RuntimeError("H.264 forbidden_zero_bit was set")
            result.append(header & 0x1F)
    return result

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--encoder", default="libx264")
    parser.add_argument("--width", type=int, default=320)
    parser.add_argument("--height", type=int, default=180)
    parser.add_argument("--frames", type=int, default=60)
    parser.add_argument("--fps", type=int, default=60)
    parser.add_argument("--bitrate", default="8M")
    parser.add_argument("--allow-unavailable", action="store_true")
    args = parser.parse_args()

    if not shutil.which("ffmpeg") or not shutil.which("ffprobe"):
        raise SystemExit("ffmpeg and ffprobe are required")
    if args.width <= 0 or args.height <= 0 or args.frames <= 0 or args.fps <= 0:
        raise SystemExit("dimensions, frames, and fps must be positive")
    if not encoder_available(args.encoder):
        report = {"encoder": args.encoder, "available": False, "passed": bool(args.allow_unavailable)}
        ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        ARTIFACT.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report))
        return 0 if args.allow_unavailable else 2

    with tempfile.TemporaryDirectory(prefix="latencydesk-h264-") as directory:
        temp = Path(directory)
        raw = temp / "input.bgra"
        encoded = temp / "stream.h264"
        decoded = temp / "decoded.bgra"
        psnr_log = temp / "psnr.log"
        write_bgra(raw, args.width, args.height, args.frames)
        frame_bytes = args.width * args.height * 4
        expected_raw_bytes = frame_bytes * args.frames
        if raw.stat().st_size != expected_raw_bytes:
            raise RuntimeError("raw generator size mismatch")

        command = [
            "ffmpeg", "-hide_banner", "-loglevel", "error", "-y",
            "-f", "rawvideo", "-pixel_format", "bgra",
            "-video_size", f"{args.width}x{args.height}",
            "-framerate", str(args.fps), "-i", str(raw),
            "-an", *encoder_arguments(args.encoder, args.bitrate, args.fps),
            "-f", "h264", str(encoded),
        ]
        begin = time.perf_counter_ns()
        encode = run(command, check=False)
        encode_ns = time.perf_counter_ns() - begin
        if encode.returncode != 0:
            report = {
                "encoder": args.encoder,
                "available": True,
                "passed": False,
                "encode_returncode": encode.returncode,
                "stderr": encode.stderr[-4000:],
            }
            ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
            ARTIFACT.write_text(json.dumps(report, indent=2) + "\n")
            print(json.dumps(report))
            return 3

        probe = run([
            "ffprobe", "-v", "error", "-count_frames", "-select_streams", "v:0",
            "-show_entries", "stream=codec_name,width,height,nb_read_frames",
            "-of", "json", str(encoded),
        ])
        stream = json.loads(probe.stdout)["streams"][0]
        frames_probe = run([
            "ffprobe", "-v", "error", "-select_streams", "v:0",
            "-show_entries", "frame=pict_type,key_frame", "-of", "json", str(encoded),
        ])
        frame_records = json.loads(frames_probe.stdout).get("frames", [])
        picture_types = [record.get("pict_type") for record in frame_records]
        b_frames = sum(picture_type == "B" for picture_type in picture_types)
        keyframes = sum(int(record.get("key_frame", 0)) for record in frame_records)
        nal_types = annex_b_nal_types(encoded.read_bytes())

        begin = time.perf_counter_ns()
        decode = run([
            "ffmpeg", "-hide_banner", "-loglevel", "error", "-y",
            "-flags", "low_delay", "-i", str(encoded),
            "-f", "rawvideo", "-pix_fmt", "bgra", str(decoded),
        ], check=False)
        decode_ns = time.perf_counter_ns() - begin
        if decode.returncode != 0:
            raise RuntimeError(f"decode failed: {decode.stderr[-2000:]}")

        psnr = run([
            "ffmpeg", "-hide_banner", "-y",
            "-f", "rawvideo", "-pixel_format", "bgra",
            "-video_size", f"{args.width}x{args.height}",
            "-framerate", str(args.fps), "-i", str(raw),
            "-i", str(encoded),
            "-lavfi", f"[0:v][1:v]psnr=stats_file={psnr_log}",
            "-f", "null", "-",
        ], check=False)
        match = re.search(r"average:([0-9.]+|inf)", psnr.stderr)
        average_psnr = match.group(1) if match else None
        decoded_bytes = decoded.stat().st_size
        decoded_frames = decoded_bytes // frame_bytes
        encoded_bytes = encoded.stat().st_size
        report = {
            "encoder": args.encoder,
            "available": True,
            "passed": (
                stream.get("codec_name") == "h264"
                and int(stream.get("width", 0)) == args.width
                and int(stream.get("height", 0)) == args.height
                and int(stream.get("nb_read_frames", 0)) == args.frames
                and decoded_frames == args.frames
                and len(frame_records) == args.frames
                and b_frames == 0
                and keyframes >= 1
                and 5 in nal_types
                and 7 in nal_types
                and 8 in nal_types
            ),
            "width": args.width,
            "height": args.height,
            "frames": args.frames,
            "fps": args.fps,
            "encoded_bytes": encoded_bytes,
            "bits_per_pixel_frame": encoded_bytes * 8 / (args.width * args.height * args.frames),
            "encode_total_ms": encode_ns / 1_000_000,
            "encode_wall_ms_per_frame": encode_ns / args.frames / 1_000_000,
            "decode_total_ms": decode_ns / 1_000_000,
            "decode_wall_ms_per_frame": decode_ns / args.frames / 1_000_000,
            "decoded_frames": decoded_frames,
            "picture_type_counts": {
                picture_type: picture_types.count(picture_type)
                for picture_type in sorted(set(picture_types))
                if picture_type is not None
            },
            "b_frames": b_frames,
            "keyframes": keyframes,
            "annex_b_nal_types": sorted(set(nal_types)),
            "has_sps_pps_idr": all(nal_type in nal_types for nal_type in (7, 8, 5)),
            "average_psnr_db": average_psnr,
            "command": command,
            "note": "wall-clock batch probe; not optical or per-frame hardware latency",
        }
        ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
        ARTIFACT.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
        return 0 if report["passed"] else 4


if __name__ == "__main__":
    raise SystemExit(main())
