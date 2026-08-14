#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python3 scripts/static_validate.py
python3 scripts/source_sanity.py
python3 scripts/reference_lab.py --fuzz-iterations "${LATENCYDESK_FUZZ_ITERATIONS:-25000}"
python3 scripts/surface_reference.py --iterations "${LATENCYDESK_SURFACE_ITERATIONS:-50000}"
python3 scripts/udp_reference.py --frames "${LATENCYDESK_UDP_FRAMES:-8}"

if command -v cmake >/dev/null 2>&1 && command -v ninja >/dev/null 2>&1; then
  ./scripts/native_verify.sh
elif command -v ffmpeg >/dev/null 2>&1 && command -v ffprobe >/dev/null 2>&1; then
  python3 scripts/ffmpeg_h264_probe.py --encoder libx264 --frames 30
fi
