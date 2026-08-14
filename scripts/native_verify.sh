#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
rm -rf build
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
mkdir -p artifacts
./build/native/latencydesk_linux_capability_probe > artifacts/linux-capabilities.json
if command -v Xvfb >/dev/null 2>&1; then
  Xvfb :99 -screen 0 320x240x24 > artifacts/xvfb.log 2>&1 &
  xvfb_pid=$!
  trap 'kill "$xvfb_pid" 2>/dev/null || true' EXIT
  sleep 0.5
  DISPLAY=:99 ./build/native/latencydesk_linux_x11_capture_probe --frames 20 \
    > artifacts/x11-capture-probe.json
  kill "$xvfb_pid" 2>/dev/null || true
  wait "$xvfb_pid" 2>/dev/null || true
  trap - EXIT
fi
if command -v ffmpeg >/dev/null 2>&1 && command -v ffprobe >/dev/null 2>&1; then
  python3 scripts/ffmpeg_h264_probe.py
fi
