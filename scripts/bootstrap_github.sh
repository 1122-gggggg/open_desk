#!/usr/bin/env bash
set -euo pipefail
OWNER="${GITHUB_OWNER:-1122-gggggg}"
REPO="${GITHUB_REPO:-latencydesk}"
FULL="$OWNER/$REPO"

command -v gh >/dev/null 2>&1 || { echo "gh CLI unavailable" >&2; exit 2; }
gh auth status >/dev/null 2>&1 || { echo "gh CLI unauthenticated" >&2; exit 3; }

declare -A COLORS=(
  ["area: protocol"]="5319e7"
  ["area: windows"]="0078d4"
  ["area: linux"]="f5a623"
  ["area: codec"]="c2185b"
  ["area: transport"]="1d76db"
  ["area: benchmark"]="0e8a16"
  ["area: security"]="b60205"
  ["area: backend"]="6f42c1"
  ["milestone: m1"]="d4c5f9"
  ["milestone: m2"]="bfdadc"
  ["milestone: m3"]="c2e0c6"
  ["milestone: m4"]="fef2c0"
  ["milestone: m5"]="f9d0c4"
  ["milestone: m6"]="e4e669"
)
for label in "${!COLORS[@]}"; do
  gh label create "$label" --repo "$FULL" --color "${COLORS[$label]}" --force >/dev/null
 done

create_issue_once() {
  local title="$1" labels="$2" body="$3"
  if gh issue list --repo "$FULL" --state all --search "in:title $title" --json title --jq '.[].title' | grep -Fxq "$title"; then
    return
  fi
  gh issue create --repo "$FULL" --title "$title" --label "$labels" --body "$body" >/dev/null
}

create_issue_once "[M1] Deterministic loopback laboratory" "milestone: m1,area: protocol" \
"Implement fake capture, bounded fragment/reassembly, exact test codec, hostile network simulator, input snapshots, and fuzz/property tests. Exit criteria: docs/ROADMAP.md M1."

create_issue_once "[M2] Windows DDA capture and bounded surface ownership" "milestone: m2,area: windows,area: backend" \
"Implement per-user DDA capture with prompt release of acquired frames, adapter-aware import, and forced GPU/CPU copy fallback. Include 30-minute soak and queue telemetry."

create_issue_once "[M2] Low-delay H.264 provider and continuity contract" "milestone: m2,area: codec,area: backend" \
"Implement the first hardware H.264 provider with no B-frames/lookahead, bounded surfaces, codec epochs, conservative dependency metadata, and recovery-point requests."

create_issue_once "[M3] Linux Wayland hardware decode and renderer" "milestone: m3,area: linux,area: backend" \
"Build Windows-host to Linux-client path with bounded hardware decode/render queue, local cursor, color/scale tests, and forced-copy fallback."

create_issue_once "[M4] Linux Portal/PipeWire/libei host backend" "milestone: m4,area: linux,area: backend" \
"Implement explicit portal lifecycle, PipeWire capture with DMA-BUF capability and MemFd/copy fallback, libei input, revoke/cancel handling, and stuck-key tests."

create_issue_once "[M5] QUIC control/media/input transport" "milestone: m5,area: transport,area: security" \
"Implement TLS-authenticated QUIC streams and DATAGRAM paths, path-MTU-safe packetization, bounded reassembly, pacing/adaptation, recovery coalescing, and weak-network tests."

create_issue_once "[M6] Sparse exact tile refinement" "milestone: m6,area: codec,area: benchmark" \
"After baseline freeze, implement independently discardable exact tiles, bounded cache/epochs/hash checks, idle refinement policy, and comparative text/bandwidth/latency benchmarks."

create_issue_once "[Benchmark] Build optical input-to-photon rig and public protocol" "area: benchmark" \
"Implement and document high-speed-camera or photodiode measurement. Publish raw traces, p50/p95/p99, display scanout method, hardware, network profile, and competitor settings."

echo "GitHub labels and issues initialized for $FULL"
