#!/usr/bin/env bash
# LatencyDesk Linux Packaging Script
# Generates release binaries, SHA-256 checksums, release-manifest.json, and distribution tarball.

set -euo pipefail

OUT_DIR="${1:-artifacts/release/linux-x86_64}"
TARGET="${2:-x86_64-unknown-linux-gnu}"

echo "=== LatencyDesk Linux Packaging ==="
echo "Target: $TARGET"
echo "Output Directory: $OUT_DIR"

# 1. Build release binaries
echo -e "\n[1/4] Building release binaries..."
cargo build --release --target "$TARGET" -p latencydesk-host -p latencydesk-client

# 2. Ensure output directory
mkdir -p "$OUT_DIR"

HOST_BIN="target/$TARGET/release/latencydesk-host"
if [[ ! -f "$HOST_BIN" ]]; then
    HOST_BIN="target/release/latencydesk-host"
fi
CLIENT_BIN="target/$TARGET/release/latencydesk-client"
if [[ ! -f "$CLIENT_BIN" ]]; then
    CLIENT_BIN="target/release/latencydesk-client"
fi

cp "$HOST_BIN" "$OUT_DIR/latencydesk-host"
cp "$CLIENT_BIN" "$OUT_DIR/latencydesk-client"
chmod +x "$OUT_DIR/latencydesk-host" "$OUT_DIR/latencydesk-client"

# 3. Compute SHA-256 checksums
echo -e "\n[2/4] Computing SHA-256 checksums..."
HOST_HASH=$(sha256sum "$OUT_DIR/latencydesk-host" | awk '{print $1}')
CLIENT_HASH=$(sha256sum "$OUT_DIR/latencydesk-client" | awk '{print $1}')
HOST_SIZE=$(stat -c%s "$OUT_DIR/latencydesk-host" 2>/dev/null || stat -f%z "$OUT_DIR/latencydesk-host")
CLIENT_SIZE=$(stat -c%s "$OUT_DIR/latencydesk-client" 2>/dev/null || stat -f%z "$OUT_DIR/latencydesk-client")

echo "Host:   $HOST_HASH ($HOST_SIZE bytes)"
echo "Client: $CLIENT_HASH ($CLIENT_SIZE bytes)"

# 4. Generate release manifest
echo -e "\n[3/4] Generating release manifest..."
GIT_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
ISO_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

cat <<EOF > "$OUT_DIR/release-manifest.json"
{
  "schema_version": 1,
  "product": "LatencyDesk",
  "version": "0.1.0-alpha.2",
  "commit": "$GIT_COMMIT",
  "target_triple": "$TARGET",
  "created_at": "$ISO_DATE",
  "provider_matrix": {
    "capture": "xdg_portal_screencast_pipewire",
    "encoder": "hardware_vaapi_v4l2_h264",
    "renderer": "wayland_dmabuf_presentation_time",
    "input": "xdg_portal_remotedesktop_libei"
  },
  "default_profile": {
    "resolution": "1920x1080",
    "fps": 120,
    "color_space": "SDR_BT709",
    "transport": "quinn_quic_tls13_direct_lan"
  },
  "artifacts": [
    {
      "name": "latencydesk-host",
      "path": "latencydesk-host",
      "sha256": "$HOST_HASH",
      "size_bytes": $HOST_SIZE
    },
    {
      "name": "latencydesk-client",
      "path": "latencydesk-client",
      "sha256": "$CLIENT_HASH",
      "size_bytes": $CLIENT_SIZE
    }
  ]
}
EOF

echo "Manifest written to $OUT_DIR/release-manifest.json"

# 5. Create distribution tarball
echo -e "\n[4/4] Creating tarball distribution archive..."
mkdir -p "artifacts/release"
TAR_PATH="artifacts/release/LatencyDesk-linux-x86_64.tar.gz"
tar -czf "$TAR_PATH" -C "$OUT_DIR" .
echo "Distribution archive created: $TAR_PATH"

echo -e "\nPackaging completed successfully!"
