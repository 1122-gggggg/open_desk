# LatencyDesk

**Ultra-Low-Latency Native Remote Desktop Engine for Direct LAN 1080p120**

LatencyDesk is a high-performance, security-hardened remote desktop system engineered for sub-frame latency, zero-unbounded-queueing, and strict hardware ownership.

---

## Key Highlights

- **Direct-LAN 1080p120 Profile**: End-to-end hardware pipeline engineered for high-refresh-rate, low-jitter desktop interaction over wired LAN.
- **QUIC / TLS 1.3 Transport**: Single Quinn QUIC connection providing authenticated reliable control/input streams and deadline-expiring media DATAGRAMs.
- **Zero-Unbounded-Queue Architecture**: Every buffer, queue, and allocation has static capacity (1..=4 frames in flight); stale frames are automatically dropped before queue buildup.
- **Hardware-Accelerated Windows Path**:
  - **Capture**: DXGI Desktop Duplication (DDA) and Windows Graphics Capture (WGC) with epoch-bound protected content masking.
  - **Color Conversion**: Direct3D 11 Video Processor hardware BGRA $\to$ NV12 conversion with strict BT.709 color contract.
  - **Encoding**: Media Foundation hardware H.264 encoder configured for ultra-low latency, real-time rate control, 0 B-frames, and dynamic forced IDR recovery.
  - **Input & Presentation**: UIPI-gated `SendInput` with emergency release-all and Direct3D 11 swap chain presentation with fence completion tracking.
- **Modern Linux Path**: XDG Desktop Portal ScreenCast/RemoteDesktop, PipeWire DMA-BUF zero-copy buffer import, Wayland presentation timing, and libei input.
- **Cryptographic Device Identity**: Pinned TLS SPKI fingerprints and short authentication string (SAS) pairing without unauthenticated data paths.

---

## Architecture Overview

```
 ┌───────────────────────────────────────────────────────────────────────────┐
 │                               HOST SYSTEM                                 │
 │                                                                           │
 │  ┌───────────────────────┐         ┌───────────────────────────────────┐  │
 │  │ DXGI Desktop Output   │         │ D3D11 Video Processor             │  │
 │  │ (DDA / WGC Capture)   │────────▶│ (Hardware BGRA -> NV12 Conversion)│  │
 │  └───────────────────────┘         └─────────────────┬─────────────────┘  │
 │                                                      │                    │
 │  ┌───────────────────────┐         ┌─────────────────▼─────────────────┐  │
 │  │ Win32 SendInput       │         │ Media Foundation H.264 Encoder    │  │
 │  │ (UIPI / Security Gate)│         │ (Low-Delay, 0 B-Frames, IDR Sync) │  │
 │  └───────────▲───────────┘         └─────────────────┬─────────────────┘  │
 └──────────────┼───────────────────────────────────────┼────────────────────┘
                │ Control / Input Streams               │ Media DATAGRAMs
                │ (Reliable Ordered)                    │ (Deadline Expiring)
                ▼                                       ▼
 ┌───────────────────────────────────────────────────────────────────────────┐
 │                     QUINN QUIC / TLS 1.3 TRANSPORT                        │
 └───────────────────────────────────────────────────────────────────────────┘
                │                                       │
                ▼                                       ▼
 ┌───────────────────────────────────────────────────────────────────────────┐
 │                              CLIENT SYSTEM                                │
 │                                                                           │
 │  ┌───────────────────────┐         ┌───────────────────────────────────┐  │
 │  │ Client Local Input    │         │ H.264 Hardware Decoder            │  │
 │  │ (Reconciler & Sync)   │         │ (Continuity & Recovery Tracker)   │  │
 │  └───────────────────────┘         └─────────────────┬─────────────────┘  │
 │                                                      │                    │
 │                                    ┌─────────────────▼─────────────────┐  │
 │                                    │ Direct3D 11 / Wayland Swap Chain  │  │
 │                                    │ (Presentation Completion Fences)  │  │
 │                                    └───────────────────────────────────┘  │
 └───────────────────────────────────────────────────────────────────────────┘
```

---

## Building & Packaging

### Prerequisites
- **Rust**: 1.78+ (`rustup toolchain install stable`)
- **Windows**: Visual Studio 2022 / Build Tools with C++20 and Windows 11 SDK
- **Linux**: GCC/Clang with C++20, CMake 3.20+, `libx11-dev`, `libpipewire-0.3-dev`

### Compilation
```bash
# Build all workspace packages
cargo build --release --workspace

# Run complete workspace tests
cargo test --workspace --all-targets

# Run linter and formatting checks
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

### Packaging Release Binaries
- **Windows**:
  ```powershell
  pwsh -File scripts/package.ps1
  ```
  Produces `artifacts/release/windows-x86_64/` with `latencydesk-host.exe`, `latencydesk-client.exe`, `release-manifest.json`, and `LatencyDesk-windows-x86_64.zip`.

- **Linux**:
  ```bash
  ./scripts/package.sh
  ```
  Produces `artifacts/release/linux-x86_64/` with `latencydesk-host`, `latencydesk-client`, `release-manifest.json`, and `LatencyDesk-linux-x86_64.tar.gz`.

---

## Quick Start Guide

### 1. Launching Host
```bash
# Start host listening on all interfaces with 1080p120 profile
latencydesk-host --listen 0.0.0.0:9000 --1080p120-profile
```

### 2. Connecting Client
```bash
# Connect to remote host
latencydesk-client --connect 192.168.1.100:9000 --1080p120-profile
```

### 3. Pairing & Security Verification
Upon initial connection, both sides compute and display a 6-digit Short Authentication String (SAS) derived from SHA-256 over canonical pairing evidence. Once confirmed, the peer TLS SPKI fingerprint is permanently pinned.

---

## Latency Benchmark & Comparison Protocol

To ensure reproducible, truthful performance statements against any baseline remote desktop solution:

1. **Strict Metadata Validation**: Both baseline and candidate must operate on identical resolution (1920x1080), framerate (120 fps or 60 fps), color format (SDR BT.709), and physical network medium (direct wired LAN).
2. **Comparison Tool**:
   ```bash
   python scripts/compare-latency.py path/to/baseline.json path/to/latencydesk.json
   ```
3. The comparison report evaluates per-stage p50, p95, and p99 metrics:
   - Capture to Color Convert
   - Convert to Encode Submit
   - Hardware Video Encode
   - QUIC Transport Delivery
   - Receive to Decode
   - Decode to Present Fence
   - Total Pipeline Processing

---

## License

Apache-2.0 or MIT.
