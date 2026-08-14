# QUIC-First Native Remote Desktop Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `subagent-driven-development` or `executing-plans` task-by-task. Each checkbox is an independently reviewable, tested change.

**Goal:** Ship native Windows and Linux Host/Client binaries for the approved direct-LAN 1080p120 SDR profile, with measured per-stage latency, pinned device identity, explicit host authorization, bounded GPU/resource ownership, and deployable release artifacts.

**Architecture:** One Quinn QUIC/TLS 1.3 connection carries bounded application control and input streams plus frame-expiring media DATAGRAMs. Safe Rust owns framing, authorization, capacity, epochs, and lifecycle gates. Platform crates retain all OS/COM/Portal/GPU interaction behind existing provider traits. `latencydesk-runtime` is the only product composition root.

**Tech Stack:** Rust 1.78; Quinn 0.11.8 with Tokio and rustls-ring; TLS 1.3; existing H.264/transport/telemetry crates; C++20 D3D11/DXGI/Media Foundation bridge on Windows; XDG Portal/PipeWire/EIS/libei-capability path on Linux.

## Global Constraints

- v0.1 is one logged-in interactive session, one authorized SDR display, direct LAN only. WSL, relays, NAT traversal, secure desktop/UAC, unattended control, HDR, audio, clipboard, file transfer, and generic Wayland input bypass are excluded.
- TLS 1.3 through QUIC is the sole transport cryptographic construction. Do not add Noise, a second AEAD layer, custom UDP retransmission, application nonces, or 0-RTT application data.
- `latencydesk-protocol` has no runtime, crypto, transport, session, or platform dependency. Every peer-controlled length is checked before allocation; every application parser rejects trailing bytes.
- Production capture, decode, encode, render, and input paths use finite queues and existing ownership guards. A failed capability probe must close safely or select a documented bounded fallback; it must not silently create CPU round trips.
- `FakeCapture`, `ExactTestCodec`, raw `UdpEndpoint`, and simulated `--interactive` input remain test/lab-only and are absent from product Host/Client dependency graphs.
- Windows and Linux processes bind their own native sockets. All application messages wait for full TLS authentication; do not use `Connecting::into_0rtt`.
- Every provider invocation rechecks `{ generation, authorization_epoch, display_epoch, codec_epoch }`. Close/revocation/input failure releases local held input before waiting for media or presentation work.
- An AnyDesk-performance statement requires same-device, same-monitor-mode, same-wired-network raw benchmark evidence. Until then describe only the measured LatencyDesk profile.

## File Structure

| Path | Responsibility |
|---|---|
| `Cargo.toml`, `Cargo.lock` | Pin QUIC runtime dependencies once and remove the obsolete Noise dependency graph. |
| `crates/protocol/src/quic.rs` | Bounded application control/input envelopes, session stamp, media envelope, canonical framing. |
| `crates/protocol/src/lib.rs` | Re-export QUIC-agnostic protocol types; retire legacy unauthenticated pairing bytes after session migration. |
| `crates/socket-transport/src/quic.rs` | Quinn endpoint, authenticated connection admission, finite stream readers/writers, DATAGRAM outcome policy. |
| `crates/socket-transport/src/lib.rs` | Public QUIC transport API; test-only raw socket types remain explicitly lab scoped. |
| `crates/session/src/{pairing,runtime}.rs` | Persistent identity pin, SAS approval, host lease, dispatch stamps, close/release authority. |
| `crates/platform/src/lib.rs` | `DeviceIdentityStore`, independent emergency input release, provider selection and stable diagnostics. |
| `crates/runtime/src/lib.rs` | Host/Client role coordinators that gate native providers through accepted QUIC sessions. |
| `crates/platform-windows/src/*`, `native/windows/*` | DDA/WGC selection, D3D11 ownership, Media Foundation encode/decode/present, SendInput, WER guard. |
| `crates/platform-linux/src/*`, `native/linux/*` | Portal lifetime, PipeWire buffer import, Wayland presentation, authorized input and core-dump guard. |
| `crates/telemetry/src/lib.rs`, `apps/lab/src/main.rs` | Same-clock stage measurements, reproducible latency report, compare-input fixture. |
| `apps/{host,client}/src/main.rs` | Native-only role CLI, pairing UI, provider selection, runtime diagnostics. |
| `scripts/{package.ps1,package.sh}`, `.github/workflows/ci.yml` | Reproducible platform artifacts, checksums, core/native test matrix. |

---

## Task 1: Migrate the dependency boundary to QUIC

**Files:**
- Modify: `Cargo.toml`, `Cargo.lock`
- Modify: `crates/socket-transport/Cargo.toml`
- Modify: `crates/session/Cargo.toml`
- Modify: `crates/runtime/Cargo.toml`, `crates/runtime/src/lib.rs`
- Modify: `apps/host/Cargo.toml`, `apps/client/Cargo.toml`

**Interfaces:**
- `latencydesk-runtime` remains the only composition crate.
- Workspace pins `quinn = "0.11.8"` with `runtime-tokio`, `rustls-ring`, and `log`; socket transport owns the direct Quinn/Tokio runtime boundary.
- `snow` is absent from all manifests and lockfile; `zeroize` remains only where session/private identity material requires it.

- [x] **Step 1: Add the failing dependency-boundary documentation test.**

```rust
//! ```compile_fail
//! use latencydesk_socket_transport::SecureSessionRuntime;
//! let _ = SecureSessionRuntime::new();
//! ```
```

- [x] **Step 2: Run `cargo test -p latencydesk-runtime --doc`; confirm the unavailable composition type rejects.**

- [x] **Step 3: Add Quinn/Tokio dependencies only to `latencydesk-socket-transport`; remove `snow`; retain application dependencies only if their product caller still exists.**

```toml
quinn = { version = "0.11.8", default-features = false, features = ["runtime-tokio", "rustls-ring", "log"] }
tokio = { version = "1", features = ["io-util", "macros", "net", "rt-multi-thread", "sync", "time"] }
```

- [x] **Step 4: Run `cargo test -p latencydesk-runtime --doc` and `cargo metadata --no-deps --format-version 1`; verify protocol remains dependency-free.**

- [x] **Step 5: Commit `build: establish QUIC runtime boundary`.**

## Task 2: Define bounded QUIC application framing

**Files:**
- Create: `crates/protocol/src/quic.rs`
- Modify: `crates/protocol/src/lib.rs`
- Test: inline tests in `crates/protocol/src/quic.rs`

**Interfaces:**

```rust
pub struct SessionStamp {
    pub session_id: u64,
    pub generation: u64,
    pub authorization_epoch: u32,
    pub display_epoch: u32,
    pub codec_epoch: u32,
}
pub enum StreamKind { Control, Input }
pub struct StreamRecord<'a> { pub kind: StreamKind, pub stamp: SessionStamp, pub payload: &'a [u8] }
pub struct MediaDatagram<'a> { pub stamp: SessionStamp, pub expires_at_ns: u64, pub packet: MediaPacket<'a> }
```

- [x] **Step 1: Write failing tests for exact stream record length, reserved bits, zero session/generation, inactive input/media stamps, invalid stream class, media expiry, truncated header, and trailing bytes. Pairing control records deliberately permit zero authorization/display/codec epochs before activation.**

```rust
#[test]
fn media_datagram_rejects_trailing_or_declared_length_mismatch() { /* exact bytes only */ }
#[test]
fn stream_record_rejects_control_as_media_and_input_as_control() { /* class policy */ }
#[test]
fn input_record_rejects_pending_stamp() { /* authorization/display required */ }
```

- [x] **Step 2: Run `cargo test -p latencydesk-protocol quic -- --nocapture`; confirm the types are absent.**

- [x] **Step 3: Implement fixed-width network-byte-order encoders/decoders using stack headers and validated borrowed payloads. Media wraps the existing `MediaPacket` rather than copying a second frame buffer.**

- [x] **Step 4: Add the control/input payload cap constants and use checked `usize` arithmetic before allocation.**

- [x] **Step 5: Run `cargo test -p latencydesk-protocol && cargo clippy -p latencydesk-protocol -- -D warnings`; commit `feat(protocol): add QUIC application framing`.**

## Task 3: Implement authenticated Quinn lane transport

**Files:**
- Create: `crates/socket-transport/src/quic.rs`
- Modify: `crates/socket-transport/src/lib.rs`
- Modify: `crates/socket-transport/Cargo.toml`
- Test: inline loopback tests in `crates/socket-transport/src/quic.rs`

**Interfaces:**

```rust
pub struct QuicConnection { /* private Quinn connection and peer identity */ }
pub enum MediaSendOutcome { Sent, DroppedExpired, DroppedTooLarge, Unsupported }
impl QuicConnection {
    pub async fn send_control(&self, record: &[u8]) -> Result<(), QuicTransportError>;
    pub async fn send_input(&self, record: &[u8]) -> Result<(), QuicTransportError>;
    pub fn send_media(&self, datagram: Bytes, now_ns: u64, expires_at_ns: u64) -> Result<MediaSendOutcome, QuicTransportError>;
    pub async fn receive_media(&self) -> Result<Bytes, QuicTransportError>;
}
```

- [x] **Step 1: Write loopback tests using ephemeral test certificates for full TLS authentication, independent reliable control/input order, DATAGRAM size rejection, expiry drop, connection close, and no 0-RTT admission.**

```rust
#[tokio::test]
async fn expired_media_is_dropped_without_blocking_control() { /* fixed clock */ }
#[tokio::test]
async fn control_and_input_keep_independent_ordered_streams() { /* A/B records */ }
```

- [x] **Step 2: Run the tests; confirm the absent `QuicConnection` API fails to compile.**

- [x] **Step 3: Build `quinn::Endpoint` with address-family-specific bind configuration, fully await `Connecting`, create exactly one bounded send writer per reliable lane, and reject all messages before connection authentication.**

- [x] **Step 4: Map `SendDatagramError::{UnsupportedByPeer, Disabled, TooLarge, ConnectionLost}` to the explicit outcome/error policy. Do not retry, queue, or reroute expired media onto a stream.**

- [x] **Step 5: Read every received stream with a protocol cap, decode before session dispatch, and close on malformed authenticated application data.**

- [x] **Step 6: Run `cargo test -p latencydesk-socket-transport`; commit `feat(transport): add bounded QUIC lanes`.**

## Task 4: Replace legacy pairing with pinned TLS device identity

**Files:**
- Modify: `crates/session/src/pairing.rs`, `crates/session/src/lib.rs`
- Create: `crates/session/src/runtime.rs`
- Modify: `crates/platform/src/lib.rs`
- Modify: `crates/protocol/src/lib.rs`
- Test: inline session and protocol tests

**Interfaces:**

```rust
pub trait DeviceIdentityStore: Send + Sync {
    fn load_or_create_identity(&self) -> Result<DeviceIdentity, PlatformError>;
    fn load_peer_pin(&self, alias: &PeerAlias) -> Result<Option<PeerPin>, PlatformError>;
    fn store_peer_pin(&self, alias: &PeerAlias, pin: PeerPin) -> Result<(), PlatformError>;
}
pub struct PairingEvidence { pub session_id: SessionId, pub local_fingerprint: [u8; 32], pub peer_fingerprint: [u8; 32], pub expires_at_ns: u64, pub capabilities: CapabilitySet }
```

- [ ] **Step 1: Write failing tests: a pin mismatch rejects before SAS; either local approval without peer acknowledgement cannot activate; three wrong SAS attempts terminate the attempt; store failure closes; no pairing diagnostic contains secret material.**
- [ ] **Step 2: Implement a six-digit SAS from the canonical pairing evidence and SHA-256, without retaining SAS/transcript material after confirmation. The TLS peer certificate/SPKI fingerprint must equal the selected pin before `AcceptedSession` exists.**
- [ ] **Step 3: Migrate the sole callers of `PairingWireKind`, `PairingRequestWire`, `PairingResponseWire`, and `SasConfirmWire`; remove their public exports and tests atomically.**
- [ ] **Step 4: Define `SessionAuthority::{acquire_dispatch,recheck,close}` with every epoch in `DispatchStamp`; `close` returns the old input ledger and an independent release deadline.**
- [ ] **Step 5: Run `cargo test -p latencydesk-session -p latencydesk-protocol`; commit `feat(session): pin QUIC peer identity and authority`.**

## Task 5: Compose real Host and Client runtime coordinators

**Files:**
- Modify: `crates/runtime/src/lib.rs`
- Modify: `crates/runtime/Cargo.toml`
- Test: inline runtime tests with recording providers

**Interfaces:**

```rust
pub struct HostRuntime<C, E, I, S> { /* capture, encoder, input, session */ }
pub struct ClientRuntime<D, R, I, S> { /* decoder, renderer, local input, session */ }
pub enum RuntimeProgress { PairingPending, AwaitingLocalApproval, Streaming, Recovering, Closing, Closed }
```

- [ ] **Step 1: Write recording-provider tests showing unapproved media never invokes encode/decode/render, stale generation never invokes a provider, input release precedes non-input draining, and expired media cannot block control.**
- [ ] **Step 2: Have Host acquire a dispatch permit before capture/encode/send; use the existing `EncoderSubmissionGuard` and release only after native completion.**
- [ ] **Step 3: Have Client validate reassembly/continuity, retain at most one newest valid decoded frame, and use `PresentationSubmissionGuard` through exact completion.**
- [ ] **Step 4: Route all close and recovery transitions through `SessionAuthority::close`; zeroize transient identity/session material and expose secret-free diagnostics only.**
- [ ] **Step 5: Run `cargo test -p latencydesk-runtime`; commit `feat(runtime): compose QUIC-gated roles`.**

## Task 6: Build the Windows native provider boundary

**Files:**
- Modify: `crates/platform-windows/Cargo.toml`, `crates/platform-windows/src/lib.rs`
- Create: `crates/platform-windows/build.rs`, `crates/platform-windows/src/native.rs`
- Create/modify: `native/windows/include/latencydesk_windows_bridge.h`, `native/windows/src/latencydesk_windows_bridge.cpp`
- Modify: `native/CMakeLists.txt`
- Test: native C++ contract tests and Rust recording tests

- [ ] **Step 1: Define a CXX ABI with opaque capture/encoder/renderer/input handles; Rust never receives a raw COM pointer.**
- [ ] **Step 2: Implement WER exclusion before identity/capture startup, DDA target selection, and WGC only for authorized target semantics. DDA access loss and protected-content masking invalidate the active epoch.**
- [ ] **Step 3: Implement D3D11 bounded owned-surface conversion and Media Foundation H.264 low-delay configuration: AVC 8-bit 4:2:0, no B frames, no lookahead, finite input/output queues, IDR recovery.**
- [ ] **Step 4: Implement D3D11 native presentation completion fences and SendInput only for the logged-in non-elevated interactive desktop. Expose an independently callable release-all handle.**
- [ ] **Step 5: Run CMake native tests and `cargo test -p latencydesk-platform-windows`; commit `feat(windows): add bounded native media providers`.**

## Task 7: Build Linux Portal/PipeWire native providers

**Files:**
- Modify: `crates/platform-linux/Cargo.toml`, `crates/platform-linux/src/lib.rs`
- Create: `crates/platform-linux/src/{portal,pipewire,security,presentation}.rs`
- Modify: `native/linux/{capability_probe,pipewire_import_probe}.cpp`, `native/CMakeLists.txt`
- Test: Linux provider tests and portal/pipewire probe tests

- [ ] **Step 1: Write capability fixtures for capture-only, capture-and-control, permission revocation, DMA-BUF tuple mismatch, MemFd fallback, and emergency release.**
- [ ] **Step 2: Call `prctl(PR_SET_DUMPABLE, 0)` before identity/session material; fail startup on error. Request Portal ScreenCast and RemoteDesktop separately and preserve their revocation lifetime.**
- [ ] **Step 3: Consume the direct PipeWire remote FD; validate format, modifier, plane, device, and fence metadata before import. Use bounded GPU conversion or explicitly recorded CPU copy if no safe direct import exists.**
- [ ] **Step 4: Use EIS/libei only under an active RemoteDesktop Portal grant; surface capture-only capability when input is denied.**
- [ ] **Step 5: Run native/Linux package tests; commit `feat(linux): add portal native providers`.**

## Task 8: Replace fake application loops with native role composition

**Files:**
- Modify: `apps/host/src/main.rs`, `apps/client/src/main.rs`
- Modify: `apps/host/Cargo.toml`, `apps/client/Cargo.toml`
- Test: role CLI tests and two-process local QUIC smoke test

- [ ] **Step 1: Write parser tests for `--listen`, `--connect`, `--role`, `--peer-alias`, `--pairing-timeout`, `--1080p120-profile`, and explicit local SAS approval. Reject `--interactive` in both product binaries.**
- [ ] **Step 2: Remove all direct `FakeCapture`, `ExactTestCodec`, `UdpEndpoint`, raw session success events, and synthetic pointer loops from product binaries and manifests.**
- [ ] **Step 3: Construct only selected native providers and `HostRuntime`/`ClientRuntime`; print non-secret peer fingerprint, session prefix, selected provider tuple, CopyLedger grade, epochs, connection state, and close reason.**
- [ ] **Step 4: Run `cargo run -p latencydesk-host -- --help` and `cargo run -p latencydesk-client -- --help`; run an authenticated two-process local QUIC smoke scenario.**
- [ ] **Step 5: Commit `feat(apps): run native QUIC roles`.**

## Task 9: Make 1080p120 latency evidence first-class

**Files:**
- Modify: `crates/telemetry/src/lib.rs`
- Modify: `apps/lab/src/main.rs`
- Create: `scripts/compare-latency.py`
- Test: telemetry unit tests and deterministic lab fixture

- [ ] **Step 1: Add fixed-schema stage records for capture-to-convert, convert-to-encode-submit, encode-to-send, receive-to-decode, decode-to-present-fence, and input round-trip. Keep host/client clocks separate unless a clock model records its uncertainty.**
- [ ] **Step 2: Add bounded p50/p95/p99 summaries, provider tuple, monitor mode, wired profile, frame expiry, recovery, queue depth, CopyLedger class, and raw sample export.**
- [ ] **Step 3: Add the comparison script that rejects different display modes, codec settings, device metadata, or network profiles before calculating deltas.**
- [ ] **Step 4: Run `cargo test -p latencydesk-telemetry` and the lab JSON/CSV smoke scenario; commit `feat(telemetry): record comparable 1080p120 evidence`.**

## Task 10: Produce deployable artifacts and acceptance evidence

**Files:**
- Create: `scripts/package.ps1`, `scripts/package.sh`
- Modify: `.github/workflows/ci.yml`, `README.md`, `README.zh-TW.md`, `docs/ROADMAP.md`
- Create: `artifacts/release-manifest.schema.json`

- [ ] **Step 1: Package Windows and Linux native binaries plus a machine-readable manifest containing revision, SHA-256 checksums, supported provider matrix, build target, and benchmark configuration.**
- [ ] **Step 2: Make CI run formatting, Clippy with warnings denied, workspace tests, QUIC loopback tests, package manifest validation, CMake native contracts, and platform-specific compilation.**
- [ ] **Step 3: Add installation, pairing, direct-LAN firewall, Portal, and 1080p120 benchmark procedures without claiming unmeasured performance.**
- [ ] **Step 4: Run the Windows Host → Linux Client and Linux Host → Windows Client physical-machine matrix. Capture raw reports for normal streaming, forced held-input disconnect, display/Portal reconfiguration, and provider failure.**
- [ ] **Step 5: Run the controlled AnyDesk comparison only after both products meet identical input, display, codec, and wired-network metadata requirements. Publish no comparison outcome without its raw evidence.**
- [ ] **Step 6: Run the final Windows and Linux package smoke tests; commit `release: package native direct-LAN product`.**

## Verification Order

1. `python scripts/static_validate.py`
2. `cargo fmt --all -- --check`
3. `cargo clippy --workspace --all-targets --all-features -- -D warnings`
4. `cargo test --workspace --all-targets`
5. Windows: configure/build/test `native` with MSVC; run provider probes on an interactive desktop.
6. Linux: configure/build/test `native`; run Portal/PipeWire capability and authorized-session probes.
7. Start actual Host and Client binaries on two physical machines, exercise pairing/approval/stream/input/recovery, and archive the redacted evidence.
