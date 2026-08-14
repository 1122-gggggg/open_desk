The media path must preserve **decoder continuity** whenever predictive video frames are dropped or reordered.

# Technical Line Audit

**Review date:** 2026-08-13  
**Scope:** Windows/Linux bidirectional remote desktop, latency-first, permissive open-source core  
**Verdict:** Feasible within the scoped logged-in-session product boundary. Not feasible as a credible single-step effort to “beat AnyDesk everywhere.” Performance superiority must be workload- and hardware-specific and established by the benchmark gates.

## 1. Feasibility matrix

| Area | Decision | Feasibility | Primary risk | Mandatory gate |
|---|---|---:|---|---|
| Windows screen capture | Desktop Duplication primary, WGC optional | High | capture lease starvation, protected content | 60/120 Hz soak without outstanding-frame growth |
| Linux Wayland capture | XDG portal + PipeWire standard backend | High for logged-in sessions | compositor/portal variance, user authorization | GNOME + KDE matrix; copy fallback passes |
| Generic Wayland unattended/login screen | Deferred | Low as a portable v0.1 promise | security model and compositor policy | separate platform-specific design required |
| Windows input | SendInput in per-user agent | High with limits | UIPI, secure desktop/UAC | integrity-level behavior documented and tested |
| Linux Wayland input | RemoteDesktop portal + libei | Medium-high | portal capabilities and session lifecycle | keyboard, pointer, release reconciliation |
| GPU zero-copy | Capability optimization | Medium | format/modifier/sync incompatibility | safe import plus measured bounded copy fallback |
| H.264 baseline | Hardware provider architecture | High | hardware availability, SDK/license differences | encode/decode capability negotiation and recovery |
| Software H.264 fallback | Optional provider only | Medium | patents, binary distribution, latency | separate feature/distribution review |
| QUIC transport | streams + DATAGRAM | High | MTU, queueing, congestion, library maturity | loss/RTT profiles and bounded reassembly |
| NAT traversal | ICE/STUN, relay later | High but non-MVP | operational complexity and abuse | direct LAN passes before Internet work starts |
| Hybrid desktop codec | staged base-video + exact refinements | Medium | sync, cache invalidation, quality attribution | baseline locked; deterministic tile tests |
| True E2E latency | external optical measurement | High | unsynchronized clocks and display scanout | high-speed/photodiode protocol published |

## 2. Product and process boundary

### Approved v0.1 boundary

- One logged-in user session per host.
- Windows 10/11 and recent GNOME/KDE Wayland distributions.
- One display initially; multi-monitor after the single-display state machine is stable.
- Direct LAN sessions first.
- Hardware H.264 8-bit 4:2:0 reference path; exact raw/test codec for deterministic CI.
- Keyboard, pointer, local cursor, secure pairing, and telemetry.

### Explicit non-goals for v0.1

- Generic Wayland login-screen or unattended control.
- Windows secure desktop/UAC control.
- DRM/protected-content capture.
- Audio, clipboard, file transfer, printer/device redirection.
- Mobile clients, browser client, multi-user host.
- “Faster than AnyDesk” marketing claims.

This boundary is not cosmetic. Each omitted feature adds a privilege boundary, new data channel, or latency variable that would prevent clean validation of the core pipeline.

## 3. Capture review

### 3.1 Windows

**Primary backend:** DXGI Desktop Duplication (DDA) for whole-output capture. It supplies a GPU surface and desktop metadata useful for later sparse updates.  
**Secondary backend:** Windows Graphics Capture (WGC) for user-selected monitor/window capture and cases where DDA is unsuitable.

Required architecture:

```text
Windows system service
  ├─ identity, updates, privileged policy, session discovery
  └─ per-user agent in interactive session
       ├─ DDA/WGC capture
       ├─ input broker within allowed integrity boundary
       └─ IPC to service
```

A service running in Session 0 must not be treated as the desktop-capture process. The user agent owns capture and normal input injection. Secure desktop and higher-integrity targets are separate capability work.

**Capture lease rule:** `AcquireNextFrame`-style resources cannot be queued into an asynchronous encoder without a lifetime boundary. Within the capture callback the provider must do exactly one of:

1. establish a documented, synchronized encoder-owned import; or
2. copy into a bounded encoder-owned GPU/CPU pool.

The original capture lease is then released immediately. Queue depth and copy path are telemetry fields.

**Gate:** 30-minute 1080p120 and 4K60 capture-only soak; no unbounded outstanding textures, no monotonically increasing latency, and no capture starvation.

### 3.2 Linux Wayland

**Standard backend:**

```text
XDG RemoteDesktop + ScreenCast portals
                 ↓
              PipeWire
                 ↓
    DMA-BUF when negotiated and importable
          otherwise MemFd/CPU copy
```

**Input:** RemoteDesktop portal session plus libei where the compositor/backend exposes it. Portal authorization and session lifetime are part of the UI/state machine, not hidden setup details.

**Why KMS is not the default:** direct KMS capture can be useful as a later performance or appliance backend, but it introduces privileges, compositor/device contention, multi-GPU complications, and packaging differences. It cannot replace the portable portal backend.

**DMA-BUF conditions:** zero-copy requires compatible pixel format, modifier, device, ownership, and explicit/implicit synchronization semantics. Failure is normal, not exceptional. The provider reports `zero_copy`, `gpu_copy`, or `cpu_copy`; all three paths must be tested.

**Gate:** GNOME and KDE tests for session creation/cancellation/revocation, monitor selection, resizing, cursor mode, DMA-BUF import, and MemFd/copy fallback. No claim of unattended support.

### 3.3 X11

X11 is a compatibility backend after the Wayland reference path. It may use XDamage/XShm and XTest, but it must implement the same capture/input provider contracts. X11 support must not weaken Wayland security assumptions.

## 4. Surface, format, color, and synchronization review

A captured frame is not merely `width × height × pixels`. The provider boundary needs:

- memory domain: CPU, D3D11, DMA-BUF, vendor opaque;
- pixel format and plane layout;
- color primaries, transfer, matrix, range, and HDR metadata;
- adapter/device identity;
- synchronization primitive/fence semantics;
- rotation and logical-to-physical coordinate transform;
- capture sequence and host-local monotonic timestamp;
- lease/import/copy path.

Initial normalization target is **NV12, 8-bit, SDR, limited/full range explicitly signaled**. BGRA capture may require GPU color conversion. P010/HDR is deferred until SDR conformance passes.

A bounded pool is mandatory. Recommended initial caps:

- capture leases outstanding: 1 per source;
- encoder-owned surfaces: 3;
- encoded frames awaiting send: 2, with dependency-aware policy;
- client complete frames awaiting decode: 1 plus current recovery point;
- decoded frames awaiting presentation: 1.

The numbers are starting hypotheses and must be tuned from traces, not increased to hide stalls.

## 5. Codec review

### 5.1 Baseline decision

Start with one full-frame **low-delay H.264** stream:

- 8-bit 4:2:0;
- no B-frames;
- no lookahead;
- bounded/small rate-control buffer;
- low-delay reference structure;
- explicit codec configuration epoch;
- recovery point on join, reconfiguration, continuity failure, and bounded periodic policy;
- capability-negotiated bitrate, resolution, frame rate, profile, and level.

H.264 is selected for the first reference path because hardware encode/decode coverage is broader than newer codecs. This is an engineering baseline, not a permanent codec mandate.

### 5.2 Provider model

```text
EncoderProvider
  ├─ NVENC (Windows/Linux)
  ├─ Windows Media Foundation / Intel/AMD path
  ├─ VA-API / oneVPL (Linux Intel/AMD as available)
  ├─ AMF provider where distribution terms permit
  └─ exact test codec (CI/loopback only)
```

Every provider reports:

- supported input memory domains and formats;
- whether import is zero-copy or copied;
- codec/profile/level/rate-control capabilities;
- maximum dimensions/frame rate;
- reconfigure support;
- conservative dependency metadata;
- whether an output is an independently decodable recovery point.

Do not silently fall back to a high-latency software pipeline. Negotiation either selects an explicitly supported provider or returns an actionable error. An optional OpenH264 provider may be offered separately, but source licensing, Cisco binary distribution, and patent obligations are distinct questions.

### 5.3 Frame dropping and recovery

“Late frames are useless” is incomplete for predictive video. A dropped H.264 P-frame can invalidate later access units. The sender/client must carry:

- `codec_epoch`;
- `frame_id`;
- conservative `dependency_frame_id`;
- `recovery_point` flag;
- rate-limited recovery request.

Policy:

1. A frame marked discardable may be dropped without continuity reset.
2. If a required frame is missing, treat it as a decoder continuity failure and do not feed dependent access units to the decoder.
3. Enter `Recovering`, coalesce recovery requests, and request IDR/intra-refresh recovery according to provider capability.
4. Resume only after a validated recovery point/config epoch.
5. Encoder queue drops that break a reference chain must force the next output to be a recovery point.

### 5.4 HEVC and AV1

Both remain optional later providers. They require hardware/driver capability measurement, latency comparison, interoperability testing, and separate patent/distribution review. They must not delay the cross-OS H.264 baseline.

## 6. Transport review

### 6.1 Approved model

A single authenticated QUIC connection provides encryption, connection management, congestion control, and these logical paths:

| Path | Semantics | Examples |
|---|---|---|
| Control stream | reliable, ordered, bounded messages | auth result, capability negotiation, display/config changes |
| Media DATAGRAM | unreliable, deadline-aware | video fragments, cursor metadata, later audio/tiles |
| Input DATAGRAM | low latency, sequenced | pointer motion, key/button transitions |
| Input snapshot stream/datagram | periodic reconciliation | complete pressed-key/button state |
| Metrics stream | sampled/reliable | aggregated traces, not every raw event by default |

QUIC DATAGRAM does not make application data reliable and does not remove congestion-control responsibility. The application maintains pacing, deadlines, and bounded queues; it does not retransmit obsolete video fragments.

### 6.2 Fragmentation and reassembly

The protocol header is fixed-width and validates frame length, fragment range, flags, epoch, and dependency before allocation. The reassembler must additionally enforce:

- negotiated datagram payload below path MTU;
- maximum simultaneous incomplete frames;
- maximum bytes per stream/session/peer;
- duplicate and overlapping-fragment policy;
- fragment timeout shorter than media usefulness deadline;
- no decode until exact access-unit completeness;
- configuration epoch validation.

IP fragmentation is not a strategy. Packetization must be path-MTU-safe.

### 6.3 Congestion and adaptation

Initial implementation should rely on the QUIC implementation’s congestion controller and expose delivery/RTT/loss feedback. Application adaptation changes bitrate/frame rate/resolution; it must not build a second unconstrained queue above QUIC.

FEC is deferred until measured packet-loss traces show a benefit over bitrate reduction and rapid recovery. It adds bandwidth and latency and is not automatically beneficial.

### 6.4 NAT traversal and relay

LAN direct connection comes first. ICE/STUN/TURN-style connectivity and an E2E-encrypted relay follow only after the direct transport passes loss/RTT tests. The relay must not terminate content encryption or gain desktop plaintext.

## 7. Input review

### 7.1 Wire representation

Use stable physical key identifiers (USB HID usage where possible), explicit press/release transitions, pointer coordinate space, button mask, wheel precision, sequence number, and sender-local event timestamp. Text/IME input is a separate semantic path; do not infer characters from remote keyboard layout alone.

### 7.2 Loss recovery

Input cannot be ordinary unreliable events only. Losing `KeyUp` creates a stuck key. Use:

- immediate sequenced input events;
- periodic full key/button state snapshots;
- focus/session-loss forced release-all;
- duplicate suppression;
- absolute pointer snapshots in addition to relative motion when appropriate.

Snapshots reconcile state without placing every pointer move behind reliable head-of-line blocking.

### 7.3 Platform limits

- Windows `SendInput` is constrained by integrity/UIPI and does not imply secure-desktop control.
- Wayland input is scoped to the authorized RemoteDesktop/libei session.
- UAC secure desktop, login screen, and privileged apps require an explicit elevated design and are deferred.

**Gate:** automated stuck-key, packet-loss, focus-loss, reconnect, keyboard-layout, pointer-scale, and multi-DPI tests.

## 8. Decode, render, and cursor review

### Windows client

Preferred path: hardware decode into D3D11-compatible surfaces, GPU color conversion/composition as needed, flip-model presentation, bounded queue. A copy path remains available for unsupported adapter combinations.

### Linux client

Preferred path: hardware decode into importable surfaces, Vulkan/EGL/Wayland presentation depending on provider, DMA-BUF import when safe, measured copy fallback otherwise.

### Presentation policy

- never accumulate a deep decoded-frame queue;
- render the newest continuity-valid frame;
- record decode completion and present submission separately;
- measure compositor/vsync behavior rather than assuming immediate scanout;
- avoid spin loops as a default pacing mechanism.

### Cursor

Cursor shape and position are an independent low-bandwidth channel. The client renders locally when the capture backend provides reliable metadata. If it cannot, negotiate embedded cursor mode. Cursor state is epoch/versioned so a lost shape update does not display the wrong pointer indefinitely.

## 9. Security and privilege review

No custom cryptography. QUIC/TLS protects transport, but product security also requires:

- persistent device identity and authenticated pairing;
- explicit local consent by default;
- short-lived session authorization;
- least-privilege service/user-agent split;
- replay-resistant control messages and nonces bound to session identity;
- capability authorization per input/capture/clipboard/file channel;
- bounded parsers, queues, dimensions, and reassembly;
- secure secret storage using platform facilities;
- log redaction and no captured pixels/keystrokes in normal logs;
- signed releases and reproducible provenance later;
- relay abuse controls and rate limits before public operation.

Clipboard and file transfer are disabled until separate threat-model sections and fuzzed parsers exist.

## 10. Time and telemetry review

Host and client monotonic clocks are independent. Never calculate E2E latency by subtracting raw host capture time from raw client present time.

Valid built-in measurements:

- host capture-to-encode, encode duration, host queue duration;
- RTT and transport delivery estimates;
- client receive queue, decode duration, presentation queue;
- dropped/recovered frames, queue depth, copy path, bitrate, resolution.

An optional clock-offset model may display estimated one-way latency only with uncertainty. Published input-to-photon and screen-to-screen claims require external optical/high-speed measurement.

## 11. Hybrid desktop codec review

### Rejected first implementation

Do not begin with per-region simultaneous H.264/AV1/tile encoders. It introduces difficult region boundaries, independent timing, decoder composition, rate allocation, cache invalidation, and recovery interactions before the base pipeline is proven.

### Approved staged implementation

1. **Full-frame low-delay video base.** Always capable of complete recovery.
2. **Sparse exact tile updates.** Independently versioned, bounded, lossless tiles keyed to display/config epoch and base frame.
3. **Static refinement.** When interaction/motion falls, send exact text/UI tiles to improve 4:2:0 quality without delaying the base frame.
4. **Optional region policy research.** Only after trace-driven proof that tiles outperform tuned 4:4:4/video modes.

Tile requirements:

- deterministic tile size and coordinate space;
- display/config epoch;
- tile generation and base-frame relationship;
- exact hash/checksum after decode;
- bounded client cache;
- stale-tile rejection after resize/config change;
- clear overlap/composition order;
- refinement lower priority than input/control/recovery video;
- loss does not invalidate the video base.

## 12. Licensing and clean-room review

The core is `MIT OR Apache-2.0`. Apache-2.0 provides an explicit contributor patent grant; MIT provides simple compatibility. Contributions must not copy GPL/AGPL implementation code from RustDesk, Sunshine, Moonlight, or similar projects into the permissive core.

Allowed:

- study public specifications and official API documentation;
- observe interoperability behavior;
- describe architecture and independently implement it;
- use separately licensed optional processes/plugins with documented boundaries.

Required before shipping codec providers:

- third-party license inventory;
- SDK/header redistribution review;
- dynamic/static linking analysis;
- codec patent/distribution review by target country/channel;
- SBOM and release notices.

## 13. Go/no-go gates

| Gate | Go condition | No-go response |
|---|---|---|
| Core safety | parser/property tests, bounded queues, no panic on hostile input | stop platform integration |
| Capture lifetime | soak test has stable outstanding buffers and queue depth | fix ownership; do not increase buffers blindly |
| Cross-copy | zero-copy and forced-copy paths produce identical frames | block provider release |
| Codec continuity | loss never feeds invalid dependency chain; recovery bounded | redesign encoder/drop contract |
| Wayland | GNOME/KDE authorized sessions work and revoke cleanly | narrow supported matrix explicitly |
| Input safety | no stuck keys after loss/disconnect/focus change | block remote control release |
| Weak network | p95/p99 bounded; no multi-second queue spikes | tune adaptation/queueing before FEC |
| Security | pairing, consent, privilege separation, parser limits reviewed | no public unattended mode |
| Performance claim | optical benchmark and reproducible scripts published | do not claim competitor superiority |

## 14. Final route decision

The route is technically viable under the scoped boundary. The correct critical path is **native capture → bounded ownership → low-delay hardware H.264 → dependency-aware QUIC delivery → native decode/present → safe input → optical benchmark**. Hybrid desktop refinement is a later optimization, not the foundation required to prove interoperability.
