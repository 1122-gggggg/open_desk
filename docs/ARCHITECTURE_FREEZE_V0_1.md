# Architecture Freeze — v0.1

**Frozen:** 2026-08-13  
**Authority:** [`research/FINAL_ARCHITECTURE_DECISION.md`](research/FINAL_ARCHITECTURE_DECISION.md) and [`ARCHITECTURE_DECISIONS.md`](ARCHITECTURE_DECISIONS.md). A later code change that violates this document requires a new decision record and the relevant benchmark/prototype evidence.

## V0.1 MUST USE

### Product matrix

- One logged-in interactive user session per host.
- One display per session; the display identity, rotation, scale, colour metadata, and capture/input/codec epochs are explicit.
- Windows 10/11 logged-in interactive desktop: one authorized SDR display through DDA when supported; WGC when the requested target is a window or a valid authorized WGC display item exists.
- GNOME Wayland and KDE/KWin Wayland logged-in sessions: XDG ScreenCast plus direct PipeWire remote FD after live portal capability discovery. Capture-and-control requires RemoteDesktop v2 plus EIS/libei availability; otherwise offer capture-only or fail closed.
- Direct LAN only. Internet traversal, relay, and enterprise UDP-block fallback are not v0.1 features.

### Capture and ownership

- D3D11 is the Windows capture/encode/presentation native boundary. The selected DDA output owns the D3D11 adapter; WGC uses its documented D3D11 frame pool.
- Capture buffers are borrowed leases. Before asynchronous encode, copy or GPU-convert into a bounded engine-owned texture pool. DDA/WGC/PipeWire buffers are released/requeued only after a completion proof or safe detach edge.
- A CopyLedger records lease origin/generation, source and consumer device identities, format/planes/modifier, transfer edge, sync proof, actual copy path, fallback reason, and evidence grade.
- Normal image conversion is explicitly `gpu_convert` or `gpu_copy`; `zero_copy` is emitted only after profiler-verified direct aliasing.
- Linux PipeWire capture negotiates memory type, FourCC, modifier, planes, colour metadata, and synchronization. DMA-BUF failure falls back to bounded GPU conversion or CPU copy; it never creates an unbounded lease queue.

### Codec and presentation

- Capability-negotiated hardware H.264/AVC is the mandatory base codec: 8-bit 4:2:0, SDR, low-delay P-only configuration, no conventional B frames, no lookahead, bounded rate-control/input queues.
- Every selected provider reports encoder and decoder capability, profile/level, input domain/format, queue policy, recovery controls, provider/driver version, and whether hardware acceleration is actually active.
- The receiver accepts a predictive frame only after its conservative dependency is present. Join, reconfiguration, access loss, a confirmed dependency failure, and resource epoch change require an independently decodable recovery point; initial implementation uses IDR.
- The client keeps at most one newest continuity-valid decoded frame awaiting presentation. Cursor is one explicit mode per session: local metadata rendering **or** embedded video cursor, never both.
- A native renderer converts a decoded surface into an opaque submission only after native queue submission. The coordinator retains that submission until its exact completion fence is observed, or a recovery path has explicitly quiesced the provider; no successful path may implicitly release a surface.

### Transport and input

- One authenticated QUIC connection for direct LAN: bounded reliable ordered control stream; separate bounded reliable ordered input-transition stream; application-framed, path-MTU-safe DATAGRAM media; optional latest-wins DATAGRAM absolute-pointer samples.
- Media frames have codec epoch, frame ID, conservative dependency ID, recovery flag, bounded complete access-unit length, fragment range, local expiry, and bounded reassembly. Do not use IP fragmentation or retransmit obsolete video fragments.
- Input edges for physical keys, buttons, wheel ticks, and drag boundaries carry a transition sequence on the reliable input stream. Each edge requiring a location includes an absolute pointer anchor. Full pressed-key/button/absolute-pointer snapshots follow their covered edges in that same stream; pointer DATAGRAMs are ignored when stale.
- Focus loss, portal/session revocation, transport close, decode/display/input epoch change, controller-lease expiry, or local shutdown immediately synthesizes release-all locally. Remote delivery is an optimization, never the only stuck-key defense.

### Security and permissions

- QR/out-of-band pairing confirms persistent device public-key fingerprints; the paired identity is pinned. Each session requires explicit host authorization, short-lived session authorization, capability negotiation, and a visible active-session/revoke path.
- QUIC/TLS 1.3 is the transport cryptographic construction. Disable 0-RTT for input, authorization, or any non-idempotent control operation.
- Rust owns protocol parsing, resource caps, session state, and authorization policy. Native code is an opaque, narrow provider boundary. Normal capture/input runs in the interactive user context; no persistent elevated service is needed for v0.1.
- Logs exclude pixels, clipboard contents, typed text, credentials, pairing secrets, private keys, raw GPU handles, and raw FDs.

## V0.1 MAY USE

- DDA dirty/move/pointer metadata for diagnostics, local conversion optimization, cursor handling, and future tile invalidation hints. It is not a v0.1 network delta protocol.
- WGC for selected window capture or a pre-authorized compatible display item. It remains a target-specific session, not a transparent DDA fallback.
- Hardware-provider implementations for NVENC, Windows Media Foundation, Intel oneVPL/QSV, VA-API, or AMF only after runtime capability selection and bounded low-delay configuration succeeds.
- Provider ROI/damage hints only when capability negotiation accepts them. They never affect decoder correctness or substitute for the base frame.
- A no-CPU-copy Linux import or direct Windows alias only after exact device/format/synchronization tuple evidence gives it a CopyLedger `profiler_verified_no_application_copy` grade.
- Capture-only operation when the platform grants capture but not RemoteDesktop/EIS input.
- Experimental wlroots ScreenCast capture only after an explicit product-tier decision; no wlroots remote-control claim.

## V0.1 MUST NOT BUILD YET

- Generic Wayland unattended access, login-screen capture/control, direct KMS capture, `/dev/uinput` as a portable portal substitute, GNOME/KDE-specific preauthorization, or any bypass of Portal consent/compositor policy.
- Windows secure desktop, UAC secure-desktop, Winlogon, protected/DRM content capture, or elevated-application input bypass.
- Multi-monitor composition, cross-adapter default encode, native D3D12 capture/encode path, HDR preservation, P010, or an HDR transport contract.
- Mandatory HEVC, AV1, full-frame 4:4:4, software encoder fallback that changes the latency contract, rolling-intra-refresh recovery as a universal reset, or long-term-reference complexity.
- Lossless tile refinement, a desktop delta reconstruction protocol, or multiple simultaneous regional codecs.
- Internet relay, rendezvous, ICE/STUN/TURN, WebRTC product integration, mobile/network fallback, custom UDP/RTP transport, FEC, audio, clipboard, file transfer, printer/device redirection, central account service, or browser/mobile clients.
- Automatic-update execution, persistent unattended credentials, or a LocalSystem service that handles pixels/input.

## EXPERIMENTAL

A result applies only to its exact OS build, compositor, GPU, driver, format/modifier, provider, and network profile. A passing experiment does not widen v0.1 support automatically.

| ID | Gate | Promotion rule |
| --- | --- | --- |
| EXP-01 | DDA versus WGC and owned surface lease benchmark | Backend default can be ranked only after 30-minute no-leak/no-starvation soak and P99 comparison on each target hardware class. |
| EXP-02 | QUIC versus native WebRTC transport benchmark | WAN/relay may start only after one candidate meets bounded-memory, input-convergence, loss-recovery, connectivity, and predeclared P99 gates under matched conditions. |
| EXP-03 | H.264 ROI / 4:4:4 / static refinement benchmark | A desktop-quality alternative advances only if it preserves base correctness, improves a defined clarity/byte metric, and does not worsen P95 latency. |
| EXP-04 | PipeWire DMA-BUF exact import tuple | `gpu-direct` is permitted only after proven completion/recycle safety and no application CPU/GPU copy. Otherwise record GPU conversion, CPU copy, or unsupported. |

**Freeze interpretation:** “YOLO”/bypass-permission execution mode applies to this development harness. It does not weaken the product’s explicit OS, portal, host-approval, secure-desktop, or protected-content boundaries.
