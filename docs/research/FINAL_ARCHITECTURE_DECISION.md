# Final Architecture Decision — v0.1

**Decision date:** 2026-08-13  
**Scope:** Logged-in Windows and GNOME/KDE Wayland desktop sessions; direct LAN first. This document arbitrates the eight independent research reports. It deliberately freezes only claims supported by a narrow product boundary; hardware-, driver-, compositor-, and transport-stack-specific behavior remains an experiment, not a product promise.

## Five required answers

### Q1 — Windows capture: DXGI or WGC?

**Select DXGI Desktop Duplication as the v0.1 default for one authorized SDR display. Select Windows Graphics Capture as an explicit co-primary backend for window capture and an already-authorized display alternative.** Do not model WGC as an automatic fallback: a WGC session requires a compatible `GraphicsCaptureItem`, access, and its own border/consent policy. DDA is output-scoped and supplies dirty/move/pointer metadata; WGC is the documented display-or-window API. No primary source proves either API universally lower-latency, so automatic default ranking remains `EXPERIMENT_REQUIRED` ([DDA](https://learn.microsoft.com/en-us/windows/win32/direct3ddxgi/desktop-dup-api), [WGC](https://learn.microsoft.com/en-us/windows/apps/develop/media-authoring-processing/screen-capture)).

### Q2 — Is Portal/PipeWire + DMA-BUF enough as a production Wayland baseline?

**Yes for a production baseline limited to logged-in, user-authorized GNOME and KDE/KWin sessions, after live capability negotiation; no for generic Wayland, login screens, or unattended access.** The portal authorizes setup and returns a PipeWire remote FD; it is not a documented per-frame D-Bus relay. DMA-BUF is an optional GPU-direct capability, never the baseline data contract: FourCC, modifier, plane layout, producer/consumer device, and synchronization must all negotiate successfully, otherwise the bounded fallback is used ([ScreenCast v6](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.ScreenCast.html), [RemoteDesktop v2](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.RemoteDesktop.html), [Linux DMA-BUF](https://docs.kernel.org/driver-api/dma-buf.html)).

### Q3 — v0.1 codec: H.264, HEVC, or AV1?

**Select capability-negotiated hardware H.264/AVC, 8-bit 4:2:0, low-delay P-only as the mandatory interoperability floor.** H.264 is not declared the best desktop codec. It is the narrowest evidenced common hardware floor across the initial NVIDIA, Intel, and AMD provider directions. HEVC and AV1 remain opt-in experiments only after both endpoint capability and distribution review pass ([NVIDIA capability matrix](https://docs.nvidia.com/video-technologies/video-codec-sdk/13.0/nvenc-application-note/index.html), [Intel oneVPL matrix](https://www.intel.com/content/www/us/en/docs/onevpl/developer-reference-media-intel-hardware/1-0/features-and-formats.html)).

### Q4 — production networking baseline: QUIC, WebRTC, or custom UDP?

**For the direct-LAN v0.1 Critical Path, select QUIC with a reliable control stream, a reliable ordered input-transition stream, bounded DATAGRAM media, and optional latest-wins DATAGRAM absolute-pointer samples. For WAN, NAT traversal, and relay, do not freeze QUIC-only or WebRTC yet: run EXP-02 before admitting either as the Internet baseline. Native WebRTC is the first WAN comparison candidate because ICE/TURN, RTP repair/feedback, and SCTP channel modes remove substantial non-differentiating engineering; custom UDP is rejected.** QUIC DATAGRAM is a valid real-time primitive but has no frame protocol, fragmentation, flow control, or deadline API mandate; WebRTC does not prove latency parity and retains encoder/queue/adaptation work ([RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html), [RFC 8834](https://www.rfc-editor.org/rfc/rfc8834.html), [RFC 8835](https://www.rfc-editor.org/rfc/rfc8835.html)).

### Q5 — desktop compression: video-only, ROI, 4:4:4, lossless refinement, or hybrid regions?

**Select full-frame low-delay H.264 4:2:0 video as the v0.1 image path. Permit capture damage and encoder ROI only as optional quality hints. Defer full-frame 4:4:4, lossless static tile refinement, and concurrent hybrid region codecs.** ROI changes quantization inside one lossy access unit; it cannot replace exact-pixel delivery or cache invalidation. If benchmarked later, static lossless RGB/RGBA overlays are the preferred refinement candidate because the complete video base remains correct when a tile is missing. Simultaneous region encoders are rejected before a measured refinement win ([NVENC emphasis map](https://docs.nvidia.com/video-technologies/video-codec-sdk/13.1/nvenc-video-encoder-api-prog-guide/index.html), [oneVPL ROI](https://oneapi-spec.uxlfoundation.org/specifications/oneapi/v1.2-rev-1/elements/onevpl/source/api_ref/vpl_structs_encode), [DDA dirty/move rules](https://learn.microsoft.com/en-us/windows/win32/direct3ddxgi/desktop-dup-api)).

## Binding decisions

### Windows capture and ownership

Decision: Make capture target-selected rather than a universal fallback ladder.

Current proposal: DXGI Desktop Duplication primary; WGC secondary.

Verdict: MODIFY

Recommended solution: DDA is the default only for one authorized SDR display on its owning adapter. WGC is explicit for a selected window and only a conditional display route after its item/access/border policy succeeds. Keep capture, color conversion, and hardware encode on a D3D11 device created for the selected output adapter. Copy or GPU-convert the borrowed source to a bounded engine-owned encode slot before asynchronous encode; do not loan a DDA/WGC lease to an encoder.

Why: `ReleaseFrame` invalidates a DDA desktop surface, and WGC frame surfaces must not outlive their frame-pool lease. D3D11 is the native common boundary for DDA, WGC, and the Media Foundation D3D11 path. D3D12/11-on-12 adds synchronization and memory overhead without removing the D3D11 capture boundary ([ReleaseFrame](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/nf-dxgi1_2-idxgioutputduplication-releaseframe), [MF D3D11-aware transform](https://learn.microsoft.com/en-us/windows/win32/medfound/mf-sa-d3d11-aware), [D3D11On12](https://learn.microsoft.com/en-us/windows/win32/direct3d12/direct3d-11-on-12)).

Alternative: Directly register a borrowed DDA texture with NVENC, or bridge capture to D3D12 first.

Risk: GPU conversion costs a known GPU edge, but direct registration ties an asynchronous encoder to a capture lease and may hide RGB-to-YUV work. Cross-adapter and multi-output composition are not latency-safe defaults.

Prototype required: EXP-01 and the same-adapter ownership probe.

Evidence: [DDA lease contract](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/nf-dxgi1_2-idxgioutputduplication-acquirenextframe), [WGC frame-pool contract](https://learn.microsoft.com/en-us/uwp/api/windows.graphics.capture.direct3d11captureframepool?view=winrt-26100), [NVENC external-resource lifecycle](https://docs.nvidia.com/video-technologies/video-codec-sdk/13.1/nvenc-video-encoder-api-prog-guide/index.html#input-buffers-allocated-externally).

### Linux Wayland capture and GPU import

Decision: Freeze the portal/PipeWire route as an interactive host baseline, not a generic privileged route.

Current proposal: Portal + PipeWire + DMA-BUF with copy fallback.

Verdict: MODIFY

Recommended solution: Use a ScreenCast session for view-only and one RemoteDesktop session for view-plus-control. Discover portal interface versions and device bits at runtime; use EIS/libei only when the started RemoteDesktop v2 session exposes it. Negotiate DMA-BUF only as `{device, FourCC, planes, modifier, colour metadata, synchronization, encoder resource}`; otherwise copy into a bounded owned pool. On revoke, close, EIS loss, PipeWire failure, logout, or compositor restart, immediately stop network input, release all local state, retire the pool after its completion fences, and advance epochs.

Why: The portal separates capture from control and grants direct PipeWire access after authorization. Upstream wlroots portal supports ScreenCast but not RemoteDesktop, and GNOME/KDE policies are not interchangeable. DMA-BUF sharing preserves neither a universal format nor a universal consumer fence ([RemoteDesktop](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.RemoteDesktop.html), [portal session lifecycle](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Session.html), [EGL DMA-BUF modifiers](https://registry.khronos.org/EGL/extensions/EXT/EGL_EXT_image_dma_buf_import_modifiers.txt)).

Alternative: Direct KMS or `/dev/uinput` fallback when a portal lacks input.

Risk: That changes the security model, competes with compositor ownership, and falsely promises portable unattended access.

Prototype required: EXP-04 plus separate GNOME/KDE lifecycle probes.

Evidence: [PipeWire buffer lifecycle](https://docs.pipewire.org/group__pw__stream.html), [KDE RemoteDesktop bridge](https://invent.kde.org/plasma/xdg-desktop-portal-kde/-/raw/master/src/remotedesktop.cpp), [wlroots portal scope](https://raw.githubusercontent.com/emersion/xdg-desktop-portal-wlr/master/README.md).

### GPU CopyLedger and interop policy

Decision: Optimize for bounded, observable ownership rather than nominal zero-copy.

Current proposal: `zero_copy`, `gpu_copy`, or `cpu_copy` telemetry labels.

Verdict: MODIFY

Recommended solution: Establish the normal path as an engine-owned GPU conversion/copy pool and CPU fallback. Treat direct aliasing as evidence-gated. Add a fixed-size per-frame CopyLedger with source lease, source/destination domain and device identity, format/modifier/planes, transfer edge, synchronization token/mode, completion state, actual path, fallback reason, and evidence grade. Only profiler-verified no-application-copy aliasing may be labeled `zero_copy`; opaque driver movement is `internal_copy_unknown`.

Why: DDA is commonly BGRA while the baseline encoder surface is 4:2:0. A DMA-BUF, EGL image, Vulkan import, or NVENC registration shows access compatibility—not necessarily no allocation, conversion, or synchronization cost. NVIDIA documents a strict NVDEC-to-NVENC CUDA-array path, but it does not generalize to desktop capture or presentation ([NVENC input formats](https://docs.nvidia.com/video-technologies/video-codec-sdk/13.1/nvenc-video-encoder-api-prog-guide/index.html#selecting-input-formats), [NVDEC opaque-array path](https://docs.nvidia.com/video-technologies/video-codec-sdk/13.1/nvdec-video-decoder-api-prog-guide/index.html#nvdec-direct-output-to-block-linear-cuda-arrays)).

Alternative: Build a generic Vulkan/EGL/CUDA cross-vendor zero-copy graph now.

Risk: It expands synchronization and driver-specific failure surface before a correct GPU-copy baseline exists.

Prototype required: Exact tuple probes; no broad interop abstraction before one supports a release gate.

Evidence: [Linux DMA-BUF synchronization](https://docs.kernel.org/driver-api/dma-buf.html), [Vulkan external DMA-BUF memory](https://docs.vulkan.org/refpages/latest/refpages/source/VK_EXT_external_memory_dma_buf.html), [VA DRM PRIME definitions](https://raw.githubusercontent.com/intel/libva/master/va/va_drmcommon.h).

### Codec and refinement

Decision: Freeze one conservative video reference structure and reject premature desktop codec complexity.

Current proposal: H.264 first; hybrid codec later.

Verdict: MODIFY

Recommended solution: Require hardware H.264 8-bit 4:2:0, no conventional B-frames, no lookahead, short conservative reference chain, bounded rate-control/input queues, and an independently decodable recovery point for join/reconfiguration/confirmed continuity failure. Provider-specific ROI, dirty regions, intra refresh, and LTR are optional capability fields—not common correctness primitives. Use IDR as the initial recovery boundary. Define, but do not implement, an optional lossless tile overlay protocol with display/codec/source generations and hash validation.

Why: Lookahead queues input; rolling intra refresh is a multi-frame process and not automatically a one-frame decoder reset. Vendor capability matrices support H.264 more broadly than AV1 in the initial hardware matrix. ROI APIs express QP/importance, not exact delta delivery ([NVENC error resilience](https://docs.nvidia.com/video-technologies/video-codec-sdk/13.1/nvenc-video-encoder-api-prog-guide/index.html), [oneVPL encode structures](https://oneapi-spec.uxlfoundation.org/specifications/oneapi/v1.2-rev-1/elements/onevpl/source/api_ref/vpl_structs_encode), [H.264](https://www.itu.int/rec/T-REC-H.264/en)).

Alternative: HEVC 4:4:4, AV1, or concurrent regional codecs as initial transport.

Risk: They create an unsupported provider/decoder/legal matrix or independent recovery/composition system before cross-OS video correctness is measured.

Prototype required: EXP-03 and per-provider capability/recovery tests.

Evidence: [NVIDIA matrix](https://docs.nvidia.com/video-technologies/video-codec-sdk/13.0/nvenc-application-note/index.html), [Intel matrix](https://www.intel.com/content/www/us/en/docs/onevpl/developer-reference-media-intel-hardware/1-0/features-and-formats.html), [AV1 specification](https://aomediacodec.github.io/av1-spec/).

### Transport, input, and security

Decision: Keep separate logical semantics; do not trade correctness or authorization for a “bypass” mode.

Current proposal: QUIC streams + DATAGRAM; sequenced input plus snapshots; TLS security.

Verdict: MODIFY

Recommended solution: In LAN v0.1, use one TLS-authenticated QUIC connection: a bounded reliable ordered control stream; a bounded reliable ordered input-transition stream carrying key/button/wheel/drag edges and full state snapshots; deadline-aware DATAGRAM media; and an optional sequenced latest-wins DATAGRAM lane only for absolute pointer samples. An input edge carries a reliable absolute anchor. On focus loss, portal revoke, session/transport close, or epoch transition, locally synthesize release-all regardless of network delivery. Pair devices through an out-of-band QR confirmation bound to persistent device public keys; pin the peer identity after pairing; disable 0-RTT for authorization/input/control; use a short-lived session authorization and visible local consent. Do not introduce a persistent privileged Windows service, relay, unattended credentials, clipboard/file transfer, or auto-update execution in v0.1.

Why: QUIC DATAGRAM is deliberately unreliable and application-multiplexed; it needs an explicit media-frame and stale-drop policy. A state snapshot can repair a missed held state, but cannot recreate a lost short tap, double click, wheel tick, or drag boundary whose final state is already released. Reliable ordered delivery therefore protects discrete state transitions; the optional pointer DATAGRAM is safe only because a newer absolute sample replaces it and reliable edges carry anchors. QUIC 0-RTT application data is replayable. TLS 1.3 and QUIC already provide standard channel cryptography; Noise would add a second handshake without a stated need ([RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html), [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html), [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html), [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html)).

Alternative: Custom UDP, all-DATAGRAM discrete input, a central account service, or hidden bypass of portal/host authorization.

Risk: A lost reliable edge head-of-line-blocks later discrete input; bounded queue admission and controller-lease expiry limit that trade-off. QUIC library scheduling and WAN behavior require measurement; permission bypass would invalidate platform security claims and enlarge the threat model.

Prototype required: EXP-02 for transport scheduling and WAN choice; deterministic input edge/snapshot loss, reconnect, and convergence tests.

Evidence: [QUIC transport](https://www.rfc-editor.org/rfc/rfc9000.html), [QUIC DATAGRAM](https://www.rfc-editor.org/rfc/rfc9221.html), [QUIC applicability](https://www.rfc-editor.org/rfc/rfc9308.html), [WebRTC data channels](https://www.rfc-editor.org/rfc/rfc8831.html), [ICE](https://www.rfc-editor.org/rfc/rfc8445.html), [TURN](https://www.rfc-editor.org/rfc/rfc8656.html).

## Conflict arbitration

| Conflict | Evidence and arbitration | Binding result |
| --- | --- | --- |
| DDA-primary versus WGC-primary | Neither API publishes a comparative latency guarantee. DDA is output-specific with metadata; WGC is target/consent-specific and supports windows. | Target-selected backend: DDA default for one SDR display; WGC co-primary for window capture and only authorized display remediation. |
| Direct zero-copy versus owned GPU pool | Capture leases cannot outlive their producer contracts, while source format conversion is usually required. | Engine-owned same-adapter GPU conversion/copy is normal; direct aliasing is experimental with a CopyLedger. |
| H.264 versus HEVC/AV1 | AV1/HEVC have desktop-quality opportunities, but cited encode/decode availability is less uniform and requires provider/legal matrix work. | H.264 4:2:0 compatibility floor; HEVC/AV1 experimental only. |
| ROI/4:4:4/tiles/region codecs | ROI is only an encoder hint; 4:4:4 is not a portable H.264 baseline; tiles retain a complete video fallback. | ROI optional; full-frame 4:4:4 and tiles deferred; simultaneous region codecs rejected. |
| QUIC versus WebRTC | QUIC fits LAN scope but needs an application media profile. WebRTC supplies ICE/TURN/RTP/SCTP machinery but its native stack behavior is version-specific. | QUIC is the LAN v0.1 baseline. EXP-02 decides the Internet baseline; custom UDP is out. |
| Discrete input DATAGRAMs versus reliable edges | A snapshot repairs an eventually held state but cannot recreate a lost short press/release, click, wheel tick, or drag boundary. Optional absolute pointer motion is replaceable; state transitions are not. | Use a reliable ordered input-transition stream for discrete edges and snapshots; allow DATAGRAM only for negotiated latest-wins absolute pointer samples with reliable edge anchors. |
| User-requested permission bypass versus product security | Portal and host consent are part of the supported Linux/Windows model; bypassing them is a different privileged/unattended product. | Harness-level YOLO execution does not alter product authorization. v0.1 fails closed on unavailable/revoked permission. |

## EXPERIMENT_REQUIRED

### EXP-01 — Windows capture backend and ownership

- **Question:** For the same authorized SDR display and adapter, which of DDA and WGC has lower P99 capture-available-to-encoder-submit latency without lease starvation?
- **Harness:** `capture_benchmark.exe`; capture one display, copy/convert into a fixed three-slot D3D11 NV12 pool, timestamp availability/submission/completion. It does not open network, decoder, renderer, or remote input.
- **Controlled variables:** Windows build, GPU/driver, display refresh/resolution, capture target, D3D11 device/adapter, encoder settings, power mode.
- **Metrics:** P50/P95/P99 capture-available-to-submit; frame cadence; lease hold duration; acquired-frame/owned-pool high-water marks; drop count; corruption checksum.
- **Pass/fail:** A default backend is promotable only if it sustains the target mode for 30 minutes with no unreleased lease, no corruption, no growing queue, and lower or statistically indistinguishable P99. Otherwise keep capability-selected choice and do not claim latency ranking.

### EXP-02 — QUIC DATAGRAM versus native WebRTC RTP/SRTP

- **Question:** Under identical encoded access units, discrete input edges/snapshots, and network impairment, which common stack meets the required correctness/connectivity gate with lower P99 frame age and input delivery latency?
- **Harness:** `transport_benchmark`; sends pre-encoded H.264 access units, synthetic reliable input edge/snapshot records, and optional replaceable absolute-pointer samples. It does not capture, encode, decode, or render a desktop.
- **Controlled variables:** payload cadence/size, path MTU, RTT, loss/reorder/jitter, datagram expiration, input lane policy, ICE/TURN route, priority policy, host hardware.
- **Metrics:** send-queue residence; expired-frame drops; complete/decode-eligible access units; recovery time; discrete edge application latency; snapshot convergence; pointer sample age; direct/relay connection success; bandwidth/CPU.
- **Pass/fail:** Promote a WAN candidate only if it has zero lost/reordered discrete input outcomes, bounded memory, valid recovery after loss, supported connectivity paths, and a predeclared meaningful P99 margin. If neither meets it, WAN/relay remains out of v0.1.

### EXP-03 — H.264 ROI / 4:4:4 / static refinement value

- **Question:** On representative IDE, terminal, and browser frames, does one alternative improve measured text quality or delivered bytes without exceeding the H.264 4:2:0 base latency budget?
- **Harness:** `codec_quality_benchmark`; feeds a fixed RGB desktop corpus into selected hardware provider configurations and optional independent tile compressor. It does not implement remote control or transport.
- **Controlled variables:** source corpus, resolution, target bitrate, cadence, provider/driver, fixed low-delay configuration, network byte budget.
- **Metrics:** encode latency, output bytes, chroma/text crop objective metric and visual review, tile invalidation correctness, queue depth.
- **Pass/fail:** No alternative advances unless it preserves base-frame correctness, improves a predefined text/byte metric, and does not worsen P95 latency. ROI remains a hint even if it wins.

### EXP-04 — PipeWire DMA-BUF to selected encoder

- **Question:** For one explicit compositor/GPU/driver/FourCC/modifier tuple, can a PipeWire DMA-BUF be consumed by the selected encoder without CPU copy and without unsafe buffer recycle?
- **Harness:** `pipewire_import_probe`; creates an authorized local ScreenCast stream, records negotiated SPA buffer metadata, imports one tuple, waits for the actual completion primitive, and requeues. It does not establish a remote desktop session.
- **Controlled variables:** compositor/portal version, PipeWire version, GPU/driver, encoder provider, source format/modifier, explicit versus implicit synchronization.
- **Metrics:** negotiated tuple, import/registration result, CopyLedger path/evidence grade, CPU-copy bytes, GPU conversion edge, fence/recycle timing, visual checksum.
- **Pass/fail:** Mark `gpu-direct` only when the complete tuple passes sustained reuse with a completion proof and no application copy. Otherwise retain `gpu_convert` or `cpu_copy`; unsupported is a valid result.

## Critical path after this freeze

1. Core correctness and bounded ownership contracts.
2. Windows capture on the D3D11 same-adapter profile.
3. Linux portal/PipeWire capture with revocation correctness.
4. Native presentation and local cursor path.
5. Hardware H.264 provider capability probe and low-delay configuration.
6. Direct-LAN QUIC media/control/input profile.
7. Input injection, snapshots, and release-all invariants.
8. Pairing, authorization, and privilege separation.
9. Cross-platform interoperability and forced-copy matrix.
10. Optical and stage benchmark harnesses.
11. WAN transport bake-off.
12. Relay/ICE only after the WAN choice and separate security review.
13. UX, packaging, signed release/update design only after the prior gates.

## Hard product boundary

v0.1 is one logged-in interactive user session, one display, SDR, direct LAN, and no claims of secure-desktop/UAC control, protected-content capture, generic unattended Wayland, login-screen capture, DRM circumvention, clipboard/file transfer, audio, relay, central account service, or automatic-update execution. A platform capability failure is an explicit diagnostic or capture-only mode—not a permission bypass.

## Primary sources

- [Microsoft Desktop Duplication](https://learn.microsoft.com/en-us/windows/win32/direct3ddxgi/desktop-dup-api)
- [Microsoft Windows Graphics Capture](https://learn.microsoft.com/en-us/windows/apps/develop/media-authoring-processing/screen-capture)
- [XDG ScreenCast v6](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.ScreenCast.html)
- [XDG RemoteDesktop v2](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.RemoteDesktop.html)
- [Linux DMA-BUF synchronization](https://docs.kernel.org/driver-api/dma-buf.html)
- [NVIDIA NVENC programming guide](https://docs.nvidia.com/video-technologies/video-codec-sdk/13.1/nvenc-video-encoder-api-prog-guide/index.html)
- [RFC 9000 — QUIC](https://www.rfc-editor.org/rfc/rfc9000.html)
- [RFC 9221 — QUIC DATAGRAM](https://www.rfc-editor.org/rfc/rfc9221.html)
- [RFC 8835 — WebRTC transports](https://www.rfc-editor.org/rfc/rfc8835.html)
- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html)
