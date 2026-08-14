# QUIC-First Cross-Platform Remote Desktop

## Status

Accepted architecture direction on 2026-08-15: direct-LAN 1080p120 is the first performance profile. “Outperform AnyDesk” is a benchmark objective, not a claim; it may be made only after a reproducible same-hardware comparison passes.

## Goal

Deliver deployable, native Windows and Linux Host/Client binaries for one logged-in interactive desktop session. The product must make the low-latency path observable and bounded: native capture, GPU-owned conversion, hardware H.264, QUIC media delivery, hardware decode, native presentation, and remote input must remain on explicit resource and epoch contracts.

The first supported acceptance profile is SDR 1920×1080 at 120 Hz on a wired Gigabit LAN, using mutually negotiated hardware H.264 encode/decode. The product does not promise the profile on unsupported drivers, software codec fallbacks, Wi-Fi, WAN, secure desktop, or unavailable compositor permissions.

## Product Boundary

- Each operating system can run either the controlled Host or controlling Client role.
- Windows 10/11 supports one authorized SDR display through DDA when its target is an adapter output and WGC when the selected target is a window or authorized WGC item.
- GNOME Wayland and KDE/KWin Wayland use the XDG ScreenCast Portal and the direct PipeWire remote FD. Remote input requires an authorized RemoteDesktop v2 session plus EIS/libei; otherwise the endpoint is capture-only or fails closed.
- v0.1 is direct LAN only. No Internet traversal, relay, hosted service, WSL proxy, port forwarding, unattended access, secure desktop, HDR, audio, clipboard, file transfer, or generic Wayland input bypass is a product path.
- A Windows executable and Linux executable each bind their own native socket. No role may enter `FakeCapture`, `ExactTestCodec`, or simulated interactive input except in a test/lab binary.

## Architecture Decision

Use one authenticated QUIC/TLS 1.3 connection per session. QUIC owns encryption, loss recovery, congestion control, path validation, and MTU discovery. The application does not add Noise, a second AEAD record layer, arbitrary nonce management, custom UDP retransmission, or a parallel security boundary.

`latencydesk-protocol` owns bounded application framing and versioned semantic validation; it has no transport, runtime, crypto, or platform dependency. `latencydesk-session` owns device pairing, peer pins, host authorization, controller lease, dispatch generation, epochs, and close semantics. `latencydesk-quic-transport` owns Quinn endpoint lifecycle and maps the application lanes to QUIC streams and DATAGRAMs. `latencydesk-runtime` is the only composition root that joins authenticated session authority to platform providers.

The selected transport follows the existing architecture freeze and Quinn's current model: endpoint binding is address-family-sensitive on Windows, reliable unidirectional streams are subject to QUIC flow control, and a DATAGRAM may be unsupported, disabled, or too large. A media sender must drop expired video instead of blocking or silently converting it into reliable traffic. Quinn documents that 0-RTT data precedes TLS client authentication; v0.1 does not invoke `into_0rtt` and sends no input, authorization, pairing, or media before full connection authentication.

## Reference-Derived Constraints

- RustDesk separates capture, input, media/server, rendezvous, and platform code. LatencyDesk adopts that boundary but rejects its unbounded media notifier queue: every production handoff has an explicit finite capacity and an expiry policy. Source: <https://github.com/rustdesk/rustdesk#file-structure> and <https://github.com/rustdesk/rustdesk/blob/master/src/server/video_service.rs>.
- Sunshine probes real display/encoder availability and has distinct hardware-input paths. LatencyDesk selects a complete provider tuple from observed capability, adapter, format, synchronization, and queue evidence; it never assumes a vendor or API name is automatically fastest. Source: <https://github.com/LizardByte/Sunshine#-feature-compatibility> and <https://github.com/LizardByte/Sunshine/blob/master/src/video.cpp>.
- Moonlight treats hardware decoding, codecs, HDR, pointer modes, and input as client capabilities. LatencyDesk keeps the same capability-oriented receiver boundary, but v0.1 negotiates only H.264 8-bit 4:2:0 SDR and one explicit cursor mode. Source: <https://github.com/moonlight-stream/moonlight-qt#features>.

## Data Planes

```text
Host
  capture lease -> owned D3D11/PipeWire surface -> GPU conversion -> H.264 encoder
      -> bounded media datagram -> QUIC DATAGRAM -> Client reassembly
      -> hardware decode -> native presentation submission -> completion fence

Client
  local input -> ordered transition record -> QUIC reliable input stream -> Host
      -> session authority + epoch permit -> authorized native input backend
```

### Control lane

One bounded, length-prefixed reliable ordered stream carries pairing messages, capability selection, session authorization, lease state, recovery requests, close reasons, and diagnostics. A parsed control record must be completely available, below its class-specific cap, and canonical before session mutation.

### Input lane

One bounded, length-prefixed reliable ordered stream carries keyboard/button transitions, wheel ticks, drag boundaries, and state snapshots. Every coordinate-dependent edge includes an absolute pointer anchor. Latest-wins absolute pointer samples may use a separate DATAGRAM only after the reliable input stream has established its current anchor. Any transport close, permission revocation, focus loss, deadline expiry, or epoch change performs local release-all independently of remote delivery.

### Media lane

A QUIC DATAGRAM carries exactly one bounded media fragment with protocol version, session ID, authorization/display/codec epochs, stream ID, frame ID, conservative dependency ID, expiry, fragment range, recovery flag, and payload length. The sender rejects an oversize fragment before `send_datagram`, drops a frame that expires or loses continuity, and requests/produces an IDR rather than retransmitting obsolete P-frame fragments. Reassembly is byte- and entry-capped; the receiver retains at most one newest continuity-valid decoded frame awaiting presentation.

## Identity, Pairing, and Authorization

Each endpoint creates or loads a persistent device identity from OS user-secret storage. A pairing attempt is locally initiated, short-lived, rate-limited, and binds both device public-key fingerprints, a generated pending-session ID, selected capabilities, and expiry to a six-digit out-of-band SAS. Both local operators explicitly approve equality. Only then is the peer public identity stored under the selected alias.

The QUIC TLS certificate identity is checked against the selected peer pin before application session activation. If the pin is absent, pairing is required; if it mismatches, the connection closes before media or input admission. A successful TLS connection alone never permits capture or input: the Host must also grant an explicit short-lived controller lease and the session authority must issue an exact dispatch permit.

The product disables 0-RTT for every application lane. It logs neither private keys, certificate material, SAS values, QR payloads, pixels, typed text, clipboard data, raw GPU handles, nor PipeWire FDs. Crash/core-dump protections are established before identity or session material is created; inability to establish the platform guard is a startup failure.

## Provider and Resource Contracts

A `ProviderSelection` is an immutable tuple of capture, conversion, encoder, decoder, renderer, and input providers plus the observed device, format, queue policy, driver/provider version, recovery controls, and CopyLedger evidence. Selection succeeds only if the tuple can produce H.264 AVC 8-bit 4:2:0 SDR for the target display and the chosen input capability is authorized.

Capture leases remain provider-owned. Before asynchronous encoding, the runtime either performs an explicit bounded GPU conversion/copy into an engine-owned surface or obtains a profiler-verified direct aliasing proof. `CopyLedger` records the exact edge and calls it `zero_copy` only when no application CPU or GPU copy is proven. A DDA/WGC/PipeWire lease is returned only after the resulting submission fence completes or a quiesce path safely detaches it.

Every provider call receives a `DispatchStamp { generation, authorization_epoch, display_epoch, codec_epoch }` and rechecks it immediately before native work. A resource error, display change, access loss, decode continuity loss, or authorization mutation advances the generation, fences old work, and requires an independently decodable IDR before presentation resumes.

## Latency and Reliability Gates

The first performance report records per-stage p50/p95/p99 for capture-to-convert, convert-to-encode-submit, encode-to-datagram, one-way network arrival, decode-to-submit, submit-to-present-fence, and closed-loop input. It also records frame expiry, reassembly rejection, recovery-IDR count, provider queue depth, CopyLedger class, selected driver, display mode, and network profile.

A 30-minute 1080p120 wired-Gigabit soak is a prerequisite for promotion of a provider tuple. It must show bounded memory, no retained capture lease, no stuck input after forced disconnect, no stale-epoch presentation, and a report for every latency stage. DDA versus WGC and direct aliasing are selected only by the existing exact-hardware experiment gates. The eventual AnyDesk comparison uses the same two devices, monitor modes, cable/switch path, codec profile, capture target, and workload; a performance claim requires the raw measurements and comparison method in the release evidence.

## Deployment and Operations

Windows builds use the MSVC Rust target, Visual C++ Build Tools, Windows SDK, and a narrow C++ bridge for D3D11/Media Foundation/COM interaction. Linux builds use its native target and the selected Portal, PipeWire, EIS/libei, and renderer development packages. CI builds and tests the Rust core on both platforms and runs native bridge contract tests where the runner supports them.

Release artifacts are native architecture-specific packages with a manifest containing version, Git revision, supported provider matrix, licensing, checksums, and the benchmark configuration. Packaging must fail if a production binary links the test-only capture/codec/input implementations or if its supported matrix claims an unverified provider tuple.

## Explicit Non-Claims

No release may claim lower latency than AnyDesk, universal 1080p120 support, zero-copy, HDR, WAN reliability, secure-desktop control, or provider support until the required local measurement and acceptance evidence exists. A failed capability probe must result in a precise diagnostic and safe closure or a documented supported fallback, never a silent CPU round-trip or permission bypass.
