# Architecture Decision Table

**Status:** Architecture Freeze v0.1. “Confidence” is confidence in the scoped decision, not a promise about an untested driver, compositor, or network path. `EXPERIMENT_REQUIRED` blocks promotion of the named capability, not the conservative fallback.

| Area | Candidates | Selected | Confidence | Prototype required |
| Windows capture | DXGI / WGC | DDA default for one authorized SDR display; WGC explicit window backend and authorized display alternative | Medium | EXP-01 selects a latency default; same-adapter ownership probe |
| Linux capture | Portal/PipeWire / KMS | Runtime-probed XDG Portal + direct PipeWire; no KMS | High for logged-in GNOME/KDE capture; low outside matrix | EXP-04 plus GNOME/KDE lifecycle matrix |
| GPU interop | D3D / Vulkan / EGL | D3D11 owned GPU conversion on Windows; negotiated DMA-BUF import with owned fallback on Linux | High for fallback; low for direct aliasing | EXP-04 exact tuple probes |
| Base codec | H264 / HEVC / AV1 | Hardware H.264 AVC, 8-bit 4:2:0, low-delay P-only compatibility floor | Medium-high | Provider/decoder capability probe and recovery tests |
| Text quality | ROI / 444 / tiles | Base video only; ROI is optional hint; static exact tiles later | High for deferral | EXP-03 |
| Media transport | QUIC / WebRTC / UDP | QUIC stream + DATAGRAM profile for direct LAN; WAN undecided pending bake-off | Medium for LAN; low for WAN | EXP-02 |
| Input | stream / datagram hybrid | Reliable ordered transition stream + ordered snapshots; optional latest-wins DATAGRAM absolute motion; forced release-all | High | Edge/snapshot loss-reorder convergence and send-priority test |
| NAT | ICE / custom | No v0.1 NAT traversal; ICE/TURN/WebRTC first WAN candidate after EXP-02 | High for deferral | EXP-02 WAN connectivity matrix |
| Crypto | TLS / Noise | TLS 1.3 through QUIC; pinned device public keys; no second Noise handshake | High | Pairing/replay/revocation test |
| Language | Rust / C++ hybrid | Rust bounded core; narrow native C++/platform provider boundary | High | Native ABI/ownership stress tests |

## Rationale and binding constraints

### Windows capture

DDA is tied to an adapter output and exposes metadata useful for diagnostics; WGC captures displays or windows but brings a distinct target/access/border model. Neither API documents a universal lower latency, so it is incorrect to encode an automatic “DDA then WGC” fallback ladder. The binding selector is **target semantics + live capability**, not an assumed performance ranking. A DDA `ProtectedContentMaskedOut` frame remains a live capture session but signals that the caller must clear or replace stale reconstruction history before forwarding the already-masked image. Lock, secure desktop, and an inaccessible desktop pause capture without retry or permission bypass. Access loss and display reconfiguration recreate with bounded backoff. Sources: [DDA](https://learn.microsoft.com/en-us/windows/win32/direct3ddxgi/desktop-dup-api), [DuplicateOutput](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/nf-dxgi1_2-idxgioutput1-duplicateoutput), [DXGI frame info](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/ns-dxgi1_2-dxgi_outdupl_frame_info), [WGC](https://learn.microsoft.com/en-us/windows/apps/develop/media-authoring-processing/screen-capture).

### Linux capture

The ordinary Wayland host must authorize through the portal, then consume frames directly through the PipeWire remote FD. Runtime interface and device discovery determines whether capture-only or capture-and-control is offered. Portal sessions are revocable; PipeWire buffer ownership is borrowed. GNOME and KDE/KWin form separate validation profiles. wlroots `xdg-desktop-portal-wlr` is not a v0.1 remote-control target because its upstream scope is ScreenCast/Screenshot. Sources: [ScreenCast](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.ScreenCast.html), [RemoteDesktop](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.RemoteDesktop.html), [Session](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Session.html), [wlroots portal](https://raw.githubusercontent.com/emersion/xdg-desktop-portal-wlr/master/README.md).

### GPU interop

The performance baseline is a **known GPU conversion/copy into an owned bounded surface**, not an unverified direct import. Windows RGB capture normally needs conversion for NV12 H.264 input. Linux DMA-BUF needs exact format/modifier/device/fence compatibility. The public CopyLedger label is derived from the detailed per-frame ledger: only profiler-verified no-application-copy aliasing can be `zero_copy`; imports with opaque movement are `internal_copy_unknown`. Sources: [NVENC input formats](https://docs.nvidia.com/video-technologies/video-codec-sdk/13.1/nvenc-video-encoder-api-prog-guide/index.html#selecting-input-formats), [DMA-BUF](https://docs.kernel.org/driver-api/dma-buf.html), [EGL modifiers](https://registry.khronos.org/EGL/extensions/EXT/EGL_EXT_image_dma_buf_import_modifiers.txt).

### Codec and text quality

H.264 is selected because the initial vendor evidence supports a wider low-delay hardware floor, not because it yields the sharpest desktop text. Full-frame 4:4:4 constrains compatibility. ROI is a provider QP/importance hint and does not create independent exact pixels or a recoverable delta stream. Static lossless tiles are a later overlay candidate because missing tiles leave the base image intact; concurrent regional encoders are rejected until the baseline proves insufficient. Sources: [NVIDIA capability matrix](https://docs.nvidia.com/video-technologies/video-codec-sdk/13.0/nvenc-application-note/index.html), [Intel oneVPL matrix](https://www.intel.com/content/www/us/en/docs/onevpl/developer-reference-media-intel-hardware/1-0/features-and-formats.html), [oneVPL ROI](https://oneapi-spec.uxlfoundation.org/specifications/oneapi/v1.2-rev-1/elements/onevpl/source/api_ref/vpl_structs_encode).

### Transport and input

QUIC DATAGRAM is suitable only as a low-latency media primitive coupled to an explicit bounded frame protocol, pacing, access-unit expiry, and dependency recovery. The direct-LAN scope accepts that work. WAN compatibility is not frozen: WebRTC receives the first bake-off because ICE/TURN, RTP repair/feedback, and SCTP modes exist; a custom UDP stack would recreate congestion, MTU, NAT, relay, and security work. Discrete input edges—key/button down/up, wheel ticks, and drag boundaries—use a reliable ordered transition stream because a snapshot cannot reconstruct a completely lost short action. Periodic snapshots live in the same ordered history; optional latest-wins DATAGRAMs carry only replaceable absolute pointer samples, with reliable anchors for click/drag edges. Focus/revoke/close release-all, sequence/epoch rejection, and a host controller lease bound the remaining stuck-state risk. Sources: [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html), [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html), [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002.html), [RFC 8831](https://www.rfc-editor.org/rfc/rfc8831.html), [RFC 8835](https://www.rfc-editor.org/rfc/rfc8835.html), [RFC 8445](https://www.rfc-editor.org/rfc/rfc8445.html).

### Security and language

QUIC brings TLS 1.3; it does not replace device identity, pairing, local authorization, session capability checks, bounded parsing, local privacy, or release signing. Pair with QR/out-of-band confirmation of device public-key fingerprints, pin the identity, disable 0-RTT for non-idempotent application actions, and use short-lived session authorization. No v0.1 product feature may silently bypass host consent, Portal consent, Windows integrity/UAC boundaries, or platform lock/security surfaces. Rust owns untrusted protocol/session/resource logic; C++ remains limited to platform graphics/media APIs that cannot be expressed safely in the portable core. Sources: [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html), [RFC 8446](https://www.rfc-editor.org/rfc/rfc8446.html), [Windows DPAPI](https://learn.microsoft.com/en-us/windows/win32/secauthn/data-protection), [Freedesktop Secret Service](https://specifications.freedesktop.org/secret-service/latest-single/).

## Experiment gate registry

- **EXP-01:** DDA versus WGC capture availability-to-encode submission and owned-surface lease behavior.
- **EXP-02:** QUIC DATAGRAM versus native WebRTC under matched pre-encoded media/input impairment and connectivity profiles.
- **EXP-03:** H.264 ROI / 4:4:4 / static refinement benchmark on desktop corpus.
- **EXP-04:** PipeWire DMA-BUF exact tuple import to the chosen Linux encoder with safe recycle.

Detailed single-question specifications and pass/fail rules are in [`research/FINAL_ARCHITECTURE_DECISION.md`](research/FINAL_ARCHITECTURE_DECISION.md#experiment_required).
