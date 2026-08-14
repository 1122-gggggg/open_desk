# Windows capture and GPU-boundary research

_Evidence-led challenge to the current Windows capture proposal. Scope: native logged-in-user capture on Windows desktop; Microsoft and NVIDIA primary documentation reviewed on 2026-08-13. API availability, access, HDR, and GPU behavior are Windows-version-, driver-, compositor-, and adapter-specific._

---

## Direct answers

| # | Answer |
| --- | --- |
| 1 | **Lowest-latency backend:** no primary source publishes a comparative capture-to-encoder latency guarantee for DXGI Desktop Duplication (DDA) versus Windows Graphics Capture (WGC). **EXPERIMENT_REQUIRED**: choose by p50/p99 capture-to-encode-submit latency on each supported adapter/driver class, not by API folklore. DDA exposes an acquired DXGI surface; WGC exposes a checked-out D3D11 frame surface, but those contracts do not establish a latency ordering. [DDA overview](https://learn.microsoft.com/en-us/windows/win32/direct3ddxgi/desktop-dup-api) [WGC screen capture](https://learn.microsoft.com/en-us/windows/apps/develop/media-authoring-processing/screen-capture) |
| 2 | **Should DXGI be primary?** **Yes only for the v0.1 single-display SDR desktop profile, and only after capability checks; no as a project-wide capture policy.** DDA is uniquely valuable there because it supplies per-output dirty/move/pointer metadata and directly exposes a DXGI surface. It is not usable in several documented states and does not capture an arbitrary window. [DDA overview](https://learn.microsoft.com/en-us/windows/win32/direct3ddxgi/desktop-dup-api) [DuplicateOutput](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/nf-dxgi1_2-idxgioutput1-duplicateoutput) |
| 3 | **Should WGC be a fallback?** **No—not merely.** It is a co-primary, target-specific backend for application-window capture and a conditional display backend. An automatic DXGI→WGC switch is valid only when a compatible `GraphicsCaptureItem` already exists and WGC support, access, consent, and border policy pass; otherwise the proposed “fallback” cannot start capture. WGC’s picker is secure user UI and normally draws a notification border. [WGC screen capture](https://learn.microsoft.com/en-us/windows/apps/develop/media-authoring-processing/screen-capture) [programmatic target interop](https://learn.microsoft.com/en-us/windows/win32/api/windows.graphics.capture.interop/nn-windows-graphics-capture-interop-igraphicscaptureiteminterop) |
| 4 | **When is DXGI unavailable?** At creation it can fail for a wrong-adapter device or second duplication of the same output in one process (`E_INVALIDARG`); inaccessible secure desktop (`E_ACCESSDENIED`); unsupported 8-bpp/non-DWM scenarios (`DXGI_ERROR_UNSUPPORTED`); the default four-concurrent-duplication limit (`DXGI_ERROR_NOT_CURRENTLY_AVAILABLE`); or a disconnected session (`DXGI_ERROR_SESSION_DISCONNECTED`). Existing duplication becomes invalid on desktop/mode/DWM/full-screen producer changes (`DXGI_ERROR_ACCESS_LOST`). The Windows 7 Platform Update path returns `E_NOTIMPL`. Do **not** claim that all connected RDP sessions are categorically unsupported from these sources; test the actual supported Windows/RDP matrix. [DuplicateOutput](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/nf-dxgi1_2-idxgioutput1-duplicateoutput) [AcquireNextFrame](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/nf-dxgi1_2-idxgioutputduplication-acquirenextframe) |
| 5 | **Best capture→encoder GPU-memory path:** create the capture, GPU conversion, and hardware encoder on the output-owning adapter’s D3D11 device; copy/convert the borrowed capture surface into an application-owned encode-slot texture (normally the H.264 input format negotiated with the encoder, commonly NV12) entirely on that GPU; then wrap that owned texture in `MFCreateDXGISurfaceBuffer` and submit it to a D3D11-aware hardware MFT through an `IMFDXGIDeviceManager`. Avoid CPU staging and do not loan a borrowed capture surface to an asynchronous encoder. [MFCreateDXGISurfaceBuffer](https://learn.microsoft.com/en-us/windows/win32/api/mfapi/nf-mfapi-mfcreatedxgisurfacebuffer) [MF_SA_D3D11_AWARE](https://learn.microsoft.com/en-us/windows/win32/medfound/mf-sa-d3d11-aware) |
| 6 | **Is D3D12 necessary?** **No for v0.1.** Both capture APIs naturally meet at D3D11: DDA returns a D3D11-compatible surface and WGC is explicitly a `Direct3D11CaptureFramePool`. Media Foundation can wrap either `ID3D11Texture2D` or `ID3D12Resource`, but adding 11-on-12 introduces resource state, acquire/release, flush, and lifetime obligations; Microsoft documents moderate CPU and significant memory overhead for 11-on-12. [WGC frame pool](https://learn.microsoft.com/en-us/uwp/api/windows.graphics.capture.direct3d11captureframepool?view=winrt-26100) [DXGI media buffer](https://learn.microsoft.com/en-us/windows/win32/api/mfapi/nf-mfapi-mfcreatedxgisurfacebuffer) [D3D11On12](https://learn.microsoft.com/en-us/windows/win32/direct3d12/direct3d-11-on-12) |
| 7 | **Most rational v0.1 plan:** a D3D11-only, single-output, SDR H.264 8-bit 4:2:0 path with a capability-selected backend: DDA default for authorized display capture; WGC explicit for window capture and conditional remediation of DDA failure. Use a small owned GPU texture ring, same-adapter hardware encode when available, a hard protected/locked state that sends no usable pixels or input, explicit cursor policy, and restart-on-invalidation. Defer multi-output stitching, cross-adapter transfer, native D3D12, HDR preservation, and DDA dirty-rectangle transport semantics until their narrow experiments pass. |

## Why a single fallback ladder is the wrong abstraction

The baseline’s valuable observation is that DDA is efficient for a visible desktop. But **“DXGI primary, WGC fallback” conflates two independent choices**:

1. **Target semantics:** DDA duplicates one adapter output; a whole desktop requires one duplication object per active output and has no explicit cross-output timing synchronization. WGC is the documented API that can acquire from either a display *or an application window*. [DuplicateOutput](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/nf-dxgi1_2-idxgioutput1-duplicateoutput) [WGC screen capture](https://learn.microsoft.com/en-us/windows/apps/develop/media-authoring-processing/screen-capture)
2. **Permission/UX semantics:** WGC’s standard flow includes secure user selection and a visible border. Programmatic target selection is only available from Windows 10 1903; the access-kind APIs arrive in Windows 10 20348, and borderless access is separately consent/capability-gated. A DDA failure therefore cannot automatically become a WGC success without a valid item and authorization. [IGraphicsCaptureItemInterop](https://learn.microsoft.com/en-us/windows/win32/api/windows.graphics.capture.interop/nn-windows-graphics-capture-interop-igraphicscaptureiteminterop) [GraphicsCaptureAccessKind](https://learn.microsoft.com/en-us/uwp/api/windows.graphics.capture.graphicscaptureaccesskind?view=winrt-26100) [RequestAccessAsync](https://learn.microsoft.com/en-us/uwp/api/windows.graphics.capture.graphicscaptureaccess.requestaccessasync?view=winrt-26100)

Use a **backend selector**, not a fallback order:

| Requested target / state | v0.1 selection | Reason |
| --- | --- | --- |
| One authorized SDR display; DDA creates on its owning adapter | DDA | Direct D3D11 surface plus dirty/move/pointer metadata |
| Specific application window | WGC | WGC explicitly supports application-window capture; DDA is output-only |
| DDA unavailable and pre-authorized WGC display item exists | WGC | Conditional remediation, not unconditional fallback |
| Lock, secure desktop, protected/inaccessible desktop | No capture; protected state | Do not bypass desktop security |
| Multi-output desktop spanning adapters | Out of v0.1 scope | DDA requires per-output capture and explicit timestamp composition; cross-adapter costs are not latency-safe by default |
| HDR preservation requested | Explicit HDR experiment/profile | WGC documents a float pipeline; classic DDA is BGRA8, while `DuplicateOutput1` has a fullscreen high-color exception |

## Decision records

### 1. Capture backend selection

Decision: Replace the universal DXGI-primary/WGC-fallback rule with target- and capability-selected capture.

Current proposal: DXGI Desktop Duplication primary with WGC secondary.

Verdict: MODIFY

Recommended solution: Make DDA the default only for the v0.1 **single, authorized, SDR display** profile. Make WGC the explicit backend for window capture and a conditional display alternative only after `GraphicsCaptureSession::IsSupported`, target-item availability, access status, and visible-border policy are satisfied. Persist the selected backend and failure HRESULT/status in session telemetry.

Why: DDA returns one output’s desktop surface and metadata; it cannot itself represent window capture. WGC is designed for display or application-window frames, but its documented picker/border model means it is not a transparent substitute. [DDA overview](https://learn.microsoft.com/en-us/windows/win32/direct3ddxgi/desktop-dup-api) [WGC screen capture](https://learn.microsoft.com/en-us/windows/apps/develop/media-authoring-processing/screen-capture)

Alternative: Always use WGC to simplify one code path.

Risk: WGC may impose unsupported-device, consent, programmatic-access, or notification-border constraints and has no documented comparative latency advantage. Conversely, a DDA-only plan loses supported window semantics and fails in documented desktop states.

Prototype required: Yes — **EXPERIMENT_REQUIRED**: measure DDA and WGC end-to-end latency and frame cadence on each target GPU/driver/display topology before setting an automatic default.

Evidence: DDA’s output-specific model and documented failure cases are in [DuplicateOutput](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/nf-dxgi1_2-idxgioutput1-duplicateoutput). WGC mandates a support check and documents picker/border behavior in [Screen capture](https://learn.microsoft.com/en-us/windows/apps/develop/media-authoring-processing/screen-capture).

### 2. Latency claim and backpressure policy

Decision: Treat capture-backend latency ranking as a measured product property, not an architectural fact.

Current proposal: DXGI is implicitly assumed to be the lowest-latency backend.

Verdict: EXPERIMENT

Recommended solution: Timestamp at capture availability (`LastPresentTime`/`SystemRelativeTime` where applicable), owned-texture readiness, encoder submission, and encoded access unit completion. Report p50/p95/p99 and dropped/coalesced frames for each backend, adapter, display refresh rate, and HDR mode. Under pressure, discard stale frames before encoder submission rather than queueing them.

Why: DDA exposes QPC-derived present and pointer times, accumulated-frame count, and coalescing state; WGC exposes a QPC `SystemRelativeTime`. Neither documentation set promises an ordering between their capture latency. [DXGI_OUTDUPL_FRAME_INFO](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/ns-dxgi1_2-dxgi_outdupl_frame_info) [WGC screen capture](https://learn.microsoft.com/en-us/windows/apps/develop/media-authoring-processing/screen-capture)

Alternative: Declare DDA fastest and optimize only it.

Risk: A driver/compositor/version-specific result becomes a global assumption, creating regressions on hybrid GPUs, HDR, window capture, or a future Windows release.

Prototype required: Yes — **EXPERIMENT_REQUIRED**: does DDA or WGC have the lower p99 capture-available-to-encoder-submit time for the same authorized display on each supported hardware class?

Evidence: DDA documents `AccumulatedFrames` and `RectsCoalesced`, showing that capture consumers can fall behind. [DXGI_OUTDUPL_FRAME_INFO](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/ns-dxgi1_2-dxgi_outdupl_frame_info) WGC documents asynchronous frame delivery and warns against heavy `FrameArrived` work on the UI thread. [Screen capture](https://learn.microsoft.com/en-us/windows/apps/develop/media-authoring-processing/screen-capture)

### 3. Capture-surface ownership and capture-to-encoder path

Decision: Copy or GPU-convert every borrowed capture surface into an application-owned same-adapter encode slot before asynchronous encoding.

Current proposal: Opportunistic zero-copy with bounded copy fallback.

Verdict: MODIFY

Recommended solution: Define two distinct leases: **capture lease** (DDA acquired frame or WGC checked-out frame) and **encode-slot lease** (engine-owned texture/sample). On the output-owning D3D11 device, convert/copy the valid capture surface directly into a bounded ring of owned encoder-input textures; wrap the owned texture with `MFCreateDXGISurfaceBuffer`; submit only that owned texture to a D3D11-aware hardware MFT after setting its DXGI device manager. No CPU readback/staging is on the latency path.

Why: DDA states that after `ReleaseFrame` its desktop surface is invalid for DirectX operations. WGC states that its frame surface must not be retained after the frame is checked back into the pool. `MFCreateDXGISurfaceBuffer` wraps an existing D3D11 texture rather than requiring a CPU copy, and `MF_SA_D3D11_AWARE` identifies MFTs that accept the D3D11 device-manager path. [ReleaseFrame](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/nf-dxgi1_2-idxgioutputduplication-releaseframe) [WGC frame lifetime](https://learn.microsoft.com/en-us/windows/apps/develop/media-authoring-processing/screen-capture) [MFCreateDXGISurfaceBuffer](https://learn.microsoft.com/en-us/windows/win32/api/mfapi/nf-mfapi-mfcreatedxgisurfacebuffer) [MF_SA_D3D11_AWARE](https://learn.microsoft.com/en-us/windows/win32/medfound/mf-sa-d3d11-aware)

Alternative: Register/submit the DDA or WGC producer surface directly to the encoder as “zero-copy.”

Risk: The source is BGRA for classic DDA while the H.264 MFT may require a different negotiated input format; more importantly, an async encoder can outlive the capture lease. A direct path is valid only if the encoder format, device, synchronization contract, and lease lifetime are proven together. **EXPERIMENT_REQUIRED**.

Prototype required: Yes — **EXPERIMENT_REQUIRED**: can an immediate same-device GPU copy followed by capture-lease release remain artifact-free under high motion on every target driver, without waiting for a GPU completion primitive?

Evidence: DDA returns a DXGI surface and uses BGRA8 in the classic API. [DDA overview](https://learn.microsoft.com/en-us/windows/win32/direct3ddxgi/desktop-dup-api) WGC uses a D3D11 frame pool and supplies a native DXGI-interface bridge. [Frame pool](https://learn.microsoft.com/en-us/uwp/api/windows.graphics.capture.direct3d11captureframepool?view=winrt-26100) [GetDXGIInterface-IDirect3DSurface](https://learn.microsoft.com/en-us/windows/win32/api/windows.graphics.directx.direct3d11.interop/nf-windows-graphics-directx-direct3d11-interop-getdxgiinterface-r1) NVIDIA’s current encoder guide likewise distinguishes D3D11 resource input from D3D12 resource input, rather than making them interchangeable. [NVENC Programming Guide](https://docs.nvidia.com/video-technologies/video-codec-sdk/13.1/nvenc-video-encoder-api-prog-guide/index.html)

### 4. D3D11 versus D3D12

Decision: Keep the v0.1 capture-to-encode boundary entirely in D3D11.

Current proposal: Rust core with native boundary; graphics API choice is unresolved beyond DXGI/WGC.

Verdict: KEEP

Recommended solution: Use one native D3D11 device per chosen capture adapter, expose opaque native resource leases across the Rust boundary, and keep D3D12 out of the normal capture/encode path. Permit a later D3D12 implementation only behind a capability and benchmark gate for a native D3D12 encoder or a measured cross-adapter need.

Why: DDA’s duplication device must come from the output’s adapter; WGC’s frame-pool API is explicitly D3D11; and Media Foundation accepts D3D11 texture-backed buffers. D3D11On12 adds wrapped-resource acquire/release, queue flush, resource-state, and GPU-completion requirements. Microsoft says 11-on-12 is not optimized for performance and can have moderate CPU and significant memory overhead. [DuplicateOutput](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/nf-dxgi1_2-idxgioutput1-duplicateoutput) [WGC frame pool](https://learn.microsoft.com/en-us/uwp/api/windows.graphics.capture.direct3d11captureframepool?view=winrt-26100) [MFCreateDXGISurfaceBuffer](https://learn.microsoft.com/en-us/windows/win32/api/mfapi/nf-mfapi-mfcreatedxgisurfacebuffer) [D3D11On12](https://learn.microsoft.com/en-us/windows/win32/direct3d12/direct3d-11-on-12)

Alternative: Start with D3D12 and bridge every capture frame through D3D11On12.

Risk: More synchronization and state transitions can add CPU work, memory cost, and failure surface without removing the D3D11 capture boundary.

Prototype required: No for v0.1. **EXPERIMENT_REQUIRED** before any D3D12 path is enabled as a default.

Evidence: `MFCreateDXGISurfaceBuffer` now accepts both `IID_ID3D11Texture2D` and `IID_ID3D12Resource`; that is compatibility, not evidence that a D3D12 detour improves a D3D11-origin capture pipeline. [MFCreateDXGISurfaceBuffer](https://learn.microsoft.com/en-us/windows/win32/api/mfapi/nf-mfapi-mfcreatedxgisurfacebuffer)

### 5. Dirty/move metadata and cursor

Decision: Consume DDA metadata for correctness and diagnostics, but do not make it a v0.1 transport codec; make cursor behavior explicit per backend.

Current proposal: Full-frame low-delay H.264 8-bit 4:2:0, with no stated metadata/cursor contract.

Verdict: MODIFY

Recommended solution: For DDA, obtain move rects before dirty rects whenever maintaining a persistent reconstruction surface; apply moves before dirties; tolerate empty lists and coalesced rectangles; record `AccumulatedFrames`/`RectsCoalesced`. For v0.1 full-frame H.264, use this metadata for cursor correctness, diagnostics, and optional local GPU-update optimization—not as a remote tile/move protocol. On DDA, cache pointer shape and reconcile position with `LastMouseUpdateTime` across outputs; composite it into the owned encode texture or transmit a separately rendered cursor, but never both. On WGC, set `IsCursorCaptureEnabled` explicitly rather than relying on a default.

Why: DDA explicitly supplies non-overlapping dirty rectangles and move rectangles, warns that accumulated updates may coalesce to cover pixels not actually changed, and requires moves before dirties for visual correctness. A capture wakeup can be pointer-only. DDA may return the cursor in the image or separately; WGC has an explicit cursor inclusion switch from Windows 10 2004. [DDA overview](https://learn.microsoft.com/en-us/windows/win32/direct3ddxgi/desktop-dup-api) [DXGI_OUTDUPL_FRAME_INFO](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/ns-dxgi1_2-dxgi_outdupl_frame_info) [WGC cursor property](https://learn.microsoft.com/en-us/uwp/api/windows.graphics.capture.graphicscapturesession.iscursorcaptureenabled?view=winrt-26100)

Alternative: Ignore rectangles and cursors, then rely on every captured bitmap to contain the pointer.

Risk: Missing, double-rendered, stale, or cross-monitor cursor images; incorrect reconstruction after move rectangles; and false assumptions that dirty rectangles identify exactly changed pixels.

Prototype required: No for basic metadata/cursor handling. **EXPERIMENT_REQUIRED** before using DDA metadata to skip conversion/encoding work under all coalescing and pointer-only cases.

Evidence: `PointerShapeBufferSize == 0` does not mean pointer state is absent; a nonzero mouse timestamp contains a valid position and shape must be cached until it changes. [DXGI_OUTDUPL_FRAME_INFO](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/ns-dxgi1_2-dxgi_outdupl_frame_info) WGC’s documented frame surface has no equivalent dirty/move contract. [WGC screen capture](https://learn.microsoft.com/en-us/windows/apps/develop/media-authoring-processing/screen-capture)

### 6. Access loss, lock, secure desktop, and UAC

Decision: Model session/desktop transitions as a protected capture state, not as a GPU retry loop.

Current proposal: Logged-in user-authorized sessions and LAN first, without a defined lock/UAC path.

Verdict: MODIFY

Recommended solution: Register the user-session helper for `WM_WTSSESSION_CHANGE`. On `WTS_SESSION_LOCK`, remote disconnect, or DDA `DXGI_ERROR_ACCESS_LOST`, stop acquisition, invalidate capture resources, clear borrowed leases, prevent remote input injection, and send a protected/paused session state—not the last usable frame. On `WTS_SESSION_UNLOCK` or `WTS_SESSION_DESKTOP_READY`, re-enumerate outputs/adapter, recreate DDA or WGC resources, reset cursor and frame-history state, and request an IDR. Treat `E_ACCESSDENIED` as an inaccessible desktop and wait for a qualifying transition; never busy-loop or try to bypass UAC/Winlogon.

Why: DDA says desktop switches can invalidate an existing duplication object and requires destruction/recreation. It says secure-desktop access is denied to a normal process, with `LOCAL_SYSTEM` given as the access example. Windows emits lock, unlock, and desktop-ready notifications to registered applications. UAC’s secure-desktop switch is enabled by default. [AcquireNextFrame](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/nf-dxgi1_2-idxgioutputduplication-acquirenextframe) [DuplicateOutput](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/nf-dxgi1_2-idxgioutput1-duplicateoutput) [WM_WTSSESSION_CHANGE](https://learn.microsoft.com/en-us/windows/win32/termserv/wm-wtssession-change) [UAC settings](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/settings-and-configuration)

Alternative: Keep retrying DDA through lock/UAC or configure Windows to put elevation prompts on the interactive desktop.

Risk: The first leaks stale pixels or spins/restarts indefinitely; the second weakens an OS security boundary and changes enterprise policy rather than solving capture correctness.

Prototype required: Yes — **EXPERIMENT_REQUIRED**: on each supported Windows build, what exact WGC event/frame behavior occurs at lock, unlock, and a secure-desktop UAC prompt?

Evidence: `AcquireNextFrame` documents `DXGI_ERROR_ACCESS_LOST` and its recovery. [AcquireNextFrame](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/nf-dxgi1_2-idxgioutputduplication-acquirenextframe) UAC documents that “Switch to the secure desktop when prompting for elevation” is enabled by default. [UAC settings](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/settings-and-configuration)

### 7. Multi-GPU and cross-adapter handling

Decision: Require same-adapter capture and encode in v0.1; defer cross-adapter transfer and multi-output composition.

Current proposal: Opportunistic zero-copy plus bounded copy fallback, without an adapter contract.

Verdict: MODIFY

Recommended solution: Enumerate the selected `IDXGIOutput` and create its D3D11 device on the owning adapter. Match the hardware encoder to that adapter’s LUID. One capture session owns one output, one D3D11 device, and an owned texture ring. If a suitable same-adapter hardware encoder is unavailable, surface the degraded path explicitly; do not silently call it latency-first. Support one output in v0.1. Treat multi-output stitching and cross-adapter transport as a later capability.

Why: DDA requires the supplied device to have been created from the output’s adapter; the full desktop needs a duplication object per active output and no explicit timing synchronization is supplied. D3D12 cross-adapter shared heaps are system-memory-backed, restrict resource/layout choices, require explicit barriers and cross-adapter fences, and are not efficient on discrete/NUMA architectures. [DuplicateOutput](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/nf-dxgi1_2-idxgioutput1-duplicateoutput) [Shared heaps](https://learn.microsoft.com/en-us/windows/win32/direct3d12/shared-heaps)

Alternative: Capture on an iGPU and always share/copy into a dGPU encoder.

Risk: The copy/encode route may be slower than same-adapter encoding; forcing D3D12 cross-adapter heaps creates a capability and synchronization dependency that D3D11 capture does not need.

Prototype required: Yes — **EXPERIMENT_REQUIRED**: on each hybrid-GPU target, does same-adapter hardware encoding beat cross-adapter transfer plus the other adapter’s hardware encoder at p99 latency and power?

Evidence: Microsoft explicitly advises confining cross-adapter heaps to scenarios that require them and notes their memory-pool/layout efficiency constraints. [Shared heaps](https://learn.microsoft.com/en-us/windows/win32/direct3d12/shared-heaps)

### 8. HDR and protected content

Decision: Make v0.1 SDR-only at the transport contract and treat HDR/protected-content handling as explicit, fail-closed capability paths.

Current proposal: Full-frame low-delay H.264 8-bit 4:2:0, with no explicit HDR or protected-content policy.

Verdict: MODIFY

Recommended solution: For v0.1, negotiate SDR output only: reject HDR preservation or perform a clearly selected GPU HDR-to-SDR tone-map before the owned 8-bit H.264 input texture. Do not silently treat HDR source values as SDR. For DDA, inspect `ProtectedContentMaskedOut` every frame; if true, notify the peer and purge/replace any reconstruction or frame-history state that could display older protected pixels before sending the next frame. Never attempt to defeat display affinity, DRM, or secure desktop protection. **[INFERENCE]**: forcing a clean output frame/IDR after a protection-state transition avoids stale cached imagery on the receiver.

Why: Classic `DuplicateOutput` always converts to BGRA8. `DuplicateOutput1` can preserve a high-color original fullscreen back buffer only when the requested scan-out formats permit it; that is a fullscreen/version/content-specific exception, not a general HDR desktop promise. WGC recommends `R16G16B16A16_FLOAT` through every capture component for HDR content and notes that HDR encoding or HDR-to-SDR tone mapping may be required. DDA marks protected content already blacked out, and Windows 10 2004 introduced `WDA_EXCLUDEFROMCAPTURE`, where a protected window does not appear outside the monitor. [DDA overview](https://learn.microsoft.com/en-us/windows/win32/direct3ddxgi/desktop-dup-api) [DuplicateOutput1](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_5/nf-dxgi1_5-idxgioutput5-duplicateoutput1) [WGC HDR guidance](https://learn.microsoft.com/en-us/windows/apps/develop/media-authoring-processing/screen-capture) [DXGI_OUTDUPL_FRAME_INFO](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/ns-dxgi1_2-dxgi_outdupl_frame_info) [SetWindowDisplayAffinity](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowdisplayaffinity)

Alternative: Advertise HDR support merely because a Windows capture API returns pixels, or preserve last good pixels through an exclusion/protection transition.

Risk: Washed-out/highlight-clipped content, false HDR claims, or exposure of stale sensitive imagery. Exact WGC behavior for DRM/display-affinity content is not established by the sources above.

Prototype required: Yes — **EXPERIMENT_REQUIRED**: on an HDR display, does each requested DDA `DuplicateOutput1` format and WGC float frame-pool path preserve the tested source’s color values through the chosen encoder/tone-map path? **EXPERIMENT_REQUIRED**: what user-visible frame/event result does WGC produce for `WDA_EXCLUDEFROMCAPTURE` and protected video on each supported Windows build?

Evidence: WGC’s HDR guidance is explicitly format-pipeline-wide. [WGC screen capture](https://learn.microsoft.com/en-us/windows/apps/develop/media-authoring-processing/screen-capture) `ProtectedContentMaskedOut` is a DDA frame-level signal, not permission to recover the masked data. [DXGI_OUTDUPL_FRAME_INFO](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/ns-dxgi1_2-dxgi_outdupl_frame_info)

## Required operational boundaries

### Resource lease release boundaries

| Boundary | Required rule |
| --- | --- |
| DDA `AcquireNextFrame` succeeds | The duplication object owns an acquired-frame lease. Query/copy metadata and source only while the lease is valid. A second acquire without release is `DXGI_ERROR_INVALID_CALL`. [AcquireNextFrame](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/nf-dxgi1_2-idxgioutputduplication-acquirenextframe) |
| DDA capture source → engine-owned texture | Submit the same-adapter GPU copy/convert while the source is valid. Do not give the source to an asynchronous encoder. **EXPERIMENT_REQUIRED** for whether a submitted, not-yet-complete GPU copy permits immediate `ReleaseFrame` on every target driver; the conservative boundary is source-copy completion. |
| DDA `ReleaseFrame` | Call exactly once after the capture lease no longer needs the source, then immediately proceed toward the next acquire. After release, the desktop surface is invalid for DirectX operations; Microsoft recommends minimizing the interval before the next acquire. [ReleaseFrame](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/nf-dxgi1_2-idxgioutputduplication-releaseframe) |
| WGC `TryGetNextFrame` | Hold `Direct3D11CaptureFrame` and its underlying surface only long enough to copy the `ContentSize` sub-rectangle into an owned slot. Dispose/close the frame immediately after that; never retain the checked-in frame or surface. [WGC frame lifetime](https://learn.microsoft.com/en-us/windows/apps/develop/media-authoring-processing/screen-capture) |
| WGC resize/device-loss recreation | Drain/complete pending borrowed-frame work before `Recreate`; Microsoft discards existing frames at recreation. [WGC screen capture](https://learn.microsoft.com/en-us/windows/apps/develop/media-authoring-processing/screen-capture) |
| Owned encode slot | Reuse only after both the GPU work and the selected encoder’s asynchronous ownership of its `IMFSample` have ended. **[INFERENCE]**: model this with a fence/completion token per slot; exact completion notification is MFT/vendor-specific. |
| Teardown/access loss | First stop new acquisition, then retire borrowed leases, then wait/retire owned GPU/encoder slots before releasing devices. Never allow a stale frame or cursor cache to cross into a recreated session. |

### Access-loss state machine

- `DXGI_ERROR_WAIT_TIMEOUT` is a normal no-new-frame result; use finite waits because DDA waits cannot be cancelled. [AcquireNextFrame](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/nf-dxgi1_2-idxgioutputduplication-acquirenextframe)
- On `DXGI_ERROR_ACCESS_LOST` from acquire **or release**, invalidate the complete duplication object, not just the frame; destroy it and create a new one after the desktop transition. [AcquireNextFrame](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/nf-dxgi1_2-idxgioutputduplication-acquirenextframe) [ReleaseFrame](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/nf-dxgi1_2-idxgioutputduplication-releaseframe)
- On `E_ACCESSDENIED`, `DXGI_ERROR_SESSION_DISCONNECTED`, or a WTS lock event, enter `ProtectedOrUnavailable`; remove remote input authority and do not substitute the previous desktop frame.
- On desktop-ready/unlock, re-enumerate adapters/outputs, recreate resources, reset cursor/metadata and receiver history, and force the first encoded frame to be independently decodable. **[INFERENCE]**: forcing an IDR is the safest H.264 recovery boundary.
- `DXGI_ERROR_UNSUPPORTED` and `DXGI_ERROR_NOT_CURRENTLY_AVAILABLE` are capability/availability conditions, not reasons to loop at full speed. Wait for the documented display/desktop notification or back off and report the state. [DuplicateOutput](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/nf-dxgi1_2-idxgioutput1-duplicateoutput)

### Version and compositing notes

- DDA’s documented baseline is Windows 8; its Windows 7 Platform Update path returns `E_NOTIMPL`. [DuplicateOutput](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/nf-dxgi1_2-idxgioutput1-duplicateoutput)
- WGC’s D3D11 frame pool begins in Windows 10 1803; programmatic monitor/window target interop begins in 1903; explicit cursor inclusion begins in 2004; `GraphicsCaptureAccessKind` begins in 20348. [Frame pool](https://learn.microsoft.com/en-us/uwp/api/windows.graphics.capture.direct3d11captureframepool?view=winrt-26100) [IGraphicsCaptureItemInterop](https://learn.microsoft.com/en-us/windows/win32/api/windows.graphics.capture.interop/nn-windows-graphics-capture-interop-igraphicscaptureiteminterop) [WGC cursor property](https://learn.microsoft.com/en-us/uwp/api/windows.graphics.capture.graphicscapturesession.iscursorcaptureenabled?view=winrt-26100) [GraphicsCaptureAccessKind](https://learn.microsoft.com/en-us/uwp/api/windows.graphics.capture.graphicscaptureaccesskind?view=winrt-26100)
- HDR behavior depends on Windows build, content mode, monitor, compositor, driver, capture API, and encoder. Cross-adapter behavior is adapter/vendor/topology-specific. Do not promote any experiment result to an OS-wide truth.

## Sources

### Official

- [Microsoft Learn — Desktop Duplication API](https://learn.microsoft.com/en-us/windows/win32/direct3ddxgi/desktop-dup-api)
- [Microsoft Learn — IDXGIOutput1::DuplicateOutput](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/nf-dxgi1_2-idxgioutput1-duplicateoutput)
- [Microsoft Learn — IDXGIOutputDuplication::AcquireNextFrame](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/nf-dxgi1_2-idxgioutputduplication-acquirenextframe)
- [Microsoft Learn — IDXGIOutputDuplication::ReleaseFrame](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/nf-dxgi1_2-idxgioutputduplication-releaseframe)
- [Microsoft Learn — DXGI_OUTDUPL_FRAME_INFO](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/ns-dxgi1_2-dxgi_outdupl_frame_info)
- [Microsoft Learn — Windows Graphics Capture](https://learn.microsoft.com/en-us/windows/apps/develop/media-authoring-processing/screen-capture)
- [Microsoft Learn — Direct3D11CaptureFramePool](https://learn.microsoft.com/en-us/uwp/api/windows.graphics.capture.direct3d11captureframepool?view=winrt-26100)
- [Microsoft Learn — GraphicsCaptureItem desktop interop](https://learn.microsoft.com/en-us/windows/win32/api/windows.graphics.capture.interop/nn-windows-graphics-capture-interop-igraphicscaptureiteminterop)
- [Microsoft Learn — MFCreateDXGISurfaceBuffer](https://learn.microsoft.com/en-us/windows/win32/api/mfapi/nf-mfapi-mfcreatedxgisurfacebuffer)
- [Microsoft Learn — MF_SA_D3D11_AWARE](https://learn.microsoft.com/en-us/windows/win32/medfound/mf-sa-d3d11-aware)
- [Microsoft Learn — D3D11On12](https://learn.microsoft.com/en-us/windows/win32/direct3d12/direct3d-11-on-12)
- [Microsoft Learn — Shared heaps](https://learn.microsoft.com/en-us/windows/win32/direct3d12/shared-heaps)
- [Microsoft Learn — UAC settings and configuration](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/settings-and-configuration)
- [Microsoft Learn — WM_WTSSESSION_CHANGE](https://learn.microsoft.com/en-us/windows/win32/termserv/wm-wtssession-change)
- [Microsoft Learn — SetWindowDisplayAffinity](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-setwindowdisplayaffinity)
- [NVIDIA — NVENC Video Encoder API Programming Guide](https://docs.nvidia.com/video-technologies/video-codec-sdk/13.1/nvenc-video-encoder-api-prog-guide/index.html)

### Upstream

- No upstream source code or competitor implementation was used as decisive evidence.

### Standards

- No open standard was decisive; these boundaries are Windows and vendor API contracts.

### Other

- No marketing, blog, Reddit, or copied competitor material was used as evidence.

## Candidate experiments

- **EXPERIMENT_REQUIRED:** Does DDA or WGC have the lower p99 capture-available-to-encoder-submit latency for the same authorized SDR display on each supported GPU/driver class?
- **EXPERIMENT_REQUIRED:** Does immediate `ReleaseFrame` after a submitted same-device DDA GPU copy ever corrupt the owned destination under sustained high-motion load on each target driver?
- **EXPERIMENT_REQUIRED:** Does a D3D11-aware hardware H.264 MFT accept an owned same-device texture without CPU staging on every supported adapter?
- **EXPERIMENT_REQUIRED:** What input format does each selected D3D11-aware H.264 MFT negotiate for the owned texture?
- **EXPERIMENT_REQUIRED:** Does same-adapter capture/encode have lower p99 latency than cross-adapter transfer plus alternate-adapter encoding on each hybrid-GPU target?
- **EXPERIMENT_REQUIRED:** What WGC frame/event state occurs when the session locks?
- **EXPERIMENT_REQUIRED:** What WGC frame/event state occurs while a secure-desktop UAC prompt is visible?
- **EXPERIMENT_REQUIRED:** What WGC frame/event state occurs after unlock or display reconfiguration?
- **EXPERIMENT_REQUIRED:** Does `DuplicateOutput1` preserve tested HDR source values through the chosen HDR-to-SDR/H.264 path?
- **EXPERIMENT_REQUIRED:** Does a WGC float frame-pool path preserve tested HDR source values through the chosen HDR-to-SDR/H.264 path?
- **EXPERIMENT_REQUIRED:** What exact WGC result occurs for `WDA_EXCLUDEFROMCAPTURE` on each supported Windows build?
- **EXPERIMENT_REQUIRED:** What exact WGC result occurs for protected-video content on each supported Windows build?
