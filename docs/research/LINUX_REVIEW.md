# Linux Wayland host pipeline — red-team research sprint

**Evidence snapshot:** 2026-08-13. This report treats the existing Portal + PipeWire + DMA-BUF plan as a hypothesis to break. The hypothesis survives only for an **interactive, logged-in, runtime-probed** host. It does **not** establish a uniform Linux remote-control or zero-copy platform.

## Executive finding

The most reliable official route for a normal Wayland desktop is XDG Desktop Portal authorization followed by a **direct PipeWire remote FD** for capture, with RemoteDesktop + EIS/libei only when that exact portal backend advertises it. `OpenPipeWireRemote` returns an FD used to create a `pw_core`; the portal is not specified as a per-frame media relay. [ScreenCast v6](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.ScreenCast.html) [RemoteDesktop v2](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.RemoteDesktop.html)

That finding refutes three stronger readings of the baseline:

1. **Portal capability is not Linux capability.** It is an API front-end whose compositor/backend decides what is actually available.
2. **DMA-BUF is not automatically zero-copy.** A FD can identify the same allocation, yet its DRM format/modifier, explicit/implicit fencing, GPU affinity, and encoder input format can still force conversion, a copy, or rejection. [Linux DMA-BUF guidance](https://docs.kernel.org/driver-api/dma-buf.html) [DRM pixel-buffer exchange guidance](https://docs.kernel.org/userspace-api/dma-buf-alloc-exchange.html)
3. **Unattended Wayland control is not a portable portal feature.** GNOME, KDE, and wlroots have materially different answers, including no upstream RemoteDesktop portal at all in `xdg-desktop-portal-wlr`. [wlroots portal README](https://raw.githubusercontent.com/emersion/xdg-desktop-portal-wlr/master/README.md)

## Direct answers

### 1. Most reliable official route

For **view-only**, use `ScreenCast.CreateSession → SelectSources → Start → OpenPipeWireRemote`, then attach a PipeWire input stream to the returned remote. For **view + control**, create a `RemoteDesktop` session, call `SelectDevices`, call `ScreenCast.SelectSources` on that same remote-desktop session, call `RemoteDesktop.Start`, open its PipeWire remote, and then call `ConnectToEIS` once. The portal specification expressly permits a RemoteDesktop session to use the ScreenCast methods, returns PipeWire streams from `RemoteDesktop.Start`, and requires `ConnectToEIS` only after `Start`. [RemoteDesktop v2](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.RemoteDesktop.html) [ScreenCast v6](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.ScreenCast.html)

The implementation MUST discover the live D-Bus interface version and advertised source/device bits, not infer support from `XDG_CURRENT_DESKTOP`, distro, or a package name. In particular, `ConnectToEIS` is version 2; once an EIS connection exists, the specification forbids mixing EIS with the legacy `Notify*` calls. [RemoteDesktop v2](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.RemoteDesktop.html)

### 2. GNOME/KDE differences

Both can expose the standard portal surface, but they are not interchangeable backends.

- **GNOME:** GNOME 46 introduced a vendor-owned RDP *remote login* path for systems not already in use; GNOME 47 made those remote-login sessions persistent after a disconnect. This is useful evidence that unattended operation exists in a GNOME-specific product path, but it is not evidence that an arbitrary portal client may bypass portal authorization. GNOME 47 also documents hardware screen-capture encoding for Intel and AMD and says NVIDIA support was still foundational work. [GNOME 46 release notes](https://release.gnome.org/46/) [GNOME 47 release notes](https://release.gnome.org/47/)
- **KDE/KWin:** the current `xdg-desktop-portal-kde` source checks a KWin Wayland streaming capability, opens an EIS connection through `org.kde.KWin.EIS.RemoteDesktop`, tears it down when the portal session closes, and has a KDE-specific preauthorization branch. [KDE RemoteDesktop portal source](https://invent.kde.org/plasma/xdg-desktop-portal-kde/-/raw/master/src/remotedesktop.cpp) KDE documents that preauthorization as a **Plasma 6.3** feature only for `remote-desktop`; it also warns that host applications can impersonate an app ID and that an empty app ID can match too broadly. [KDE portal preauthorization](https://develop.kde.org/docs/administration/portal-permissions/)
- **wlroots:** upstream `xdg-desktop-portal-wlr` implements Screenshot and ScreenCast only. It cannot supply the portable RemoteDesktop/EIS control leg, so it is not a control-capable equivalent of GNOME/KDE. [wlroots portal README](https://raw.githubusercontent.com/emersion/xdg-desktop-portal-wlr/master/README.md)

### 3. Do portals add material latency?

Not inherently in the steady-state frame path: `OpenPipeWireRemote` gives the application an FD to the restricted PipeWire remote and says the application creates its own `pw_core`; this is not a portal-mediated per-frame D-Bus API. [ScreenCast v6](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.ScreenCast.html) The portal **does** add startup authorization, and the backend/compositor/PipeWire graph may add capture scheduling and buffering. Therefore: **no assumed portal-per-frame hop, but total capture latency is EXPERIMENT_REQUIRED**. Compare portal PipeWire timestamps and an optical end-to-end trace; do not market a latency number from the architecture alone.

### 4. Can DMA-BUF be genuinely zero-copy?

**Yes, in a narrow meaning; no, as a portable guarantee.** A genuine no-CPU-copy path is possible when the producer exports DMA-BUF and the consumer imports the same allocation with an accepted FourCC, plane layout, modifier, synchronization contract, and GPU/device topology. Linux DMA-BUF provides shared buffer objects plus `dma_fence`/`dma_resv` synchronization, while EGL and Vulkan expose optional DMA-BUF import extensions. [Linux DMA-BUF guidance](https://docs.kernel.org/driver-api/dma-buf.html) [EGL DMA-BUF import](https://registry.khronos.org/EGL/extensions/EXT/EGL_EXT_image_dma_buf_import.txt) [Vulkan DMA-BUF extension](https://docs.vulkan.org/refpages/latest/refpages/source/VK_EXT_external_memory_dma_buf.html)

However, format modifiers can encode tiling, compression, or additional planes and must be explicitly supported by every consumer; both the kernel guidance and EGL modifier extension require enumeration/validation. [DRM pixel-buffer exchange guidance](https://docs.kernel.org/userspace-api/dma-buf-alloc-exchange.html) [EGL DMA-BUF modifiers](https://registry.khronos.org/EGL/extensions/EXT/EGL_EXT_image_dma_buf_import_modifiers.txt) RGB desktop capture to H.264 4:2:0 can also need colour conversion even when no CPU copy occurs. Call the fast path **GPU-direct only after measured proof**, record every conversion/copy, and retain the bounded copy fallback.

### 5. NVIDIA/AMD/Intel differences

There is no vendor-wide DMA-BUF-to-encoder promise.

| GPU family | Evidence-led assessment | v0.1 posture |
|---|---|---|
| Intel / AMD | libva defines DRM PRIME 2/3 import/export, including modifier and multi-plane descriptors, but explicitly says a driver may support only a subset of representations and may reject a layout. GNOME 47’s hardware capture encoding supports Intel and AMD, which is encouraging but not proof of this engine’s import chain. [libva DRM PRIME header](https://raw.githubusercontent.com/intel/libva/master/va/va_drmcommon.h) [GNOME 47 release notes](https://release.gnome.org/47/) | First hardware targets; probe the actual PipeWire format/modifier and encoder import, otherwise use bounded copy. **EXPERIMENT_REQUIRED** per driver/kernel/compositor. |
| NVIDIA desktop | NVENC documents CUDA and Linux-only OpenGL device paths, and its documented external resources are CUDA arrays/device pointers or OpenGL textures—not a DMA-BUF FD. CUDA-array input can avoid NVENC’s documented preprocessing copy, but getting a PipeWire DMA-BUF into that compatible object is a separate EGL/CUDA interop problem. [NVENC programming guide](https://docs.nvidia.com/video-technologies/video-codec-sdk/13.1/nvenc-video-encoder-api-prog-guide/index.html) | Treat DMA-BUF→NVENC as a vendor/driver-specific experiment; never claim direct PipeWire→NVENC zero-copy. Keep MemFd/CPU or GPU-copy fallback. |
| Hybrid / cross-GPU | DMA-BUF identifies shareable memory, not a guarantee that the encoder on another adapter can consume it without a transfer. Modifier and synchronization compatibility still applies. [Linux DMA-BUF guidance](https://docs.kernel.org/driver-api/dma-buf.html) | Classify as copied/unknown until a topology test proves otherwise. |

### 6. Does KMS belong in scope?

**No for the v0.1 portable logged-in Wayland provider.** A compositor normally owns the primary DRM node/current DRM master, while ordinary GPU clients use render nodes; KMS is neither the portal authorization mechanism nor an input-mediation mechanism. [Linux DRM UAPI](https://docs.kernel.org/gpu/drm-uapi.html) Direct KMS capture would create a separate privileged/appliance security model, compete with the compositor’s display ownership, and still leave input authorization unresolved. It MAY become a later, explicitly privileged **appliance/headless provider**, never a fallback silently selected from the ordinary portal path.

### 7. Maturity of unattended Wayland

**Fragmented and compositor-specific; not production-portable.** Portal persistence is a permission request with a one-use restore token; if the selected source disappeared or permission was withdrawn, the portal may prompt normally. It is not a durable capture/input capability and does not create a login session. [ScreenCast v6](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.ScreenCast.html) [RemoteDesktop v2](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.RemoteDesktop.html)

GNOME has a separate configured RDP remote-login product path beginning in GNOME 46 and persistent sessions in GNOME 47. KDE has Plasma-6.3-specific RemoteDesktop preauthorization with material host-app-ID caveats. wlroots’ standard portal backend lacks RemoteDesktop entirely. [GNOME 46 release notes](https://release.gnome.org/46/) [GNOME 47 release notes](https://release.gnome.org/47/) [KDE portal preauthorization](https://develop.kde.org/docs/administration/portal-permissions/) [wlroots portal README](https://raw.githubusercontent.com/emersion/xdg-desktop-portal-wlr/master/README.md) A generic LatencyDesk claim of unattended Wayland control would therefore be false.

### 8. What v0.1 should and should not support

**Should support:** a logged-in user starting an interactive capture; PipeWire capture through a runtime-probed ScreenCast portal; optional keyboard/pointer only after a version-2 RemoteDesktop session successfully provides EIS; GNOME and KDE/KWin as separately tested target profiles; DMA-BUF when a complete import/fence/encoder test succeeds; and MemFd/CPU or explicitly measured GPU-copy fallback. It should expose capture-only when input is absent rather than attempting a privileged substitute.

**Should not support:** login-screen capture/control, generic unattended control, direct KMS, `/dev/uinput` as a portable fallback, an assumed wlroots control path, legacy portal `Notify*` as the primary input route, reusable portal session handles/FDs, an unconditional “zero-copy” claim, or untested NVIDIA/cross-GPU direct encode. All of these require a separate provider and a threat model.

## Required lifecycle and ownership model

### Session and revocation state machine

```text
Created
  └─ select sources/devices → Awaiting authorization
       └─ Start accepted → PipeWire connected
            └─ ConnectToEIS accepted (optional, exactly once) → Active
Any state ── Session::Closed / D-Bus disappearance / PipeWire failure /
             EIS disconnect / logout / compositor restart ──> Revoking
Revoking ── resources quiesced; input state reset; epochs advanced ──> Closed
```

A portal session may be closed by the implementation at any time, `Session.Close` ends related interaction, and loss of the client’s D-Bus presence closes all its active sessions. [Session interface](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Session.html) `ConnectToEIS` is single-use; the portal specification says the session should close when its EIS implementation disconnects. [RemoteDesktop v2](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.RemoteDesktop.html)

On `Session::Closed`, the host MUST atomically stop accepting network input, stop/deactivate PipeWire, close the EIS connection, cancel/drain its bounded encoder work, destroy imported images/surfaces after their fences, emit local all-up state, and increment capture/input/codec epochs. For a deliberate close, send releases before disconnect where EIS remains live. Whether every compositor neutralizes pressed state after an abrupt EIS loss is **EXPERIMENT_REQUIRED**; do not rely on it as a safety mechanism.

Do not retain node IDs as stable display identities: ScreenCast v6 says node IDs can be reused and supplies a nonreused `pipewire-serial` for targeting. Older interface versions need a stricter connection/session epoch and re-enumeration policy. [ScreenCast v6](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.ScreenCast.html)

### Buffer ownership and synchronization

PipeWire capture returns a `pw_buffer` for consumption and requires `pw_stream_queue_buffer` to recycle it; it separately supports MemFd, DMA-BUF, and newer synchronization object/timeline forms. DMA-BUF data may not be CPU-mappable. [PipeWire Stream 1.6.8](https://docs.pipewire.org/group__pw__stream.html) [PipeWire SPA buffers 1.6.8](https://docs.pipewire.org/group__spa__buffer.html)

Use the following ownership rules:

1. Negotiate memory type, FourCC, plane count/offset/stride, modifier, dimensions, colour metadata, and synchronization capability. `SPA_DATA_DmaBuf` is an FD to DMA-BUF memory, not an invitation to assume a linear CPU pointer. [PipeWire SPA buffers 1.6.8](https://docs.pipewire.org/group__spa__buffer.html)
2. Treat PipeWire-provided `spa_data` descriptors and `pw_buffer` objects as **borrowed capture leases**. Do not close PipeWire’s FD or use its buffer after requeue. If an importer needs an owned FD, duplicate it `CLOEXEC`; own and close only the duplicate.
3. A DMA-BUF fast path may requeue only after the consumer’s GPU/encoder completion fence makes exporter reuse safe. If that cannot happen inside a fixed pool, drop the newest capture buffer and requeue it; never create an unbounded async lease queue.
4. For copy fallback, finish the bounded copy into encoder-owned storage before requeue. For a GPU import, record whether the encoder read the imported allocation or a conversion/copy surface.
5. EGL import takes a reference to imported DMA-BUFs but does not take ownership of the caller’s FDs; this is why a duplicated FD is the conservative bridge between PipeWire ownership and EGL ownership. [EGL DMA-BUF import](https://registry.khronos.org/EGL/extensions/EXT/EGL_EXT_image_dma_buf_import.txt)
6. On format/modifier/source change, retire the entire importer pool only after fences signal, then recreate it and advance the capture/codec epoch. Do not mix frames across epochs.

For EIS, match absolute-device regions to the ScreenCast stream `mapping_id` rather than inventing a display-coordinate transform; the portal specification defines that pairing and libei exposes virtual-device regions in desktop-wide coordinates. [ScreenCast v6](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.ScreenCast.html) [libei device API](https://libinput.pages.freedesktop.org/libei/api/group__libei-device.html)

## Concrete support matrix

This is a **commitment matrix**, not a claim that a package installation implies success. “Probe” means inspect D-Bus properties/methods and complete the specific startup negotiation before offering the feature.

| Environment | Capture | Control | Unattended | Buffer path | v0.1 commitment |
|---|---|---|---|---|---|
| GNOME Wayland, logged-in | ScreenCast + PipeWire: **probe**, expected target | RemoteDesktop v2 + `ConnectToEIS`: **probe**; otherwise capture-only | GNOME RDP remote login is separate/vendor-owned, not LatencyDesk portal mode | DMA-BUF only after importer/fence/encoder probe; MemFd fallback | **Tier 1** after profile validation |
| KDE Plasma 6 / KWin Wayland, logged-in | ScreenCast + PipeWire: **probe** | Current KDE source has KWin EIS bridge; still probe actual interface/device bits | Plasma 6.3 preauthorization exists but is KDE-specific and has host-app-ID caveats | Same negotiated policy | **Tier 1** after profile validation; never auto-enable preauthorization |
| wlroots/Sway with `xdg-desktop-portal-wlr` | ScreenCast + PipeWire: **probe** | **No upstream portable control** in this backend | No standard portal route | Copy/DMA-BUF only if capture negotiates it | Not a v0.1 control target; capture-only experimental if admitted |
| Other Wayland compositor/backend | Unknown until live probe | Unknown until live probe | Unknown | Unknown | Unsupported in v0.1 |
| KMS/direct DRM | Separate privileged design | No portal input authorization | Appliance-specific only | Separate provider | Explicitly out of scope |

## Shared-schema decisions

### D1 — standard interactive Wayland host route

Decision: Use portal authorization plus a direct PipeWire remote for the ordinary user-session capture path.

Current proposal: Portal + PipeWire + DMA-BUF Wayland is the primary Linux path.

Verdict: MODIFY

Recommended solution: Keep XDG ScreenCast/PipeWire for capture, but make RemoteDesktop/EIS an independently negotiated input capability; use one RemoteDesktop session for combined capture/control and a ScreenCast-only session for viewing.

Why: The official API separates capture and control capabilities, returns the media stream through a PipeWire FD, and limits EIS to a started RemoteDesktop v2 session. [ScreenCast v6](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.ScreenCast.html) [RemoteDesktop v2](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.RemoteDesktop.html)

Alternative: Use compositor-private capture and input protocols directly.

Risk: Private protocols multiply compositor support, lose portal mediation, and still do not solve feature discovery.

Prototype required: Yes — one GNOME and one KDE/KWin session that records discovered interfaces, actual source/device bits, `pipewire-serial`, and EIS availability.

Evidence: The API itself exposes source/device availability, ScreenCast streams, PipeWire remote FD access, and a one-time EIS bridge. [ScreenCast v6](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.ScreenCast.html) [RemoteDesktop v2](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.RemoteDesktop.html)

### D2 — latency claim and media scheduling

Decision: Do not assign a fixed latency tax to portals; measure the full capture graph.

Current proposal: Portal capture is suitable for a latency-first engine.

Verdict: EXPERIMENT

Recommended solution: Treat portal calls as setup/control-plane work, timestamp PipeWire receive, import completion, encode submission, and encoded output, and publish only measured end-to-end data per compositor/GPU path.

Why: The portal hands the client a PipeWire FD rather than defining a per-frame portal transport, but neither the portal nor PipeWire documentation supplies an end-to-end desktop-capture latency bound. [ScreenCast v6](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.ScreenCast.html) [PipeWire Stream 1.6.8](https://docs.pipewire.org/group__pw__stream.html)

Alternative: Bypass portals to seek lower latency.

Risk: That trades an unmeasured possible gain for loss of the supported authorization route and portable support.

Prototype required: Yes — optical/timestamp comparison of identical encode settings on GNOME and KDE with portal capture.

Evidence: `OpenPipeWireRemote` is direct PipeWire access; measured compositor scheduling remains unspecified. [ScreenCast v6](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.ScreenCast.html)

### D3 — DMA-BUF and ownership contract

Decision: DMA-BUF is a negotiated GPU-direct optimization, not the baseline data contract.

Current proposal: Opportunistic zero-copy plus bounded copy fallback.

Verdict: MODIFY

Recommended solution: Preserve the bounded fallback, but require a full tuple of {producer DRM device, consumer device, FourCC, planes, modifier, colour metadata, synchronization mechanism, encoder resource type}; report the actual path as `gpu-direct`, `gpu-convert`, `cpu-copy`, or `rejected`.

Why: DMA-BUF provides sharing and fencing primitives, while formats/modifiers are vendor/generation-specific and EGL implementations must reject unsupported combinations. [Linux DMA-BUF guidance](https://docs.kernel.org/driver-api/dma-buf.html) [DRM pixel-buffer exchange guidance](https://docs.kernel.org/userspace-api/dma-buf-alloc-exchange.html) [EGL DMA-BUF modifiers](https://registry.khronos.org/EGL/extensions/EXT/EGL_EXT_image_dma_buf_import_modifiers.txt)

Alternative: Force linear CPU-mappable buffers everywhere.

Risk: It predictably raises bandwidth/CPU cost and discards valid hardware paths; it is acceptable only as fallback.

Prototype required: Yes — import and encode a portal DMA-BUF for each target GPU family while verifying no premature PipeWire requeue and no implicit conversion/copy telemetry.

Evidence: PipeWire distinguishes MemFd from non-mappable DMA-BUF, and EGL/Vulkan DMA-BUF import is optional capability machinery rather than a universal format. [PipeWire SPA buffers 1.6.8](https://docs.pipewire.org/group__spa__buffer.html) [EGL DMA-BUF import](https://registry.khronos.org/EGL/extensions/EXT/EGL_EXT_image_dma_buf_import.txt) [Vulkan DMA-BUF extension](https://docs.vulkan.org/refpages/latest/refpages/source/VK_EXT_external_memory_dma_buf.html)

### D4 — vendor and multi-GPU policy

Decision: Start with Intel/AMD validation but do not elevate either to a guarantee; quarantine NVIDIA and cross-GPU direct paths behind explicit probes.

Current proposal: DMA-BUF import when compatible, otherwise copy fallback.

Verdict: KEEP

Recommended solution: Keep the policy, add a device/topology identity and vendor-specific import result to capability negotiation/telemetry, and never expose “zero-copy” merely because a DMA-BUF was received.

Why: libva’s DRM PRIME API permits import/export but allows drivers to support only subsets; NVENC’s documented external input resources are CUDA/OpenGL objects rather than DMA-BUF FDs. [libva DRM PRIME header](https://raw.githubusercontent.com/intel/libva/master/va/va_drmcommon.h) [NVENC programming guide](https://docs.nvidia.com/video-technologies/video-codec-sdk/13.1/nvenc-video-encoder-api-prog-guide/index.html)

Alternative: Publish a single DMA-BUF path for every Linux GPU.

Risk: Driver, modifier, and encoder-resource mismatches turn that into opaque startup failure or hidden copy.

Prototype required: Yes — one Intel, one AMD, one NVIDIA, and one hybrid-GPU test with the same PipeWire source and encoder configuration.

Evidence: GNOME’s own 47 release separates Intel/AMD hardware capture encoding from incomplete NVIDIA work, reinforcing that this remains vendor-specific. [GNOME 47 release notes](https://release.gnome.org/47/)

### D5 — KMS and unattended access

Decision: Exclude direct KMS and generic unattended Wayland from v0.1.

Current proposal: Logged-in user-authorized sessions; KMS/uinput later optional backends.

Verdict: KEEP

Recommended solution: Preserve the logged-in interactive boundary. Make any future KMS/headless or GNOME/KDE unattended integration a named privileged/vendor provider with separate consent, installation identity, lock/login behavior, and threat-model review.

Why: DRM primary-node/master ownership belongs to the display stack, portal restore tokens can fall back to a prompt or be invalidated, and unattended support differs sharply across GNOME, KDE, and wlroots. [Linux DRM UAPI](https://docs.kernel.org/gpu/drm-uapi.html) [ScreenCast v6](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.ScreenCast.html) [KDE portal preauthorization](https://develop.kde.org/docs/administration/portal-permissions/) [wlroots portal README](https://raw.githubusercontent.com/emersion/xdg-desktop-portal-wlr/master/README.md)

Alternative: Use KMS or `/dev/uinput` as a hidden fallback when a portal lacks input.

Risk: It bypasses the consent model, requires privileges, can conflict with the compositor, and misrepresents security posture.

Prototype required: Yes — only after a separate appliance/unattended specification exists.

Evidence: GNOME remote login and KDE preauthorization are real but vendor/version-specific paths; they do not define a cross-compositor portal guarantee. [GNOME 46 release notes](https://release.gnome.org/46/) [GNOME 47 release notes](https://release.gnome.org/47/) [KDE RemoteDesktop portal source](https://invent.kde.org/plasma/xdg-desktop-portal-kde/-/raw/master/src/remotedesktop.cpp)

### D6 — v0.1 support boundary

Decision: Ship only the explicit matrix above and fail closed to capture-only or unsupported when control/zero-copy probes fail.

Current proposal: GNOME/KDE primary test targets with portals/PipeWire/libei where exposed.

Verdict: MODIFY

Recommended solution: Declare GNOME and KDE/KWin logged-in interactive profiles as Tier 1 only after their exact combinations are validated; allow wlroots capture-only only if product scope accepts an experimental tier; offer no generic Wayland control claim.

Why: KDE’s source directly implements KWin EIS but requires a compatible Wayland/KWin streaming environment, whereas upstream wlroots portal implements no RemoteDesktop portal. [KDE RemoteDesktop portal source](https://invent.kde.org/plasma/xdg-desktop-portal-kde/-/raw/master/src/remotedesktop.cpp) [wlroots portal README](https://raw.githubusercontent.com/emersion/xdg-desktop-portal-wlr/master/README.md)

Alternative: Label every desktop that starts a ScreenCast session as fully supported.

Risk: Users would receive a false promise of keyboard/pointer control, persistence, or direct GPU encode.

Prototype required: Yes — acceptance tests must exercise revoke, logout, compositor restart, EIS loss, PipeWire format change, and forced DMA-BUF disablement for each Tier-1 profile.

Evidence: Portal sessions are revocable/lifetime-bound, and PipeWire buffers require explicit recycle discipline. [Session interface](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Session.html) [PipeWire Stream 1.6.8](https://docs.pipewire.org/group__pw__stream.html)

## Sources

### Official

- [XDG Desktop Portal — ScreenCast v6](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.ScreenCast.html) — interface/version and PipeWire remote semantics.
- [XDG Desktop Portal — RemoteDesktop v2](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.RemoteDesktop.html) — device selection, combined ScreenCast session, EIS lifecycle.
- [XDG Desktop Portal — Session](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.Session.html) — `Closed`, client disappearance, and close semantics.
- [PipeWire Stream API 1.6.8](https://docs.pipewire.org/group__pw__stream.html) and [SPA buffer API 1.6.8](https://docs.pipewire.org/group__spa__buffer.html) — buffer types, mapping, queue/recycle, and sync metadata; version-specific.
- [libei device API 1.6.0](https://libinput.pages.freedesktop.org/libei/api/group__libei-device.html) — virtual devices, regions, and asynchronous removal; version-specific.
- [GNOME 46 release notes](https://release.gnome.org/46/) and [GNOME 47 release notes](https://release.gnome.org/47/) — GNOME remote-login and capture-encoding behavior; GNOME-version-specific.
- [KDE XDG Portal Pre-Authorization](https://develop.kde.org/docs/administration/portal-permissions/) — Plasma-6.3-only `remote-desktop` policy and caveats.
- [NVIDIA NVENC Video Encoder API Programming Guide 13.1](https://docs.nvidia.com/video-technologies/video-codec-sdk/13.1/nvenc-video-encoder-api-prog-guide/index.html) — Linux input-resource and encoder behavior; NVIDIA-SDK/driver-specific.

### Upstream

- [KDE `xdg-desktop-portal-kde` RemoteDesktop implementation](https://invent.kde.org/plasma/xdg-desktop-portal-kde/-/raw/master/src/remotedesktop.cpp) — KWin EIS bridge, close handling, and preauthorization branch; `master` snapshot, not a stable ABI promise.
- [wlroots portal README](https://raw.githubusercontent.com/emersion/xdg-desktop-portal-wlr/master/README.md) — upstream Screenshot/ScreenCast-only scope; `master` snapshot.
- [libva DRM PRIME definitions](https://raw.githubusercontent.com/intel/libva/master/va/va_drmcommon.h) — PRIME import/export descriptor constraints; upstream `master` snapshot.

### Standards

- [Linux kernel DMA-BUF sharing and synchronization](https://docs.kernel.org/driver-api/dma-buf.html) — shared-buffer, fence, and reservation semantics.
- [Linux kernel pixel-buffer exchange guidance](https://docs.kernel.org/userspace-api/dma-buf-alloc-exchange.html) and [DRM userland API](https://docs.kernel.org/gpu/drm-uapi.html) — modifiers, ownership, and DRM-master boundary.
- [Khronos EGL DMA-BUF import](https://registry.khronos.org/EGL/extensions/EXT/EGL_EXT_image_dma_buf_import.txt), [EGL modifier import](https://registry.khronos.org/EGL/extensions/EXT/EGL_EXT_image_dma_buf_import_modifiers.txt), and [Vulkan DMA-BUF extension](https://docs.vulkan.org/refpages/latest/refpages/source/VK_EXT_external_memory_dma_buf.html) — optional import capability and format/modifier validation.

### Other

- None.

## Candidate experiments

- **EXPERIMENT_REQUIRED:** On a GNOME Tier-1 candidate, does portal-to-PipeWire capture add a measurable steady-state frame delay beyond compositor capture scheduling?
- **EXPERIMENT_REQUIRED:** On a KDE/KWin Tier-1 candidate, does revoking or closing an EIS session neutralize every pressed key/button without a client-sent release?
- **EXPERIMENT_REQUIRED:** For each Intel/AMD/NVIDIA target, can the negotiated PipeWire DMA-BUF FourCC/modifier enter the selected encoder with no CPU copy and no hidden GPU conversion?
- **EXPERIMENT_REQUIRED:** On a hybrid-GPU host, does the selected capture-device/encoder-device pair consume the same DMA-BUF allocation without a cross-adapter transfer?
- **EXPERIMENT_REQUIRED:** Does a ScreenCast v6 `pipewire-serial` remain correctly associated through hotplug, suspend/resume, and PipeWire reconnect on each Tier-1 compositor?
