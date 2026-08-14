# GPU ownership and copy-path feasibility

## Scope and terms

This report challenges the current proposal that treats opportunistic zero-copy as a broadly available optimization. Here, **strict zero-copy** means that one backing allocation reaches the next consumer without a full-frame CPU transfer, application-issued GPU blit/compute conversion, or a new frame allocation. Handle registration/import is not itself proof of strict zero-copy: if a vendor's internal transform cannot be observed, the result is `internal_copy_unknown`, not `zero_copy`.

The distinction matters for the proposed 8-bit 4:2:0 H.264 baseline. Desktop Duplication normally exposes `DXGI_FORMAT_B8G8R8A8_UNORM`; a BGRA source and an NV12-like 4:2:0 encoder input do not have identical pixel representations. NVENC accepts several RGB and YUV formats, but applications must enumerate supported input formats at runtime; an encoder-side RGB→YUV transform must not be reported as proven zero-copy merely because the application did not call `CopyResource`. [NVENC programming guide](https://docs.nvidia.com/video-technologies/video-codec-sdk/13.1/nvenc-video-encoder-api-prog-guide/index.html#selecting-input-formats) [Desktop Duplication API](https://learn.microsoft.com/en-us/windows/win32/direct3ddxgi/desktop-dup-api)

## Direct answers

1. **True zero-copy paths.** The defensible strict path is narrow: same physical GPU, already encoder-compatible surface format/layout, a documented consumer import, and a compatible synchronization handoff. NVIDIA documents an actual no-preprocessing-copy path for a block-linear `CUarray` passed from its opaque NVDEC output to NVENC's `CUDAARRAY` input, but that is **NVDEC→NVENC**, not either requested presentation or desktop-capture path. [NVDEC opaque output](https://docs.nvidia.com/video-technologies/video-codec-sdk/13.1/nvdec-video-decoder-api-prog-guide/index.html#nvdec-direct-output-to-block-linear-cuda-arrays) [NVENC CUDA-array input](https://docs.nvidia.com/video-technologies/video-codec-sdk/13.1/nvenc-video-encoder-api-prog-guide/index.html#reference-traditional-vs-cuda-array-input) A same-device PipeWire DMA-BUF→VAAPI import can be a *logical* aliasing path, but its physical no-copy property is driver-specific and therefore `EXPERIMENT_REQUIRED`.

2. **GPU-copy-only paths.** These are the reliable fast paths: DDA BGRA→an application-owned NV12 encoder texture on the same D3D11 device; same-device NVDEC output→a D3D11 presentation texture through CUDA/D3D11 interop; and PipeWire DMA-BUF→an owned EGL/Vulkan/VA surface after a GPU conversion or blit. They avoid host pixel transfers but must be recorded as `gpu_copy` (or `gpu_convert`), not zero-copy. NVDEC's traditional `cuvidMapVideoFrame` already post-processes and copies into an output surface, and NVIDIA's documented display path then converts decoded YUV to RGBA and maps that RGBA surface to a graphics texture. [NVDEC frame mapping](https://docs.nvidia.com/video-technologies/video-codec-sdk/13.1/nvdec-video-decoder-api-prog-guide/index.html#preparing-the-decoded-frame-for-further-processing) [NVDEC display pipeline](https://docs.nvidia.com/video-technologies/video-codec-sdk/13.1/nvdec-video-decoder-api-prog-guide/index.html#video-decoder-pipeline)

3. **CPU-copy cases.** Use CPU readback/upload when capture and encoder devices cannot interoperate, a cross-adapter resource cannot be opened/registered by NVENC, a PipeWire stream supplies `MemFd`/`MemPtr`, no common `(fourcc, modifier)` exists, synchronization cannot be proven, or import/registration fails. Desktop Duplication on an integrated display GPU and NVENC on a discrete GPU is especially risky: Windows cross-adapter resources are optional, linear allocations with strict layout constraints, not a promise that an acquired DDA texture is a valid NVENC input. [Windows cross-adapter resources](https://learn.microsoft.com/en-us/windows-hardware/drivers/display/using-cross-adapter-resources-in-a-hybrid-system) [PipeWire DMA-BUF negotiation and SHM fallback](https://docs.pipewire.org/1.4/page_dma_buf.html)

4. **Does zero-copy merit significant complexity?** **No for v0.1.** It merits a small, per-provider capability probe after a measured GPU-copy baseline exists; it does not merit a generic EGL/Vulkan/CUDA cross-vendor surface graph. The normal path should be one bounded, encoder-owned GPU surface pool plus GPU conversion/copy, with a bounded CPU fallback. Strict aliasing should be enabled only after the exact adapter, format, modifier, fence, and encoder-registration tuple has passed a soak test. This changes the proposal from “opportunistic zero-copy” to “evidence-gated direct aliasing.”

5. **Best CopyLedger model.** Use a fixed-size, append-only **per-frame ownership ledger**, not a `zero_copy: bool`. It must distinguish source lease, allocation identity, transfer operation, synchronization proof, and certainty of physical behavior. Its rules and telemetry are specified below.

## Path feasibility matrix

| Requested path | Best supported classification | Why it is not a general strict-zero-copy path | Required release boundary |
|---|---|---|---|
| DDA → D3D11 → NVENC, same adapter | `gpu_convert` normal path; direct registration is `EXPERIMENT_REQUIRED` | DDA normally supplies BGRA, while the baseline requires 4:2:0; direct use also retains a borrowed DDA surface until NVENC no longer uses it. | DDA `ReleaseFrame` only after the source is no longer needed, or after a correctly ordered copy into an owned surface. |
| DDA on iGPU → NVENC on dGPU | `cpu_copy` portable; `gpu_copy` only if a tested cross-adapter route works | Cross-adapter allocations are optional and constrained to a linear shared allocation; the acquired DDA texture is not automatically such an allocation. | Capture lease follows the source copy/consumer completion, not the application's desire to enqueue another frame. |
| NVDEC → D3D → Present | `gpu_copy` / `gpu_convert` | Traditional NVDEC maps to a CUDA device pointer; D3D11 interop exposes a separately registered D3D texture to CUDA. A conversion/copy into that texture is still required for normal presentation. | `cuvidUnmapVideoFrame` only after CUDA has stopped reading the mapped output; D3D texture only after CUDA unmap/order completion. |
| PipeWire → DMA-BUF → EGL → NVENC | `EXPERIMENT_REQUIRED`; likely `gpu_convert` | EGL can import the exact DMA-BUF layout, and CUDA can register an `EGLImage`, but no vendor documentation establishes arbitrary desktop PipeWire DMA-BUF→NVENC direct aliasing. Desktop CUDA's direct DMA-BUF import is not a supported general path. | `pw_stream_queue_buffer` only after every EGL/CUDA/NVENC reader is complete or an owned copy has detached it. |
| PipeWire → DMA-BUF → Vulkan → NVENC | `EXPERIMENT_REQUIRED`; `gpu_copy` baseline | Vulkan imports require a compatible physical device/driver and exact modifier layout; NVENC has no Vulkan device type. A Vulkan→CUDA bridge needs separately proven external memory and semaphore support. | Same PipeWire lease rule; import success does not establish execution ordering. |
| PipeWire → DMA-BUF → VAAPI | `EXPERIMENT_REQUIRED` logical alias; otherwise `gpu_convert` | `vaCreateSurfaces` can import DRM PRIME descriptors, but a VA driver may accept only a subset of layouts and a BGRx/RGB capture still needs conversion to a compatible encode surface. | `vaSyncSurface` or a verified equivalent fence before recycling the PipeWire buffer. |

## Decisions

### D1 — make a GPU-owned conversion pool the Windows capture baseline

Decision:
Current proposal: DXGI Desktop Duplication is primary, with opportunistic zero-copy and release of the original capture lease immediately after a synchronized import or copy.
Verdict: MODIFY
Recommended solution: On the capture adapter, queue a BGRA→NV12 GPU conversion/copy into a bounded application-owned encoder surface; then release the DDA frame. Admit direct DDA-resource registration to NVENC only as a same-adapter, format-qualified experiment whose lease remains held until NVENC completion.
Why: `AcquireNextFrame` returns a desktop-bitmap resource and rejects acquiring another frame before the previous one is released. More decisively, `ReleaseFrame` makes that surface invalid for DirectX operations. NVENC externally allocated resources must be registered, mapped for an encode, unmapped, and not used outside NVENC while mapped. Therefore direct DDA→NVENC ties encoder completion to the capture lease; it cannot simultaneously be called “immediate release” and “direct aliasing.” [AcquireNextFrame](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/nf-dxgi1_2-idxgioutputduplication-acquirenextframe) [ReleaseFrame](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/nf-dxgi1_2-idxgioutputduplication-releaseframe) [NVENC externally allocated input](https://docs.nvidia.com/video-technologies/video-codec-sdk/13.1/nvenc-video-encoder-api-prog-guide/index.html#input-buffers-allocated-externally)
Alternative: Hold each DDA frame until its NVENC completion event, then call `ReleaseFrame`.
Risk: Holding capture leases can starve or delay capture; a GPU conversion costs bandwidth but makes the downstream surface lifetime deterministic. A direct same-adapter path may also contain an undocumented RGB→YUV transform, so it cannot claim strict zero-copy without profiling.
Prototype required: Yes — `EXPERIMENT_REQUIRED`: compare a bounded owned-NV12 pool against direct DDA registration at 1080p120 and 4K60, including capture-starvation, queue-age, and correctness checks.
Evidence: Microsoft invalidates the acquired surface at `ReleaseFrame`; NVIDIA requires the mapped resource to be NVENC-only and requires `NvEncUnmapInputResource` before reuse/destruction. [Microsoft ReleaseFrame](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/nf-dxgi1_2-idxgioutputduplication-releaseframe) [NVIDIA NVENC resource lifecycle](https://docs.nvidia.com/video-technologies/video-codec-sdk/13.1/nvenc-video-encoder-api-prog-guide/index.html#input-buffers-allocated-externally)

### D2 — classify hybrid Windows and NVDEC presentation as copy paths

Decision:
Current proposal: Windows prefers D3D11-compatible hardware decode/presentation and leaves a copy path for unsupported adapter combinations.
Verdict: MODIFY
Recommended solution: Make `NVDEC → CUDA/D3D11 registered presentation texture → Present` an explicit `gpu_copy`/`gpu_convert` path. For DDA on one adapter and NVENC on another, default to CPU readback/upload unless a per-adapter-pair cross-adapter GPU transfer and NVENC registration test succeeds.
Why: Traditional NVDEC output is a CUDA device pointer and `cuvidMapVideoFrame` performs post-processing/copy to an output surface; NVIDIA's own display outline requires decoded YUV→RGBA conversion and mapping that RGBA surface to a graphics texture. CUDA/D3D11 interop requires a hardware D3D11 device, registration once, map/unmap for access, and forbids D3D access while CUDA has the resource mapped. [NVDEC mapping](https://docs.nvidia.com/video-technologies/video-codec-sdk/13.1/nvdec-video-decoder-api-prog-guide/index.html#preparing-the-decoded-frame-for-further-processing) [CUDA D3D11 interop](https://docs.nvidia.com/cuda/cuda-programming-guide/04-special-topics/graphics-interop.html#direct3d-interoperability)
Alternative: Build a cross-adapter row-major shared-resource path and use it when both drivers expose the required capability.
Risk: A cross-adapter resource has one linear allocation, aperture residency, 128-byte pitch alignment, four-row height alignment, and page-aligned start; support is a driver/platform property, not a guarantee for the DDA texture or NVENC. [Windows cross-adapter resources](https://learn.microsoft.com/en-us/windows-hardware/drivers/display/using-cross-adapter-resources-in-a-hybrid-system) `EXPERIMENT_REQUIRED`: measured GPU-only transfer may still be slower than a predictable local copy on some hybrid laptops.
Prototype required: Yes — `EXPERIMENT_REQUIRED`: test each capture-adapter/NVENC-adapter pair for open, format conversion, `NvEncRegisterResource`, repeated encode, and device-removal resilience.
Evidence: NVIDIA documents a true no-preprocessing-copy opaque NVDEC `CUarray`→NVENC route, but it is not a D3D presentation route; it establishes the contrast rather than validating this path as zero-copy. [NVDEC opaque arrays](https://docs.nvidia.com/video-technologies/video-codec-sdk/13.1/nvdec-video-decoder-api-prog-guide/index.html#nvdec-direct-output-to-block-linear-cuda-arrays) [NVENC CUDA array comparison](https://docs.nvidia.com/video-technologies/video-codec-sdk/13.1/nvenc-video-encoder-api-prog-guide/index.html#reference-traditional-vs-cuda-array-input)

### D3 — treat Linux DMA-BUF import as a negotiated capability, not an NVENC promise

Decision:
Current proposal: Portal + PipeWire + DMA-BUF is the Wayland path, with opportunistic zero-copy and bounded fallback.
Verdict: MODIFY
Recommended solution: Negotiate and record exact `(DRM fourcc, modifier, plane offsets, pitches, producer DRM device, consumer DRM device, sync mode)` tuples. Permit DMA-BUF→VAAPI direct import only when that tuple is accepted; use a GPU conversion into an owned VA/NVENC surface otherwise. Keep EGL/Vulkan→NVENC aliasing outside the v0.1 normal path.
Why: PipeWire requires a modifier-aware DMA-BUF alternative and a shared-memory fallback; DMA-BUFs may be tiled/compressed, may carry extra synchronization FDs, and must not be treated as mmap-able linear pixels. EGL validates the full base-format/per-plane-modifier combination. Vulkan similarly requires the received modifier and plane layout, and its import valid usage requires compatible physical device/driver provenance. [PipeWire DMA-BUF sharing](https://docs.pipewire.org/1.4/page_dma_buf.html) [EGL DMA-BUF modifiers](https://registry.khronos.org/EGL/extensions/EXT/EGL_EXT_image_dma_buf_import_modifiers.txt) [Vulkan DRM modifiers](https://registry.khronos.org/VulkanSC/specs/1.0-extensions/man/html/VK_EXT_image_drm_format_modifier.html) [Vulkan FD import ownership and compatibility](https://registry.khronos.org/VulkanSC/specs/1.0-extensions/man/html/VkImportMemoryFdInfoKHR.html)
Alternative: Build a universal DMA-BUF→Vulkan→opaque-FD→CUDA→NVENC bridge.
Risk: NVENC's documented device types do not include Vulkan. CUDA's current Driver API states that direct `CU_EXTERNAL_MEMORY_HANDLE_TYPE_DMABUF_FD` import is supported only on Tegra Jetson Thor and cannot be mapped as a CUDA mipmapped array; an arbitrary desktop PipeWire DMA-BUF therefore has no documented CUDA-array→NVENC route. CUDA can register an `EGLImage`, but its API explicitly leaves synchronization to the application and does not certify the PipeWire producer, modifier, or NVENC resource type. [NVENC device types](https://docs.nvidia.com/video-technologies/video-codec-sdk/13.1/nvenc-video-encoder-api-prog-guide/index.html#initializing-encode-device) [CUDA DMA-BUF limitation](https://docs.nvidia.com/cuda/cuda-driver-api/group__CUDA__EXTRES__INTEROP.html) [CUDA EGL interop](https://docs.nvidia.com/cuda/cuda-runtime-api/group__CUDART__EGL.html)
Prototype required: Yes — `EXPERIMENT_REQUIRED`: validate one exact compositor/GPU/driver/format/modifier tuple at a time before enabling any direct alias path.
Evidence: libva supports `VA_SURFACE_ATTRIB_MEM_TYPE_DRM_PRIME_2` import via `VADRMPRIMESurfaceDescriptor`, including objects, layers, plane offsets, pitches, and modifiers, but explicitly warns that a driver may support only a subset of representations. [libva DRM PRIME interfaces](https://raw.githubusercontent.com/intel/libva/master/va/va_drmcommon.h)

### D4 — replace the three-value copy label with a verifiable CopyLedger

Decision:
Current proposal: Providers report `zero_copy`, `gpu_copy`, or `cpu_copy`.
Verdict: MODIFY
Recommended solution: Implement the fixed-size per-frame CopyLedger described below, retaining the compact public path label as a derived field only. A direct-alias success requires an explicit evidence grade; otherwise report `internal_copy_unknown` rather than zero-copy.
Why: A DMA-BUF, D3D shared handle, `EGLImage`, Vulkan import, or NVENC registration describes ownership/access compatibility, not necessarily physical movement. Vulkan's format mapping is incomplete/lossy, and an external-memory import establishes memory access but not execution ordering. [Vulkan modifier format translation](https://registry.khronos.org/VulkanSC/specs/1.0-extensions/man/html/VK_EXT_image_drm_format_modifier.html) [Vulkan external semaphore FD](https://registry.khronos.org/VulkanSC/specs/1.0-extensions/man/html/VK_KHR_external_semaphore_fd.html)
Alternative: Keep only a provider-supplied boolean or enum.
Risk: A richer record has implementation cost and must avoid per-frame heap allocation; use numeric enums, bounded plane fields, device IDs, and timestamps rather than strings, raw FDs, or COM pointers.
Prototype required: No — the model can be introduced with the first GPU-copy provider; only evidence-grade promotion to strict zero-copy is `EXPERIMENT_REQUIRED`.
Evidence: PipeWire's explicit-sync capability is negotiated after format negotiation and can add SyncObjTimeline metadata/FDS; Linux DMA-BUF export/import fence snapshots are not atomic, so a ledger must record the synchronization mode and producer/consumer token rather than infer safety from an imported handle. [PipeWire explicit sync](https://docs.pipewire.org/1.4/page_dma_buf.html) [Linux DMA-BUF synchronization](https://docs.kernel.org/driver-api/dma-buf.html)

## CopyLedger specification

### Fixed per-frame fields

| Group | Fields | Purpose |
|---|---|---|
| Identity | `session_generation`, `capture_sequence`, `surface_generation`, `parent_surface_generation` | Prevents confusing a recycled pool slot with the frame that once occupied it. |
| Borrowed source lease | `lease_kind` (`dda_frame`, `pipewire_buffer`, `decoder_surface`, `owned`), `lease_id`, `acquired_at_ns`, `source_release_state` | Makes source invalidation/recycle observable. |
| Allocation and device | `source_domain`, `destination_domain`, source/destination adapter identity (DXGI LUID or DRM render-node/PCI identity), `same_physical_device` | Detects hybrid/multi-GPU transitions rather than assuming shared handles cross devices. |
| Layout and color | dimensions, DXGI/Vulkan/DRM/VA format IDs, plane count, bounded per-plane offset/pitch, modifier, chroma, bit depth, primaries/transfer/matrix/range | Makes a format conversion and modifier mismatch attributable. |
| Transfer edge | `path` (`direct_alias`, `gpu_blit`, `gpu_convert`, `cpu_readback_upload`, `encoder_internal_unknown`), bytes read/written by CPU and application GPU work, source/destination pool IDs | Counts known movement separately from unobservable driver work. |
| Synchronization | `acquire_sync_kind/value`, `consumer_done_sync_kind/value`, `sync_mode` (`D3D order`, `NVENC event`, `CUDA event`, `Vulkan semaphore`, `DMA-BUF implicit`, `SyncObjTimeline`, `VA sync`, `CPU wait`) | States what actually authorizes use and later release. |
| Outcome | `attempted_path`, `chosen_path`, `evidence_grade`, fallback reason/status, `completed_at_ns`, `dropped` | Distinguishes capability failure from intentional policy fallback. |

`evidence_grade` must be one of `api_only`, `runtime_success`, `profiler_verified_no_application_copy`, or `internal_copy_unknown`. Only the third grade may derive the public `zero_copy` label. A bitstream readback is recorded separately from surface movement; compressed-output handling must not turn an otherwise GPU-resident surface path into a false `cpu_copy` classification.

### Ownership-transfer rules

1. **Borrowed is not owned.** `AcquireNextFrame` yields a DDA lease; `pw_stream_dequeue_buffer` yields a PipeWire capture buffer. Neither becomes application-owned merely because an API import succeeds. DDA's surface becomes invalid after `ReleaseFrame`; a PipeWire buffer becomes recyclable when queued. [DDA release semantics](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/nf-dxgi1_2-idxgioutputduplication-releaseframe) [PipeWire buffer lifecycle](https://docs.pipewire.org/group__pw__stream.html)
2. **A detach edge must be explicit.** A DDA GPU copy/conversion to an owned destination is a ledger edge with `gpu_blit` or `gpu_convert`; only after that copy has been correctly submitted/ordered may downstream work use the destination rather than the DDA lease. Direct NVENC use retains the DDA lease through encoder completion.
3. **Never transfer borrowed PipeWire FDs blindly.** Import while the `pw_buffer` lease is held. If an API consumes FD ownership, first duplicate the FD and record the duplicate as transferred; do not close PipeWire's borrowed descriptor. Successful Vulkan FD import transfers FD ownership to Vulkan. libva's DRM PRIME import explicitly does **not** close the supplied FD, and states that releasing it does not destroy the created surface. [Vulkan FD ownership](https://registry.khronos.org/VulkanSC/specs/1.0-extensions/man/html/VkImportMemoryFdInfoKHR.html) [libva descriptor ownership](https://raw.githubusercontent.com/intel/libva/master/va/va_drmcommon.h)
4. **Resource registration is not a release.** NVENC registration/map state, CUDA/D3D map state, and EGL registration are separate claims from the source lease. NVENC's mapped resource is exclusive to NVENC until unmap; CUDA says graphics/CUDA concurrent access while mapped is undefined; CUDA EGL explicitly assigns synchronization responsibility to the application. [NVENC mapped-resource rule](https://docs.nvidia.com/video-technologies/video-codec-sdk/13.1/nvenc-video-encoder-api-prog-guide/index.html#input-buffers-allocated-externally) [CUDA graphics interop](https://docs.nvidia.com/cuda/cuda-programming-guide/04-special-topics/graphics-interop.html) [CUDA EGL rule](https://docs.nvidia.com/cuda/cuda-runtime-api/group__CUDART__EGL.html)

### Synchronized-release rules

* Do not release/recycle a source lease merely because its consumer submission returned success. Release requires either (a) a completed consumer token, or (b) a proven detach edge to an application-owned destination whose queue ordering preserves the source read. The latter is `EXPERIMENT_REQUIRED` for the DDA implementation and must be soak-tested.
* For direct NVENC input, wait for the encoder completion event in asynchronous Windows mode before reusing the input/output sample; unmap before reuse, unregister before destruction. [NVENC asynchronous operation](https://docs.nvidia.com/video-technologies/video-codec-sdk/13.1/nvenc-video-encoder-api-prog-guide/index.html#asynchronous-mode)
* For traditional NVDEC output, defer `cuvidUnmapVideoFrame` until all CUDA work reading its device pointer has completed or is conclusively ordered; failure to unmap exhausts `ulNumOutputSurfaces`. [NVDEC map/unmap rules](https://docs.nvidia.com/video-technologies/video-codec-sdk/13.1/nvdec-video-decoder-api-prog-guide/index.html#preparing-the-decoded-frame-for-further-processing)
* For a PipeWire DMA-BUF sent to VAAPI, recycle only after `vaSyncSurface`, or after an interoperable explicit completion fence has been proven for that driver. `vaEndPicture` is non-blocking; `vaSyncSurface` blocks until pending operations on the surface complete. [libva synchronization](https://raw.githubusercontent.com/intel/libva/master/va/va.h)
* For implicit/explicit DMA-BUF bridging, record the actual access mode. Linux documents that exported `sync_file` fences are snapshots and the export-submit-import sequence is not atomic; serialize the bridge at the application layer. [Linux DMA-BUF synchronization](https://docs.kernel.org/driver-api/dma-buf.html)

### Observable telemetry

At minimum expose: chosen/attempted path and evidence grade; source and encoder device identities; exact format/modifier tuple; conversion direction; known GPU-copy and CPU-copy bytes; source-lease hold time; acquire/wait/copy/encode submission/completion timings; outstanding DDA/PipeWire/NVDEC leases; buffer-pool occupancy; synchronization mode and wait duration; fallback reason (`adapter_mismatch`, `format_mismatch`, `modifier_mismatch`, `import_failed`, `registration_failed`, `sync_unavailable`, `lease_timeout`); and frames dropped because freshness policy chose not to retain a lease. Never expose raw file descriptors, pointers, or handles in normal telemetry.

## Compatibility caveats

* **Hybrid and multi-GPU Windows:** the capture output's adapter and the NVENC device can differ. Shared handles/keyed mutexes solve neither physical allocation compatibility nor NVENC registration. Cross-adapter resources require a specific linear shared allocation and are not a guarantee for the DDA resource. [Windows cross-adapter resources](https://learn.microsoft.com/en-us/windows-hardware/drivers/display/using-cross-adapter-resources-in-a-hybrid-system)
* **Linux DRM device topology:** DMA-BUF alone does not mean the compositor device, EGL/Vulkan device, CUDA device, and VA device are compatible. Vulkan's imported FD must originate from a compatible underlying physical device/driver; modifier support is vendor-specific. [Vulkan import validity](https://registry.khronos.org/VulkanSC/specs/1.0-extensions/man/html/VkImportMemoryFdInfoKHR.html) [DRM modifier semantics](https://registry.khronos.org/VulkanSC/specs/1.0-extensions/man/html/VK_EXT_image_drm_format_modifier.html)
* **Modifiers and plane layout:** modifier, FourCC, per-plane offsets, and pitches are all part of the image contract. `DRM_FORMAT_MOD_INVALID` delegates layout to the implementation; guessing linear layout or mmap-ing a tiled/compressed DMA-BUF is invalid or slow. [PipeWire warning](https://docs.pipewire.org/1.4/page_dma_buf.html) [EGL modifier validation](https://registry.khronos.org/EGL/extensions/EXT/EGL_EXT_image_dma_buf_import_modifiers.txt)
* **Pixel and color conversion:** BGRA/RGB capture, NV12/P010 encoder surfaces, YUV decoder outputs, color range, transfer and matrix are separate compatibility checks. Vulkan's DRM/Vulkan format mapping is incomplete and lossy, including RGB/sRGB ambiguity. Treat every conversion as a ledger edge even when it executes wholly on GPU. [Vulkan format translation](https://registry.khronos.org/VulkanSC/specs/1.0-extensions/man/html/VK_EXT_image_drm_format_modifier.html)
* **Version/vendor/compositor specificity:** NVIDIA claims above are for Video Codec SDK 13.1 and CUDA 13.3.1 documentation; actual input formats and opaque-NVDEC capabilities must be queried on the installed GPU/driver. PipeWire explicit sync requires both endpoints and a capable DRM render node, so it is compositor/portal/version-specific. VA DRM PRIME import support and accepted layouts are backend-driver-specific. [NVENC capability queries](https://docs.nvidia.com/video-technologies/video-codec-sdk/13.1/nvenc-video-encoder-api-prog-guide/index.html#querying-encoder-capabilities) [PipeWire explicit sync](https://docs.pipewire.org/1.4/page_dma_buf.html) [libva PRIME caveat](https://raw.githubusercontent.com/intel/libva/master/va/va_drmcommon.h)

## Candidate experiments

1. Does same-adapter NVENC accept an acquired DDA texture for the requested H.264 input format?
2. Does direct DDA→NVENC completion before `ReleaseFrame` sustain 1080p120 without capture-lease starvation?
3. Does DDA→owned-NV12 GPU conversion permit correct immediate DDA lease release under a 4K60 soak?
4. Does a selected PipeWire `(fourcc, modifier)` tuple import into EGL on the selected desktop NVIDIA driver?
5. Does CUDA expose the imported EGLImage in an NVENC-registerable representation on that tuple?
6. Does the selected PipeWire DMA-BUF import into the selected VAAPI driver with `VA_SURFACE_ATTRIB_MEM_TYPE_DRM_PRIME_2`?
7. Does VAAPI completion permit PipeWire-buffer recycle without `vaSyncSurface` when negotiated explicit sync is enabled?
8. Does the selected Windows iGPU/dGPU pair pass a cross-adapter texture through `NvEncRegisterResource` for 30 minutes?

## Sources

### Official

- [Microsoft — IDXGIOutputDuplication::AcquireNextFrame](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/nf-dxgi1_2-idxgioutputduplication-acquirenextframe)
- [Microsoft — IDXGIOutputDuplication::ReleaseFrame](https://learn.microsoft.com/en-us/windows/win32/api/dxgi1_2/nf-dxgi1_2-idxgioutputduplication-releaseframe)
- [Microsoft — Cross-adapter resources in hybrid systems](https://learn.microsoft.com/en-us/windows-hardware/drivers/display/using-cross-adapter-resources-in-a-hybrid-system)
- [NVIDIA — NVENC Video Encoder API Programming Guide 13.1](https://docs.nvidia.com/video-technologies/video-codec-sdk/13.1/nvenc-video-encoder-api-prog-guide/index.html)
- [NVIDIA — NVDEC Video Decoder API Programming Guide 13.1](https://docs.nvidia.com/video-technologies/video-codec-sdk/13.1/nvdec-video-decoder-api-prog-guide/index.html)
- [NVIDIA — CUDA graphics interoperability](https://docs.nvidia.com/cuda/cuda-programming-guide/04-special-topics/graphics-interop.html)
- [NVIDIA — CUDA EGL interoperability API](https://docs.nvidia.com/cuda/cuda-runtime-api/group__CUDART__EGL.html)
- [NVIDIA — CUDA external-resource interoperability API](https://docs.nvidia.com/cuda/cuda-driver-api/group__CUDA__EXTRES__INTEROP.html)
- [PipeWire — DMA-BUF sharing](https://docs.pipewire.org/1.4/page_dma_buf.html)
- [PipeWire — stream buffer lifecycle](https://docs.pipewire.org/group__pw__stream.html)

### Upstream

- [libva — DRM PRIME surface interfaces](https://raw.githubusercontent.com/intel/libva/master/va/va_drmcommon.h)
- [libva — core surface synchronization](https://raw.githubusercontent.com/intel/libva/master/va/va.h)
- [Linux kernel — DMA-BUF sharing and synchronization](https://docs.kernel.org/driver-api/dma-buf.html)

### Standards

- [Khronos — EGL_EXT_image_dma_buf_import_modifiers](https://registry.khronos.org/EGL/extensions/EXT/EGL_EXT_image_dma_buf_import_modifiers.txt)
- [Khronos — VK_EXT_external_memory_dma_buf](https://registry.khronos.org/VulkanSC/specs/1.0-extensions/man/html/VK_EXT_external_memory_dma_buf.html)
- [Khronos — VK_EXT_image_drm_format_modifier](https://registry.khronos.org/VulkanSC/specs/1.0-extensions/man/html/VK_EXT_image_drm_format_modifier.html)
- [Khronos — VkImportMemoryFdInfoKHR](https://registry.khronos.org/VulkanSC/specs/1.0-extensions/man/html/VkImportMemoryFdInfoKHR.html)
- [Khronos — VK_KHR_external_semaphore_fd](https://registry.khronos.org/VulkanSC/specs/1.0-extensions/man/html/VK_KHR_external_semaphore_fd.html)

### Other

- None.
