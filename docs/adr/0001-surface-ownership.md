# ADR-0001: Non-cloneable surface leases and explicit copy fallbacks

- **Status:** accepted
- **Milestone:** M2 foundation
- **Decision date:** 2026-08-13

## Context

Windows Graphics Capture frames and other platform capture buffers are provider-owned resources with explicit lifetime rules. PipeWire likewise recycles buffers supplied by a stream. A remote-desktop pipeline cannot safely retain such a buffer in an asynchronous encoder queue unless it first establishes a valid native import or copies the contents into its own bounded storage.

The project also cannot assume every D3D11 texture or Linux DMA-BUF is directly consumable by every encoder. Adapter identity, pixel format, memory modifier, synchronization mechanism, and driver support can force a GPU or CPU copy.

Primary platform references:

- Microsoft, *Screen capture*: https://learn.microsoft.com/windows/apps/develop/media-authoring-processing/screen-capture
- Microsoft, `Direct3D11CaptureFrame.Close`: https://learn.microsoft.com/uwp/api/windows.graphics.capture.direct3d11captureframe.close
- PipeWire, *SPA buffer data types*: https://docs.pipewire.org/group__spa__buffer.html
- XDG ScreenCast portal: https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.ScreenCast.html

## Decision

1. A platform callback may return only:
   - an owned CPU frame; or
   - a `SurfaceLease` representing storage already imported or copied into a LatencyDesk-owned bounded pool.
2. `SurfaceLease` is movable but not cloneable.
3. Every token is scoped by `pool_id`, `slot`, and `generation` so a stale token cannot alias a later user of the same slot.
4. `Drop` and explicit `release` return both the slot and byte reservation.
5. Every frame records one import path: `ZeroCopy`, `GpuCopy`, or `CpuCopy`.
6. Pool limits include slot count, per-surface bytes, aggregate bytes, and high-water telemetry.
7. Native raw handles remain outside the safe core. A future backend process or narrowly audited FFI crate owns those handles.

## Consequences

- Capture callbacks cannot enqueue borrowed provider buffers directly.
- Zero-copy remains an optimization rather than a product requirement.
- Backpressure is visible as `PoolExhausted` or byte-budget rejection instead of hidden buffering.
- Native backends require a synchronous import/copy boundary before returning a frame.
- Additional copies can be benchmarked and reported honestly.
