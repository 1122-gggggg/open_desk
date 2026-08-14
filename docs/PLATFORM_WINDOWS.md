# Windows Platform Plan

## Process model

```text
LatencyDesk per-user agent (logged-in interactive user context)
  ├─ DDA/WGC capture
  ├─ ordinary SendInput path
  ├─ encoder/decoder provider
  ├─ visible consent/session UI
  └─ narrow local IPC authenticated against the peer PID, token,
     session, logon LUID, and pipe ACL
```

V0.1 has no persistent LocalSystem pixel/input service. Capture and ordinary
input stay in the logged-in interactive user context; secure desktop, UAC
secure desktop, and elevated-target bypass remain unsupported. A local IPC
peer proof only binds the agent to that user session; it does not authorize
remote control without the later authenticated transport identity, host
approval, and controller lease.

## Capture provider

### DDA first

Use DDA for whole-output capture and retain:

- acquired D3D11 texture;
- dirty/move metadata for future refinement hints;
- pointer metadata;
- rotation/output identity;
- access-lost and display-mode-change handling.

The capture callback must release each acquired frame promptly. Import into the encoder only when device/format/synchronization compatibility is proven; otherwise copy into the bounded encoder pool.

### WGC second

Add WGC for selected-window/monitor capture and fallback scenarios. It is a separate provider with its own consent/picker and frame-pool behavior, not a transparent alias for DDA.

## GPU/device considerations

- enumerate capture and encode adapter identities;
- detect hybrid-GPU/cross-adapter paths;
- report zero-copy versus GPU-copy versus CPU-copy;
- keep BGRA→NV12 conversion on GPU where possible;
- synchronize explicitly and avoid global device flushes;
- handle resolution/rotation changes by incrementing codec/display epoch.

## Input

Use a user-session agent and `SendInput` for normal targets. Track physical usages, logical text/IME separately, and force release-all on session loss. UIPI/integrity restrictions and UAC secure desktop are documented limitations, not bugs hidden by retry loops.

## Decode/render

Reference path:

```text
encoded H.264
  → hardware decoder / D3D11 surface
  → GPU color conversion/composition
  → flip-model swap chain
  → local cursor overlay
```

Keep one newest continuity-valid frame pending. Test tearing/vsync/present modes rather than hard-coding an assumption about minimum latency.

## Acceptance tests

- display connect/disconnect, rotate, sleep/wake, lock/unlock;
- DDA access lost and recreation;
- 100%/125%/150%/mixed DPI mapping;
- multi-GPU forced-copy path;
- protected-content behavior is nonfatal and documented;
- normal/elevated target input behavior;
- capture/encode 30-minute soak at 1080p120 and 4K60 where hardware supports it;
- no unreleased capture frames or growing queue.
