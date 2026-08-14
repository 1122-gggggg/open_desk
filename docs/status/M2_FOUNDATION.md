# M2 Platform and Surface Foundation Status

**Status:** safe ownership and real localhost socket foundation implemented; native Windows capture/codec/render work is still pending on Windows reference hardware.

## Implemented

- non-cloneable `SurfaceLease` with RAII release;
- pool-scoped, generation-safe surface tokens;
- hard slot, per-surface, and aggregate byte budgets;
- high-water and rejection telemetry;
- explicit `ZeroCopy`, `GpuCopy`, and `CpuCopy` import paths;
- provider-neutral capture capabilities and permission/session scope;
- an honest `LoggedInUser` versus `SystemDesktop` distinction;
- single-slot newest-frame presentation coordinator that rejects invalid/stale generations, clears continuity on reset, creates canonical full-epoch receipts, and requires exact lease return before a failed submit releases a surface;
- bounded cursor-shape validation;
- input injection/reconciliation provider contracts;
- loopback-only, insecure UDP adapter for real socket queue tests;
- Rust localhost UDP smoke application;
- independent Python surface-lifetime and localhost UDP reference gates.

## Executed evidence

```bash
python3 scripts/surface_reference.py --iterations 200000 --seed 20260813
python3 scripts/udp_reference.py --frames 12 --seed 20260813
```

Observed surface reference result:

- 200,000 randomized operations;
- 59,542 successful acquisitions and releases;
- 92,039 stale-release attempts, zero accepted;
- 1,014 cross-pool forged-release attempts, zero accepted;
- maximum eight active surfaces;
- maximum 134,213,335 reserved bytes under the 128 MiB aggregate cap;
- zero surfaces and zero reserved bytes after cleanup.

Observed real localhost UDP reference result:

- 12 exact frames;
- 648 datagrams sent and received through operating-system UDP sockets;
- zero silent mismatch;
- no receiver hang or timeout;
- zero reassembly reservation after cleanup.

Artifacts:

- `artifacts/surface-reference.json`
- `artifacts/udp-reference.json`

## Not yet proven

- DDA or WGC capture on Windows;
- hardware H.264 encoding/decoding;
- D3D11 presentation timing;
- Windows input integrity/UAC behavior;
- native handle import across D3D11 devices;
- 1080p60 or 1440p120 performance;
- QUIC/TLS security or congestion control.

The localhost UDP adapter is intentionally unusable for production: it accepts only loopback addresses and supplies no security. The authoritative Rust `fmt`, Clippy, and test gates remain pending in this bootstrap environment because no Rust toolchain is installed.
