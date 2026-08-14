# ADR 0003: Zero-copy is negotiated; a bounded copy fallback is mandatory

- Status: Accepted
- Date: 2026-08-13

## Decision

D3D11 and DMA-BUF imports are capability paths. Capture providers must release
capture-owned buffers promptly after safe import or bounded copy into
encoder-owned storage. Every successful handoff carries a fixed-size
`CopyLedger` containing source-lease identity, device identities, layouts,
transfer edge, synchronization proof, completion state, actual path, fallback
reason, and evidence grade. `DirectAlias` is valid only with a completed
same-device profiler proof; opaque driver movement is
`InternalCopyUnknown`, not a zero-copy claim.

## Consequences

The architecture works across adapter/driver/format mismatches and can quantify
the cost instead of failing or silently retaining buffers. A provider cannot
turn a capture lease into an owned surface without a ledger whose source
sequence, source layout, completion proof, and evidence pass validation.
