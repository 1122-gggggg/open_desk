# ADR 0007: Native providers must cross a bounded ownership boundary

## Decision

Every capture callback must either import the native resource safely or copy it into a
fixed-capacity core-owned pool before returning the OS capture lease. Native buffers,
COM callbacks, PipeWire buffers, and GPU fences cannot be retained by unbounded queues.

Every provider reports one of:

- `ZeroCopy`
- `GpuCopy`
- `CpuCopy`

Zero-copy is an optimization, not a prerequisite for correctness.

## Consequences

- Backpressure becomes observable as pool exhaustion instead of memory growth.
- Error paths release native leases through RAII.
- Slow encoders drop work at a bounded boundary.
- Benchmarks can distinguish codec cost from hidden memory copies.
