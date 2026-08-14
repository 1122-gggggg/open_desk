# Contributing

LatencyDesk is pre-alpha infrastructure handling untrusted network data and remote input. Correctness, bounds, and reproducibility take priority over feature volume.

## Before opening code

1. Read `docs/TECHNICAL_AUDIT.md`, `docs/PROTOCOL.md`, and `docs/THREAT_MODEL.md`.
2. Open or reference an issue with an entry/exit gate.
3. State platform/GPU/driver assumptions.
4. Disclose implementation projects studied and their licenses.
5. Do not copy GPL/AGPL implementation code into this permissive core.

## Required checks

```bash
python3 scripts/static_validate.py
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets
```

Platform work additionally needs forced-copy and failure-path tests. Network parsers require malformed/boundary tests and a fuzz plan. Performance changes require raw traces and the exact benchmark configuration.

## Design requirements

- all peer-controlled lengths and dimensions are bounded before allocation;
- queues have item and byte caps;
- capture/PipeWire leases are not held across unbounded asynchronous work;
- zero-copy is negotiated and has a measured copy fallback;
- predictive-frame dropping respects dependency/recovery semantics;
- host/client timestamps are not directly subtracted;
- privileges and user authorization are explicit;
- no performance claim without optical/reproducible evidence.

## Unsafe code

Core crates forbid unsafe code. Platform FFI/provider crates may eventually use narrowly scoped unsafe code with:

- a safe wrapper and documented invariants;
- tests for null/error/lifetime paths;
- reviewer familiar with the target API;
- no unsafe code in wire parsing unless separately approved.

## Commit and PR scope

Prefer one architectural concern per PR. Include:

- problem and rejected alternatives;
- resource/latency/security impact;
- tests and platform matrix;
- telemetry needed to validate it;
- documentation/ADR update.
