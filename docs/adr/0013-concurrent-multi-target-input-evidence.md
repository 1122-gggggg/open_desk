# ADR 0013: Concurrent multi-target input evidence

**Status:** Accepted

**Date:** 2026-08-31

## Context

Independent single-target latency runs cannot prove that one Client controller
keeps multiple input paths responsive at the same time. Simply finding two
successful result lines also permits sequential execution, mixed target logs,
or samples from the wrong lifecycle to be mislabeled as concurrency.

## Decision

1. Multi-target probe mode uses the existing process-isolation boundary: one
   supervisor expands each exact `(address, peer certificate)` into a child and
   forwards the same bounded probe count. It never forwards `--target`, so a
   child cannot recursively become a supervisor.
2. Each child emits flushed `input-latency-start`, `input-latency-stop`, and
   `input-latency` records containing its selected target, complete product
   stamp, and sample count. The raw result also contains every input sequence
   and local send-to-ACK duration.
3. Concurrent overlap is accepted only when both start records have been
   observed while the supervisor and both Hosts are alive and before either
   stop or result record. Every boundary and result must later match exactly.
4. Per-target validation is positional only at the process boundary and keyed
   by target everywhere else. It requires an exact Host certificate hash,
   mTLS markers on both sides, route, full lifecycle, unique session ID, one
   real desktop stream, ReleaseAll, natural exits, raw-statistic recomputation,
   binary hashes, and removal of temporary credentials.
5. A permissive 100 ms p95 ceiling remains a stall detector. The artifact is
   application-ACK RTT evidence, not physical input-to-photon latency or a
   competitor comparison.

## Consequences

- A single controller now has reproducible two-Host control-plane latency
  evidence under actual overlapping probe work.
- Combined inherited stdout is safe for this bounded diagnostic because each
  record is target/full-stamp keyed, explicitly flushed, and any malformed
  interleaving fails parsing. General interactive log aggregation remains a
  separate product concern.
- The gate does not establish 4/8/16-Host resource scaling, cross-machine
  behavior, visible UI response, continuous typing latency, or WAN performance.
