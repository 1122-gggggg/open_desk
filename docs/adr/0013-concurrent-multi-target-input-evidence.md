# ADR 0013: Concurrent multi-target input evidence

**Status:** Accepted

**Date:** 2026-08-31

## Context

Independent single-target latency runs cannot prove that one Client controller
keeps multiple input paths responsive at the same time. Simply finding several
successful result lines also permits sequential execution, mixed target logs,
or samples from the wrong lifecycle to be mislabeled as concurrency.

## Decision

1. Multi-target probe mode uses the existing process-isolation boundary: one
   supervisor expands each exact `(address, peer certificate)` into a child and
   forwards the same bounded probe count. The scale harness permits only 2, 4,
   8, or 16 targets. It never forwards `--target`, so a child cannot recursively
   become a supervisor.
2. Each child emits flushed `input-latency-start`, `input-latency-stop`, and
   `input-latency` records containing its selected target, complete product
   stamp, and sample count. The raw result also contains every input sequence
   and local send-to-ACK duration.
3. Concurrent overlap is accepted only when every start record has been
   observed while the supervisor and all Hosts are alive and before any stop or
   result record. Every boundary and result must later match exactly.
4. Per-target validation is positional only at the process boundary and keyed
   by target everywhere else. It requires an exact Host certificate hash,
   mTLS markers on both sides, route, full lifecycle, unique session ID, one
   real desktop stream, ReleaseAll, natural exits, raw-statistic recomputation,
   binary hashes, and removal of temporary credentials.
5. A permissive 100 ms p95 ceiling remains a stall detector. The artifact is
   application-ACK RTT evidence, not physical input-to-photon latency or a
   competitor comparison.
6. Hosts bind `127.0.0.1:0`; the harness parses and validates each actual,
   unique OS-assigned listen address before constructing the supervisor plan.
   This removes pre-allocation port races from the evidence path.
7. At the overlap point, Linux `/proc` must contain one supervisor plus exactly
   N Client processes in its group and N single-process Host groups. Two samples
   must keep `(PID, start time, process group, executable device/inode)` stable.
   RSS/peak-RSS sums, CPU ticks, FD counts, and thread counts are retained as
   observations because shared pages and runner hardware make universal limits
   misleading without a calibrated soak.
8. Every secure Host and Client process uses two Tokio workers. This preserves
   separate progress for blocking media/provider work and input/network work,
   while avoiding the default one-worker-per-CPU multiplication across 16
   isolated targets. The supervisor takes the multi-target branch before
   constructing a Tokio runtime. In probe mode it uses two bounded pipe-drain
   threads per child to serialize stdout/stderr without cross-target line
   interleaving; each child/Host has its main thread plus two workers. The
   `/proc` gate allows modest runtime overhead (`Client group <= 1 + 6N`, Hosts
   total `<= 4N`) while preventing a return to CPU-count-multiplied thread
   topology; the source configuration, rather than that upper bound alone,
   establishes two workers.

## Consequences

- A single controller now has reproducible 2/4/8/16-Host single-machine
  control-plane latency evidence under actual overlapping probe work.
- Probe-mode children use dedicated stdout/stderr pipes. Concurrent drain
  threads forward complete lines through one supervisor mutex, so long raw
  records cannot interleave across targets; any forwarding error or thread
  panic fails the supervisor. General interactive log aggregation remains a
  separate product concern.
- The gate does not establish cross-machine scaling, leak-free long-duration
  resource behavior, visible UI response, continuous typing latency, or WAN
  performance.
