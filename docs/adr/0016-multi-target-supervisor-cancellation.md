# ADR 0016: Fail-closed multi-target supervisor cancellation

**Status:** Accepted

**Date:** 2026-08-31

## Context

The multi-target Client isolates every Host in a direct child process. The
original supervisor waited for children sequentially and handled cleanup only
when spawning failed. Ctrl-C could therefore terminate the supervisor while
leaving active Clients, QUIC sessions, input state, and output-draining threads
behind.

## Decision

1. One Tokio Ctrl-C future is pinned and polled with biased priority before the
   first `Command::spawn`. The same future remains active through every spawn
   and the supervision loop, so there is no handler-registration gap once a
   child can exist.
2. Every child has an explicit Running, Reaped, or PollFailed state. Natural
   nonzero exits remain per-target failures. A polling or signal-handler error
   changes the whole supervisor to fail-safe cancellation.
3. Cancellation kills every unreaped direct child, polls for termination under
   a five-second deadline, and uses kill-then-wait fallback when polling itself
   fails. A child is counted only after the OS process handle is reaped.
4. Captured stdout/stderr forwarders are joined only for reaped children, after
   pipe EOF. Kill, wait, reap, and join failures remain terminal; cancellation
   always returns a nonzero supervisor result.
5. Stable logs disclose only target address, PID, and cleanup counts. The Linux
   process gate sends SIGINT only to the supervisor PID and independently checks
   the exact process group, stable PID/start-time/executable identities, four
   reaps, eight forwarder joins, identity disappearance, and Host ReleaseAll.

## Consequences

- Ctrl-C no longer silently abandons a directly spawned multi-target Client.
- The guarantee covers direct children created by this supervisor. It does not
  claim arbitrary descendant-tree cleanup, platform logout/service shutdown,
  cross-machine GUI behavior, or leak-free long-duration operation.
- A future Windows Job Object / Unix process-group abstraction is required
  before child processes are permitted to create their own descendants.
