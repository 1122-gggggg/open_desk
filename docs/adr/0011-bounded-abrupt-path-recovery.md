# ADR 0011: Bounded abrupt-path recovery

**Status:** Accepted

**Date:** 2026-08-30

## Context

ADR 0010 made a clean successor distinguishable from its predecessor, but an
idle timeout or stateless reset still terminated the Linux Host listener and the
Client. Treating every error as recoverable would be unsafe: certificate,
protocol, codec, provider, and explicit nonzero application-close failures are
usually persistent and must remain visible.

Remote input adds a stricter invariant. A lost path must release every held key
and pointer button before the Host admits a successor, and delayed records from
the retired input epoch must never reactivate it.

## Decision

1. QUIC uses a two-second configured idle timeout and a 500 ms keepalive. QUIC's
   effective timeout rules still apply, including the minimum based on three
   probe timeouts.
2. Only an authenticated connection `Reset` or `TimedOut` is a recoverable
   established-path failure. Bounded candidate timeouts are retryable while
   exact-certificate mismatch, TLS/protocol violations, explicit application
   closes, local shutdown, resource exhaustion, and provider/codec failures are
   terminal.
3. The Linux Host always finishes input-worker cleanup and `ReleaseAll` before
   returning to the same endpoint's accept loop. A lost session consumes one of
   the explicit `--max-sessions` slots; exhausting the slots on a peer loss is
   an error rather than a false success.
4. A headless Client may opt in with `--reconnect-attempts 0..=8`. Attempts are
   global to that run, use a monotonic total budget equal to the smaller of the
   operation timeout and 15 seconds, and use exponential
   100/200/400/800/1600 ms delay with per-session jitter capped at two seconds.
5. Recovery recreates the complete ProductSession, control/input lanes, codec
   negotiation, decoder/reassembler, and queues. The Client accepts it only
   through `client_successor`, requiring a new session ID and strictly greater
   generation, authorization, display, and codec epochs.
6. `InputReconciler::disconnect_release_plan` retires the active input epoch.
   Later records from that epoch are ignored even if the reconciler remains in
   memory; only a strictly newer epoch can resume input.
7. Linux CI blackholes both directions through a loopback UDP proxy after the
   first real desktop stream starts, proves that packets were dropped, restores
   the path, and requires an authenticated successor within two seconds plus
   ReleaseAll before the successor activation.

## Consequences

- A dead path is detected far sooner than the former 30-second idle policy,
  while idle sessions remain live through bounded keepalives.
- Reconnect cannot turn authentication or protocol failures into an infinite
  retry loop.
- The current automatic supervisor is intentionally limited to headless Client
  sessions. Interactive viewer restart, Windows Host persistence, QUIC path
  migration, Wi-Fi/cellular handoff, and cross-machine recovery remain separate
  gates.
- The loopback blackhole is deterministic fault evidence, not a claim about
  physical network recovery time or competitive superiority.

## Sources

- QUIC idle timeout and liveness testing:
  https://www.rfc-editor.org/rfc/rfc9000.html#section-10.1
- QUIC connection migration and path validation:
  https://www.rfc-editor.org/rfc/rfc9000.html#section-9
- Quinn 0.11.8 idle-timeout configuration:
  https://docs.rs/quinn/0.11.8/quinn/struct.TransportConfig.html#method.max_idle_timeout
- Quinn 0.11.8 keepalive configuration:
  https://docs.rs/quinn/0.11.8/quinn/struct.TransportConfig.html#method.keep_alive_interval
