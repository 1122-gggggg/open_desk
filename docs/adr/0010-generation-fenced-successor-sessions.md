# ADR 0010: Generation-fenced successor sessions

**Status:** Accepted

**Date:** 2026-08-30

## Context

`ProductSession` previously synthesized generation, authorization, display, and
codec epochs as `1` for every connection. A random session ID usually separated
connections, but the product handshake could not express or enforce that a
replacement connection was newer than its predecessor. The Linux secure Host
also closed its QUIC endpoint after one session, preventing a clean successor
from using the same listener.

## Decision

1. `ProductStampAllocator` owns random nonzero session IDs and strictly
   increasing generation, authorization, display, and codec epochs. RNG failure,
   repeated zero IDs, or counter exhaustion fails closed without advancing
   allocator state.
2. The Host supplies the complete active `SessionStamp` to
   `ProductSession::host_with_stamp`. Compatibility constructors retain the
   initial `1/1/1/1` stamp only for callers that have not adopted lifecycle
   allocation.
3. `ProductSession::client_successor` requires a different session ID and every
   generation, authorization, display, and codec epoch to be strictly greater
   than the prior authenticated session. It rejects the handshake and closes
   the connection otherwise.
4. Remote disconnect messages must match both the active session ID and
   authorization epoch before they can close a session.
5. The Linux X11 secure Host can accept a bounded 1–16 sequential session
   sequence with one endpoint. Each session recreates its ProductSession,
   capture/encoder state, input worker, reconciler, reassembler, and queues;
   `ReleaseAll` completes before the listener accepts the successor.
6. Windows remains limited to one secure Host session in this iteration. It
   already uses lifecycle-allocated stamps, but persistent Windows provider
   teardown/restart needs its own native soak evidence before enabling the loop.

## Consequences

- A clean successor is distinguishable and strictly ordered at the product wire
  boundary, not only inside the authorization model.
- Old dispatch permits, disconnect records, input, and media cannot match the
  successor's full stamp.
- The secure process smoke runs one headless Client that automatically creates
  two valid connections around one persistent Host and requires distinct IDs,
  strictly increasing lifecycle epochs, and a `ReleaseAll` marker between
  activations.
- This is a safe sequential successor foundation, not automatic interactive
  reconnect, transport migration, simultaneous controllers, or recovery from
  every provider failure.

## Sources

- QUIC connection lifecycle and application close:
  https://www.rfc-editor.org/rfc/rfc9000.html
- QUIC TLS and replay constraints:
  https://www.rfc-editor.org/rfc/rfc9001.html
- Quinn 0.11.8 connection close behavior:
  https://docs.rs/quinn/0.11.8/quinn/struct.Connection.html#method.close
