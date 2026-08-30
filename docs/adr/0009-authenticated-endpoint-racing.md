# ADR 0009: Authenticated endpoint racing before ICE

**Status:** Accepted

**Date:** 2026-08-30

## Context

The secure Client previously accepted one fixed `SocketAddr`. A stale DNS
answer, dead port, alternate interface, or temporarily broken address therefore
failed the whole connection before another known address could be tried. The
repository already contained ICE candidate and direct/relay routing models, but
they were not connected to network I/O and could invent a TURN fallback without
an allocated relay candidate.

Shipping pretend ICE would be worse than retaining direct IP: RFC 8445 requires
authenticated STUN connectivity checks, candidate-pair state, nomination, and
consent handling. No rendezvous, STUN, or TURN service is deployed yet.

## Decision

1. The secure Client may receive one primary `--connect` address and up to three
   repeatable `--fallback-address` values for the same exact-pinned Host.
2. `connect_exact_peer_candidates` races at most four unique addresses. Every
   attempt independently completes TLS 1.3 and exact-leaf certificate equality;
   a UDP or QUIC handshake alone cannot win.
3. Each attempt has a nonzero local timeout. Tokio `JoinSet` owns all attempts;
   once one authenticated connection wins, unfinished attempts are aborted and
   drained.
4. An IPv4-bound endpoint rejects IPv6 candidates before starting. An IPv6 bind
   such as `[::]:0` may use Quinn's documented dual-stack behavior, while
   retaining ordinary connection failure handling on systems that cannot create
   a dual-stack socket.
5. The session router treats its direct timeout as a duration beginning at the
   first selection for the current candidate generation. It advances past failed
   high-priority pairs, rotates background probes, resets stale active state when
   candidates change, and creates a relay fallback only when a valid locally
   allocated relay candidate plus nonzero relay/session identity exists. A
   remote peer advertising a relay does not create a local allocation.
6. ICE candidates reject inconsistent type/provider combinations: relayed
   candidates require a relay provider, while direct candidates cannot claim
   one.

## Consequences

- Multiple known addresses no longer serialize behind the first timeout.
- Existing exact-certificate security is preserved on every raced path.
- CI's secure X11 process smoke deliberately supplies an unreachable primary
  and requires the exact-pinned fallback to win.
- This is not ICE, STUN, TURN, NAT hole punching, relay deployment, automatic
  active-session reconnect, or QUIC path migration. Those remain separate
  milestones with their own threat reviews and infrastructure.

## Sources

- RFC 8445 ICE candidate pairs and checklist scheduling:
  https://www.rfc-editor.org/rfc/rfc8445.html
- Quinn 0.11.8 endpoint and dual-stack binding behavior:
  https://docs.rs/quinn/0.11.8/quinn/struct.Endpoint.html
- Tokio 1.44.2 `JoinSet` cancellation/lifecycle behavior:
  https://docs.rs/tokio/1.44.2/tokio/task/struct.JoinSet.html
