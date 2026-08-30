# ADR 0017: Bounded Sans-I/O ICE before Quinn socket handoff

**Status:** Accepted

**Date:** 2026-08-31

## Context

Candidate advertisement alone cannot prove reachability. Implementing a full
RFC 8445 checklist, role conflict, nomination, retransmission, and liveness
engine from scratch would add high-risk protocol work. Letting a raw ICE reader
compete with Quinn for the same socket would also lose or misclassify packets.

## Decision

1. Pin the focused `is` 0.11.0 Sans-I/O ICE core (MIT OR Apache-2.0), not the
   complete str0m/WebRTC stack and not an application-owned async socket agent.
2. Wrap it with fixed product bounds: eight local candidates, eight remote
   candidates, 64 pairs, one address family, UDP host/server-reflexive types,
   2,048-byte inbound cap, bounded Ta/RTO/retransmits, and a 40-second maximum
   establishment deadline.
3. Generate local ufrag/password material and the role tie-breaker with the OS
   CSPRNG. Debug output redacts credentials and the wrapper zeroizes its own
   copies. HMAC-SHA1 remains enabled solely because RFC 8445 STUN
   `MESSAGE-INTEGRITY` requires it; it is not used for password storage or
   signatures.
4. Validate exact STUN length/magic, one final FINGERPRINT and CRC before the
   upstream parser. The upstream transaction ID remains a correlation value;
   CSPRNG credentials plus HMAC authenticate checks and responses.
5. Enforce sequential socket ownership. ICE sends and receives raw UDP first.
   After both sides nominate the exact pair, raw reads stop, queued ICE packets
   are drained, and those same bound sockets move into Quinn. Quinn must then
   complete TLS 1.3 mutual authentication and expose the expected peer chains;
   nomination alone grants no session or input authority.
6. Negative gates cover wrong credentials, fingerprint mutation, mixed/
   duplicate/unbounded candidates, role conflict, establishment expiry, and
   liveness loss. The real loopback gate checks nominated addresses, retained
   socket ports, Quinn peer addresses, and both certificate chains.

## Consequences

- LatencyDesk now has a standards-based connectivity-check and same-socket
  ICE→QUIC handoff seam without inventing an ICE state machine or concurrent
  socket demultiplexer.
- The current application does not exchange ICE credentials, run rendezvous,
  promote nominated routes, enumerate interfaces, emulate NAT, or allocate
  TURN relays. The result is in-process loopback evidence, not automatic
  Internet traversal or AnyDesk/RustDesk parity.
- A later product integration must bind credentials/candidates to the existing
  exact-mTLS session, test real NAT/CGNAT/IPv6 matrices, define consent and
  route rollback, and preserve the old path until new Quinn mTLS succeeds.

## Sources

- RFC 8445, ICE: https://www.rfc-editor.org/rfc/rfc8445.html
- RFC 8489, STUN: https://www.rfc-editor.org/rfc/rfc8489.html
- `is` 0.11.0 API: https://docs.rs/is/0.11.0/is/
- str0m repository: https://github.com/algesten/str0m
