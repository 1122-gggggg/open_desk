# ADR 0014: Same-socket STUN discovery foundation

**Status:** Accepted

**Date:** 2026-08-31

## Context

A STUN request made from a disposable side socket discovers the NAT mapping for
the wrong UDP port. Likewise, learning a server-reflexive address is not an ICE
candidate exchange, connectivity check, nomination, consent result, or peer
identity. Treating either shortcut as Internet connectivity would create false
evidence and weaken the existing exact-certificate trust boundary.

## Decision

1. `latencydesk-protocol::stun` implements only bounded RFC 8489 Binding wire
   primitives: the 20-byte header, fixed cookie, 96-bit transaction ID, exact
   datagram length, padded TLVs, XOR-MAPPED-ADDRESS for IPv4/IPv6, and a final
   FINGERPRINT. Unknown comprehension-required, duplicate semantic, malformed,
   trailing, oversized, or invalid messages fail parsing.
2. `latencydesk-socket-transport::stun` obtains transaction IDs only from the OS
   CSPRNG. It requires the configured source address and transaction ID,
   boundedly ignores unrelated, stale, malformed, or unusable datagrams, caps
   ignored traffic, and uses configurable RFC-style exponential retransmission
   under a total deadline.
3. The Client accepts only an explicit `--stun-server <IP:PORT>` literal for one
   secure target. It performs no DNS lookup or redirect and rejects address
   family mismatch, multicast, unspecified address, port zero, unsafe UDP mode,
   and multi-target mode.
4. Discovery occurs on the already-bound Client UDP socket. After response
   processing and a bounded receive-queue drain, ownership of that exact socket
   moves into `quinn::Endpoint::new`; no competing reads continue.
5. STUN output is diagnostic candidate metadata only. It never changes route
   selection, certificate pins, authorization epochs, input permission, or
   reconnect classification. Every connection still performs TLS 1.3
   exact-leaf mTLS and the complete product handshake.
6. Linux process evidence requires four equal addresses: the fake server's
   observed STUN source, Client local address, decoded reflexive address, and
   Host-observed authenticated QUIC source. It separately requires the exact
   Host route, mTLS, lifecycle, real X11 frames, ReleaseAll, binary hashes, and
   temporary-credential cleanup.

## Consequences

- The code now has a real same-port srflx discovery/socket handoff seam on which
  authenticated candidate signaling and ICE checks can be built.
- FINGERPRINT detects framing corruption or protocol confusion; it is a CRC,
  not authentication or integrity against an attacker.
- No claim is made for NAT traversal, connection success rate, public STUN
  service operation, ICE nomination/consent, TURN/relay, UDP-blocked fallback,
  cross-machine behavior, or AnyDesk/RustDesk parity.

## Sources

- RFC 8489, STUN: https://www.rfc-editor.org/rfc/rfc8489.html
- RFC 8445, ICE: https://www.rfc-editor.org/rfc/rfc8445.html
- RFC 9000, QUIC: https://www.rfc-editor.org/rfc/rfc9000.html
