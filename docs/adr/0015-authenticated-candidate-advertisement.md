# ADR 0015: Authenticated candidate advertisement before ICE

**Status:** Accepted

**Date:** 2026-08-31

## Context

ADR 0014 established same-socket server-reflexive discovery, but its result was
local diagnostic metadata. RFC 8445 requires peers to exchange bounded
candidate information before forming pairs, while also making clear that an
advertised address is not a successful connectivity check or a nominated path.
Accepting candidate bytes before peer authentication, mixing them across
successor sessions, or applying them directly to routing would weaken the
existing exact-certificate boundary and create false Internet-connectivity
evidence.

## Decision

1. Candidate advertisement is an explicitly negotiated capability on the
   existing reliable control lane. Neither peer sends a candidate body before
   TLS 1.3 exact-leaf mTLS and the session-stamped product handshake complete.
2. `CandidateExchange` v1 has an exact wire version, exchange ID, generation,
   count, and length-delimited candidates. It accepts 1–8 candidates, one IP
   family, and UDP host/server-reflexive types only. TCP and relayed types wait
   for separately defined transport and allocation semantics.
3. The exchange ID must equal the active random product session ID. Generation
   starts at 1 and advances by exactly one on the reliable ordered lane.
   Pre-handshake, malformed, wrong-kind, cross-session, replayed, stale,
   skipped-generation, changed-ID, mixed-family, duplicate, unusable-address,
   and oversized inputs fail closed for that connection.
4. Duplicate detection uses the conservative component/transport/address/port
   endpoint key. This is intentionally stricter than complete RFC 8445
   redundancy because the current descriptor does not model a separate base.
5. A same-socket host mapping and an identical server-reflexive mapping collapse
   to one host candidate. Distinct same-family mappings retain their related
   base address.
6. Received candidates are diagnostic connectivity metadata only. V1 performs
   no pair formation, STUN connectivity check, pacing, role selection,
   nomination, consent freshness, route switch, QUIC migration, rendezvous, or
   relay allocation. Certificate pins, authorization, reconnect policy, and the
   already authenticated route remain unchanged.
7. Process evidence must prove STUN/QUIC source equality, exchange ordering
   after exact-mTLS, session-ID binding, generation 1, mirrored nonzero counts,
   an unchanged exact Host route, a real desktop frame, ReleaseAll, clean exits,
   binary hashes, and temporary-credential cleanup.

## Consequences

- LatencyDesk now has a bounded and authenticated signaling seam on which a
  later ICE checklist can be built without trusting STUN or candidate data as
  identity.
- The opt-in probe is intentionally not enabled for multi-target or unspecified
  Client bind addresses; interface enumeration and privacy policy remain
  separate work.
- No claim is made for NAT traversal, Internet connection success, ICE
  completion, TURN/relay, UDP-blocked fallback, cross-machine behavior, or
  AnyDesk/RustDesk parity or superiority.

## Sources

- RFC 8445, ICE candidate gathering and exchange: https://www.rfc-editor.org/rfc/rfc8445.html
- RFC 8489, STUN: https://www.rfc-editor.org/rfc/rfc8489.html
- RFC 8838, Trickle ICE: https://www.rfc-editor.org/rfc/rfc8838.html
- RFC 9000, QUIC: https://www.rfc-editor.org/rfc/rfc9000.html
