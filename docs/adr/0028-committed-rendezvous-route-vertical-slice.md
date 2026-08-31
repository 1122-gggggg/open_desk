# ADR 0028: Committed rendezvous as a two-route admission capability

## Status

Accepted for the bounded same-machine process gate. Normal desktop
orchestration, ICE/TURN selection, and public deployment remain pending.

## Context

The rendezvous daemon, two-path `ProductRouteSet`, and TLS-exporter route
binding were independently real, but a caller could still run the route harness
with CLI destination addresses. Independent evidence did not prove that a
committed reciprocal registration was the source of the two product paths.

## Decision

`latencydesk-route-probe` has an optional integrated mode with these invariants:

1. Both roles bind two product UDP endpoints before registration. Binding grants
   no route authority.
2. Client and Server connect separately to the exact-pinned mTLS rendezvous
   daemon and advertise the two PID-owned endpoints as ordered UDP Host
   candidates.
3. Product connection work cannot start until `exchange_registration` returns
   the non-constructible `CommittedRendezvousDelivery` after Complete.
4. The integrated Client rejects `--host` and `--host2`. Its two product
   destinations come only from the committed Responder registration.
5. Both tokens must agree on exact local/peer device IDs, complementary roles,
   match ID, generation, exchange ID, and exactly two distinct loopback Host
   candidates.
6. After exact-mTLS product connection, Client-observed destinations must equal
   the indexed committed Responder candidates and Server-observed source tuples
   must equal the indexed committed Initiator candidates.
7. Route digest input is canonical and symmetric. Both roles hash, in order:
   the domain tag, path index, length-prefixed Initiator registration,
   length-prefixed Responder registration, ordered exact device IDs, every
   big-endian `SessionStamp` field, and the length-prefixed indexed Responder
   candidate. String socket formatting is forbidden.
8. The two peers must derive the same nonzero and distinct digest for each
   path. `ProductSession` then binds it to the actual connection using the
   fixed-label TLS exporter. Existing Prepare/Prepared/Commit,
   Activated/Confirmed, active failure, and retained rollback rules are
   unchanged.

The committed token is retained for the integrated route lifetime. It is
same-process Rust type-state, not serializable durable attestation or a
third-party proof.

## Evidence and limits

`scripts/rendezvous_route_process_test.py` launches a real rendezvous daemon,
route Server, and route Client with fresh exact DER identities. The Client
command contains no product destination. The gate requires exact versions and
binary/log hashes, DER-pair validation, daemon ownership, every marker-declared
route-process UDP socket, committed candidate/source equality, and identical
committed match/generation/exchange and route digests,
two exact-mTLS ProductSessions, epoch 2 promotion, injected active-path failure,
epoch 3 rollback, and exact control/input/media exchange. CI retains the JSON
artifact. The legacy non-rendezvous route gate remains as a regression test.

This is local IPv4 loopback Host-candidate evidence. It does not prove normal
Host/Client integration, ICE checks or consent, TURN selection, NAT/CGNAT,
public rendezvous operation, Internet availability, physical latency, or
competitor superiority.
