# ADR 0024: Route epoch and candidate activation barrier

## Status

Accepted for the bounded two-path product harness. Automatic desktop-route
creation from rendezvous, ICE, or TURN remains pending.

## Decision

Product wire version 2 and ALPN `latencydesk/2` add a nonzero 64-bit
`route_epoch` to the complete `SessionStamp`. It is encoded on reliable stream
records and media datagrams, and therefore also covers product control and
input. Input-applied acknowledgements and the isolated ICE transcript encode
the same epoch explicitly.

`ProductRouteSet` is the sole owner of two parallel product connections in the
route harness. Both must:

- carry the same complete lifecycle stamp;
- authenticate the same exact peer leaf;
- have distinct QUIC stable connection identities; and
- have immutable route/transcript bindings attached to those exact
  connections.

Only one connection has application authority. The second is returned by an
unauthorized candidate constructor and exposes no application send path before
the route set consumes it.

Promotion is:

1. Prepare on the active route.
2. Prepared on the active route.
3. Commit on the active route, advancing the wire fence but not yet granting
   the initiator candidate authority.
4. Activated over the candidate connection.
5. Confirmed over the candidate connection.

The responder and initiator switch at different final handshake steps, but a
fixed timer remains armed until confirmation. A partition at any step closes
and deauthorizes both connections rather than restoring an ambiguous route.
Cancellation guards cover route-set network awaits and revoke both paths if a
future is dropped. Rollback uses the same barrier and increments the epoch
again; it never reuses the old route number.

## Evidence and limits

`latencydesk-route-probe` and `scripts/route_promotion_process_test.py` exercise
two real OS processes, two distinct loopback UDP paths, TLS 1.3 exact-leaf
mTLS, epoch 1→2 promotion, control/input/media transfer, injected active-path
failure, retained-path rollback control, and epoch 2→3 recovery. CI retains the
JSON artifact.

This does not prove that the desktop apps automatically build the pair, that a
TURN allocation survives path loss, that route evidence came from a physical
router or carrier, or that switching improves latency. Those remain separate
release gates.
