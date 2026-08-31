# ADR 0027: ProductSession vertical slice in the isolated NAT matrix

## Status

Accepted for local Linux namespace evidence. Physical router, carrier, and
public Internet qualification remain pending.

## Decision

Keep mapping/filter classification in `nat_netns_matrix.py`, but add a second
gate that reuses the exact same rootless executor and topology setup while
running native `latencydesk-product-probe` processes. The product gate covers
LAN IPv4, endpoint-independent mapping/filtering, double NAT, a
private→`100.64/10`→public CGNAT address path, and native IPv6.

Both probes bind fixed UDP port 38765, complete exact-leaf TLS 1.3 mutual
authentication, and then exchange ProductSession control, input, and media.
Success requires matching random session/challenge evidence, route epoch one,
the exact NAT-visible source tuple, native executable and socket ownership,
process netns equal to its owned node netns, distinct endpoint/executor
namespaces, and nonzero inner/outer counters for two-layer profiles.

Native IPv6 runs a bounded repeated 1,200-byte UDP preflight before QUIC. This
warms routed-neighbor state in the artificial short-lived topology, resembles a
connectivity-check transport effect only, and grants no authorization. The
subsequent exact-mTLS ProductSession exchange remains mandatory.

## Consequences

The repository can now distinguish raw topology behavior from a real product
transport vertical slice. This still does not implement candidate gathering,
rendezvous-driven ICE pair checks, nomination/consent, TURN selection,
promotion/rollback, NAT64, captive portal handling, physical ISP behavior,
Internet availability, or competitor latency superiority.
