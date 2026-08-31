# ADR 0018: Isolated ICE connectivity probe

**Status:** Accepted
**Date:** 2026-08-31

The `ICE_CONNECTIVITY_PROBE` capability is selectable only with authenticated
ICE credentials. Each peer creates exactly one fresh IPv4 Host candidate using
the authenticated peer IP and a different UDP port; roles and generation are
fixed. A two-phase `Nominated` then `HandoffReady` barrier
keeps raw ICE alive until both sides are ready, then bounded drain/cancellation
hands the exact socket/port to an isolated second Quinn endpoint. Exact-leaf mTLS
binds the transcript to the full `SessionStamp`, generation, both control
nonces, and a fresh 32-byte challenge. The probe has no `ProductSession` or
desktop authority, and the original frame plus `ReleaseAll` route is unchanged.

`scripts/ice_connectivity_probe_test.py` writes
`artifacts/ice-connectivity-probe.json`. Evidence is limited to single-machine
IPv4 loopback. It does not prove STUN on the probe, route promotion/rollback,
consent, rendezvous, NAT/CGNAT/IPv6, TURN/relay, Internet reachability,
latency superiority, or AnyDesk superiority. Borrowed buffers and upstream ICE
internal credential copies are not guaranteed zeroized.
