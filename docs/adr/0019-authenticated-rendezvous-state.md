# ADR 0019: Authenticated rendezvous state before a public service

**Status:** Accepted

## Decision

Introduce a bounded rendezvous wire/state boundary before opening any network
service. The transport—not the registration payload—must supply `DeviceId` from
the authenticated mTLS client certificate. Registrations contain a 128-bit
opaque match ID, 5–120-second TTL, expected exact peer certificate fingerprint,
complementary initiator/responder role, generation, and bounded ICE
credentials/candidates. Two registrations match only when both authenticated
devices name each other and all generation/exchange constraints agree.

The in-memory broker admits at most 1,024 pending registrations and four per
device. It preserves a valid waiter when a stranger, same-role peer, or wrong
generation arrives; delivery is one-shot, expired/replayed IDs are tombstoned,
and secret-bearing objects/encoded buffers retain their zeroization boundary.

## Consequences

- The rendezvous server will be unable to impersonate a device merely by
  rewriting a payload identity.
- The broker can observe connectivity metadata and short-term ICE material, so
  service logging must remain redacted and storage ephemeral.
- There is still no listening rendezvous application, public authentication
  operation, DNS/discovery, NAT matrix, TURN/relay, route promotion, desktop
  payload path, Internet reachability, or AnyDesk superiority claim.
