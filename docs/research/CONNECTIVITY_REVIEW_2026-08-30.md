# Connectivity review — direct-first, relay fallback, and reconnect

## Scope and evidence limits

This review covers session establishment and recovery, not an end-to-end proof that open_desk is faster than AnyDesk. Standards define interoperability and safety properties; they do not establish a product's optical input-to-photon latency. Any performance claim requires a matched, reproducible lab.

## Findings

### Direct-first establishment

Use an authenticated rendezvous service only to exchange opaque session identifiers, candidate batches, and short-lived credentials. Each peer gathers host and server-reflexive candidates, then performs ICE connectivity checks; ICE defines candidate pairs and nominated paths, and requires consent/failure handling rather than trusting an advertised address ([RFC 8445](https://www.rfc-editor.org/rfc/rfc8445.html)). Prefer the lowest-cost validated direct pair, with IPv6 and same-LAN candidates first, but race families within a bounded budget (for example 250 ms) so a broken IPv6 route does not stall IPv4.

RustDesk's upstream rendezvous code is useful behavioral evidence: it tests NAT type, attempts local/direct paths, and forces relay for symmetric NAT or policy ([rendezvous mediator](https://github.com/rustdesk/rustdesk/blob/master/src/rendezvous_mediator.rs), [server](https://github.com/rustdesk/rustdesk-server/blob/master/src/rendezvous_server.rs)). Its AGPL-3.0 licensing means open_desk must not copy implementation, constants, or code; implement from the RFCs and independently observed behavior ([RustDesk license](https://github.com/rustdesk/rustdesk/blob/master/LICENCE)).

### STUN, TURN, and regional relays

STUN is for discovering a server-reflexive mapping and checking reachability; it is not a general relay. TURN allocates a relay and forwards traffic when endpoint-dependent mappings or firewall policy defeat direct connectivity ([RFC 8489](https://www.rfc-editor.org/rfc/rfc8489.html), [RFC 8656](https://www.rfc-editor.org/rfc/rfc8656.html)). For UDP-blocked networks, provide TURN over TCP and TLS; the WebRTC transport requirements explicitly call out these fallbacks and require TURN for difficult NATs ([RFC 8835](https://www.rfc-editor.org/rfc/rfc8835.html)). Selkies documents the operational consequence: a remote peer cannot use private host candidates behind static NAT, and a single distant TURN location adds latency and stutter ([Selkies firewall guidance](https://github.com/selkies-project/selkies/blob/main/docs/firewall.md)).

Deploy relays regionally and choose by measured RTT, not geography alone. A relay must be selected only after a direct check fails or policy requires it; expose the selected route and relay region in telemetry. Relay credentials should be short-lived, scoped to one session, bandwidth-limited, and rejected after expiry. Never make a public unauthenticated TURN allocation endpoint.

### QUIC path constraints and migration

QUIC connection IDs allow an established connection to survive a NAT rebinding or address change, subject to path validation; QUIC does not perform initial ICE candidate discovery or provide a TURN service ([RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html)). Therefore, use ICE/rendezvous to choose the initial UDP path, then run QUIC on the nominated 5-tuple. On migration, validate the new path before sending sensitive traffic and keep the old path until validation succeeds. A relay fallback may be a new QUIC connection, not an implicit path swap.

Keep control on a reliable stream and media/input on bounded DATAGRAM lanes. QUIC DATAGRAM is congestion-controlled, non-retransmitted, and not fragmented by QUIC ([RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html)); payload sizing must be path-safe and expired media must be dropped by the application. Quinn exposes stream priority, but scheduler behavior remains implementation-specific ([Quinn 0.11.8 `SendStream::set_priority`](https://docs.rs/quinn/0.11.8/quinn/struct.SendStream.html#method.set_priority)).

### Reconnect and session epoch safety

Model every connection attempt with a monotonically increasing `session_epoch` and random session nonce. All control, input, and media messages carry the epoch; receivers reject old epochs before dispatch. On disconnect: stop input immediately, release local keys/buttons, cancel old streams, and retain only idempotent desired state. Reconnect must re-authenticate and re-pin the peer identity; do not accept 0-RTT for input or other non-idempotent actions because QUIC 0-RTT application data can be replayed ([RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html)).

Use bounded exponential backoff with jitter, a total attempt deadline, and a route sequence: validated direct candidates → regional TURN/QUIC relay → TCP/TLS relay where policy permits. A reconnect must not create an unbounded second session: the server atomically accepts the greatest epoch/nonce and closes the predecessor. On successful path migration, preserve authorization state only after the authenticated channel confirms the same peer identity.

## Recommended incremental architecture

1. Add a small rendezvous protocol: signed device identity, candidate batches, ICE credentials, relay list, and policy flags. Rendezvous never carries desktop data.
2. Implement an ICE-lite-compatible candidate/check engine around standards-compliant STUN; require explicit nomination, consent freshness, and candidate-pair telemetry.
3. Put the existing QUIC session behind a `PathProvider` interface. Direct and TURN/UDP paths use the same authenticated framing; relay selection is an explicit provider, not a hidden proxy.
4. Add TURN/TCP and TURN/TLS fallback as a separate provider, with a stricter latency label and per-session byte/time caps.
5. Add epoch-scoped reconnect state and fault-injection tests before enabling automatic reconnect for unattended access.
6. Operate at least three relay regions, health-check them, and select using recent RTT/loss EWMA with a hard maximum relay distance/RTT policy.

## Threat and resource bounds

- Authenticate rendezvous and relay control; bind allocations to device identity, session nonce, expiry, and maximum bitrate.
- Rate-limit candidate checks and allocations per device/IP; cap candidate count, STUN response size, relay lifetime, concurrent sessions, and aggregate relay bandwidth.
- Reject stale epochs, duplicate nonces, malformed length/fragment fields, and unauthenticated path changes before allocation or input dispatch.
- Protect against relay amplification: require authenticated allocation before forwarding, enforce ingress/egress quotas, and never reflect arbitrary UDP.
- Log route type, region, epoch transitions, and failure class without logging screen contents, keys, or raw input.

## Rejected alternatives

- **Raw UDP hole punching without ICE/STUN:** cannot provide standardized candidate checks or a reliable answer for symmetric NAT and UDP-blocked enterprise paths ([RFC 8445](https://www.rfc-editor.org/rfc/rfc8445.html), [RFC 8656](https://www.rfc-editor.org/rfc/rfc8656.html)).
- **Always relay:** predictable compatibility but adds distance, cost, and latency; Selkies explicitly warns that a single distant relay can stutter ([Selkies firewall guidance](https://github.com/selkies-project/selkies/blob/main/docs/firewall.md)).
- **QUIC migration as initial traversal:** migration handles an existing connection's path change; it is not rendezvous, ICE, or TURN ([RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html)).
- **Unscoped automatic reconnect:** risks stale input and duplicate sessions; epoch/nonce fencing is mandatory.
- **Copying RustDesk or Selkies code:** RustDesk is AGPL-3.0 and Selkies is MPL-2.0 ([RustDesk license](https://github.com/rustdesk/rustdesk/blob/master/LICENCE), [Selkies license](https://github.com/selkies-project/selkies/blob/main/LICENSE)); use them as behavioral references only and preserve open_desk's licensing policy.

## Test gates

Do not call the connectivity slice complete until all gates pass:

- Direct LAN, IPv4/IPv6, full-cone/restricted/symmetric NAT, UDP-blocked, TURN/UDP, TURN/TCP, and TURN/TLS paths establish with a recorded nominated pair.
- At least 99.9% connection success over a fixed matrix of repeated trials; direct paths win whenever they are valid and policy allows.
- Forced address/port rebinding and Wi-Fi↔LTE transitions either preserve QUIC or reconnect within 2 seconds, with zero stale input after epoch change.
- Inject loss, duplication, delay, and reordering during reconnect; assert no old-epoch control/input/media is applied and no stuck key/button remains.
- Relay routing chooses the lowest measured RTT region within policy; compare direct versus relay P50/P95/P99 latency, loss, bytes, and queue residence.
- Fuzz STUN/TURN signaling, candidate parsing, epoch fields, and relay framing; enforce allocation, memory, stream, and bitrate caps under load.
- Run multi-session stress (at least 16 concurrent sessions) and verify one congested relay/session cannot starve another session's input or control.

These gates establish a credible connectivity foundation for competing on latency; only an optical benchmark against AnyDesk under identical hardware, codec, display, and network conditions can establish “surpasses AnyDesk.”

## Sources

- [RFC 8445 — ICE](https://www.rfc-editor.org/rfc/rfc8445.html)
- [RFC 8489 — STUN](https://www.rfc-editor.org/rfc/rfc8489.html)
- [RFC 8656 — TURN](https://www.rfc-editor.org/rfc/rfc8656.html)
- [RFC 8835 — WebRTC transports](https://www.rfc-editor.org/rfc/rfc8835.html)
- [RFC 9000 — QUIC transport](https://www.rfc-editor.org/rfc/rfc9000.html)
- [RFC 9001 — QUIC TLS](https://www.rfc-editor.org/rfc/rfc9001.html)
- [RFC 9221 — QUIC DATAGRAM](https://www.rfc-editor.org/rfc/rfc9221.html)
- [Quinn 0.11.8 SendStream priority](https://docs.rs/quinn/0.11.8/quinn/struct.SendStream.html#method.set_priority)
- [RustDesk rendezvous mediator](https://github.com/rustdesk/rustdesk/blob/master/src/rendezvous_mediator.rs)
- [RustDesk server rendezvous](https://github.com/rustdesk/rustdesk-server/blob/master/src/rendezvous_server.rs)
- [Selkies firewall guidance](https://github.com/selkies-project/selkies/blob/main/docs/firewall.md)
