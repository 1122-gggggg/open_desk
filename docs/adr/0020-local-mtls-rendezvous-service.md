# ADR 0020: Local exact-mTLS rendezvous service before public operation

**Status:** Accepted

## Decision

Exercise the bounded rendezvous broker through a real TLS 1.3 QUIC process
before attempting a public deployment. The evidence daemon requires an explicit
unicast listener, its own persistent identity, exactly two allowed client
certificate files, a total deadline, and a two-successful-registration match
profile. Rejected attempts are separately capped and do not consume a valid
registration slot.
Rustls authenticates against the bounded roots; the wrapper then byte-checks the
accepted leaf against the exact allowlist and derives `DeviceId` from its
fingerprint.

Each authenticated connection opens one session-stamped control lane and sends
one maximum-4-KiB registration. `Waiting` and one-shot peer-delivery responses
share the server's single persistent control lane. Stranger certificates,
malformed frames, role/generation mismatch, and replay do not terminate the
listener before its fixed rejection cap or consume a valid waiter.
Secret-bearing outbound `Vec` temporaries are zeroized where owned. Inbound
Quinn `Bytes` and decoder-internal copies cannot be guaranteed zeroized; their
`Debug` representation is redacted and they must never be logged or retained.

The two delivery sends are sequential, not an atomic distributed commit. The
server reports success only after both sends succeed; a send failure closes the
connections and produces no success evidence, but one peer may already have
received its one-shot offer. Transactional retry requires a later broker/wire
protocol revision.

## Consequences

- The repository now has a real local rendezvous process and client, not merely
  an in-memory broker.
- The process cannot carry desktop, input, media, or relay payloads and has no
  route authority.
- Dynamic device enrollment, public DNS/TLS operations, account recovery,
  horizontal state, DDoS controls, NAT/CGNAT/IPv6 evidence, TURN/relay, and
  Internet availability remain separate gates.

## Sources

- Rustls 0.23 `WebPkiClientVerifier` builder:
  https://docs.rs/rustls/0.23.43/rustls/server/struct.WebPkiClientVerifier.html#method.builder_with_provider
- QUIC TLS security: https://www.rfc-editor.org/rfc/rfc9001.html
