# ADR 0022: Bounded RFC 8656 UDP TURN relay before public deployment

**Status:** Accepted for local process evidence

## Decision

Implement a real UDP TURN allocation and relay process as a separate service.
The wire subset uses STUN framing, 96-bit transactions, IPv4/IPv6 XOR
addresses, Allocate, Refresh, CreatePermission, ChannelBind, Send/Data
indications, and ChannelData. The current authenticated profile is explicitly
preconfigured SHA-256 long-term credentials with full 32-byte
`MESSAGE-INTEGRITY-SHA256`; legacy MD5/SHA-1 is not accepted.

Allocation authority is keyed by the UDP client/server 5-tuple. The state
stores the integrity key, and only a wire request verified with that key can
produce a sealed mutation token. State-instance, allocation-incarnation, and
credential-generation fences prevent old tokens from crossing deletion,
recreation, or another state shard. Relayed transport addresses are unique.

The product profile caps allocation lifetime at the RFC default 600 seconds.
Permissions are IP-only and expire after 300 seconds. Channel bindings use the
RFC 8656 range `0x4000..=0x4fff`, expire after 600 seconds, and enforce the
five-minute different-pair rebind quarantine. Global, per-user,
per-allocation, packet, and byte quotas are explicit and checked before state
mutation.

The daemon binds a real UDP socket per allocation. Client Send indications and
ChannelData leave from that relayed address; permitted peer datagrams return as
Data indications or ChannelData. Payload bytes are opaque to the relay and are
never parsed as desktop/input/media. A password is accepted only from an
owner-only file. The local loopback process profile requires an explicit lab
flag; this evidence binary rejects non-loopback control and relay addresses.
That prevents treating a local proof service without public rate limiting and
abuse controls as an Internet-facing TURN deployment.

## Evidence and limitations

The process gate performs a 401 realm/nonce challenge, authenticated Allocate,
CreatePermission, ChannelBind, two exact-byte bidirectional relay exchanges,
and Refresh(0) cleanup using separate server and client processes plus a UDP
echo peer. Negative tests cover wrong integrity, stale nonce, unsupported TCP
allocation (442), unpermitted peers, transaction replay, quota, expiry, and
authorization-token ABA.

This is not a public TURN deployment or a complete interoperability claim.
`PASSWORD-ALGORITHMS` negotiation, nonce-cookie downgrade protection,
OpaqueString normalization, FINGERPRINT after integrity, TURN over TCP/TLS or
DTLS, RFC 6062 TCP allocations, dual-family translation, public DNS/certs,
regional capacity, abuse response, and Internet/NAT-matrix evidence remain
separate gates. Client-to-server TCP/TLS in RFC 8656 would still relay UDP to
the peer; it must not be described as TCP allocation support.

## Sources

- RFC 8656 (TURN): https://datatracker.ietf.org/doc/html/rfc8656
- RFC 8489 (STUN): https://www.rfc-editor.org/rfc/rfc8489.html
- RFC 6062 (TURN TCP allocations): https://www.rfc-editor.org/rfc/rfc6062.html
