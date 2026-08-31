# ADR 0026: Authenticated TURN allocation as a Quinn product route

## Status

Accepted for the bounded local UDP TURN product probe. Public TURN deployment
and automatic Host/Client route selection remain pending.

## Decision

`AuthenticatedTurnRoute` is a deep module with one construction path. It must
complete and verify the source-bound 401 challenge, SHA-256 long-term message
integrity, Allocate success and relayed address/lifetime, CreatePermission, and
ChannelBind before it can implement Quinn's abstract UDP socket interface.

One task owns all reads and demultiplexes transaction responses from bounded
ChannelData. The unsigned exception is limited to the initial Allocate/401
bootstrap. Every authenticated response is checked with the request's retained
SHA-256 integrity key before the pending transaction is removed. A signed 438
must authenticate with the old key and may atomically rotate realm, nonce, and
key once for Allocate, CreatePermission, ChannelBind, or Refresh; 401 or a
second 438 ends the operation. A server-side stale challenge is idempotent: it
returns the allocation's current nonce without advancing allocation state, even
when the stale request is replayed under a new transaction ID. The relay state
encodes this signed response through a sealed, Debug-redacted object and never
exposes the integrity key to the runtime. Control requests retransmit a
bit-identical transaction with a 500-ms exponential RTO capped at 4 seconds,
at most seven attempts, and one fixed deadline. Pending transactions and ChannelData are
bounded by item count and bytes. A supervisor refreshes the allocation before
expiry and also renews the shorter permission plus channel authority.
Cancellation during establishment aborts the reader and releases its socket;
expiry, read failure, or renewal failure revokes I/O. Explicit shutdown sends
Refresh(0), surfaces a failure, and always revokes locally. Drop performs only
local revoke/abort.

The abstract socket accepts only the configured peer and channel, rejects GSO
and source-IP override, caps payload to the TURN wire budget, and reports the
relayed address to Quinn. It conservatively reports possible fragmentation so
Quinn does not run unsupported outer-path MTU discovery. Like Quinn's fallback
UDP adapter, requested ECN metadata is not preserved by this ChannelData path;
QUIC detects the absence of ECN feedback and disables it.

## Evidence and limits

Unit tests cover transcript integrity, authenticated stale-nonce rotation,
bad-integrity response rejection without transaction consumption,
relayed/lifetime validation, bounded retransmission, wrong source/channel,
payload and transmit metadata, renewal, Refresh(0), revoke, and establishment
cancellation. The process gate starts a real TURN daemon plus native Host/Client
probes and carries exact-mTLS
ProductSession control, input, and media through the forced allocation. The
Host-observed source must equal the relayed tuple, traffic counters must be
bidirectional, and the allocation must be deallocated.

This is IPv4 loopback evidence with a preconfigured SHA-256 credential. It does
not prove public interoperability, TURN over TLS/DTLS, RFC 6062, NAT64,
physical CGNAT, regional operation, automatic promotion/rollback, latency
improvement, or AnyDesk superiority.
