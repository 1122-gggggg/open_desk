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
ChannelData. Control requests retransmit a bit-identical transaction under a
fixed deadline. A supervisor refreshes the allocation before expiry and also
renews the shorter permission plus channel authority. Cancellation during
establishment aborts the reader and releases its socket; expiry, read failure,
or renewal failure revokes I/O. Explicit shutdown sends Refresh(0), surfaces a
failure, and always revokes locally. Drop performs only local revoke/abort.

The abstract socket accepts only the configured peer and channel, rejects GSO
and source-IP override, caps payload to the TURN wire budget, and reports the
relayed address to Quinn. It conservatively reports possible fragmentation so
Quinn does not run unsupported outer-path MTU discovery. Like Quinn's fallback
UDP adapter, requested ECN metadata is not preserved by this ChannelData path;
QUIC detects the absence of ECN feedback and disables it.

## Evidence and limits

Unit tests cover transcript integrity, relayed/lifetime validation, bounded
retransmission, wrong source/channel, payload and transmit metadata, renewal,
Refresh(0), revoke, and establishment cancellation. The process gate starts a
real TURN daemon plus native Host/Client probes and carries exact-mTLS
ProductSession control, input, and media through the forced allocation. The
Host-observed source must equal the relayed tuple, traffic counters must be
bidirectional, and the allocation must be deallocated.

This is IPv4 loopback evidence with a preconfigured SHA-256 credential. It does
not prove public interoperability, TURN over TLS/DTLS, RFC 6062, NAT64,
physical CGNAT, regional operation, automatic promotion/rollback, latency
improvement, or AnyDesk superiority.
