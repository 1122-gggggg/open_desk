# Protocol Design v0

This document specifies invariants required before a concrete QUIC library is selected. Wire compatibility is not stable before v1.

## 1. Session phases

```text
Idle → Connecting → Authenticating → Negotiating → Streaming
                                                ↘ Recovering ↗
Any active state → Closing → Closed
Any nonterminal state → Failed
```

Media and input remain disabled until peer authentication, local authorization, and capability negotiation all succeed.

## 2. Transport mapping

LatencyDesk plans one TLS-authenticated QUIC connection:

- bidirectional reliable control stream;
- QUIC DATAGRAM media path;
- QUIC DATAGRAM input path plus periodic state reconciliation;
- optional reliable metrics stream;
- later clipboard/file streams, each separately authorized.

Every message type has an explicit maximum length. Reliable stream messages use length-prefixed frames with a negotiated cap; they never deserialize an unbounded nested object.

Every active connection carries a nonzero session ID plus generation,
authorization, display, and codec epochs. A successor connection uses a fresh
random session ID and strictly greater generation, authorization, display, and
codec epochs. The Client rejects a replacement handshake that reuses the
session ID or fails to advance any epoch; old
disconnect, input, control, and media records therefore cannot target the
successor even if delayed work survives transport teardown.

An established path is eligible for automatic replacement only when Quinn
reports peer reset or idle timeout. The replacement repeats TLS 1.3,
exact-certificate verification, and the product handshake; it never resumes old
streams or 0-RTT input. Certificate mismatch, malformed protocol data,
non-monotonic lifecycle values, explicit application close, and local/provider
failure are terminal. A retired input epoch remains rejected after ReleaseAll.

Input records reserve one versioned `ACK_REQUESTED` flag. When set, a Linux
Host replies on the authenticated control lane only after reconciliation and
all platform injection calls plus the probe's platform synchronization return.
`InputAppliedAck` binds the full session
stamp, input epoch, original sequence, and a per-session ACK sequence; it carries
no key/button content. ACKs are measurement reports only and never authorize or
replay input. Unknown input flags, ACK versions/statuses, reserved bits, stale
stamps, and unexpected sequences fail closed. A platform injection or X11
synchronization failure is reported as `ApplyFailed` before the Host terminates
that input lane; only `Applied` ACKs may contribute latency samples.

The Client offers `INPUT_APPLIED_ACK` with its receiver capabilities. The Host
advertises it in the selected stream configuration only when both the offer and
its platform path implement that ordering. Probe Clients reject a missing bit
immediately after stream negotiation, before sending input; unknown capability
or stream flags are protocol errors. Linux X11 currently intersects the bit and
Windows Host does not.

An optional pre-QUIC RFC 8489 Binding transaction may discover one
server-reflexive address. It uses a CSPRNG 96-bit transaction ID, exact response
source/transaction matching, bounded retransmission/deadline/ignored-datagram
counts, XOR-MAPPED-ADDRESS, and a required final FINGERPRINT. Malformed, stale,
spoofed, or unusable responses are discarded within those bounds. The exact UDP
socket is then transferred to Quinn without rebinding. The address is untrusted
telemetry only: it is not a candidate route, identity, authorization, ICE
nomination, or consent result, and exact-certificate mTLS remains mandatory.

After exact-mTLS and the session-stamped product handshake, a Client may offer
`AUTHENTICATED_CANDIDATE_EXCHANGE`. A supporting Host selects the matching
stream flag before either side sends `ControlKind::IceCandidate`. The v1 body
contains an explicit version, an exchange ID equal to the active random session
ID, a consecutive generation beginning at 1, and 1–8 length-delimited
candidate descriptors. It accepts one IP family and UDP host/server-reflexive
candidates plus UDP TURN-relayed metadata. A relayed entry requires the exact
`Relayed`/`Turn` type/provider pair, RFC 8445 relay type preference, and a
component-consistent priority byte. Zero/unusable addresses, TCP, DERP,
peer-reflexive signaling, provider/type drift, mixed families, conservative
endpoint duplicates, truncation, trailing bytes, replay, gaps, and ID changes
fail closed. Candidate records remain untrusted even though their transport is
authenticated: v1 records are observable advertisements only and cannot prove
an allocation or alter the existing QUIC route, certificate identity,
authorization, or reconnect policy. Connectivity checks, pair nomination,
consent freshness, rendezvous matching, and automatic relay selection are not
implemented by this message.

The transport layer has a separate bounded Sans-I/O RFC 8445 adapter. It uses
OS-CSPRNG short-term credentials and role tie-breakers, standard STUN
`MESSAGE-INTEGRITY` HMAC-SHA1 (not SHA-1 password hashing), a unique final
FINGERPRINT, one address family, at most eight local and eight remote candidates
and 64 pairs, and bounded Ta/RTO/retransmits/establishment time. Wrong
credentials, corrupted fingerprints, unexpected destination sockets, and
post-deadline packets are rejected. ICE and Quinn own a UDP socket sequentially,
never concurrently: after nomination, raw ICE reads stop and the exact socket is
handed to Quinn for a new TLS 1.3 exact-peer connection. The upstream ICE
transaction ID is only a correlation value; authentication depends on the
CSPRNG password and HMAC. This adapter is currently an in-process loopback gate,
not an application signaling, route-selection, NAT traversal, or relay path.

After exact-mTLS and capability negotiation, the typed ICE signaling API may
exchange bounded short-term credentials followed immediately by candidates.
Both the validated offer and selected stream configuration must carry the
authenticated-credential capability before use. Roles are then fixed per
session: Client is controlling and Host is controlled.
Each exchange is bound to the active session and a strictly consecutive
generation. Generic ICE control sends and receives are rejected, and a session
cannot mix credential generations with advertisement-only signaling. Cancelling
a typed send poisons the signaling mode and closes the connection; cancelling a
receive closes it while retaining the pending generation so it cannot be
reinterpreted as a legacy advertisement. Credential values are debug-redacted;
credential objects and encoded temporaries owned by the
signaling wrapper are zeroized. Borrowed transport buffers and the upstream ICE
core's internal credential copy are not guaranteed to be zeroized and must
never be logged or retained. This slice does not prove connectivity checks,
nomination, consent freshness, path selection/promotion, rollback, rendezvous,
NAT/CGNAT, TURN/relay, Internet reachability, or AnyDesk superiority.

An explicit `ICE_CONNECTIVITY_PROBE` capability is valid only with authenticated
ICE credentials. The opt-in probe uses exactly one fresh IPv4 Host candidate
per peer: the authenticated peer IP and a different UDP port. Fixed
roles/generation and a two-phase `Nominated` → `HandoffReady`
barrier while the raw runner remains alive. Bounded traffic, deadline, drain,
cancellation, and join handling then hands the same socket/port to an isolated
second Quinn endpoint. Exact-leaf mTLS binds its transcript to the full
`SessionStamp`, generation, both control nonces, and a fresh 32-byte challenge.
The probe has no `ProductSession` or desktop authority; the original frame and
`ReleaseAll` route remains unchanged. This is single-machine IPv4 loopback
evidence only, not STUN on the probe path, route promotion/rollback, consent,
rendezvous, NAT/CGNAT/IPv6, TURN/relay, Internet reachability, latency, or
AnyDesk superiority. Borrowed buffers and upstream ICE internal credential
copies are not guaranteed zeroized.

An authenticated rendezvous registration is a maximum 4 KiB exact-length
record: version, initiator/responder role, reserved bytes, generation, 5–120
second TTL, 128-bit match ID, expected peer certificate fingerprint, bounded
credential/candidate lengths, then one `IceCredentialExchange` and one
`CandidateExchange`. Credential and candidate exchange IDs/generations must
agree, and the role fixes controlling/controlled ICE semantics. The rendezvous
transport must supply the actual `DeviceId` from its mTLS client certificate;
there is deliberately no self-identity claim in the payload.

`CandidateExchange` may carry same-family UDP Host, server-reflexive, and
TURN-relayed metadata. Relayed entries require the exact `Relayed`/`Turn`
type/provider pair and an RFC 8445 relay type-preference byte of zero. TCP,
DERP, provider/type mismatch, mixed address families, and duplicate endpoints
fail closed. A relayed entry is not proof of a live allocation and cannot
authorize or select a product route.

The bounded broker matches only reciprocal exact fingerprints and complementary
roles. Registrations are one-shot, replay/generation/role drift does not consume
the valid waiter, expired entries are tombstoned, and pending/delivery state is
bounded. The broker returns connectivity metadata only and never selects a
route or handles desktop content. No public rendezvous deployment, NAT matrix,
public relay operation, or Internet-connectivity claim exists yet.

The local evidence daemon transports a registration inside one canonical
session-stamped control stream after TLS 1.3 client-certificate authentication.
The server allowlist contains 1–16 unique exact leaves; every accepted leaf is
checked byte-for-byte again after the handshake. A response is either bounded
`Waiting` metadata or one peer registration. Each connection submits one
request, delivery is one-shot, and the daemon exposes no product/input/media
lane. The current CLI evidence profile intentionally allows exactly two clients
and one match before exit. Owned outbound secret buffers are zeroized; inbound
Quinn `Bytes` and decoder copies are only debug-redacted and are not guaranteed
to be zeroized.

## 3. Capability negotiation

### Local UDP TURN evidence profile

The local TURN process uses RFC 8489 STUN framing for RFC 8656 Allocate,
Refresh, CreatePermission, ChannelBind, Send/Data, and ChannelData. It uses an
out-of-band agreed SHA-256 long-term password algorithm and a full 32-byte
`MESSAGE-INTEGRITY-SHA256`. Allocation state is bound to the UDP 5-tuple and
stored integrity key; mutation APIs accept only a sealed request produced by
state-owned verification. Permissions match peer IP only. Channel bindings
match exact peer transport addresses and use `0x4000..=0x4fff`.

This profile does not implement password-algorithm negotiation, FINGERPRINT,
legacy SHA-1/MD5, TCP/TLS/DTLS client transports, RFC 6062 TCP allocations, or
IPv4/IPv6 translation. TURN success allocates a candidate; it does not itself
authorize route promotion, desktop, media, or input.

Each peer advertises:

- protocol version range;
- host/client role support;
- capture source types and display descriptors;
- input modes;
- codecs/profiles/levels/pixel formats;
- encoder/decoder memory domains;
- resolution/frame-rate limits;
- cursor embedded/metadata modes;
- tile refinement version, initially absent;
- maximum datagram payload;
- optional feature permissions.

The selected configuration receives a monotonically increasing `codec_epoch`. A change in codec, dimensions, pixel format, color metadata, or decoder configuration increments the epoch and requires a recovery point.

## 4. Media fragment header

The M0 parser implements a fixed 44-byte network-order header:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 4 | magic `LDSK` |
| 4 | 1 | wire version |
| 5 | 1 | media kind |
| 6 | 2 | flags |
| 8 | 4 | stream_id |
| 12 | 4 | codec_epoch |
| 16 | 8 | frame_id |
| 24 | 8 | dependency_frame_id |
| 32 | 4 | total frame_len |
| 36 | 4 | fragment_offset |
| 40 | 2 | fragment_len |
| 42 | 2 | reserved, zero |

Version-1 limits include a 16 MiB maximum encoded access unit and a protocol-level fragment cap. The actual negotiated datagram payload must be path-MTU-safe and normally much smaller.

Before allocation, a receiver validates:

- magic/version/media kind/known flags;
- nonzero bounded frame and fragment length;
- checked `fragment_offset + fragment_len` within frame length;
- zero reserved bits;
- valid codec epoch/stream;
- keyframe/recovery point has no inter-frame dependency;
- session-wide incomplete-frame/byte/time limits.

Overlapping fragments are rejected unless byte-identical behavior is explicitly specified and tested. Incomplete frames expire before their presentation deadline.

## 5. Decoder continuity

`dependency_frame_id` is a conservative application-level dependency supplied by the provider. The first implementation constrains encoders to a low-delay structure that the provider can model safely. If exact references are unavailable, a non-recovery access unit is treated as depending on the immediately preceding accepted access unit.

Receiver algorithm:

1. Independently decodable recovery point: reset decoder/configuration for `codec_epoch`, accept frame, clear recovery request.
2. Non-recovery frame: accept only when epoch matches and its conservative dependency is present.
3. Missing dependency, corrupt frame, or decoder error: discard dependent data, enter `Recovering`, send a coalesced/rate-limited recovery request.
4. Resume normal decode only after a validated recovery point.

The sender must also detect queue drops. If it drops an encoded access unit that later output references, it requests/reconfigures the provider so the next transmitted output is a recovery point. Merely dropping stale P-frames is invalid.

## 6. Input messages

Immediate input datagrams carry:

- session/input epoch;
- device identifier;
- monotonically increasing sequence;
- event type;
- physical key usage or pointer/button/wheel data;
- coordinate space and display id;
- sender-local event timestamp.

Periodic snapshots carry the full pressed-key and button state plus absolute pointer state where supported. A receiver:

- ignores duplicates/old epochs;
- applies immediate events;
- reconciles with newer snapshots;
- releases all state on focus loss, permission revocation, transport close, or epoch change.

IME/text composition is a separate negotiated semantic channel; it is not reconstructed solely from physical key events.

## 7. Scheduling and deadlines

Initial class order:

```text
input
control
recovery video
realtime video
audio (future)
static refinement
```

Each class has item and byte budgets. Input may preempt stale/lower-priority media, but control messages use their own reserved budget so a media flood cannot block shutdown or reconfiguration. Equal-priority replacement follows an explicit class policy rather than generic silent eviction.

Media usefulness deadlines are local scheduling concepts. They are not transmitted as absolute timestamps across unsynchronized machines. The receiver computes deadlines from arrival time, frame cadence, negotiated latency target, and optional clock estimate with uncertainty.

## 8. Congestion and pacing

QUIC DATAGRAM delivery remains congestion-controlled by the QUIC stack. LatencyDesk additionally:

- avoids an application queue above the congestion window;
- paces fragments/access units;
- adapts bitrate, frame rate, and resolution;
- reports queue depth and drop reason;
- never retries obsolete media on a reliable stream;
- coalesces recovery requests;
- defers FEC until measured benefit.

## 9. Sparse exact tile extension

The future tile stream is subordinate to the video base. A tile update includes:

- display/config epoch;
- tile-grid version and coordinates;
- tile generation;
- base frame relation or “current epoch” semantics;
- exact decoded size and hash;
- compression method and bounded compressed length.

Tiles are lossless, independently discardable refinements. Loss cannot break video decoder continuity. Resize/config changes invalidate the entire tile cache. Refinement packets are lowest priority and suppressed under motion/congestion.

## 10. Clock domains

Host timestamps and client timestamps come from different monotonic clocks. The protocol may exchange clock samples and uncertainty, but raw values are never subtracted as ground truth. Stage latency stays local; published E2E latency is optical.

## 11. Security invariants

- transport uses standard QUIC/TLS, not custom encryption;
- peer identity and local user consent precede media/input;
- session/codec/input epochs prevent stale cross-session application;
- limits are checked before allocation/decompression;
- decompressed dimensions and tile output size are bounded;
- control messages are authenticated by the connection and authorized by capability;
- relay forwarding does not terminate content encryption.
