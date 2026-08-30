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

## 3. Capability negotiation

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
