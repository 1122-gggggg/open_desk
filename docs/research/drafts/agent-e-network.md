# Agent E — Real-time media, input, and control networking

## Scope and evidence limits

This report challenges the current mapping in [`docs/PROTOCOL.md`](../../PROTOCOL.md): one authenticated QUIC connection with a reliable control stream plus QUIC DATAGRAM media and input. It evaluates wire semantics, not capture, encoding, decoding, or rendering latency. Those stages can dominate end-to-end remote-desktop latency, so no transport choice alone proves parity with a commercial product.

The browser-facing [W3C WebRTC Recommendation](https://www.w3.org/TR/webrtc/) is an API specification, not a native-engine performance guarantee. The current upstream [libwebrtc GoogCC implementation](https://webrtc.googlesource.com/src/+/main/modules/congestion_controller/goog_cc/goog_cc_network_control.h?format=TEXT) contains delay-, loss-, probe-, feedback-, and pacing-related components, but that is implementation- and revision-specific rather than a normative WebRTC congestion-control algorithm. Likewise, the 3–5% all-UDP-blocked figure reported by [RFC 9308](https://www.rfc-editor.org/rfc/rfc9308.html) comes from historical measurements; it is evidence that a fallback is required, not a current global availability estimate. No competitor implementation or marketing claim is treated as evidence here.

## Comparison before a decision

| Concern | QUIC Streams + DATAGRAM | Native WebRTC RTP/SRTP + SCTP DataChannel | Custom UDP / RTP-like |
|---|---|---|---|
| Delivery / HOL | A QUIC stream is ordered, but independent streams avoid cross-stream delivery HOL; DATAGRAM is unordered and is not retransmitted. The sender still owns packetization and scheduling. [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html) [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html) | SRTP media is datagram-oriented. SCTP DataChannels can be reliable or partial, ordered or unordered; ordering is only within an ordered SCTP stream. [RFC 8831](https://www.rfc-editor.org/rfc/rfc8831.html) | Exactly the behavior implemented; a reliable subchannel recreates HOL unless it has explicit expiration/cancellation semantics. |
| Pacing / congestion control | DATAGRAM shares QUIC congestion control; an unsent DATAGRAM must wait or be dropped. QUIC pacing is required or bursts must be bounded, but low-latency packetization/priority API behavior is implementation-specific. [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html) [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002.html) [RFC 9308](https://www.rfc-editor.org/rfc/rfc9308.html) | WebRTC requires media adaptation and congestion control, with RTCP feedback. Its standardized framework intentionally does not mandate one interactive-media controller, so observed behavior depends on the selected native implementation. [RFC 8834](https://www.rfc-editor.org/rfc/rfc8834.html) | The application must implement aggregate rate control, probing, pacing, queue bounds, PMTU behavior, and fairness correctly. [RFC 8085](https://www.rfc-editor.org/rfc/rfc8085.html) |
| Loss / repair / FEC | Base QUIC DATAGRAM supplies no media packetization, FEC, frame-deadline protocol, or automatic retransmission of a lost video fragment. It is path-MTU bounded and cannot be fragmented by QUIC. [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html) | RTP has H.264 packetization; WebRTC specifies NACK/RTX use and negotiated FEC, while warning that retransmission and FEC must be useful before the playout deadline. [RFC 6184](https://www.rfc-editor.org/rfc/rfc6184.html) [RFC 8834](https://www.rfc-editor.org/rfc/rfc8834.html) | All packet formats, feedback, dependency handling, FEC policy, and decoder-recovery behavior are owned by LatencyDesk. |
| NAT / enterprise fallback | QUIC supports migration after a connection exists, but does not itself perform peer candidate discovery or connectivity checks. UDP blocking requires a fallback or accepted failure; this is not LAN-v0.1 work. [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html) [RFC 9308](https://www.rfc-editor.org/rfc/rfc9308.html) | ICE, STUN, and TURN are part of the stack. WebRTC requires full ICE, TURN for difficult NATs, and TURN-over-TCP and TURN-over-TLS for UDP-blocking firewalls. This improves compatibility, not guarantees it. [RFC 8835](https://www.rfc-editor.org/rfc/rfc8835.html) [RFC 8445](https://www.rfc-editor.org/rfc/rfc8445.html) [RFC 8656](https://www.rfc-editor.org/rfc/rfc8656.html) | Must build or integrate the same ICE/TURN/relay behavior; raw UDP alone has no answer for symmetric NAT or UDP-blocking enterprise egress. |
| Security boundary | QUIC integrates TLS and lets reliable and unreliable traffic share one cryptographic context. [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html) [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html) | Media uses DTLS-SRTP; DataChannel uses SCTP over DTLS over ICE/UDP. [RFC 8835](https://www.rfc-editor.org/rfc/rfc8835.html) [RFC 8831](https://www.rfc-editor.org/rfc/rfc8831.html) | Must use an established security construction, e.g. DTLS-SRTP for RTP, rather than invent packet crypto. [RFC 5764](https://www.rfc-editor.org/rfc/rfc5764.html) |

## Decisions

### 1. Best media transport

Decision: Best media transport, separated by delivery scope.

Current proposal: QUIC DATAGRAM is the primary video path in one QUIC/TLS session, with LAN first.

Verdict: MODIFY

Recommended solution: For LAN v0.1, retain a **QUIC DATAGRAM media candidate** behind a transport-neutral media interface, rather than freeze it as the primary architecture. Its profile must be application-defined: path-safe fragment size, access-unit/fragment identifiers, codec epoch, dependency/recovery metadata, local send expiry, and bounded reassembly. For later WAN and relay delivery, make **native WebRTC RTP/SRTP over ICE/TURN** the first production candidate because it already has H.264 RTP packetization plus repair and feedback machinery; do not make a browser API part of the product boundary.

Why: QUIC DATAGRAM is a genuinely low-latency primitive: it is unreliable, ack-eliciting, congestion-controlled, and delivered to the application without stream ordering. But it cannot be fragmented by QUIC, has no explicit flow control, and only permits—not requires—an implementation to expose an application send-expiration API. A full H.264 access unit therefore needs LatencyDesk framing and a late-fragment drop policy. In contrast, RTP has standardized H.264 packetization, and WebRTC defines NACK/RTX and FEC behavior around interactive usefulness rather than blind recovery. [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html) [RFC 6184](https://www.rfc-editor.org/rfc/rfc6184.html) [RFC 8834](https://www.rfc-editor.org/rfc/rfc8834.html)

Alternative: Send video on QUIC streams and reset one stream per obsolete frame. QUIC applicability guidance says this can emulate partial reliability, but it adds stream lifecycle/flow-control decisions and does not establish a desktop-video packetization or repair ecosystem. The current Media over QUIC transport draft demonstrates active work on objects, priorities, streams, datagrams, and delivery timeouts, but it is explicitly work in progress, not a stable v0.1 dependency. [RFC 9308](https://www.rfc-editor.org/rfc/rfc9308.html) [draft-ietf-moq-transport-18](https://datatracker.ietf.org/doc/html/draft-ietf-moq-transport-18)

Risk: The proposed two-candidate path can create duplicate integration effort. QUIC’s shared congestion window can also delay a fresh frame when media already occupies the send queue, even though receiver-side stream HOL is absent.

Prototype required: Yes — EXPERIMENT_REQUIRED before promoting either candidate beyond LAN v0.1.

Evidence: [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html) defines QUIC DATAGRAM’s non-retransmission, MTU-bound, congestion-controlled behavior; [RFC 9308](https://www.rfc-editor.org/rfc/rfc9308.html) warns that implementations may optimize packet packing rather than latency; [RFC 8834](https://www.rfc-editor.org/rfc/rfc8834.html) specifies RTP repair/FEC and interactive-media adaptation.

### 2. Best input transport

Decision: Best immediate-input transport and correctness backstop.

Current proposal: Input uses QUIC DATAGRAM with monotonically increasing sequence numbers and periodic state reconciliation.

Verdict: KEEP

Recommended solution: Keep **QUIC DATAGRAM for immediate input** in the QUIC route: send only bounded, sequenced, epoch-scoped events; replace stale pointer/motion state instead of queueing it; and retain periodic complete key/button/pointer snapshots plus local release-all on focus loss, authorization revocation, or transport close. Treat a WebRTC implementation as semantically equivalent only when it uses a **dedicated unordered, zero-retransmission SCTP DataChannel** for immediate input and preserves the same state-reconciliation protocol. Never send user-authorized input actions in QUIC 0-RTT.

Why: Freshness beats delivery order for pointer movement and delayed input can be harmful. QUIC DATAGRAM neither retransmits nor flow-controls an overloaded receiver, so application caps, sequence rejection, and reconciliation are required. WebRTC SCTP explicitly supports ordered/unordered and full/partial reliability; zero retransmissions plus unordered delivery gives a UDP-like once-sent service. Reliable, ordered immediate-input messages would allow a lost earlier message to delay later events on that stream. [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html) [RFC 8831](https://www.rfc-editor.org/rfc/rfc8831.html)

Alternative: Use a reliable ordered QUIC stream or reliable ordered DataChannel for all keyboard and pointer events. It improves eventual delivery but turns a transient loss into stale-event replay and intra-stream HOL; use it only for infrequent, explicitly idempotent configuration/state messages.

Risk: Key/button state can temporarily diverge after loss. A one-connection QUIC scheduler or an SCTP association can still defer input when media has exhausted congestion/pacing capacity; protocol semantics do not prove scheduling latency. QUIC 0-RTT can replay application data, so it is unsuitable for non-idempotent input. [RFC 9308](https://www.rfc-editor.org/rfc/rfc9308.html)

Prototype required: Yes — EXPERIMENT_REQUIRED to prove that the chosen transport library prioritizes a fresh input datagram ahead of obsolete media at the send boundary.

Evidence: [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html) makes DATAGRAM application-multiplexing and overload handling the application’s responsibility; [RFC 8831](https://www.rfc-editor.org/rfc/rfc8831.html) defines SCTP’s partial/unordered modes; [RFC 9308](https://www.rfc-editor.org/rfc/rfc9308.html) documents 0-RTT replay risk.

### 3. Best control transport

Decision: Best transport for authorization, negotiation, recovery requests, and configuration control.

Current proposal: One bidirectional reliable QUIC control stream, with later file/clipboard streams kept separate.

Verdict: KEEP

Recommended solution: Keep a **bounded, length-delimited, bidirectional reliable QUIC control stream** for the QUIC route. Keep bulk clipboard/file transfer on separate streams and make state-changing control commands versioned and idempotent where feasible. If a later WAN route adopts native WebRTC, use a **dedicated reliable ordered DataChannel** for the same control protocol, distinct from input and bulk data channels. Keep immediate local safety actions such as release-all independent of remote control delivery.

Why: Control requires reliable ordered delivery, while QUIC’s independent streams prevent receiver-side delivery HOL from a separate media or bulk stream. SCTP ordering is also per stream, so a dedicated reliable DataChannel has the appropriate semantic shape. [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html) [RFC 9308](https://www.rfc-editor.org/rfc/rfc9308.html) [RFC 8831](https://www.rfc-editor.org/rfc/rfc8831.html)

Alternative: Put control in a TCP/TLS signaling connection or multiplex it into the input lane. TCP fallback may be appropriate for session establishment after a QUIC failure, but it restores connection-level HOL and does not improve active-session latency. Input datagrams are not an adequate correctness carrier for authorization or codec reconfiguration.

Risk: A lost reliable control packet can delay later messages on that control stream, and a congested shared connection can delay control transmission. This is acceptable only when the application reserves control budget and avoids queuing bulk traffic in the same stream.

Prototype required: No for the semantic mapping; yes if the selected QUIC library cannot demonstrate stream priority and bounded control admission under media load.

Evidence: [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html) defines independently concurrent ordered streams; [RFC 9308](https://www.rfc-editor.org/rfc/rfc9308.html) states that QUIC priorities are sender-managed and that different network treatment requires distinct 5-tuples; [RFC 8831](https://www.rfc-editor.org/rfc/rfc8831.html) limits SCTP ordering to an ordered stream.

### 4. Is QUIC DATAGRAM genuinely suitable for video?

Decision: Whether QUIC DATAGRAM is a video transport rather than merely a packet primitive.

Current proposal: Full-frame low-delay H.264 is carried through QUIC DATAGRAM, with pacing and no retry of obsolete media.

Verdict: MODIFY

Recommended solution: Answer **yes for the unreliable wire primitive, no as a complete video solution**. Retain QUIC DATAGRAM only with an explicit LatencyDesk media profile that makes frame deadline/drop, fragmentation, reassembly memory caps, decoder dependency, loss feedback, and recovery requests observable. Drop an unsent expired access unit before it reaches a transport queue; never retransmit an obsolete fragment; negotiate a path-safe payload rather than relying on IP fragmentation. Do not enable FEC until the bake-off shows that it decodes a frame before its deadline more often than its bandwidth cost causes queueing.

Why: RFC 9221 expressly targets real-time applications, but DATAGRAM frames have no stream association, do not retransmit, do not fragment, have no explicit flow control, and leave logical-flow identifiers to the application. It allows a stack to offer send expiration, but does not require that API or prescribe deadline-driven scheduling. WebRTC’s RTP profile does not make repair free: it requires the sender to judge whether NACK/RTX will arrive in time, and it notes that FEC consumes steady bandwidth and can increase playout delay. [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html) [RFC 8834](https://www.rfc-editor.org/rfc/rfc8834.html)

Alternative: Use WebRTC RTP for the WAN route and adopt its H.264 packetization, RTCP feedback, NACK/RTX, and negotiated FEC profile. This is not an argument that WebRTC automatically meets a desktop frame deadline; native implementation buffering and encoder interaction remain version-specific.

Risk: A DATAGRAM-only frame can become undecodable when any required fragment is lost. Conversely, FEC/RTX can worsen latency by consuming the same bottleneck bandwidth needed for fresh video and input.

Prototype required: Yes — EXPERIMENT_REQUIRED for deadline-aware send/drop behavior, loss recovery, and selected-implementation queue residence.

Evidence: [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html) specifies non-fragmentation, absent flow control, congestion-control deferral/drop, and optional expiration; [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002.html) requires pacing or bounded bursts; [RFC 8834](https://www.rfc-editor.org/rfc/rfc8834.html) specifies the NACK/RTX/FEC trade-offs.

### 5. Does WebRTC remove enough NAT and congestion-control engineering?

Decision: Whether WebRTC should be a later WAN/relay candidate rather than QUIC plus bespoke traversal and congestion work.

Current proposal: LAN first; relay and NAT traversal are deferred while QUIC remains the planned session transport.

Verdict: MODIFY

Recommended solution: Do **not** introduce WebRTC merely to solve LAN v0.1. For later WAN/relay support, make a native WebRTC RTP/SRTP + SCTP + ICE/TURN implementation the first comparison candidate, retaining LatencyDesk’s pairing, authorization, input, and control semantics above it. Require direct ICE, TURN/UDP, TURN/TCP, and TURN/TLS test paths. Keep QUIC as a separate WAN candidate only if the project is prepared to integrate equivalent ICE/TURN/relay behavior and measure its congestion scheduler.

Why: Full ICE exchanges candidates and performs connectivity checks; TURN provides a relay when direct traversal fails. WebRTC requires full ICE, TURN for endpoint-dependent NATs, and TURN-over-TCP/TLS support for UDP-blocking firewalls. This removes much of the non-differentiating traversal, security, RTP feedback, and data-channel work. It does **not** remove encoder rate adaptation, bounded queues, packet priority, state reconciliation, application authorization, relay operations, or controller tuning. WebRTC’s RTP specification explicitly says it had no single standardized interactive-media congestion-control algorithm, and upstream controller behavior is version-specific. [RFC 8445](https://www.rfc-editor.org/rfc/rfc8445.html) [RFC 8656](https://www.rfc-editor.org/rfc/rfc8656.html) [RFC 8835](https://www.rfc-editor.org/rfc/rfc8835.html) [RFC 8834](https://www.rfc-editor.org/rfc/rfc8834.html) [libwebrtc GoogCC source](https://webrtc.googlesource.com/src/+/main/modules/congestion_controller/goog_cc/goog_cc_network_control.h?format=TEXT)

Alternative: Pair QUIC with an ICE/TURN subsystem and native relay implementation. QUIC connection IDs help an established connection survive NAT rebinding, but that is not initial peer discovery or connectivity checking; this follows from the distinct QUIC and ICE scopes. [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html) [RFC 8445](https://www.rfc-editor.org/rfc/rfc8445.html)

Risk: TURN-over-TCP/TLS restores a TCP segment of the path and can introduce HOL under loss. WebRTC fallback support increases connection success probability relative to raw UDP, but enterprise policy, proxy behavior, and relay placement remain deployment-specific.

Prototype required: Yes — EXPERIMENT_REQUIRED on real direct, symmetric-NAT, relay, UDP-blocked, and mobile-network paths.

Evidence: [RFC 8835](https://www.rfc-editor.org/rfc/rfc8835.html) requires ICE/TURN and TCP/TLS TURN fallback for UDP-blocking firewalls; [RFC 8656](https://www.rfc-editor.org/rfc/rfc8656.html) explains why direct hole punching can fail and why a relay is then necessary; [RFC 9308](https://www.rfc-editor.org/rfc/rfc9308.html) reports historical all-UDP blocking and requires QUIC applications to accept failure or provide fallback.

### 6. Is custom UDP / RTP-like transport worth it?

Decision: Whether to build a proprietary UDP transport, FEC scheme, and congestion controller now.

Current proposal: Standard QUIC/TLS is preferred over custom encryption, with custom media framing above it.

Verdict: REJECT

Recommended solution: Do not begin a custom UDP transport for v0.1 or as the first WAN route. Differentiate in the desktop-media profile, state model, and scheduling policy while using QUIC or native WebRTC transport. Reconsider a custom RTP-like path only after it beats both common-stack candidates by a predeclared P99 latency/recovery margin under the same capture, codec, network, security, and relay conditions. If reached, reuse established ICE/TURN and DTLS-SRTP rather than inventing NAT traversal or packet cryptography.

Why: UDP has no inherent congestion control; its application must control aggregate traffic fairly and safely, avoid fragmentation, discover PMTU behavior, handle loss/reordering, and work through middleboxes. WAN P2P additionally needs candidate exchange, connectivity checks, relaying, credentialing, and keepalive behavior. DTLS-SRTP provides a standardized key-establishment and media-protection path for RTP; replacing it is not a latency differentiator. [RFC 8085](https://www.rfc-editor.org/rfc/rfc8085.html) [RFC 8445](https://www.rfc-editor.org/rfc/rfc8445.html) [RFC 8656](https://www.rfc-editor.org/rfc/rfc8656.html) [RFC 5764](https://www.rfc-editor.org/rfc/rfc5764.html)

Alternative: A custom payload over QUIC DATAGRAM, or a native RTP/SRTP profile with application-specific desktop dependency metadata and measured FEC/repair policy. Both preserve room for differentiation without assuming responsibility for every Internet transport primitive.

Risk: Waiting could expose an implementation limitation in the chosen QUIC or WebRTC stack. That is a measurable exit criterion, not justification to pre-build a high-risk transport.

Prototype required: No until the QUIC-versus-WebRTC bake-off has a clear, reproducible loser; then yes — EXPERIMENT_REQUIRED as a narrowly scoped third candidate.

Evidence: [RFC 8085](https://www.rfc-editor.org/rfc/rfc8085.html) calls congestion control and middlebox behavior mandatory design work for UDP applications and recommends established transports where possible; [RFC 5764](https://www.rfc-editor.org/rfc/rfc5764.html) specifies DTLS-SRTP keying and media protection; [RFC 8656](https://www.rfc-editor.org/rfc/rfc8656.html) describes relay necessity when direct traversal fails.

### 7. Which route is most likely to reach AnyDesk/Parsec/Moonlight-class latency?

Decision: Time-to-credible parity route, not an unsupported claim of achieved parity.

Current proposal: A LAN-first QUIC baseline is intended to evolve toward resilient QUIC and later relay support.

Verdict: EXPERIMENT

Recommended solution: For **LAN v0.1**, keep QUIC DATAGRAM as a bounded, instrumented laboratory candidate because it preserves one secure session and avoids introducing WAN complexity. For **later WAN/relay**, native WebRTC is the most likely route to reach a credible low-latency result soon because it brings mature ICE/TURN, SRTP/RTP feedback, DataChannel modes, and a deployed native congestion-control implementation. A custom UDP/RTP-like engine has the possible long-term optimization ceiling, but it has the lowest probability of reaching that result quickly because it must first recreate the surrounding transport/NAT/repair discipline. This is not proof that either common stack reaches commercial-class end-to-end latency: EXPERIMENT_REQUIRED.

Why: QUIC avoids cross-stream receiver HOL and supplies congestion control/pacing, but its latency behavior still depends on transport packetization, priority, application queues, and an application-defined video protocol. WebRTC reduces WAN engineering but does not standardize a single controller or eliminate local media-pipeline latency. Neither standard measures the target hardware, encoder, decoder, display, input, relay geography, or supported networks. [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002.html) [RFC 9308](https://www.rfc-editor.org/rfc/rfc9308.html) [RFC 8834](https://www.rfc-editor.org/rfc/rfc8834.html) [RFC 8835](https://www.rfc-editor.org/rfc/rfc8835.html)

Alternative: Freeze QUIC as the sole future WAN transport now. This is cheaper in the immediate repository but assumes that a QUIC stack plus bespoke ICE/TURN, frame repair, and priority behavior will beat or match native WebRTC without evidence.

Risk: A native WebRTC integration can impose build/ABI and implementation-specific tuning costs; a QUIC-only route can defer unavoidable WAN compatibility work until it is expensive to change.

Prototype required: Yes — EXPERIMENT_REQUIRED via the bake-off below before any architecture freeze.

Evidence: [RFC 9308](https://www.rfc-editor.org/rfc/rfc9308.html) requires QUIC fallback or accepted failure on UDP-blocked networks; [RFC 8835](https://www.rfc-editor.org/rfc/rfc8835.html) defines WebRTC’s required traversal/fallback components; [RFC 8834](https://www.rfc-editor.org/rfc/rfc8834.html) documents the necessity, but not standardization, of interactive-media congestion control.

## Bake-off definition — required before WAN architecture freeze

Compare these routes without changing capture, encode, decode, renderer, authentication, input semantics, frame cadence, recovery policy, or telemetry:

1. **A — QUIC:** the current reliable-control + DATAGRAM media/input profile, including explicit access-unit fragmentation, local expiry, and bounded queues.
2. **B — Native WebRTC:** RTP/SRTP video, RTCP feedback, SCTP DataChannels mapped to the same control and input semantics, full ICE, and TURN relay fallback.
3. **C — Custom UDP/RTP-like:** run only if A and B both miss the predeclared gate; it must use the same DTLS-SRTP and ICE/TURN services so the comparison isolates media transport/scheduling rather than security or traversal omissions.

Use identical direct-LAN, induced-loss/reorder/queue, direct-WAN, difficult-NAT, TURN/UDP, TURN/TLS, UDP-blocked, and representative mobile-network paths. Record optical input-to-photon and capture-to-photon latency at P50/P95/P99, input-application latency and stuck-state recoveries, frame age at decode, deadline misses, recovery-to-decodable-frame time, queue residence, packet loss/reorder, goodput, retransmission/FEC bytes, CPU, connection success rate, and relay path selection. Predeclare the target gates and a meaningful P99 margin before collecting data. Promote a route only if it meets every correctness/connectivity gate and wins the latency/recovery margin under matched conditions; otherwise retain the simpler route for its scoped deployment.

## Sources

### Official

- [W3C — WebRTC: Real-Time Communication in Browsers](https://www.w3.org/TR/webrtc/) — browser API recommendation; not a native latency benchmark.

### Upstream

- [libwebrtc — `GoogCcNetworkController` source](https://webrtc.googlesource.com/src/+/main/modules/congestion_controller/goog_cc/goog_cc_network_control.h?format=TEXT) — current-source implementation evidence only; revision and field-trial behavior are vendor-specific.

### Standards

- [RFC 9000 — QUIC: A UDP-Based Multiplexed and Secure Transport](https://www.rfc-editor.org/rfc/rfc9000.html)
- [RFC 9002 — QUIC Loss Detection and Congestion Control](https://www.rfc-editor.org/rfc/rfc9002.html)
- [RFC 9221 — An Unreliable Datagram Extension to QUIC](https://www.rfc-editor.org/rfc/rfc9221.html)
- [RFC 9308 — Applicability of the QUIC Transport Protocol](https://www.rfc-editor.org/rfc/rfc9308.html)
- [RFC 8445 — Interactive Connectivity Establishment (ICE)](https://www.rfc-editor.org/rfc/rfc8445.html)
- [RFC 8656 — Traversal Using Relays around NAT (TURN)](https://www.rfc-editor.org/rfc/rfc8656.html)
- [RFC 8835 — Transports for WebRTC](https://www.rfc-editor.org/rfc/rfc8835.html)
- [RFC 8834 — Media Transport and Use of RTP in WebRTC](https://www.rfc-editor.org/rfc/rfc8834.html)
- [RFC 8831 — WebRTC Data Channels](https://www.rfc-editor.org/rfc/rfc8831.html)
- [RFC 6184 — RTP Payload Format for H.264 Video](https://www.rfc-editor.org/rfc/rfc6184.html)
- [RFC 8085 — UDP Usage Guidelines](https://www.rfc-editor.org/rfc/rfc8085.html)
- [RFC 5764 — DTLS Extension to Establish Keys for SRTP](https://www.rfc-editor.org/rfc/rfc5764.html)

### Other

- [draft-ietf-moq-transport-18 — Media over QUIC Transport](https://datatracker.ietf.org/doc/html/draft-ietf-moq-transport-18) — May 2026 Internet-Draft, explicitly work in progress and not a stable dependency.

## Candidate experiments

- Does the selected QUIC library expose send expiry and traffic priority that prevent a fresh input datagram from waiting behind obsolete media?
- With identical capture, encode, decode, and induced loss/reorder, which of QUIC DATAGRAM and native WebRTC RTP/SRTP has lower P99 photon-to-photon latency?
- On supported UDP-blocked enterprise paths, what direct-or-relayed connection-success rate and P99 latency does WebRTC TURN/TLS achieve?
- At the target RTT and loss rate, does RTX/NACK or one fixed FEC profile deliver more decodable frames before their deadline?
- Does a DTLS-SRTP/ICE custom RTP-like candidate beat the winning common stack by the predeclared P99 margin without reducing connectivity or input correctness?
