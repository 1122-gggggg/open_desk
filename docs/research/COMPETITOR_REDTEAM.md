# LatencyDesk competitor red-team architecture review

_Independent, pessimistic architecture review; evidence gathered 2026-08-13. This is not a feature comparison or a performance claim._

---

## Evidence boundary

The current proposal is a native Windows↔Linux engine with Desktop Duplication/Windows Graphics Capture, Portal+PipeWire, opportunistic GPU import with a bounded copy path, full-frame low-delay H.264 8-bit 4:2:0, QUIC Streams plus DATAGRAM, and a logged-in LAN-first product boundary ([baseline](../../../README.md), [protocol](../../PROTOCOL.md)). It is not yet a product: it explicitly lacks a production QUIC connection, hardware codec integrations, UI/pairing, Internet traversal/relay, audio, clipboard, file transfer, and unattended access.

This review treats public protocol specifications, upstream repositories, and administrator documentation as evidence of an architectural mechanism. It does **not** treat vendor latency, bandwidth, security, or market-leadership assertions as independent evidence. In particular, AnyDesk and Parsec publish technical marketing pages rather than wire specifications; NoMachine publishes a vendor security statement; and the Steam Remote Play page exposes product/API behavior but not its media protocol. Claims based only on those sources are marked **vendor-reported**. Absence of a public specification in material reviewed here is not proof that one does not exist.

Version and platform caveats matter: the Amazon DCV dual WebSocket/QUIC default is documented for DCV 2024.0 and later; Sunshine's provider knobs explicitly vary by GPU, driver, OS, and capture route; Chrome Remote Desktop's source is enterprise policy guidance; NoMachine's Network discussion is version-9 vendor documentation; and the Microsoft RDP documents are protocol revision snapshots. None of these sources proves behavior on a particular Wayland compositor or driver. Such claims are **EXPERIMENT_REQUIRED**.

## 1–2. Strongest competitor layer and where LatencyDesk is worse

| Competitor | Strongest layer supported by public evidence | Where the current proposal is worse |
|---|---|---|
| **AnyDesk** | The only technically identifiable public layer is the proprietary DeskRT image-transfer codec plus an Erlang-based service fabric. The page's performance numbers are **vendor-reported**, not benchmark evidence, and it supplies no public wire or congestion-control contract ([AnyDesk](https://anydesk.com/en/performance)). | As a product, LatencyDesk is materially behind in deployment/access workflows because its v0.1 excludes pairing UI, relay, unattended operation, and ancillary channels. It is not possible to substantiate an algorithmic DeskRT comparison from public material; any claim that H.264 or future tiles beat it is **EXPERIMENT_REQUIRED**. |
| **RustDesk** | Explicit rendezvous/relay topology: `hbbs` tracks/reaches peers and attempts hole punching; `hbbr` relays after direct setup fails ([RustDesk self-host documentation](https://rustdesk.com/docs/en/self-host/)). | LAN-first without a connectivity control plane is knowingly inferior for ordinary Internet reachability, device discovery, relay fallback, and operations. This is not a small transport backlog; it is a separate service domain. |
| **Parsec** | **Vendor-reported:** a native peer-to-peer transport called BUD, NAT traversal, adaptive congestion/loss behavior, H.264, hardware encode/decode, and zero-copy capture-to-encoder ([Parsec technology page](https://parsec.app/technology)). The page is not a public protocol specification or independent measurement. | The proposal has none of the stated WAN connection machinery and no production hardware pipeline. Even if the claimed numbers are ignored, the existence of a mature transport/provider integration means “Rust core + DATAGRAM” is not a differentiator. |
| **Sunshine** | The strongest public evidence is its practical encoder/provider matrix: explicit NVIDIA, Intel, AMD, VA-API, Vulkan, and software choices, plus vendor-specific low-latency/rate-control/power trade-offs ([Sunshine configuration](https://docs.lizardbyte.dev/projects/sunshine/latest/md_docs_2configuration.html)). | A NVIDIA-first reference route with Intel/AMD later is a much smaller compatibility envelope. A generic native-provider boundary does not remove per-driver, per-codec, per-capture, and per-power-management failure modes. |
| **Moonlight** | A cross-platform GameStream client core and pairing/deployment experience; its upstream library identifies itself as the core GameStream implementation, and its setup guidance covers pairing, desktop streaming, public-network ports, and hardware decode prerequisites ([Moonlight core](https://github.com/moonlight-stream/moonlight-common-c), [setup guide](https://github.com/moonlight-stream/moonlight-docs/wiki/Setup-Guide)). | LatencyDesk lacks a client product surface, pairing, application/desktop session UX, gamepad support, audio, and Internet setup. The target need not become a game streamer, but it cannot claim endpoint maturity while these remain absent. |
| **Microsoft RDP** | A published desktop-remoting protocol family with a graphics pipeline that encodes server display data for compatible client decode/render, rather than requiring all semantics to be a single video stream ([MS-RDPEGFX](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/da5c75f9-cd99-450c-98c4-014a496942b0)); it also specifies an RDP UDP transport extension ([MS-RDPEUDP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeudp/1ed440f4-6e8f-4c79-a9a3-0aea32a21daf)). | A full-frame 4:2:0 baseline has no desktop-semantic/surface path today. That does not prove it is slower, but it is structurally weaker for static text/UI updates until an objective readability, bandwidth, and latency comparison is run. |
| **FreeRDP** | An Apache-2.0 implementation ecosystem for the published RDP family, with a large channel/client surface and explicit Microsoft Open Specifications reference path ([FreeRDP upstream](https://github.com/FreeRDP/FreeRDP)). | LatencyDesk has no interoperability corpus, protocol maturity, channel/plugin ecosystem, or broad client/platform validation. It should not compete on “remote desktop completeness” in the foreseeable baseline phase. |
| **NoMachine** | **Vendor-reported:** a session/access-control deployment model with client-server operation, default proprietary NX over TCP or TCP+UDP, a user-visible access decision, and an optional packet-forwarding Network service that the vendor says cannot decrypt end-to-end traffic ([NoMachine security statement](https://kb.nomachine.com/AR04S01121)). | The proposal's consent ideas are sound but no pairable identity, user-facing authorization system, session lifecycle, relay operation, or unattended policy exists. Those are product and security systems, not incidental UI. |
| **Amazon DCV** | Explicit separation of the session plane from transport: a client needs an active, owned session to connect ([DCV session management](https://docs.aws.amazon.com/dcv/latest/adminguide/managing-sessions.html)); DCV documents QUIC/UDP data transport with WebSocket/TCP fallback and WebSocket authentication for DCV 2024.0+ ([DCV QUIC transport](https://docs.aws.amazon.com/dcv/latest/adminguide/disable-quic.html)). | A single future QUIC connection without a session service, authorization plane, gateway policy, or fallback strategy is less operable. The present proposal treats these as future items, so it is worse for managed or cloud-hosted use now. |
| **Chrome Remote Desktop** | A publicly documented connectivity control plane: Google-service negotiation followed by ICE/WebRTC direct, STUN, or TURN/relay; UDP is preferred and TCP fallback exists ([Chrome Remote Desktop network guide](https://support.google.com/chrome/a/answer/16364503?hl=en)). | The proposal has no signaling, ICE-like candidate selection, relay, policy control, or TCP contingency. LAN-first is a valid milestone, but it is not an architecture sufficient for the expected remote-access problem. |
| **Steam Remote Play** | Endpoint and input adaptation: each connected device has a session, and the documented product workflow supports phones/tablets/TVs plus touch/controller configuration ([Steam Remote Play](https://partner.steamgames.com/doc/features/remoteplay?language=english)). Its streaming wire format is not public in the reviewed source. | Keyboard/mouse-only v0.1 has no comparable device/peripheral UX, audio path, or content/session integration. This may be intentionally out of scope, but it removes Steam-like use cases rather than creating an advantage. |

**Red-team conclusion:** the proposal is only plausibly ahead at a narrow, unproven point—explicit bounded ownership/telemetry across a Rust/native boundary. Every public competitor either already demonstrates a related mechanism or has a larger product/control plane. That narrow point has no customer value until it beats a visible baseline under reproducible conditions.

## 3. Claimed innovations that already exist

| Proposed distinction | Prior art or contrary evidence | Consequence |
|---|---|---|
| Reliable control beside unreliable media on one authenticated transport | QUIC DATAGRAM itself standardizes unreliable application datagrams sharing a QUIC authentication and congestion-control context with reliable streams ([RFC 9221](https://www.rfc-editor.org/rfc/rfc9221)); DCV documents QUIC data alongside WebSocket authentication/fallback ([DCV](https://docs.aws.amazon.com/dcv/latest/adminguide/disable-quic.html)). | The mapping is a sensible implementation choice, not a defensible innovation. The differentiator would have to be measured queueing/recovery behavior. |
| Direct connection with a later relay | RustDesk documents direct hole punching then relay fallback; Chrome documents ICE direct/STUN/TURN modes ([RustDesk](https://rustdesk.com/docs/en/self-host/), [Chrome](https://support.google.com/chrome/a/answer/16364503?hl=en)). | “Relay later” postpones an already-solved but operationally expensive product layer; it is not a unique topology. |
| GPU-native capture → hardware H.264 with zero-copy when possible | Parsec **claims** a zero-copy GPU path; Sunshine exposes real provider-specific encode selections and latency trade-offs ([Parsec, vendor-reported](https://parsec.app/technology), [Sunshine](https://docs.lizardbyte.dev/projects/sunshine/latest/md_docs_2configuration.html)). | Zero-copy is not novel. The bounded fallback/observability policy may be better engineering, but needs a public before/after workload result. |
| Desktop-specific refinement after a video base | RDP's published graphics pipeline is already a desktop-aware non-single-video semantic comparator ([MS-RDPEGFX](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/da5c75f9-cd99-450c-98c4-014a496942b0)). | Sparse exact tiles may still be a useful implementation, but it cannot be sold as the first desktop-aware solution. The quality/cost trade-off is **EXPERIMENT_REQUIRED**. |
| Native code and hardware control | Parsec **claims** cross-platform native C and direct hardware control; Sunshine and Moonlight demonstrate upstream native systems ([Parsec, vendor-reported](https://parsec.app/technology), [Sunshine](https://docs.lizardbyte.dev/projects/sunshine/latest/md_docs_2configuration.html), [Moonlight](https://github.com/moonlight-stream/moonlight-common-c)). | Rust is a risk-management choice, not a user-facing innovation absent a benchmark, audit result, or operational advantage. |
| Logged-in consent and stateful sessions | DCV documents active owned sessions; NoMachine documents an authorization decision and policy surface; Steam documents a per-device session model ([DCV](https://docs.aws.amazon.com/dcv/latest/adminguide/managing-sessions.html), [NoMachine, vendor-reported](https://kb.nomachine.com/AR04S01121), [Steam](https://partner.steamgames.com/doc/features/remoteplay?language=english)). | Consent is table stakes. The proposal must prove less privilege and clearer revocation, not merely include a consent state. |

## 4. Underestimated engineering work

1. **Connectivity is a control plane, not a socket feature.** Direct versus relay choice requires signaling, identity binding, NAT policy, abuse/rate limits, observability, regional operations, and support diagnostics. Chrome's documented Direct/STUN/TURN modes and RustDesk's `hbbs`/`hbbr` split make this explicit. [INFERENCE] A “future relay” is likely to reshape authentication and telemetry contracts if deferred too long.
2. **GPU support is an adversarial matrix.** Sunshine's configuration documents vendor, encoder, rate-control, HAGS/power, and capture-specific decisions; for example, it records a Windows/NVIDIA realtime-priority failure trade-off. [INFERENCE] The actual work is not one zero-copy API but proving capture-format-fence-encoder-render combinations for each OS/GPU/driver/compositor pair.
3. **Desktop quality needs a competing semantic baseline.** RDP's published graphics pipeline demonstrates that desktop remoting can operate at a graphics/surface level. [INFERENCE] H.264 4:2:0 can be a safe low-risk baseline, but it may fail text/UI workloads before its “later” tile phase arrives; optical latency alone would miss this failure.
4. **Input is broader than key-up reconciliation.** Moonlight documents keyboard/mouse/gamepad networking and Steam documents touch/controller adaptation. [INFERENCE] IME, layout changes, accessibility devices, high-DPI/rotation/multi-monitor transforms, focus, and privileged targets must be tested separately; passing basic input datagrams proves little.
5. **Session security and UX are a joint system.** DCV treats session ownership as a prerequisite to connecting; Chrome exposes policy controls; NoMachine documents visible authorization and unattended policy. [INFERENCE] Pairing, revoke, device replacement, audit events, local-visible state, and support recovery need a single authority model before Internet or unattended scope is promised.
6. **Benchmark credibility itself is product work.** Vendor performance claims cannot support LatencyDesk's thesis. [INFERENCE] A reproducible comparator harness needs fixed hardware/driver/compositor versions, network impairment profiles, visual readability tasks, motion and static scenes, input-to-photon measurement, error recovery, and published failure cases.
7. **Clean-room process has a cost.** RustDesk Server is AGPL-3.0, while Sunshine and Moonlight's shared implementation are GPL-3.0; FreeRDP is Apache-2.0 ([RustDesk license](https://github.com/rustdesk/rustdesk-server/blob/master/LICENSE), [Sunshine upstream](https://github.com/LizardByte/Sunshine), [Moonlight upstream](https://github.com/moonlight-stream/moonlight-common-c), [FreeRDP upstream](https://github.com/FreeRDP/FreeRDP)). [INFERENCE] The permissive core cannot safely accelerate by copying source, comments, tests, constants, or derived structures; a behavioral/specification firewall and review record consume time but are cheaper than a license-contaminated release.

## 5. Best baseline architecture to study

The best **single** baseline to study first is **Chrome Remote Desktop's publicly documented control-plane topology**, not its implementation or media codec: service negotiation → identity-bound session setup → ICE candidate selection → Direct/STUN/TURN → UDP-preferred/TCP-fallback live transport. It most directly exposes LatencyDesk's largest missing architectural domain and is publicly documented without importing GPL code ([Chrome network guide](https://support.google.com/chrome/a/answer/16364503?hl=en)).

Microsoft RDP should be the **semantic comparator**, not the implementation template: its public graphics specification is a clean way to formulate desktop-update/readability tests without copying FreeRDP or Microsoft implementation expression ([MS-RDPEGFX](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/da5c75f9-cd99-450c-98c4-014a496942b0)). Sunshine/Moonlight are useful black-box/provider-matrix test subjects only; their GPL code must remain outside the implementation reading set.

## 6. Why this project may fail

- **No defensible wedge:** “native,” “low latency,” H.264, direct transport, hardware encode, consent, and fallback copies all have prior art. If the observable benefit is only architectural cleanliness, users will choose established products with complete reachability and support.
- **The scope is intentionally too narrow for the comparison set:** LAN-only logged-in sessions may be a rational engineering milestone, but it cannot win against remote-access products that solve identity, NAT traversal, relay, and lifecycle. Without a sharply chosen LAN-only customer/workload, the project can be technically sound yet commercially irrelevant. **EXPERIMENT_REQUIRED.**
- **The first visible experience may be worse:** full-frame H.264 4:2:0 risks static desktop readability and bandwidth disadvantages relative to desktop-semantic remoting before refinement exists. This is a hypothesis, not a result; it must be tested against an RDP comparator.
- **Provider and compositor entropy can consume the schedule:** the project promises Windows plus GNOME/KDE Wayland, multiple GPU vendors, and two directions while actual production provider integrations are not present. A clean abstraction does not make drivers or portals uniform. **EXPERIMENT_REQUIRED.**
- **The measurement gate may reveal no advantage:** without a matched, reproducible input-to-photon and text-quality benchmark, the project cannot separate its own pipeline from encoder/driver/network variance or overturn incumbent claims.
- **Legal/process shortcuts would negate the differentiation:** studying public behavior is useful; copying GPL/AGPL expression or attempting undocumented proprietary-protocol compatibility without review creates a legal and maintenance risk. This is not legal advice; obtain jurisdiction-specific counsel before compatibility, linking, distribution, or patent decisions.

## Decisions

### Benchmark claims before product positioning

Decision:
Do not position LatencyDesk as a low-latency or desktop-quality winner before an independent matched-hardware comparator passes.

Current proposal:
The repository correctly withholds performance claims until benchmark gates pass, but its differentiating language still centers on a latency-first native architecture ([README](../../../README.md)).

Verdict: MODIFY

Recommended solution:
Freeze a published comparator protocol: same host/client hardware, driver/compositor versions, display mode, network impairment, scene set, optical input-to-photon method, text/readability rubric, and recovery cases; publish negative results too.

Why:
QUIC DATAGRAM, hardware H.264, direct paths, and native pipelines are established mechanisms, while proprietary competitor performance pages are not independent proof. A narrow measured advantage is the only defensible wedge.

Alternative:
Market implementation language, zero-copy intent, or future refinement as the primary distinction.

Risk:
A hard gate may show no advantage and delay launch, but skipping it makes the core claim non-falsifiable.

Prototype required:
Yes — one Windows-host to Linux-client optical-and-readability comparator harness.

Evidence:
[RFC 9221](https://www.rfc-editor.org/rfc/rfc9221), [Parsec vendor statement](https://parsec.app/technology), [Sunshine configuration](https://docs.lizardbyte.dev/projects/sunshine/latest/md_docs_2configuration.html), and [RDP graphics specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/da5c75f9-cd99-450c-98c4-014a496942b0).

### Make connectivity a first-class architectural seam now

Decision:
Define the identity, signaling, candidate-selection, relay authorization, and transport-fallback interfaces before the LAN implementation hardens them accidentally.

Current proposal:
Direct LAN is first; Internet traversal and relay are deferred ([README](../../../README.md)).

Verdict: MODIFY

Recommended solution:
Keep the LAN-only release boundary, but model a separate connectivity control plane now and make a direct LAN connection one policy-selected candidate path, not the sole session model.

Why:
RustDesk and Chrome publicly separate discovery/signaling from direct versus relay traffic. Retrofitting identity and transport selection after media protocol/telemetry contracts stabilize creates cross-cutting migration risk.

Alternative:
Add signaling and relay only after a complete LAN product ships.

Risk:
Premature operational build-out can consume the milestone; interface-only work must not silently expand into running public infrastructure.

Prototype required:
Yes — an in-process fake signaling service that drives Direct, relayed, and TCP-fallback selection without forwarding pixels.

Evidence:
[RustDesk self-host topology](https://rustdesk.com/docs/en/self-host/), [Chrome Remote Desktop network guide](https://support.google.com/chrome/a/answer/16364503?hl=en), and [DCV transport documentation](https://docs.aws.amazon.com/dcv/latest/adminguide/disable-quic.html).

### Treat full-frame H.264 as a kill-gated baseline, not a quality answer

Decision:
Keep full-frame H.264 only while it meets predefined static-desktop and recovery thresholds against a desktop-semantic comparator.

Current proposal:
A full-frame low-delay H.264 8-bit 4:2:0 path precedes sparse exact refinement ([ADR 0001](../../adr/0001-h264-before-hybrid.md)).

Verdict: EXPERIMENT

Recommended solution:
Set quantitative exit criteria for text sharpness, small-font task accuracy, encode/decode delay, bitrate, loss recovery, and resize/DPI transitions before beginning tiles or claiming desktop competitiveness.

Why:
RDP's published graphics pipeline confirms a credible competing design space beyond one video stream. It does not prove that tiles win; it makes the quality assumption falsifiable.

Alternative:
Commit to tiles/semantic remoting immediately.

Risk:
Premature hybrid work creates synchronization and recovery complexity; waiting without quality criteria can ship an unusable desktop baseline.

Prototype required:
Yes — a static-text and mixed-motion trace rendered through H.264 4:2:0 and one RDP reference client.

Evidence:
[MS-RDPEGFX](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/da5c75f9-cd99-450c-98c4-014a496942b0) and [FreeRDP upstream](https://github.com/FreeRDP/FreeRDP).

### Turn the provider boundary into a support matrix

Decision:
Do not call the native provider architecture portable until every promised GPU/OS/compositor cell has a measured zero-copy-or-copy result and an explicit unsupported reason.

Current proposal:
D3D11/DMA-BUF import is opportunistic with a bounded fallback; NVIDIA is the reference path and Intel/AMD follow ([ADR 0003](../../adr/0003-zero-copy-with-fallback.md), [product boundary](../../../README.md)).

Verdict: MODIFY

Recommended solution:
Version a capability matrix containing capture format, memory domain, fence/import result, encoder/decoder path, conversion path, latency distribution, failure signature, and fallback classification for each supported cell.

Why:
Sunshine exposes provider-specific encoder selection and low-latency trade-offs rather than a universal GPU path. Its public configuration is direct evidence that vendor integrations remain material after abstraction.

Alternative:
Support only the NVIDIA reference configuration until after v0.1.

Risk:
The matrix can reveal a narrow support envelope; hiding it turns user bugs into architectural claims.

Prototype required:
Yes — a forced-copy versus preferred-import soak on one NVIDIA, one Intel, and one AMD path; Wayland results remain **EXPERIMENT_REQUIRED** per compositor.

Evidence:
[Sunshine configuration](https://docs.lizardbyte.dev/projects/sunshine/latest/md_docs_2configuration.html) and [Moonlight setup guide](https://github.com/moonlight-stream/moonlight-docs/wiki/Setup-Guide).

### Maintain a strict behavioral clean-room firewall

Decision:
Use GPL/AGPL competitors only for externally observable behavior and license-aware test scenarios; prohibit implementation-derived design artifacts from entering the permissive core.

Current proposal:
The repository already prohibits copying GPL/AGPL implementation expression and requires disclosure ([licensing policy](../../LICENSING.md)).

Verdict: KEEP

Recommended solution:
Record each competitor study as source category, exact public behavior/specification observed, license, implementer/reviewer separation, and independent source used. Prefer IETF, OS-vendor, and Microsoft Open Specifications documents for wire/API decisions.

Why:
The cited RustDesk Server, Sunshine, and Moonlight components are AGPL/GPL, whereas FreeRDP is Apache-2.0. License compatibility, derivative-work analysis, patents, and undocumented-protocol interoperability are legal questions, not engineering assumptions.

Alternative:
Let engineers browse competitor source ad hoc and rely on intent not to copy.

Risk:
The process costs speed and may miss useful implementation detail, but a contaminated core or unreviewed codec/protocol dependency is a release blocker.

Prototype required:
No — conduct a source-access/review audit before accepting any compatibility or provider contribution.

Evidence:
[RustDesk Server license](https://github.com/rustdesk/rustdesk-server/blob/master/LICENSE), [Sunshine upstream](https://github.com/LizardByte/Sunshine), [Moonlight core](https://github.com/moonlight-stream/moonlight-common-c), [FreeRDP upstream](https://github.com/FreeRDP/FreeRDP), and [Microsoft Open Specifications IP notice](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/da5c75f9-cd99-450c-98c4-014a496942b0).

### Study Chrome Remote Desktop's topology first

Decision:
Adopt Chrome Remote Desktop's documented control-plane topology as the first external architecture baseline to study, while keeping LatencyDesk's media protocol independent.

Current proposal:
The protocol specifies one authenticated QUIC connection and defers relay/NAT traversal ([protocol](../../PROTOCOL.md)).

Verdict: MODIFY

Recommended solution:
Model signaling, ICE-like candidate policy, direct/STUN/relay selection, and UDP/TCP contingency as architectural concepts; do not copy Chromium code or assume Chrome's policy/product behavior is a protocol requirement.

Why:
It directly addresses the proposal's missing reachability layer with primary documentation and has a cleaner learning boundary than GPL implementation code.

Alternative:
Study Moonlight/Sunshine or RustDesk source as the principal implementation reference.

Risk:
Chrome's enterprise guidance does not establish media performance or consumer-product equivalence; overfitting to Google infrastructure would be a mistake.

Prototype required:
Yes — deterministic simulated NAT cases that prove selection and authorization state transitions, not real public relay deployment.

Evidence:
[Chrome Remote Desktop network guide](https://support.google.com/chrome/a/answer/16364503?hl=en) and [RustDesk self-host topology](https://rustdesk.com/docs/en/self-host/).

## Sources

### Official

- [AnyDesk — Performance](https://anydesk.com/en/performance) — vendor technology/performance statement; not independent benchmark evidence
- [RustDesk — Self-host](https://rustdesk.com/docs/en/self-host/) — `hbbs`/`hbbr`, hole punching, and relay topology
- [Parsec — Technology](https://parsec.app/technology) — vendor-reported BUD/provider claims; no public wire specification reviewed
- [Sunshine — Configuration](https://docs.lizardbyte.dev/projects/sunshine/latest/md_docs_2configuration.html) — documented encoder/provider and tuning matrix
- [Microsoft — MS-RDPEGFX](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpegfx/da5c75f9-cd99-450c-98c4-014a496942b0) — graphics pipeline specification and IP notice
- [Microsoft — MS-RDPEUDP](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rdpeudp/1ed440f4-6e8f-4c79-a9a3-0aea32a21daf) — RDP UDP transport extension
- [Amazon DCV — Managing sessions](https://docs.aws.amazon.com/dcv/latest/adminguide/managing-sessions.html) — active, owned session model
- [Amazon DCV — QUIC transport](https://docs.aws.amazon.com/dcv/latest/adminguide/disable-quic.html) — DCV 2024.0+ QUIC/WebSocket behavior
- [NoMachine — Security statement](https://kb.nomachine.com/AR04S01121) — vendor-reported NX, authorization, and Network architecture
- [Google — Chrome Remote Desktop network guide](https://support.google.com/chrome/a/answer/16364503?hl=en) — service negotiation, ICE/WebRTC, Direct/STUN/TURN, UDP/TCP fallback
- [Valve — Steam Remote Play](https://partner.steamgames.com/doc/features/remoteplay?language=english) — device sessions and input adaptation

### Upstream

- [RustDesk Server — AGPL-3.0 license](https://github.com/rustdesk/rustdesk-server/blob/master/LICENSE)
- [LizardByte Sunshine — GPL-3.0 upstream repository](https://github.com/LizardByte/Sunshine)
- [Moonlight common C — GameStream core, GPL-3.0](https://github.com/moonlight-stream/moonlight-common-c)
- [Moonlight — Setup guide](https://github.com/moonlight-stream/moonlight-docs/wiki/Setup-Guide)
- [FreeRDP — Apache-2.0 upstream repository](https://github.com/FreeRDP/FreeRDP)

### Standards

- [IETF RFC 9221 — An Unreliable Datagram Extension to QUIC](https://www.rfc-editor.org/rfc/rfc9221)

### Other

- No third-party commentary, benchmarks, social posts, or copied competitor code were used as evidence.

## Candidate experiments

- Does matched Windows→Linux hardware meet a predefined optical input-to-photon target under 0%, 1%, and 3% loss?
- Does low-delay H.264 4:2:0 meet a predefined small-text task-accuracy threshold against an RDP reference session?
- Does every target GPU/driver/compositor cell sustain a 30-minute bounded-pool stream with an identified import-or-copy path?
- Does the proposed session state machine select the authorized direct, relay, or TCP-fallback path correctly for deterministic NAT cases?
- Does pair/revoke/reconnect testing leave no stuck input or stale authorization across focus loss and permission revocation?
- Can an independently assigned clean-room reviewer reproduce each compatibility requirement from public specifications and black-box behavior alone?
