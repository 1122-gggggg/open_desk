# Competitor and Adjacent-System Lessons

This document records design lessons, not code provenance or unverified performance claims.

| System | Preserve as a design lesson | Limitation/gap relevant to LatencyDesk | LatencyDesk response |
|---|---|---|---|
| AnyDesk | desktop-aware compression and responsive cursor/UI focus | proprietary implementation; platform capabilities differ | independent staged base-video + exact refinement design |
| RustDesk | cross-platform product model, self-hosting, rendezvous/relay UX | general-purpose media architecture and copyleft source boundary | keep infrastructure lessons; clean-room permissive media core |
| Parsec | hardware encode/decode, high frame rate, 4:4:4-quality modes | game/creative-stream emphasis and platform host matrix | retain GPU discipline; add native Wayland host and desktop refinement |
| Sunshine/Moonlight | low-latency game-stream pipeline, pacing, recovery/telemetry | game-stream semantics; GPL implementation boundary | study public behavior/specs; independently implement remote-desktop channels |
| Microsoft RDP | separate virtual channels, graphics/video specialization, mature input semantics | Windows-centric and large protocol surface | use channel separation without reproducing full RDP complexity |
| FreeRDP | open protocol interoperability and permissive implementation reference | RDP semantics differ from the proposed engine | use only where a reviewed component boundary is preferable |
| NoMachine/NX | desktop-content optimization and cache concepts | proprietary/current architecture details and legacy X11 assumptions | modern GPU base plus exact cache/refinement research |
| Amazon DCV | UDP/QUIC-oriented remote visualization and quality modes | proprietary/cloud/enterprise orientation | preserve transport fallback and quality-mode lessons |

## Rules derived from the review

1. Do not compete on feature count before the native media path is measured.
2. Do not compare vendor-reported latency with our internal API timing.
3. Treat local cursor, input reconciliation, and bounded queues as first-class latency features.
4. Support standard Wayland portals before privileged compositor/KMS shortcuts.
5. Preserve a complete video recovery path before adding tile/static refinements.
6. Keep competitor code out of the permissive implementation; use official specifications and clean-room behavior tests.
7. Benchmark each workload separately: desktop text, scroll, video, 3D, weak network.
