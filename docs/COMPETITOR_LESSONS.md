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

## 2026-08-30 low-latency review

- RustDesk's video service demonstrates per-session codec selection, hardware
  encode paths, quality-of-service feedback, and fallbacks. The reusable lesson
  is bounded per-session ownership and adaptation, not implementation code;
  RustDesk's AGPL license remains outside this permissive clean-room core.
  Sources: [video service](https://github.com/rustdesk/rustdesk/blob/master/src/server/video_service.rs),
  [license](https://github.com/rustdesk/rustdesk/blob/master/LICENCE).
- Sunshine documents low-latency hardware encoder controls, including fast
  presets and single-frame VBV behavior. Moonlight documents the latency cost of
  queued presentation and its lowest-latency pacing mode. The reusable lesson is
  to keep capture/encode/present queues shallow and drop obsolete video rather
  than buffering interaction behind it. Sources: [Sunshine configuration](https://github.com/LizardByte/Sunshine/blob/master/docs/configuration.md),
  [Moonlight FAQ](https://github.com/moonlight-stream/moonlight-docs/wiki/Frequently-Asked-Questions).
- Selkies documents WebRTC congestion control plus STUN/TURN constraints. The
  reusable lesson is session-local congestion state and relay placement; it does
  not justify replacing the current direct-LAN QUIC path without the EXP-02
  bake-off. Source: [Selkies FAQ](https://github.com/selkies-project/selkies/blob/main/docs/faq.md).
- TigerVNC's framebuffer-update model reinforces damage/dirty-region admission
  for static desktop workloads. Its TCP/RFB behavior is not adopted as the WAN
  media baseline. Source: [TigerVNC](https://github.com/TigerVNC/tigervnc).

The implemented response in this revision is deliberately narrower than those
systems: the client can supervise bounded isolated target processes, Linux X11
input injection runs independently of blocking capture/software encode, Quinn's
reliable input stream is scheduled above control, and the stress gate overlaps
eight deterministic sessions. None of these software invariants proves a broad
competitor latency claim; the optical and fair-comparison gates still apply.
