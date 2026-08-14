# Development Roadmap and Acceptance Gates

This roadmap is ordered by dependency risk. A milestone starts only when the previous exit gate is green. Feature count is not a substitute for a measured pipeline.

## M0 — Audited core and contracts (current repository)

**Deliverables**

- protocol header with allocation/range limits;
- session state machine;
- deadline/priority/byte-bounded scheduler;
- decoder continuity tracker;
- separate host/client timing models;
- platform, security, licensing, benchmark specifications;
- CI and static validation.

**Exit gate**

- `cargo fmt`, Clippy with warnings denied, and all workspace tests pass on Windows and Linux CI;
- structural validator passes;
- no unreviewed external runtime dependencies;
- protocol fuzz target design approved.

## M1 — Deterministic loopback laboratory

**Deliverables**

- fake capture source producing deterministic BGRA/NV12 patterns;
- exact raw or simple lossless test codec with strict dimensions and byte limits;
- in-memory transport that can delay, reorder, duplicate, corrupt, and drop packets;
- bounded fragmenter/reassembler;
- input event + state-snapshot model;
- trace exporter in JSON/CSV;
- property/fuzz tests for all untrusted parsers.

**Exit gate**

- 10 million randomized protocol operations without unbounded allocation or crash;
- deterministic reconstruction under no loss;
- expected recovery under loss/reorder/duplication;
- forced queue saturation proves input/control are not blocked by stale media;
- disconnect releases all simulated keys/buttons.

## M2 — Windows native baseline

**Deliverables**

- per-user Windows agent and minimal service/IPC boundary;
- DDA full-output capture; WGC capability probe/secondary path;
- bounded capture lease and encoder-owned surface pool;
- first hardware H.264 provider, preferably NVENC reference hardware;
- Windows hardware decode and D3D11 presentation;
- Windows input injection within documented integrity boundary;
- local cursor metadata/rendering;
- LAN QUIC control/media prototype or deterministic UDP lab transport before QUIC lands.

**Exit gate**

- Windows → Windows 1080p60 and 1440p120 reference tests;
- 30-minute capture/encode soak with stable memory and queue depth;
- forced GPU-copy fallback produces correct output;
- packet loss causes bounded recovery, not decoder corruption;
- no secure-desktop/UAC capability is implied.

## M3 — Windows host → Linux Wayland client

**Deliverables**

- Linux hardware decode provider on reference NVIDIA hardware;
- Linux Wayland renderer with bounded presentation queue;
- coordinate/color conformance tests;
- Linux local cursor path;
- packaging for one supported GNOME and KDE distribution family.

**Exit gate**

- Windows → Linux at 1080p60 and 1440p120 where display supports it;
- Linux render queue never grows beyond configured cap;
- copy fallback works when GPU import is disabled;
- optical screen-to-screen benchmark protocol runs end-to-end.

## M4 — Linux Wayland host → Windows client

**Deliverables**

- XDG RemoteDesktop/ScreenCast portal flow;
- PipeWire capture with DMA-BUF capability negotiation and MemFd/copy fallback;
- libei input path where available;
- portal cancellation/revocation/session-end handling;
- Linux host color/scale/rotation metadata;
- Windows client input mapping and release reconciliation.

**Exit gate**

- Linux → Windows bidirectional control on supported GNOME and KDE matrices;
- permission revoke terminates capture/input immediately;
- DMA-BUF disabled test passes through copy path;
- no capture lease or PipeWire buffer starvation in soak tests;
- packet loss/reconnect cannot leave keys pressed.

At this point the project has the first real Windows/Linux bidirectional product slice.

## M5 — Production transport and provider matrix

**Deliverables**

- QUIC/TLS connection with reliable control and DATAGRAM media/input;
- path-MTU-safe packetization and bounded reassembly;
- bitrate/frame-rate/resolution adaptation from congestion feedback;
- reconnect and codec epoch handling;
- Intel/AMD encoder/decoder provider expansion;
- direct LAN discovery;
- capability matrix and actionable diagnostics.

**Exit gate**

Test at minimum:

| Profile | RTT | Loss | Jitter | Gate |
|---|---:|---:|---:|---|
| LAN | <2 ms | 0–0.1% | low | no avoidable queueing |
| Good WAN | 20 ms | 0.5% | 5 ms | stable p95, rapid recovery |
| Moderate WAN | 60 ms | 1–2% | 15 ms | adaptation, no multi-second spike |
| Adverse | 100 ms | 3–5% | 30 ms | graceful quality reduction, bounded memory |

Provider releases require both zero-copy-capable and forced-copy tests where applicable.

## M6 — Sparse exact desktop refinement

**Prerequisite:** M5 benchmark baseline is frozen and traceable.

**Deliverables**

- GPU/CPU tile change detector;
- exact tile payload format and hash verification;
- bounded client tile cache;
- display/config/tile epochs;
- static-idle refinement policy;
- text/UI clarity benchmark;
- bandwidth/latency policy model.

**Exit gate**

Against the full-frame H.264 baseline, on IDE/terminal/browser workloads:

- statistically significant text clarity or bandwidth improvement;
- no p95 input-to-photon regression beyond the predefined tolerance;
- lost refinement packets never corrupt the base image;
- resize/reconfigure cannot apply stale tiles;
- video workload automatically suppresses wasteful refinement.

Only after this gate may region-specific video coding experiments begin.

## M7 — Internet operation, relay, packaging, and constrained unattended modes

**Deliverables**

- ICE/STUN connectivity;
- E2E-encrypted relay fallback with abuse controls;
- secure device enrollment and pairing UX;
- signed installers/packages and update design;
- crash reporting with privacy controls;
- narrowly defined unattended modes by OS/compositor capability;
- optional audio, clipboard, and file transfer only after separate threat reviews.

**Exit gate**

- third-party security review;
- relay cannot read content plaintext;
- rate limiting and operational monitoring tested;
- secrets stored using OS facilities;
- signed release provenance and SBOM;
- documentation states exact unattended support matrix, never “all Wayland.”

## Performance claim policy

A claim such as “faster than X” requires:

1. exact competitor and project versions;
2. same host/client hardware, display refresh, resolution, codec class, and network profile;
3. optical input-to-photon/screen-to-screen measurement;
4. at least p50/p95/p99 and failure/recovery statistics;
5. public scripts and raw results;
6. separate desktop, scrolling, video, and 3D workloads.

Before these conditions are met, use only descriptive statements such as “latency-first architecture” or “targets low queue depth.”
