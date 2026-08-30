# ADR 0008: Input and multi-target isolation

**Status:** Accepted

**Date:** 2026-08-30

## Context

The secure client previously described one target per process, and the Linux
X11 Host decoded and injected input inside the same coordination loop that ran
blocking root capture, CPU conversion, software H.264 encode, and media
fragmentation. Separate QUIC lanes prevented media stream head-of-line blocking,
but local capture/encode work could still postpone XTEST injection. Control and
input streams also retained Quinn's equal default priority.

Supporting one controller connected to several computers must not create an
unbounded in-process fan-out or let one target's renderer/network failure corrupt
another target's state.

## Decision

1. The Client accepts 2–16 unique `--target <ADDR>,<PEER_CERT>` entries. It
   starts the same executable once per target with explicit argument arrays, an
   ephemeral bind port, the shared client identity, and that target's exact Host
   certificate. Each child owns its runtime, QUIC endpoint, queues, decoder, and
   viewer. A spawn failure terminates and reaps children already created.
2. The Linux secure Host opens a distinct X11 connection for input and runs
   reliable input receive, reconciliation, XTEST injection, and `ReleaseAll` in
   an independent Tokio task. Only one terminal lifecycle status crosses a
   capacity-one channel to the media loop. Every terminal input path reaches
   cleanup before publishing its status; normal shutdown uses a oneshot request
   and awaits the worker instead of aborting it.
3. The persistent QUIC input send stream uses Quinn priority 1 and control uses
   priority 0. Quinn documents that higher-priority streams transmit locally
   buffered data before lower-priority streams. Only two levels are used.
4. The deterministic stress executable overlaps eight session workers behind a
   barrier. Each runs four network profiles and must preserve frame accounting.
   Under a saturated realtime-video scheduler, each session must service input
   on its first pop.

## Consequences

- A controller can open several exact-pinned Hosts with one command while
  keeping failures and queue state isolated by an OS process boundary.
- Linux input is no longer locally serialized behind capture, conversion,
  software encode, or media fragmentation. Cleanup remains fail-closed.
- Input transition bytes take precedence over reliable control chatter once
  both streams contain locally buffered data. Media continues to use bounded,
  expiring QUIC DATAGRAMs.
- Process startup and memory are duplicated per target. This is an intentional
  alpha tradeoff until a native multi-window session manager has equivalent
  isolation and lifecycle evidence.
- This decision does not allow multiple controllers on one Host, implement
  rendezvous/relay, prove cross-machine multi-target operation, or establish a
  universal latency advantage.

## Sources

- Quinn 0.11.8 stream priority:
  https://docs.rs/quinn/0.11.8/quinn/struct.SendStream.html#method.set_priority
- RustDesk video service and license boundary:
  https://github.com/rustdesk/rustdesk/blob/master/src/server/video_service.rs
  and https://github.com/rustdesk/rustdesk/blob/master/LICENCE
- Sunshine low-latency encoder configuration:
  https://github.com/LizardByte/Sunshine/blob/master/docs/configuration.md
- Moonlight frame-pacing guidance:
  https://github.com/moonlight-stream/moonlight-docs/wiki/Frequently-Asked-Questions
- Selkies WebRTC/congestion-control notes:
  https://github.com/selkies-project/selkies/blob/main/docs/faq.md
