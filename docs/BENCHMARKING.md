# Reproducible Benchmark Specification

LatencyDesk cannot be validated by encoder API timings alone. The benchmark suite separates software stages, network behavior, visual quality, and physical input-to-photon latency.

## 1. Claim categories

1. **Internal stage metrics:** capture, conversion/import, encode, queue, network, decode, present submission.
2. **Network metrics:** RTT, delivered bitrate, loss, reordering, recovery requests, blackout duration.
3. **Visual metrics:** exact tile correctness, PSNR/SSIM/VMAF where appropriate, text-edge/chroma tests, subjective inspection.
4. **Physical E2E metrics:** input-to-photon and screen-to-screen using optical/high-speed equipment.

Only category 4 supports a broad latency claim. Host and client monotonic timestamps belong to different clock domains and cannot be directly subtracted.

## 2. Required per-frame telemetry

Host-local:

- capture sequence/time;
- capture backend and copy/import path;
- conversion begin/end;
- encode submit/output;
- codec epoch/frame/dependency/recovery status;
- application queue time and drop reason;
- send time.

Client-local:

- first/last fragment receive;
- reassembly result;
- decode submit/output;
- continuity decision;
- presentation submit;
- renderer queue depth and frame selected/dropped.

Session-level:

- RTT, loss, reordering, congestion state;
- bitrate/resolution/frame rate changes;
- CPU/GPU/memory/VRAM;
- recovery request count and recovery blackout duration;
- input reconciliation corrections.

Report p50, p95, p99, maximum, sample count, and confidence interval where applicable. Mean alone is insufficient.

## 3. Hardware matrix

Record exact:

- host/client CPU, GPU, driver, RAM;
- OS/build, kernel, desktop environment/compositor, portal backend;
- display resolution, refresh rate, VRR, HDR, scaling;
- network adapter/link and router/switch;
- codec/profile/rate-control parameters;
- application/competitor version;
- power mode and thermal state.

Reference development begins with one NVIDIA-equipped Windows machine and one NVIDIA-equipped Linux Wayland machine to reduce provider variables. Intel and AMD are separate matrix expansions, not assumed equivalent.

## 4. Workloads

Each run includes at least:

1. static IDE with repeated typing/cursor movement;
2. terminal text scroll;
3. browser page scroll and tab switching;
4. 1080p/60 video playback;
5. 3D/game-like motion;
6. mixed static UI plus video region;
7. resize, display-scale change, and reconnect;
8. five-minute idle/static refinement test after M6.

Workload automation and source content must be committed or reproducibly generated.

## 5. Network profiles

Use Linux `tc/netem` or an equivalent controlled shaper. Record actual observed values.

| Name | RTT target | Loss | Jitter | Bandwidth |
|---|---:|---:|---:|---:|
| Clean LAN | <2 ms | 0–0.1% | <1 ms | link capacity |
| Good WAN | 20 ms | 0.5% | 5 ms | 50 Mbps |
| Moderate WAN | 60 ms | 1–2% | 15 ms | 15 Mbps |
| Constrained | 100 ms | 3% | 30 ms | 8 Mbps |
| Adverse/recovery | 100 ms | 5% burst | 30 ms | 5 Mbps |

Loss profiles must include independent and burst loss. Run at least 30 repetitions for short physical tests and long enough software traces to include adaptation/recovery events.

## 6. Optical measurement

### Input-to-photon

A reproducible rig should produce a physical input and observe the first changed client-display scanout:

- microcontroller/actuator or instrumented mouse/keyboard signal;
- host application toggles a high-contrast region immediately on input;
- high-speed camera or photodiode/logic analyzer observes input trigger and client luminance change;
- account for display scan direction and refresh period;
- publish raw traces and event-selection method.

### Screen-to-screen

Toggle an LED/high-contrast host region synchronized to capture source, film host and client displays in one high-speed frame, and calculate the frame/time offset. This includes capture scheduling, codec/network, compositor, and scanout.

Do not label `capture_ts → present_submit_ts` as physical E2E latency.

## 7. Competitor comparison rules

For AnyDesk, RustDesk, Sunshine/Moonlight, Parsec, RDP, or another system:

- exact public version and settings;
- same machines, displays, network profile, resolution, and frame-rate target;
- comparable chroma/quality/bitrate where configurable;
- warm-up before measurement;
- no cherry-picked single best sample;
- disclose feature differences and vendor-only metrics;
- distinguish desktop-control and game-streaming products;
- report failures, disconnects, black frames, and recovery time.

A valid conclusion is workload-specific, for example: “On the defined 1440p120 LAN IDE workload and reference hardware, LatencyDesk commit X had lower optical p95 input-to-photon than product Y version Z.” It is not “faster everywhere.”

## 8. M6 desktop-refinement gates

Compare H.264 baseline and refinement mode using identical interaction traces. Required outputs:

- bitrate distribution;
- p50/p95/p99 input-to-photon;
- text/chroma edge score and exact-tile verification;
- number/bytes of refinement tiles;
- stale/rejected tiles;
- CPU/GPU cost;
- video workload suppression behavior.

Refinement ships only when it improves clarity or bandwidth without exceeding the predefined latency/compute tolerance.
