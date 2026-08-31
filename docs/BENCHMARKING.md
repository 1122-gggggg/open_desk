# Reproducible Benchmark Specification

LatencyDesk cannot be validated by encoder API timings alone. The benchmark suite separates software stages, network behavior, visual quality, and physical input-to-photon latency.

## 1. Claim categories

1. **Internal stage metrics:** capture, conversion/import, encode, queue, network, decode, present submission.
2. **Network metrics:** RTT, delivered bitrate, loss, reordering, recovery requests, blackout duration.
3. **Visual metrics:** exact tile correctness, PSNR/SSIM/VMAF where appropriate, text-edge/chroma tests, subjective inspection.
4. **Physical E2E metrics:** input-to-photon and screen-to-screen using optical/high-speed equipment.

Only category 4 supports a broad latency claim. Host and client monotonic timestamps belong to different clock domains and cannot be directly subtracted.

The strict optical comparison CLI accepts superiority evidence only when it can
parse and hash the raw samples itself, at least 30 analyzed physical repetitions
remain after warm-up, and the p95 bootstrap interval is informative. Metrics-only
JSON and caller-asserted hashes are development inputs, not admissible proof.

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

The legacy structural comparator below checks matched LAN/WAN reports, p95
margin, confidence intervals, and p99. It cannot authorize an AnyDesk
superiority claim because it does not bind local binaries, a physical rig,
paired crossover blocks, or retained misses:

```bash
python3 scripts/optical_latency_benchmark.py superiority-gate \
  --pair artifacts/anydesk-lan.json artifacts/latencydesk-lan.json \
  --pair artifacts/anydesk-wan.json artifacts/latencydesk-wan.json \
  --min-p95-improvement-percent 20 \
  --max-p99-regression-percent 0 \
  --json
```

A passing legacy gate is development feedback only. The physical crossover gate
in Section 9 is the sole machine path for a claim, and independent reproduction
is still required.

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

## 9. Physical AnyDesk crossover gate v2

`scripts/optical_crossover_gate.py` is fail-closed and verifies the installed
AnyDesk binary/version, the supplied local LatencyDesk binary hash, and a
locally opened/fingerprinted optical sensor. Photodiode/microcontroller rigs
must sample at least 100 kHz; a high-speed-camera clock must be at least 1,000
fps. Each
matched LAN and WAN profile contains exactly 10 deterministic randomized paired
blocks; each product/block retains exactly 20 warm-up events and 100 analyzed
events. Missed responses remain samples and are right-censored at 2000 ms.

Every event has a deterministic phase/index ID plus trigger/photon ticks from
the declared single physical clock; missed-event deadlines must equal the
2,000 ms censor. Block hashes include ID, AB/BA order, partition, and events;
the pre-run schedule/config has a separate commitment. Route observations,
settings, calibration, quality, packet capture, reliability, and block traces
must also exist as local files matching their declared hashes.
Both the pre-run commitment and final results manifest require signatures from
a notary public key whose SHA-256 was committed to the repository before data
collection. The trusted key constant is intentionally unset today, so even a
machine with a sensor cannot produce a production PASS until that independent
pre-registration step is reviewed and merged.

Do not set that key merely because the parser tests pass. Activation also
requires reviewed build provenance for the exact LatencyDesk binary, a trusted
acquisition program that derives optical events and VMAF/SSIM/bandwidth/
reliability values from the hashed raw artifacts, and an independently
timestamped append-only record proving preregistration preceded capture. Until
those controls and real sensor hardware exist, this file defines a dormant
fail-closed evidence format—not a completed comparison.

The gate performs a fixed 2,000-repeat, fixed-seed paired-block bootstrap; the
production CLI exposes no repetition override. Both the observed p95
improvement and the lower bound of its 95% interval must clear 20%; candidate
p99, miss rate, completion/disconnect reliability, VMAF/SSIM quality, measured
bandwidth, route class, workload, codec, display, hardware, and network shaping
must not regress or differ. Every raw block is canonicalized and checked against
its SHA-256 before analysis. There is no CLI synthetic-data bypass.

```bash
python3 scripts/optical_crossover_gate.py \
  --candidate-binary target/release/latencydesk-client \
  --pair artifacts/anydesk-lan-v2.json artifacts/latencydesk-lan-v2.json \
  --pair artifacts/anydesk-wan-v2.json artifacts/latencydesk-wan-v2.json \
  --output artifacts/optical-crossover-v2.json
```

Missing AnyDesk, sensor hardware, LAN/WAN coverage, raw events, or any matched
condition returns exit code 2 and `blocked: true`. A pass remains scoped to the
exact builds and rig, and still requires independent reproduction before a
public superiority claim.

For the AnyDesk arm, record the installed binary SHA-256/version and exact
settings. A latency-oriented profile uses `ad.image.quality_preset=2` (optimize
response time); record view/render mode and whether `ad.anynet.direct` is true
or false, and require the same observed `route_class` in both product reports.
These controls come from AnyDesk's official
[advanced options](https://support.anydesk.com/advanced-options) and
[display settings](https://support.anydesk.com/docs/display). The vendor notes
that LAN sessions may otherwise traverse its public network, so a direct LAN
run must also verify the direct-connection indicator described in its official
[LAN troubleshooting guide](https://support.anydesk.com/anydesk-is-slow-despite-having-a-lan-connection).
