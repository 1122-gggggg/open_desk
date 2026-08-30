# Product readiness gates

This checklist separates tested engineering foundations from a supported
remote-desktop product. Current assessment: **secure alpha; not
production-ready; no demonstrated superiority over AnyDesk or RustDesk**.

## Evidence policy

- **Verified** always names its scope. Unit, in-process integration, native
  process E2E, cross-machine E2E, soak, and independent verification are
  different evidence levels and are never interchangeable.
- **Pending** means the executable path is incomplete, the real environment was
  not exercised, evidence was not retained, or the result failed its threshold.
- Security gates fail closed. A fallback to `--unsafe-udp-lab` is a failed secure
  test even if frames arrive.
- Every result records the exact revision, commands, OS/build, CPU/GPU, displays,
  resolution/fps, codec/quality, network shaping, duration, logs, and raw metrics.
- Missing, zero-filled, or schema-incomplete metrics invalidate a comparison.

## Verified engineering scope

| Status | Scope | Reproduction and limitation |
| --- | --- | --- |
| Verified — targeted unit/in-process | Persistent identity generation/load, no-overwrite behavior, exact-server rejection, unpinned-client rejection, mTLS peer chains, and QUIC datagrams | `cargo test --locked -p latencydesk-socket-transport -p latencydesk-identity -p latencydesk-host -p latencydesk-client`; does not start two native app processes |
| Verified — targeted unit/in-process | Product handshake stamp, reliable input lane, stamp mismatch rejection, path-MTU-bounded fragmentation, and multi-fragment media reassembly | Same command; synthetic in-process peers only |
| Verified — targeted unit/in-process | Quinn input-stream priority is higher than control; multi-target CLI validation produces isolated exact-pin child plans and rejects unsafe/conflicting bounds | `cargo test --locked -p latencydesk-socket-transport -p latencydesk-client`; scheduling state and process plans only, not physical latency or cross-machine execution |
| Verified — targeted unit/in-process | Up to four known addresses are raced without waiting for an unreachable first address; the winner still completes exact-leaf mTLS; router timeouts are generation-relative and cannot invent an unallocated relay | `cargo test --locked -p latencydesk-socket-transport -p latencydesk-session -p latencydesk-client`; known-address loopback only, not ICE/STUN/TURN |
| Verified — targeted unit/in-process | RFC 8489 Binding request/success parsing is bounded; cookie/type/length/TLV/fingerprint/XOR-MAPPED IPv4/IPv6 are checked; exact source and CSPRNG transaction match are required; spoofed, stale, malformed, and unusable mappings are boundedly ignored; retransmission/deadline policy is capped; an existing UDP socket retains its port when handed to Quinn | `cargo test --locked -p latencydesk-protocol -p latencydesk-socket-transport -p latencydesk-client`; parser/socket integration only, not candidate signaling, ICE nomination/consent, NAT traversal, rendezvous, TURN, or relay |
| Verified — targeted unit/in-process | Caller-supplied lifecycle stamps survive the product handshake; successor Clients require a different session ID and strictly newer generation, authorization, display, and codec epochs; stale disconnects cannot close a successor; one QUIC endpoint accepts a second clean session | `cargo test --locked -p latencydesk-socket-transport -p latencydesk-session`; in-process exact-peer sessions only |
| Verified — targeted unit/in-process | Only authenticated QUIC reset/idle-timeout and bounded candidate timeout are classified retryable; retry count/delay/deadline are bounded; disconnected input epochs remain retired and delayed key/button/snapshot records cannot reactivate them | `cargo test --locked -p latencydesk-socket-transport -p latencydesk-session -p latencydesk-input -p latencydesk-client -p latencydesk-host`; injected error/state transitions only |
| Verified — deterministic concurrent simulation | Eight isolated workers start behind a barrier, each runs four loss/jitter profiles, all 32 session/profile identities remain unique, frame accounting is exact, and saturated video queues service input on the first scheduler pop | `cargo run --locked -p latencydesk-stress`; deterministic software simulation only, without native capture, codecs, sockets, displays, or physical input |
| Verified — CLI unit | Host/client default to secure mode; incomplete identities, mixed secure/lab flags, and legacy flags without `--unsafe-udp-lab` are rejected | Same command; parser behavior only |
| Verified — Linux process loopback (Xvfb/headless) | A rogue certificate is rejected without killing the Host, then two sequential exact-pinned Client connections use an unreachable-primary/fallback race, receive real X11 frames, show distinct monotonic lifecycle stamps, and complete ReleaseAll between sessions | `xvfb-run -a python3 scripts/secure_connect_test.py --host-bin target/debug/latencydesk-host --client-bin target/debug/latencydesk-client --identity-bin target/debug/latencydesk-identity --frames 3 --fps 10 --max-width 320 --max-height 180 --pairing-timeout 30 --output artifacts/secure-connect.json`; single-machine headless process evidence only, excluding abrupt-loss recovery, a Windows viewer, visible input effects, packet capture, cross-machine operation, and soak |
| Verified — Linux same-socket STUN→QUIC process loopback (Xvfb/headless) | A strict fake Binding server validates the Client request/fingerprint and reports its source address. Client local/srflx, fake-server-observed source, and Host-observed authenticated QUIC source must be identical; the same path then completes exact-mTLS, lifecycle, real X11 stream, requested frames, and ReleaseAll | `xvfb-run -a python3 scripts/stun_same_socket_test.py --host-bin target/debug/latencydesk-host --client-bin target/debug/latencydesk-client --identity-bin target/debug/latencydesk-identity --frames 3 --timeout 45 --output artifacts/stun-same-socket.json`; local fake-STUN socket handoff only, excluding candidate exchange, ICE checks/nomination/consent, actual NAT traversal, DNS discovery, TURN/relay, cross-machine operation, and connectivity-rate claims |
| Verified — Linux process fault injection (Xvfb/headless) | A bounded UDP proxy blackholes both directions after the first real X11 stream, QUIC reaches idle timeout, Host completes ReleaseAll without dropping its endpoint, and Client reruns exact-mTLS plus the full product handshake; the successor must authenticate within 2 s after the path is restored and alone completes the frame target | `xvfb-run -a python3 scripts/abrupt_reconnect_test.py --host-bin target/debug/latencydesk-host --client-bin target/debug/latencydesk-client --identity-bin target/debug/latencydesk-identity --frames 3 --drop-seconds 4 --output artifacts/abrupt-reconnect.json`; single-machine loopback fault evidence only, excluding physical Wi-Fi/cellular handoff, cross-machine recovery-time claims, interactive rendering, and soak |
| Verified — Linux multi-target process isolation (Xvfb/headless) | One Client supervisor launches two isolated children against two simultaneously active distinct-certificate Hosts; exact session-ID sets, routes, real desktop streams, frames, natural exits, and certificate pins all match. A second phase proves an unreachable child is reported without preventing its healthy sibling from completing | `xvfb-run -a python3 scripts/multi_target_connect_test.py --host-bin target/debug/latencydesk-host --client-bin target/debug/latencydesk-client --identity-bin target/debug/latencydesk-identity --frames 5 --fps 10 --max-width 320 --max-height 180 --output artifacts/multi-target-connect.json`; two-Host single-machine evidence only, excluding cross-machine 2/4/8/16-Host resource, latency, UI, and soak claims |
| Verified — Linux input application-ACK process latency (Xvfb/headless) | 128 opt-in relative-pointer probes each receive a full-stamp, sequence-bound ACK only after reconciliation, XTEST submission, and a subsequent X11 reply; raw samples are retained, summaries are recomputed, and loopback p95 must remain below the 100 ms stall ceiling | `xvfb-run -a python3 scripts/secure_input_latency_test.py --host-bin target/debug/latencydesk-host --client-bin target/debug/latencydesk-client --identity-bin target/debug/latencydesk-identity --samples 128 --timeout 30 --output artifacts/secure-input-latency.json`; application ACK RTT only, excluding physical input-to-photon, cross-machine/network-shaped distributions, interactive workloads, and AnyDesk/RustDesk comparison |
| Verified — concurrent Linux multi-target input application-ACK and process topology scale (Xvfb/headless) | One supervisor launches 2/4/8/16 exact-pinned children against the same number of distinct-certificate Hosts. Flushed full-stamp start/stop markers prove every interval overlaps; 2/4 targets retain 256 samples per Host and 8/16 retain 1024 so every process remains alive through two `/proc` snapshots. Each target independently passes raw sequence/statistic, route, lifecycle, certificate, mTLS, real-stream, ReleaseAll, exit, cleanup, and binary-hash checks. At the overlap point, `/proc` gates the exact Client/Host process groups, stable PID/start-time/executable identities, and the two-worker runtime thread bound while retaining RSS/CPU-tick/FD/thread observations | `for n in 2 4 8 16; do samples=256; [ "$n" -ge 8 ] && samples=1024; xvfb-run -a python3 scripts/multi_target_input_latency_test.py --host-bin target/debug/latencydesk-host --client-bin target/debug/latencydesk-client --identity-bin target/debug/latencydesk-identity --target-count "$n" --samples "$samples" --timeout 120 --output "artifacts/multi-target-input-latency-${n}.json"; done`; single-machine application ACK/point-in-time process evidence only, excluding physical input-to-photon, cross-machine/network-shaped workloads, leak-free long resource soak, and AnyDesk/RustDesk comparison |
| Verified — Windows development environment | The plaintext loopback harness has exchanged bounded synthetic/fallback frames and validates process exits, matching session IDs, and frame count | `python scripts/remote_connect_test.py --mode loopback --frames 8 --host-frames 16 --fps 30`; legacy lab evidence only, not a secure product gate |

The full workspace commands remain release requirements:

```bash
cargo build --workspace --locked
cargo test --workspace --all-targets --locked
cargo test --workspace --doc --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
```

A green workspace validates the revision's automated scope; it does not promote
any native or network gate below.

## Security and identity release gates

| Status | Required gate | Measurable acceptance evidence |
| --- | --- | --- |
| Pending | Default secure app process handshake | Separate host/client processes complete TLS 1.3 mTLS and the product handshake; wrong server, wrong client, missing pin, corrupt key, and mixed legacy flags all fail before media/input activation |
| Pending | Exact identity and confidentiality on a real network | Packet capture confirms no plaintext desktop/input and no legacy UDP; logs/fingerprints identify exactly the exchanged leaf certificates |
| Pending | Pairing, key storage, rotation, and revocation | Trusted-channel or authenticated pairing UX, OS-protected keys, explicit consent, rotation/revoke/recovery tests, and documented lost-device response |
| Pending | Session authorization and replay resistance | Process E2E tests reject replay, stale/cross-session stamps, reconnect-era input, revoked consent, malformed sequencing, and held-key leaks |
| Pending | Parser and resource-exhaustion assurance | Continuous fuzzing covers all untrusted formats; malformed/oversized fragments and frame metadata stay within declared CPU, memory, stream, and queue bounds |
| Pending | Independent security review | Defined scope and revision, no unresolved critical/high findings, remediation verification, and published summary |

## Native functionality gates

| Status | Required gate | Measurable acceptance evidence |
| --- | --- | --- |
| Pending | Linux X11 Host to Windows Viewer secure E2E | Real, recognizable screen changes render correctly for 30 minutes at 640×360/15 and 1280×720/30; no synthetic/fallback pixels; matching session/fingerprint evidence retained |
| Pending | Secure XTEST input E2E | Keyboard, pointer, buttons, wheel, absolute coordinates, focus loss, disconnect, and `ReleaseAll` are verified on a disposable X11 session with no stuck inputs |
| Pending | Windows Viewer correctness and recovery | Strict NV12 decode/presentation is content-checked; resize/DPI, multi-monitor geometry, cursor, renderer reset, corrupt frame, and window-close cleanup pass |
| Pending | Windows secure Host | Real DDA/WGC capture, encode, input consent/privilege gate, display epoch changes, protected-content policy, lock/UAC behavior, and GPU reset are connected and tested |
| Pending | Linux interactive Client validation | Existing software viewer/input path passes the same content, lifecycle, resize/DPI, and recovery matrix as Windows on supported target systems |
| Pending | Wayland Host | Portal/PipeWire capture and libei input pass GNOME/KDE consent, restore/revoke, format fallback, and session cleanup tests |
| Pending | Production video codec | At least H.264 or AV1 has interoperable hardware/software paths, bounded encode/decode queues, rate control, IDR recovery, corruption handling, and objective quality tests |

## Connectivity, reliability, and operations gates

| Status | Required gate | Measurable acceptance evidence |
| --- | --- | --- |
| Pending | Direct LAN reliability | 30-minute IPv4 and IPv6 runs for each advertised platform/profile with bounded memory, no stuck input, no unhandled disconnect, and retained p50/p95/p99 metrics |
| Pending | Multi-target Client reliability | One controller keeps 2, 4, 8, and 16 exact-pinned cross-machine sessions active under mixed workloads; one target's failure does not stall or terminate healthy targets; per-target CPU/GPU/memory/bandwidth and input-to-photon distributions are retained |
| Pending | NAT traversal and rendezvous | Reproducible connection matrix for full-cone, restricted, port-restricted, symmetric NAT, CGNAT, IPv6, and common firewall cases |
| Pending | End-to-end secure relay | Forced-relay tests prove the relay cannot decrypt content; authentication, capacity, abuse controls, regional failure, and cost limits are exercised |
| Partial | Reconnect and network handoff | Linux X11 Host/headless Client support clean successors and bounded automatic recovery from loopback-blackholed QUIC idle timeout, with fresh lifecycle stamps and ReleaseAll before successor activation; interactive recovery, Windows Host persistence, cable/Wi-Fi handoff, suspend/resume, cross-machine soak, and the declared physical recovery-time target remain Pending |
| Pending | Loss, jitter, and congestion behavior | 30-minute 0/1/3/5% loss profiles plus controlled delay/jitter report recovery time, frame drops, bitrate, quality, input latency, CPU/GPU, and memory |
| Pending | Signed packaging and updates | Reproducible builds, SBOM/provenance, platform signatures, clean install/upgrade/rollback/uninstall, tamper rejection, staged rollout, and signing-key revocation drill |
| Pending | Operational diagnostics | Opt-in/redacted logs, bounded retention, crash reports, session audit events, alerting, service ownership, and documented SLO/incident procedure |

## Performance and competitive gates

| Status | Required gate | Measurable acceptance evidence |
| --- | --- | --- |
| Pending | Practical bandwidth | A production codec supports each advertised profile within its declared bitrate/quality envelope; raw NV12 results are labeled preview-only and excluded from WAN superiority claims |
| Pending | Ground-truth interaction latency | High-speed camera or equivalent external measurement reports input-to-photon p50/p95/p99 and confidence intervals; internal timestamps alone are insufficient |
| Pending | Fair competitor baseline | Public protocol records exact competitor versions/settings, identical content and input workload, codec/quality target, hardware/display/network shaping, warm-up, repeated trials, raw data, and failures |
| Verified — evidence parser | A strict optical comparison rejects metrics-only claims, caller-supplied hashes without parsed raw samples, fewer than 30 analyzed physical samples, identical samples, and degenerate p95 confidence intervals | `python3 -m unittest scripts.tests.test_optical_latency_benchmark`; validates evidence structure only and supplies no physical measurements |
| Pending | Meaningful superiority threshold | `optical_latency_benchmark.py superiority-gate` passes at least one LAN and one WAN profile with the pre-registered p95 margin (default 20%), non-overlapping p95 confidence intervals, no p99 regression, and no worse declared quality, reliability, bandwidth, or security guardrails |
| Pending | Independent reproduction | A third party reproduces the exact revision and protocol, publishes uncertainty and regressions as well as wins, and retains machine-readable results |

## Promotion criteria

- **Developer preview:** secure native process E2E for one real
  capture/view/input slice, wrong-peer negative tests, and a 30-minute direct-LAN
  run are Verified. Raw NV12 remains visibly labeled preview-only.
- **Beta:** a production codec, supported direct plus relay connectivity,
  reconnect/loss behavior, installers/updates, and a closed independent security
  assessment are Verified for every advertised platform.
- **Production:** every advertised capability has native and cross-machine
  evidence; release/operations procedures and SLOs are exercised; there are no
  unresolved critical/high security findings.
- **“Surpasses competitor” claim:** production criteria plus the fair benchmark,
  pre-registered superiority threshold, and independent-reproduction gates are
  all Verified for the exact claim. Architecture diagrams, unit tests, raw NV12,
  loopback, or missing/zero measurements never satisfy this gate.
