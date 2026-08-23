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
| Verified — CLI unit | Host/client default to secure mode; incomplete identities, mixed secure/lab flags, and legacy flags without `--unsafe-udp-lab` are rejected | Same command; parser behavior only |
| Verified — Linux process loopback (Xvfb/headless) | A rogue certificate is rejected without killing the Host, then the exact pinned Client completes TLS 1.3 mTLS and the product handshake and receives three real 320×180 X11 frames at 10 fps | `xvfb-run -a python3 scripts/secure_connect_test.py --host-bin target/debug/latencydesk-host --client-bin target/debug/latencydesk-client --identity-bin target/debug/latencydesk-identity --frames 3 --fps 10 --max-width 320 --max-height 180 --pairing-timeout 30 --output artifacts/secure-connect.json`; single-machine process evidence only, excluding a Windows viewer, visible input effects, packet capture, cross-machine operation, and soak |
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
| Pending | Linux interactive Client | Real viewer/input implementation passes the same content, lifecycle, and recovery matrix as Windows |
| Pending | Wayland Host | Portal/PipeWire capture and libei input pass GNOME/KDE consent, restore/revoke, format fallback, and session cleanup tests |
| Pending | Production video codec | At least H.264 or AV1 has interoperable hardware/software paths, bounded encode/decode queues, rate control, IDR recovery, corruption handling, and objective quality tests |

## Connectivity, reliability, and operations gates

| Status | Required gate | Measurable acceptance evidence |
| --- | --- | --- |
| Pending | Direct LAN reliability | 30-minute IPv4 and IPv6 runs for each advertised platform/profile with bounded memory, no stuck input, no unhandled disconnect, and retained p50/p95/p99 metrics |
| Pending | NAT traversal and rendezvous | Reproducible connection matrix for full-cone, restricted, port-restricted, symmetric NAT, CGNAT, IPv6, and common firewall cases |
| Pending | End-to-end secure relay | Forced-relay tests prove the relay cannot decrypt content; authentication, capacity, abuse controls, regional failure, and cost limits are exercised |
| Pending | Reconnect and network handoff | After cable/Wi-Fi loss, address change, suspend/resume, or QUIC close, session recovery completes within the declared target and never replays stale input; no current reconnect exists |
| Pending | Loss, jitter, and congestion behavior | 30-minute 0/1/3/5% loss profiles plus controlled delay/jitter report recovery time, frame drops, bitrate, quality, input latency, CPU/GPU, and memory |
| Pending | Signed packaging and updates | Reproducible builds, SBOM/provenance, platform signatures, clean install/upgrade/rollback/uninstall, tamper rejection, staged rollout, and signing-key revocation drill |
| Pending | Operational diagnostics | Opt-in/redacted logs, bounded retention, crash reports, session audit events, alerting, service ownership, and documented SLO/incident procedure |

## Performance and competitive gates

| Status | Required gate | Measurable acceptance evidence |
| --- | --- | --- |
| Pending | Practical bandwidth | A production codec supports each advertised profile within its declared bitrate/quality envelope; raw NV12 results are labeled preview-only and excluded from WAN superiority claims |
| Pending | Ground-truth interaction latency | High-speed camera or equivalent external measurement reports input-to-photon p50/p95/p99 and confidence intervals; internal timestamps alone are insufficient |
| Pending | Fair competitor baseline | Public protocol records exact competitor versions/settings, identical content and input workload, codec/quality target, hardware/display/network shaping, warm-up, repeated trials, raw data, and failures |
| Pending | Meaningful superiority threshold | On at least two representative LAN/WAN profiles, LatencyDesk beats the best measured baseline by a pre-registered margin (for example p95 latency) without worse declared quality, reliability, bandwidth, or security guardrails |
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
