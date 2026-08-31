# LatencyDesk (`open_desk`)

> **Secure alpha — not production-ready.** The default product path now uses
> exact-leaf TLS 1.3 mutual authentication over QUIC, but the native platform
> matrix, codec, WAN connectivity, recovery, packaging, and app-level evidence
> are incomplete. LatencyDesk does not yet match or surpass AnyDesk or RustDesk.

LatencyDesk is a Rust remote-desktop project built around fail-closed peer
identity, bounded queues, reliable control/input lanes, and deadline-aware QUIC
media DATAGRAMs. Its first honest product slice is a Linux X11 host and a
Windows client on a trusted, low-latency LAN.

## Current capability

| Area | Current implementation | Status |
| --- | --- | --- |
| Secure transport | TLS 1.3-only mTLS over Quinn QUIC; both sides pin and byte-check the expected leaf certificate; no automatic UDP downgrade | Default product path; in-process tests pass |
| Device identity | `latencydesk-identity` creates persistent self-signed certificate DER and PKCS#8 private-key DER files without overwriting an existing identity | Implemented; certificate exchange is manual |
| Control and input | Authenticated product handshake; session-stamped reliable QUIC lanes; input has higher Quinn send priority; Client/Host negotiate an explicit capability and opt-in Linux probes receive a full-stamp ACK only after XTEST plus an X11 sync reply | Implemented; single- and concurrent-target application-ACK process evidence, while physical input-to-photon remains pending |
| Concurrent targets | Repeatable `--target <ADDR>,<PEER_CERT>` launches 2–16 isolated secure client processes so one controller can open several exact-pinned Hosts at once | Single-machine 2/4-target gates retain 256 and 8/16-target gates retain 1024 overlapping raw input-ACK samples per Host plus exact process-group/resource snapshots; a failed target is isolated, and Ctrl-C is fenced through bounded direct-child kill/reap and output-forwarder joins; cross-machine soak remains pending |
| Linux host | Real X11 root capture, CPU BGRA-to-NV12 conversion, and reconciled XTEST input on a connection/task isolated from blocking capture and software encode | Secure alpha path; X11-to-headless process loopback is verified, while visible input latency and cross-machine rendering remain pending |
| Successor sessions | Linux X11 Host retains one endpoint for 1–16 sequential exact-pinned sessions; a headless Client supports clean sequences plus bounded recovery from authenticated QUIC reset/idle timeout; every successor follows ReleaseAll and receives a fresh identity with strictly increasing epochs | Clean and loopback-blackhole recovery paths implemented; interactive reconnect, Windows Host persistence, physical handoff, and cross-machine soak remain pending |
| Windows client | Strict raw-NV12 validation, Direct3D 11 viewer, bounded latest-frame presentation, and native input forwarding; `--frames` provides headless mode | Secure alpha path; Windows viewer cross-machine E2E evidence is still pending |
| Other clients | Portable software viewer with OpenH264/raw-NV12 presentation and input forwarding; headless receive and input probe remain available | Alpha implementation; cross-machine and native-UX evidence pending |
| Windows host | Secure hosting is rejected before opening a socket because real capture/input providers are not connected | Unsupported |
| Media | Raw NV12 fragmented across QUIC DATAGRAMs; no production H.264/AV1 encode/decode path | Low-resolution LAN preview only |
| WAN connectivity | Direct IP plus a bounded race across four known exact-pinned addresses; opt-in RFC 8489 Binding and authenticated candidate advertisement; an explicit IPv4 loopback probe hands a nominated socket to exact-mTLS; a concurrent local exact-mTLS rendezvous daemon; an authenticated RFC 8656 UDP TURN allocation that carries a real ProductSession; rootless namespace NAT behavior plus product-connectivity matrices | Each component is verified only in isolated/local evidence. ProductSession crosses LAN IPv4, EIM/EIF, double NAT, CGNAT, and native IPv6 emulation; mapping/filter classification retains separate built-in probes. No physical ISP/router matrix, public rendezvous/TURN operation, automatic desktop route integration, Internet traversal, interactive recovery, or QUIC path migration |
| Distribution | No supported signed installer, updater, or production service | Not implemented |
| Legacy transport | Plaintext custom UDP, available only with explicit `--unsafe-udp-lab` | Local compatibility test only |

Raw NV12 is intentionally not marketed as a WAN solution. For scale, 640×360
at 15 fps is about 41.5 Mbit/s before transport overhead; the default capture
limits at 1280×720 and 60 fps would be about 664 Mbit/s. Start with the low
preview profile below on a wired LAN.

## Build and targeted verification

The repository pins Rust **1.88.0**. On Windows, native C++ checks also require
Visual Studio 2022 Build Tools with C++20 and a Windows SDK. The secure host
requires Linux with a running X11 session and `DISPLAY` set.

```bash
cargo build --workspace --locked
cargo test --workspace --all-targets --locked
cargo test --workspace --doc --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo fmt --all -- --check
```

The following narrower test command currently passes and covers identity file
handling, exact-peer mTLS success/failure, QUIC product lanes and fragmentation,
and secure-default CLI parsing:

```bash
cargo test --locked -p latencydesk-socket-transport -p latencydesk-identity -p latencydesk-host -p latencydesk-client
```

The deterministic stress gate overlaps eight independent simulated sessions,
runs all four network profiles per session, and proves that an input item is the
first scheduler pop even when each session's realtime-video queue is saturated:

```bash
cargo run --locked -p latencydesk-stress
```

This is a queue-isolation and accounting gate, not an optical latency result or
a substitute for real multi-machine testing.

The repository also has a process-level secure loopback gate for Linux X11. It
generates disposable identities, proves that a rogue certificate is rejected
before accepting the pinned client, completes TLS 1.3 mTLS and the product
handshake, and receives real X11 pixels in headless mode:

```bash
cargo build --locked -p latencydesk-host -p latencydesk-client -p latencydesk-identity
xvfb-run -a python3 scripts/secure_connect_test.py \
  --host-bin target/debug/latencydesk-host \
  --client-bin target/debug/latencydesk-client \
  --identity-bin target/debug/latencydesk-identity \
  --frames 3 --fps 10 --max-width 320 --max-height 180 \
  --pairing-timeout 30 --output artifacts/secure-connect.json
```

This proves only a single-machine Xvfb/WSL2-style X11-to-headless process
loopback. It does **not** prove Linux-to-Windows rendering, visible XTEST input
effects, packet-capture confidentiality, cross-machine operation, or
long-running network reliability. Those gates remain Pending in
[Product readiness](docs/PRODUCT_READINESS.md).

The same-socket STUN process gate starts a strict local fake RFC 8489 Binding
server, discovers the Client's reflexive address, transfers that exact UDP
socket into Quinn, completes exact-mTLS, negotiates an opt-in bounded candidate
advertisement in both directions, and receives a real X11 frame:

```bash
xvfb-run -a python3 scripts/stun_same_socket_test.py \
  --host-bin target/debug/latencydesk-host \
  --client-bin target/debug/latencydesk-client \
  --identity-bin target/debug/latencydesk-identity \
  --frames 3 --timeout 45 \
  --output artifacts/stun-same-socket.json
```

The artifact requires the fake server's observed STUN source, Client
local/reflexive address, and Host-observed authenticated QUIC source to match.
It also requires both candidate records to follow exact-mTLS, bind their
exchange IDs to the active random session ID, start at generation 1, mirror the
bounded candidate counts, and leave the authenticated Host route unchanged.
This is authenticated advertisement, not a working ICE checklist: it performs
no connectivity checks, nomination, consent, TURN, or NAT traversal.

The transport crate now also contains an isolated RFC 8445 Sans-I/O gate using
the focused `is` ICE core. Two real UDP sockets complete bounded
`MESSAGE-INTEGRITY` checks, role resolution, and nomination; raw ICE reads then
stop and those exact sockets/ports are handed to Quinn, which must still finish
TLS 1.3 mutual authentication and expose both expected certificate chains.
Wrong credentials, fingerprint mutation, oversized/mixed candidates, role
conflict, and dropped liveness checks have negative tests. This proves a safe
sequential ICE→QUIC seam on one machine. The isolated probe below now wires
authenticated credential/candidate signaling to that seam without promoting
the result; public rendezvous/TURN integration, real NATs, product route
promotion, and cross-machine success remain unimplemented.

The multi-target process gate starts two distinct-certificate Hosts, proves
both are authenticated and streaming at the same time, then runs a second
phase where an unreachable target fails while the healthy target still
completes:

```bash
xvfb-run -a python3 scripts/multi_target_connect_test.py \
  --host-bin target/debug/latencydesk-host \
  --client-bin target/debug/latencydesk-client \
  --identity-bin target/debug/latencydesk-identity \
  --frames 5 --fps 10 --max-width 320 --max-height 180 \
  --output artifacts/multi-target-connect.json
```

This is two-Host loopback process evidence, not cross-machine scale or a
16-Host resource/latency result.

The secure input probe records raw Client send → post-XTEST/X11-sync application ACK
RTTs. It is deliberately not called input-to-photon latency:

```bash
xvfb-run -a python3 scripts/secure_input_latency_test.py \
  --host-bin target/debug/latencydesk-host \
  --client-bin target/debug/latencydesk-client \
  --identity-bin target/debug/latencydesk-identity \
  --samples 128 --timeout 30 \
  --output artifacts/secure-input-latency.json
```

The artifact retains every sequence/latency sample and recomputes its summary;
the 100 ms loopback p95 ceiling is a stall detector, not a competitor claim.

The concurrent input gate uses one supervisor and 2, 4, 8, or 16 exact-pinned
Host children. Every flushed probe-start marker must arrive before any flushed
probe-stop marker; every target then retains its own 256 raw samples and full
lifecycle stamp:

```bash
xvfb-run -a python3 scripts/multi_target_input_latency_test.py \
  --host-bin target/debug/latencydesk-host \
  --client-bin target/debug/latencydesk-client \
  --identity-bin target/debug/latencydesk-identity \
  --target-count 2 --samples 256 --timeout 45 \
  --output artifacts/multi-target-input-latency.json
```

The CI scale gate repeats that command with `--target-count 4` at 256 samples,
then `8` and `16` at 1024 samples so fast children remain alive through both
fail-closed `/proc` topology snapshots.
Hosts bind OS-assigned loopback ports, and Linux `/proc` evidence requires one
supervisor plus exactly N Client children and N isolated Host process groups
with stable PID/start-time/executable identities. RSS, CPU ticks, FD and thread
counts are retained as point-in-time observations, not universal pass/fail
ceilings. Host and Client runtimes use two Tokio workers per isolated process;
the gate enforces the corresponding bounded thread topology so target count
cannot multiply one worker per machine CPU.

This adds concurrent single-machine control-plane and process-resource
evidence. It still does not measure a visible application response, a physical
display, a WAN path, cross-machine resource use, or any competitor.

## Secure LAN preview quick start

This workflow requires a Linux X11 host and either a Windows interactive client,
a portable software client, or a headless client. Use the same source revision
on both machines and a trusted wired LAN. Replace `192.168.1.20` with the Linux
host's address and allow inbound UDP port 9000 only on the trusted LAN.

### 1. Generate one persistent identity on each machine

On the Linux host:

```bash
cargo run --locked -p latencydesk-identity -- generate \
  --name "Linux X11 host" \
  --out-dir "$HOME/.local/share/latencydesk/host"
```

On the Windows client in PowerShell:

```powershell
cargo run --locked -p latencydesk-identity -- generate `
  --name "Windows client" `
  --out-dir "$env:LOCALAPPDATA\LatencyDesk\client"
```

Each directory contains `identity.cert.der` and `identity.key.der`. Exchange
**only** `identity.cert.der` over a trusted channel. Never copy or share
`identity.key.der`. Compare the printed SHA-256 fingerprints through a separate
trusted channel; they can also be inspected later with:

```bash
cargo run --locked -p latencydesk-identity -- fingerprint --cert /path/to/identity.cert.der
```

In the commands below, `peers/windows-client.cert.der` is the certificate copied
to the host, and `peers/linux-host.cert.der` is the certificate copied to the
client.

### 2. Start the Linux X11 host

```bash
cargo run --locked -p latencydesk-host -- \
  --listen 0.0.0.0:9000 \
  --identity-cert "$HOME/.local/share/latencydesk/host/identity.cert.der" \
  --identity-key "$HOME/.local/share/latencydesk/host/identity.key.der" \
  --peer-cert "$HOME/.local/share/latencydesk/peers/windows-client.cert.der" \
  --max-width 640 --max-height 360 --fps 15
```

The host accepts only the exact pinned client certificate. Capture and XTEST
open only after peer authentication succeeds.

For a bounded persistent Linux X11 listener, add `--max-sessions 2` (up to 16).
The Host tears down all session-owned state and completes `ReleaseAll` before
accepting the next exact-pinned connection. Windows currently requires the
default value `1` until native provider restart has separate soak evidence.
For a bounded headless verification sequence, add `--frames 3 --session-count 2`
to the Client; it closes each ProductSession, retains its Client endpoint, and
requires a fresh identity plus strictly newer lifecycle epochs on every successor.
To retry only recoverable QUIC reset/idle-timeout failures, add
`--reconnect-attempts 3` (maximum 8) to a headless Client and provision enough
Host `--max-sessions` capacity. Authentication, protocol, codec, provider, and
explicit application-close failures remain terminal. Retry delay is jittered,
capped at two seconds, and constrained by a monotonic total budget equal to the
smaller of the pairing timeout and 15 seconds.

### 3. Start an interactive viewer

```powershell
cargo run --locked -p latencydesk-client -- `
  --connect 192.168.1.20:9000 `
  --identity-cert "$env:LOCALAPPDATA\LatencyDesk\client\identity.cert.der" `
  --identity-key "$env:LOCALAPPDATA\LatencyDesk\client\identity.key.der" `
  --peer-cert "$env:LOCALAPPDATA\LatencyDesk\peers\linux-host.cert.der"
```

On Linux or macOS, run the same client without `--frames` to open the portable
software viewer (replace the identity paths as appropriate):

```bash
cargo run --locked -p latencydesk-client -- \
  --connect 192.168.1.20:9000 \
  --identity-cert "$HOME/.local/share/latencydesk/client/identity.cert.der" \
  --identity-key "$HOME/.local/share/latencydesk/client/identity.key.der" \
  --peer-cert "$HOME/.local/share/latencydesk/peers/linux-host.cert.der"
```

For a bounded headless receive check on any supported client platform, add
`--frames 60`. The portable viewer is an alpha software path; cross-machine
rendering, input effects, resize/DPI behavior, and long-duration recovery remain
product-readiness gates rather than verified support claims.

`--fallback-address` is optional and repeatable up to three times. Every address
must identify the same Host certificate; the Client races them concurrently and
uses only the first path that completes exact-pinned TLS authentication. This is
known-address failover, not ICE/TURN or an unauthenticated proxy. Optional
`--stun-server <IP:PORT>` only discovers/logs one srflx address on that same
socket. `--candidate-exchange-probe` can advertise the resulting bounded set
inside the already authenticated product session, but the receiver stores it as
untrusted connectivity metadata and does not add or switch a route. ICE checks,
nomination, consent, and relay remain later gates.

### 3.5 Isolated ICE connectivity probe

`--ice-connectivity-probe` requires the negotiated `ICE_CONNECTIVITY_PROBE`
capability and authenticated ICE credentials. It uses exactly one fresh IPv4
Host candidate per peer: the authenticated peer IP with a different UDP port.
Roles/generation are fixed, followed by a `Nominated` then
`HandoffReady` barrier while raw ICE continues. The exact socket/port is drained
and handed to an isolated Quinn endpoint for exact-leaf mTLS; the transcript
binds the full `SessionStamp`, generation, two control nonces, and a 32-byte
challenge. The probe has no desktop or `ProductSession` authority, and the
original frame plus `ReleaseAll` route remains unchanged.

Evidence command:

```bash
xvfb-run -a python3 scripts/ice_connectivity_probe_test.py --host-bin target/debug/latencydesk-host --client-bin target/debug/latencydesk-client --identity-bin target/debug/latencydesk-identity --frames 3 --timeout 45 --output artifacts/ice-connectivity-probe.json
```

This proves only single-machine IPv4 loopback. STUN on the probe, route
promotion/rollback, consent, rendezvous, NAT/CGNAT/IPv6, TURN/relay, Internet
reachability, latency superiority, and AnyDesk superiority remain unproven.
Borrowed buffers and upstream ICE internal credential copies are not guaranteed
zeroized.

### 3.6 Authenticated rendezvous state boundary

The `latencydesk-rendezvous` crate provides bounded matching state, and the
opt-in `latencydesk-rendezvousd` process now exercises it over TLS 1.3 exact-mTLS
QUIC. One daemon accepts 2–32 unique exact client leaves and admits at most
eight TLS/request tasks concurrently. It supplies the device
identity obtained from the authenticated client certificate; registration
payloads cannot claim or replace that identity. A match succeeds only when two
different devices name each other's exact certificate fingerprint, use
complementary roles, and agree on the match ID, generation, and ICE exchange
ID. Each side retains its own bounded credentials/candidates; the shared
delivery expiry is the earlier of the two bounded TTLs. Registration bytes are
capped at 4 KiB,
pending matches at 1,024, and each device at 16 pending matches in the daemon.
Explicit registration and match caps are related by `matches × 2 ≤
registrations`. Delivery is one-shot and does not become client-visible success
until both exact-mTLS peers complete `DeliveryAck → CommitAck` and receive the
server's final `Complete`; disconnected, expired, aborted, and replayed state is
tombstoned, while uncommitted registration capacity is refunded.

`scripts/rendezvous_process_test.py` first proves a stranger certificate cannot
kill the listener, then proves both allowed clients receive the other's offer
once. `scripts/rendezvous_multi_process_test.py` additionally proves two
independent reciprocal matches complete through four native client processes
while a stranger is rejected; it records exact binary versions/hashes, DER
identity validation, and `/proc` ownership for the daemon and both pre-responder
initiators' candidate/QUIC sockets. This remains a bounded local evidence
service—not a supported public
deployment. It has no DNS/discovery, dynamic account trust, NAT matrix, relay,
abuse operation, route selection, desktop payload access, Internet reachability,
or AnyDesk parity claim. Owned outbound secret buffers are zeroized; inbound
Quinn buffers and decoder copies are debug-redacted but are not guaranteed
zeroized.

### 3.7 Protocol-v2 route promotion and bounded rollback

`RouteTransitionController` admits a candidate only after ICE nomination,
exact-mTLS, transcript binding, and fresh consent are all present. The old route
stays active through peer prepare; commit increments an independent
`route_epoch` and retains the old route for a bounded rollback window. At the
deadline, a fresh candidate proof finalizes it; otherwise only a fresh old-route
proof may roll back with another epoch bump. If neither route remains verified,
all application-route authority is revoked and a new transition is refused.
Packets from the pre-promotion route remain stale even after returning to the
same network path. Protocol v2 carries a nonzero `route_epoch` on every reliable
control/input record, media datagram, input-applied ACK, and ICE probe. A
`ProductRouteSet` owns two distinct connections to the same exact certificate;
the candidate is unable to send application data before admission. Typed
Prepare/Prepared/Commit runs on the current route, then `Activated`/`Confirmed`
must cross the candidate route before the initiator switches authority. A
cancelled or expired transition deauthorizes and closes both connections.

The process gate below starts separate server/client processes on two distinct
loopback UDP ports, promotes epoch 1→2, transfers exact control/input/media
payloads, injects active-candidate failure, then rolls back over the retained
connection through the same authenticated barrier at epoch 3:

```bash
cargo build --locked -p latencydesk-route-probe -p latencydesk-identity
python3 scripts/route_promotion_process_test.py \
  --binary target/debug/latencydesk-route-probe \
  --identity-bin target/debug/latencydesk-identity \
  --timeout 20 --output artifacts/route-promotion-process.json
```

This is real two-process exact-mTLS product-lane evidence, but only on one
machine and two loopback paths. The normal desktop Host/Client still does not
automatically create this route set from rendezvous/ICE/TURN, and physical
router, CGNAT, relay-failure, inter-network, and latency claims remain pending.

### 3.8 Bounded UDP TURN relay process

`latencydesk-turn-relayd` now exercises a real RFC 8656 UDP allocation and
relay path. A client completes a 401 realm/nonce challenge and SHA-256
long-term message-integrity check, then creates an allocation, IP-only
permission, and channel binding. Send indications and ChannelData traverse the
allocation's real UDP relay socket in both directions; Refresh(0) removes the
allocation and joins its task. Allocation, per-user, permission, channel,
packet, byte, and absolute-deadline bounds fail closed. The relay handles
opaque bytes only and owns no desktop or end-to-end encryption key.

`AuthenticatedTurnRoute` is the product-side deep module. Its only public
construction path completes the source-bound 401 challenge, verifies SHA-256
message integrity and exact transaction transcripts, then creates the
permission and channel before Quinn receives an abstract socket. A single UDP
reader demultiplexes control responses and bounded ChannelData; bounded
retransmission, monotonic allocation refresh, permission/channel renewal,
expiry, local cancellation, and Refresh(0) all fail closed. The adapter exposes
the relayed address to Quinn, conservatively disables MTU discovery, and
forwards QUIC's encrypted packets without pretending the outer socket preserved
ECN.

`scripts/turn_relay_process_test.py` proves two exact-byte round trips with
separate daemon/client processes and a UDP echo peer.
`scripts/turn_product_process_test.py` forces `latencydesk-product-probe`
through the allocation and proves exact-leaf mTLS plus ProductSession control,
input, and media; the Host-observed QUIC source must equal the relayed address,
the cross-process challenges and random session ID must agree, the relay must
see traffic in both directions, and Refresh(0) must remove the allocation.
This is a local,
SHA-256-preconfigured UDP subset—not a public or fully interoperable TURN
service; the evidence daemon rejects non-loopback binds. Password-algorithm
negotiation, FINGERPRINT, public abuse/capacity,
TURN over TLS/DTLS, RFC 6062 TCP allocations, cross-family translation, product
execution through the namespace matrix, automatic desktop route selection,
Internet reachability, and
latency/AnyDesk claims remain unproven.

### 3.9 Isolated NAT/CGNAT/IPv6 behavior matrix

`scripts/nat_netns_matrix.py run --allow-netns` starts an outer rootless
user/mount/network/PID namespace; its PID-1 executor then self-creates a second
network namespace before any mutation and builds real client/server/observer
namespaces connected by veth and nftables. It observes LAN IPv4, RFC 4787
endpoint-independent mapping, address/address-and-port-dependent filtering, APDM
mapping to the same destination address at different ports, two-layer NAT, a
`100.64/10` CGNAT path, native IPv6, broken IPv6, and UDP blocking. Double-NAT/CGNAT evidence requires nonzero NAT
counters in both router namespaces. All ten profiles pass locally and cleanup
leaves no named veth, nft table, or namespace process.

The outer caller never invokes `ip`, `nft`, or `nsenter`. The internal executor
requires mapped UID 0 and PID 1, calls `unshare(CLONE_NEWNET)` itself, and
refuses to continue unless that syscall changes its network-namespace inode.
The public runner also verifies host, outer, and executor inodes are distinct.
A blocked required profile exits 2 and a
behavior mismatch exits 1. This is emulator evidence using built-in UDP probes,
not proof that LatencyDesk traverses a consumer router, carrier CGNAT, or public
Internet.

`scripts/nat_product_netns_test.py` reuses the same safe executor and topology
ownership but replaces the echo payload with two native
`latencydesk-product-probe` processes. Five profiles—LAN IPv4, EIM/EIF,
double NAT, a private→`100.64/10`→public CGNAT path, and native IPv6—must
complete exact-leaf mTLS plus ProductSession control/input/media on fixed UDP
port 38765. Host-observed source tuples, process executable/socket ownership,
per-process and per-node netns inodes, random challenge/session agreement, and
both double-NAT counters are retained. Native IPv6 first runs a bounded repeated
1,200-byte UDP path preflight, analogous only to route/neighbor warm-up; it
grants no session authority and ProductSession mTLS must still pass afterward.
This product subset does not replace the wider mapping/filter matrix and still
does not prove physical router/carrier behavior, full ICE candidate nomination,
NAT64, captive portals, or Internet success rates.

### 4. Open several exact-pinned Hosts concurrently

Use one repeatable `--target` entry per Host. Each Host must trust the same
client identity certificate, while every target entry supplies that Host's own
exact certificate pin. The supervisor starts an isolated child process per
target, so one Host's viewer, queue, or connection failure does not share runtime
state with another. Paths containing commas are not accepted by this alpha CLI.

```bash
cargo run --locked -p latencydesk-client -- \
  --identity-cert "$HOME/.local/share/latencydesk/client/identity.cert.der" \
  --identity-key "$HOME/.local/share/latencydesk/client/identity.key.der" \
  --target "192.168.1.20:9000,$HOME/.local/share/latencydesk/peers/host-a.cert.der" \
  --target "192.168.1.21:9000,$HOME/.local/share/latencydesk/peers/host-b.cert.der"
```

The current bound is 16 unique address/certificate pairs and requires an
ephemeral local bind port. This supports one Client controlling multiple Hosts;
it does not make one Host accept multiple controllers.

The supervisor installs its Ctrl-C handler before spawning the first child. A
cancel request stops every still-running direct child, waits up to five seconds
for reaping, joins captured-output forwarders only after process EOF, and exits
nonzero. The Linux process gate interrupts only the supervisor PID while four
probe sessions overlap, then requires four reaped children, eight joined
forwarders, vanished PID/start-time/executable identities, and Host-side
ReleaseAll. This does not yet prove cleanup of arbitrary grandchildren or a
cross-machine GUI soak.

This is the intended secure workflow. The repository retains a successful
single-machine X11-to-headless process result, but not a cross-machine Windows
viewer result. Treat failures as alpha defects, not as a supported deployment
issue.

## Unsafe legacy loopback smoke

The legacy harness is retained only to check compatibility behavior. It opts in
to `--unsafe-udp-lab`, uses a public built-in test secret, and carries plaintext
media/input. Supplying `--shared-secret` does not make this custom protocol safe.

```powershell
cargo build --workspace --locked
python scripts/remote_connect_test.py --mode loopback --frames 8 --host-frames 16 --fps 30
```

Use loopback only. Never select `lan-bind`, bind it to an external interface,
forward its port, or use real sensitive desktop content.

## Performance and competitor claims

`scripts/compare-latency.py` is a development tool, not evidence of product
superiority. Claims against AnyDesk, RustDesk, or another product require the
same content, codec/quality, resolution, frame rate, hardware, display mode,
network profile, repeated trials, raw data, and third-party reproducibility.
Missing or zero metrics are not evidence. See the quantitative gates in
[Product readiness](docs/PRODUCT_READINESS.md).

`scripts/optical_crossover_gate.py` is the only automated path that may mark an
AnyDesk latency threshold as passed. It requires the installed comparator and
physical sensor, 10 randomized paired blocks per LAN/WAN profile, 1,000 analyzed
events per product/profile, retained 2000 ms-censored misses, a paired-block 95%
confidence interval wholly beyond the 20% p95 margin, no p99 regression, and
matched quality/reliability/bandwidth/route guardrails. This workstation
currently lacks the sensor, and no trusted notary key has yet been
pre-registered, so the gate is blocked rather than passed.

## Security and license

Read [SECURITY.md](SECURITY.md) before exchanging identities or running either
transport. Repository: <https://github.com/1122-gggggg/open_desk>

Licensed under Apache-2.0 or MIT.
