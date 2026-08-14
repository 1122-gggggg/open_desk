# Cross-Platform Bidirectional Remote Desktop MVP

## Status

Accepted for specification review on 2026-08-15.

## Goal

Deliver a real, native Windows ↔ Linux remote-desktop MVP. Either operating system can run a Host (the controlled endpoint) or a Client (the controlling endpoint). The first deployment path is LAN or a shared Tailscale/ZeroTier network; it does not include general Internet NAT traversal, TURN, or a hosted relay.

The MVP proves two physical-machine flows on different local networks:

1. Windows Host → Linux Client.
2. Linux Host → Windows Client.

Each flow captures a real desktop, displays it in a native window, and carries normal keyboard and pointer input back to the Host. Every process is native to its operating system: Windows uses `.exe` binaries and Linux uses native Linux binaries. WSL and protocol proxies are not product components.

## Constraints and Non-goals

- Windows capture and normal input run in the logged-in interactive user session. Session 0, UAC secure desktop, and elevated-target bypass are unsupported.
- Linux supports logged-in GNOME and KDE Wayland sessions. Capture and input require explicit XDG RemoteDesktop/ScreenCast Portal authorization. Generic Wayland unattended control and `/dev/uinput` are excluded.
- Tailscale/ZeroTier protects network transport but is not application authorization. The application retains SAS pairing, host approval, controller lease, and input release on disconnect.
- The network endpoint is configured manually for this MVP. Discovery, ICE, STUN, TURN, relay routing, and unattended deployment follow later.
- The existing `FakeCapture`, `ExactTestCodec`, and simulated `--interactive` pointer traffic remain test/lab-only. They are not a desktop product path.

## Decision

Use one shared Rust core plus native platform providers. The shared crates own behavior that must be bit-for-bit compatible across operating systems: protocol, session authorization, pairing, transport, reassembly, media epochs, input semantics, and telemetry. Platform crates own OS APIs, FFI, GPU resource ownership, and presentation.

Do not run the Windows endpoint inside WSL. WSL2 has a separate NAT boundary; a datagram sent to a Windows Tailscale address reaches the Windows host rather than an arbitrary WSL UDP socket. The Windows endpoint must bind the Tailscale/LAN socket itself.

## Runtime Topology

```text
Windows Host                                      Linux Client
-------------                                     ------------
DDA/WGC capture → H.264 encoder                   Native Wayland/X11 window
    → authenticated UDP media ────────────────→   H.264 decoder → renderer
    ← authenticated UDP control ←──────────────   Local keyboard/pointer capture
SendInput

Linux Host                                        Windows Client
----------                                        --------------
Portal + PipeWire capture → H.264 encoder         Native D3D11 window
    → authenticated UDP media ────────────────→   H.264 decoder → renderer
    ← authenticated UDP control ←──────────────   Local keyboard/pointer capture
libei through the RemoteDesktop Portal
```

The Host owns capture, encode, media send, control validation, and input injection. The Client owns local input capture, decode, render, and control send. Role is independent of OS: every platform ships both executables.

## Module Boundaries

| Area | Ownership | Contract |
|---|---|---|
| `protocol`, `session` | Shared core | Version negotiation, SAS pairing, host approval, capability grants, controller lease, disconnect state. It never calls OS capture or input APIs. |
| `transport`, `socket-transport` | Shared core | Authenticated control/media packets, path MTU bounds, frame reassembly, loss detection, recovery requests. It never selects an OS provider. |
| `media`, `h264` | Shared core | Interoperable low-latency H.264 bitstream contract, codec/display epochs, IDR recovery and frame dependency rules. |
| `platform` | Shared core | Provider traits and safety contracts: `CaptureBackend`, `EncodeBackend`, `RenderBackend`, and `InputBackend`. It owns no unsafe OS FFI. |
| `platform-windows` | Windows only | DDA/WGC capture, Media Foundation H.264 providers, D3D11 presentation, and `SendInput`. |
| `platform-linux` | Linux only | XDG Portal lifecycle, PipeWire capture, a Wayland presentation provider, and libei input through the authorized Portal session. |
| `apps/host` | Role composition | Binds the native Host providers to the authorized session and media sender. |
| `apps/client` | Role composition | Binds the native Client providers to the authorized session and control sender. |

Platform providers own their native completion fences and resource lifetime. They must obey the existing `platform` contracts: capture buffers are synchronously detached or copied into bounded ownership before asynchronous encoding; `EncodeBackend` and `RenderBackend` quiesce their exact native submissions before destruction; `InputBackend` receives reconciled input only.

## Session and Data Flow

1. The controller manually configures the Host Tailscale/LAN address and opens a connection.
2. Both peers negotiate protocol/media capability. They perform SAS pairing; the Host displays/approves the code and grants the requested control capability.
3. Only after a valid approval and controller lease may the Host start capture and accept input.
4. The Host captures a frame, validates its display epoch, encodes H.264, fragments media within the shared MTU limit, and sends it on authenticated UDP.
5. The Client reassembles and validates media. It decodes only continuity-valid frames, hands the newest valid frame to `RenderBackend`, and presents it in a native window.
6. The Client translates local input into the shared input protocol. The Host authenticates, sequence-checks, reconciles, and injects it through its platform `InputBackend`.
7. On disconnect, lease expiry, input-path failure, or authorization revocation, the Host immediately releases every pressed key, button, wheel/gesture state, and capture/decoder resource that remains authorized.

## Media Interoperability

The production path replaces the exact test codec with a mutually decodable low-latency H.264 baseline. Negotiation must bind codec profile/level, pixel format, coded resolution, bitstream framing, keyframe policy, and a monotonically increasing codec epoch. The two platform implementations may use different hardware APIs, but their encoded output must satisfy the shared wire contract.

Capture format, display rotation, resolution, or hardware recovery increments the display and codec epochs. The Host sends an IDR before the new epoch becomes presentable. The Client rejects frames from earlier epochs. A lost or corrupt reference frame causes a recovery/IDR request; the Client must not present a dependent frame as though it were continuity-valid.

## Error and Security Semantics

- Missing SAS approval, absent host approval, expired controller lease, or denied platform capability is fail-closed: no screen frames, no accepted remote input.
- A Linux Portal revoke or compositor restart invalidates presentation authorization immediately. The session transitions through draining, releases input, and either reauthorizes into a new epoch or closes.
- A Windows DDA access loss or display change stops use of the old resource. Recovery requires a new valid surface, new epoch, and IDR; unrecoverable failure closes the session.
- UDP loss that breaks dependency continuity results in a recovery request, not visual corruption or arbitrary P-frame dropping.
- All platform errors identify the actionable capability or provider condition. Examples: Portal keyboard capability denied, DDA access lost, hardware decoder unavailable, or renderer device lost.

## Build and Deployment

- Windows builds are performed with the native MSVC Rust target and Visual C++ Build Tools/Windows SDK. The current local `link.exe` failure is a missing native linker prerequisite, not a Rust source error.
- Linux builds use the native Linux Rust target and the development packages required by the selected Portal, PipeWire, libei, and presentation providers.
- The two test machines install Tailscale or ZeroTier, join the same tailnet/network, and use their virtual IP addresses directly. Each endpoint binds its own native socket.

## Physical-Machine Acceptance Tests

Run every test with two physical machines on different LANs but the same Tailscale/ZeroTier network.

1. **Windows Host → Linux Client**: capture a real Windows desktop, render it in a Linux native window, and control an ordinary non-elevated Windows application using keyboard and pointer input.
2. **Linux Host → Windows Client**: grant the Portal explicitly, capture a real Linux desktop, render it in a Windows native window, and control an ordinary Linux application via libei.
3. **Authorization**: before SAS/host approval/lease, the Client receives no frames and the Host injects no input.
4. **Disconnect safety**: disconnect the Client while a key or pointer button is held; confirm the Host releases the full input state.
5. **Reconfiguration**: change resolution or revoke Portal permission; confirm old-epoch frames are never displayed and recovery uses a new epoch plus keyframe.
6. **Native deployment**: prove Windows execution uses a Windows-native executable and Linux execution uses a Linux-native executable; no WSL, port forwarding, or proxy is allowed on the data path.

## Implementation Sequence

1. Establish reproducible native build environments and CI matrices for Windows MSVC and Linux.
2. Split the current test Host/Client programs from product role composition, retaining fake/test tools only for lab coverage.
3. Implement Windows native Client presentation and Host capture/input paths against the `platform` contracts.
4. Implement Linux Client presentation and Host Portal/PipeWire/libei paths against the same contracts.
5. Introduce the production H.264 negotiated wire path and frame recovery while preserving bounded resource ownership.
6. Integrate actual SAS/approval/lease gating into both role applications.
7. Run the physical-machine acceptance matrix in both directions and record provider diagnostics.

## Alternatives Rejected

### WSL or Windows UDP forwarding

WSL is a Linux development environment, not a Windows endpoint. Incoming UDP addressed to a Windows Tailscale address is not a supported transparent route to a WSL socket. Windows `netsh portproxy` is TCP-only. This would make network behavior deployment-specific and fail the native endpoint requirement.

### Separate protocol stacks per platform

Duplicating session, transport, pairing, input protocol, and recovery logic creates incompatible behavior and doubles audit/test effort. It conflicts with the existing shared core and bounded resource contracts.

### Internet traversal and relay in the MVP

ICE/STUN/TURN/relay is a separate system with security, operations, and performance requirements. Tailscale/ZeroTier gives the MVP a secure routable network while preserving a clean future transport boundary.

## Consequences

The MVP is intentionally narrower than a consumer remote-desktop product: it requires an installed private overlay network and interactive user authorization. In return it establishes the correct native execution model, authenticated cross-OS protocol, real capture/render/input paths, and safe recovery semantics without creating a WSL/proxy dependency that would have to be removed later.
