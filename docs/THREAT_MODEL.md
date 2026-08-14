# Threat Model

## Assets

- captured desktop pixels and audio when enabled;
- keyboard, pointer, clipboard, and file data;
- device identity/private keys;
- user authorization state;
- host control capability;
- relay and rendezvous infrastructure;
- update/signing pipeline.

## Adversaries

- unauthenticated Internet peer;
- malicious or compromised relay/rendezvous server;
- paired device that becomes compromised;
- local unprivileged process attempting privilege escalation;
- malicious media/control packets from an authenticated peer;
- supply-chain contributor or dependency;
- passive network observer;
- user tricked into granting a portal/session.

## Trust boundaries

```text
network peer / relay
        ↓ untrusted bytes
QUIC/TLS implementation
        ↓ authenticated but still hostile messages
bounded protocol parsers
        ↓ authorized capabilities
session core
   ├─ per-user capture/input agent
   ├─ codec provider / GPU driver
   └─ privileged service via narrow local IPC
```

Authentication does not make payloads safe. All peer messages remain untrusted and bounded.

## Required controls

### Pairing and authorization

- cryptographic device identity generated locally;
- QR-only out-of-band pairing carrying at least 128 bits of OS-CSPRNG entropy, short-lived, device- and channel-bound, one-use, and atomically consumed;
- fresh full 1-RTT handshake with 0-RTT authorization disabled precedes locally generated session ID and authorization epoch;
- explicit local consent by default, with separate capability grants;
- visible active-session indicator and immediate local revoke; session revocation or expiry invalidates the authorization epoch;
- re-pair or explicit policy for unattended access.

### Transport

- standard QUIC/TLS configuration;
- certificate/device-key pinning after pairing;
- anti-replay/session nonces;
- relay forwards E2E ciphertext only;
- rate limits before expensive parsing/decompression;
- connection and incomplete-frame quotas.

### Parser/resource safety

- fixed/length-bounded messages;
- checked arithmetic before allocation;
- frame dimensions, encoded length, decompressed output, fragments, streams, and queue bytes capped;
- codec epoch/state validation;
- timeouts for incomplete frames and handshakes;
- fuzz targets for wire, reassembly, input, tile, and local IPC parsers;
- no recursion controlled by peer input.

### Privilege separation

- normal desktop agent runs as the logged-in user;
- Windows service contains only policy/update/session-discovery functions needed at elevated privilege;
- narrow authenticated local IPC;
- no captured frame or arbitrary file path accepted by privileged service;
- Linux portal grants are session scoped;
- secure desktop/login-screen work remains a separate reviewed feature.

### Logging and privacy

- no screen pixels, audio, clipboard contents, typed text, credentials, pairing secrets, or private keys in normal logs;
- diagnostic traces use IDs, durations, sizes, and capability names;
- crash dumps require user-controlled privacy policy;
- telemetry is local/off by default until a separate data policy exists.

### Updates and dependencies

- locked/reviewed dependencies;
- automated advisory scanning plus human review;
- SBOM per release;
- signed release artifacts and provenance before production distribution;
- protected release keys and two-person release policy later;
- clean-room license review for contributions inspired by GPL/AGPL projects.

## Deferred high-risk features

Clipboard, file transfer, public relay, unattended access, secure-desktop control, audio capture, and automatic update execution are not “small additions.” Each requires a threat-model extension, authorization UX, parser tests, and abuse review before implementation.

## Security release gate

No production/unattended release until:

- external security review;
- fuzzing has sustained coverage and no unresolved high-severity findings;
- pairing and revoke UX is tested against social-engineering mistakes;
- privilege boundary and local IPC are reviewed;
- relay cannot decrypt session content;
- dependency/SBOM/signing process is operational.
