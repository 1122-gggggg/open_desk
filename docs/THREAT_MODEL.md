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
- STUN/rendezvous candidates remain untrusted metadata; source/transaction
  validation and fingerprints do not replace authenticated ICE signaling,
  consent, exact-peer mTLS, or authorization;
- candidate advertisements are accepted only after exact-mTLS and the product
  handshake, are capped at eight, bind their exchange ID to the active random
  session ID, and use consecutive generations; malformed, replayed,
  cross-session, mixed-family, TCP, and relay claims close that connection;
- receiving an authenticated candidate never changes the current route. A
  future connectivity-check/nomination layer must independently authenticate
  checks, limit amplification, prove consent, and retain exact-peer identity;
- the isolated ICE adapter uses OS-CSPRNG short-term credentials and role
  tie-breakers, HMAC-authenticated STUN, unique final fingerprints, candidate/
  pair/retry/deadline caps, and exact local-socket destinations. Upstream
  transaction IDs are correlation values and never authorization nonces;
- ICE raw reads and Quinn never race on one socket: ICE ownership ends and the
  receive queue is drained before the nominated socket enters Quinn. A nominated
  pair still has no desktop authority until exact-mTLS and the product handshake;
- ICE credential signaling is available only through typed APIs after exact-mTLS
  capability negotiation. Both the offer and selected configuration must carry
  the capability; Client/Host roles are fixed as controlling/controlled,
  active-session binding and consecutive generations are required; credentials
  precede candidates and cannot mix with advertisement-only mode per session.
  typed send/receive cancellation closes fail-closed so a partial generation
  cannot be retried or reinterpreted. Generic ICE control access is rejected;
  control-message Debug output never renders payload bytes. Values are bounded
  and debug-redacted; signaling-wrapper objects and encoded temporaries are
  zeroized, while borrowed transport buffers and the upstream ICE core's
  internal copy are not guaranteed to be zeroized and must never be logged.
  This boundary does not prove
  connectivity, consent, route choice, NAT/TURN/Internet reachability, or
  AnyDesk superiority;
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
- a multi-target supervisor installs cancellation handling before the first
  direct child spawn; cancellation kills and reaps each direct child under a
  fixed deadline and joins pipe-draining threads only after process EOF;
- failure to kill, wait, or reap is an explicit orphan-risk error and can never
  be reported as clean cancellation. Descendant process-tree containment still
  requires a later platform job/process-group abstraction.

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
