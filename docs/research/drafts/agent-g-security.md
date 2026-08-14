# Agent G — Security and Product-Privilege Architecture Research

## Scope and red-team conclusion

This review treats the repository's current LAN-first, logged-in-user proposal as a hypothesis rather than evidence. It preserves its useful separation of authentication, consent, and capability negotiation, but rejects several unsafe implications: “short code or QR” is not a pairing protocol; QUIC/TLS does not authorize input; an encrypted relay is not literally zero knowledge; and an always-on `LocalSystem` service is unjustified for a v0.1 that promises neither unattended access nor secure-desktop control. The current baseline already excludes generic Wayland unattended/login-screen control, Windows secure desktop/UAC, clipboard, file transfer, and automatic updates; those exclusions should become hard release boundaries rather than aspirational deferrals ([baseline audit](../../TECHNICAL_AUDIT.md), [threat model](../../THREAT_MODEL.md)).

The recommended v0.1 is therefore deliberately smaller: a locally paired, mutually authenticated, full-1-RTT QUIC connection between two per-user agents, with local host approval for every session and no persistent elevated service, relay, unattended mode, clipboard, file transfer, or automatic update execution.

### What the protocol can guarantee, and what the product must not claim

| Product wording | Protocol/OS basis | It does guarantee | It does **not** guarantee |
|---|---|---|---|
| “Encrypted connection” | TLS 1.3 provides endpoint confidentiality and integrity after authentication; QUIC uses TLS-derived packet protection ([RFC 8446 §1](https://www.rfc-editor.org/rfc/rfc8446.html#section-1), [RFC 9001 §2.1](https://www.rfc-editor.org/rfc/rfc9001.html#section-2.1)). | A network attacker cannot read or modify accepted 1-RTT payloads without endpoint keys. | That the peer is a particular human, that the peer is uncompromised, or that the user intended a requested action. |
| “Paired device” | A pinned device public key/certificate plus proof of private-key possession. TLS supports X.509 authentication for both server and client; the application decides its authentication requirements ([RFC 9001 §2.1](https://www.rfc-editor.org/rfc/rfc9001.html#section-2.1), [§4.4](https://www.rfc-editor.org/rfc/rfc9001.html#section-4.4)). | The same enrolled private key participated. | Human presence, a safe device label, or continued authorization after revocation. |
| “End-to-end encrypted relay” | The relay forwards complete QUIC packets and never terminates QUIC/TLS. TURN is a packet relay, not an end-to-end content protocol ([RFC 8656 §1](https://www.rfc-editor.org/rfc/rfc8656.html#section-1)). | The relay lacks media/control plaintext and endpoint private keys. | Metadata privacy: TLS does not hide record lengths, and a relay necessarily observes allocation, source/destination IPs, timing, packet sizes, and availability ([RFC 8446 §1](https://www.rfc-editor.org/rfc/rfc8446.html#section-1), [RFC 9000 §21.14](https://www.rfc-editor.org/rfc/rfc9000.html#section-21.14)). Do not market this as literal “zero knowledge.” |
| “Host approved” | A local agent displays a request and enables a capability only after its local policy/UI accepts it. | A particular local policy transition occurred. | Proof that a human, rather than malware, social engineering, or a remotely controlled desktop, made the decision. |
| “Secure credential storage” | User-scoped OS secret storage protects at rest. DPAPI is normally decryptable only by the same user credential on the same machine ([Microsoft DPAPI](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)). | Resistance to offline copying by a different local user in the normal OS model. | Protection from malware running as that logged-in user, a compromised OS, or a stolen unlocked session. |
| “Signed update” | Signature/metadata verification authenticates an artifact under the configured update trust root. | A verifier can reject an unexpected or stale artifact if the design checks signatures, versions, and expiry. | Safety from a malicious but authorized release, a compromised signing quorum, or an attacker who only denies updates ([TUF §1.5.2](https://theupdateframework.github.io/specification/v1.0.33/#goals-for-protecting-against-specific-attacks)). |

The Linux portal conclusions below are interface- and backend-specific: the current ScreenCast documentation describes interface version 6 and RemoteDesktop version 2, but the compositor/portal backend decides available devices, prompting, persistence, and actual behavior ([ScreenCast](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.ScreenCast.html), [RemoteDesktop](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.RemoteDesktop.html)). Windows CNG VBS-key behavior is likewise hardware/OS dependent and Microsoft labels the VBS-key information prerelease ([NCryptCreatePersistedKey](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)).

## Direct answers

1. **Simplest secure pairing model:** v0.1 should support only a locally displayed QR invitation containing a pinned host certificate/public-key fingerprint, a short-lived one-use pairing identifier, and at least 128 bits of CSPRNG-generated secret material. The client completes a full 1-RTT, mutually authenticated TLS 1.3 handshake, proves the QR secret inside that authenticated channel, and the host locally accepts the displayed client-key fingerprint before persisting the pair. A six-digit code must not be accepted as an equivalent fallback. If manual entry is later necessary, it needs an audited PAKE profile, not a transmitted password; SPAKE2+ is an example only when its augmented-client/verifier roles fit the product ([RFC 4086](https://www.rfc-editor.org/rfc/rfc4086.html), [RFC 9383](https://www.rfc-editor.org/rfc/rfc9383.html)).
2. **Zero-knowledge relay design:** use a content-blind packet forwarder/TURN-style allocation that forwards already end-to-end QUIC-protected UDP payloads; it never terminates TLS, parses LatencyDesk media/control, holds device private keys, or decides authorization. Call it “content-blind E2E relay,” not zero knowledge. It cannot hide network metadata or prevent denial of service ([RFC 8656](https://www.rfc-editor.org/rfc/rfc8656.html), [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html)).
3. **Components needing privilege separation:** the interactive capture/input/consent agent must remain a normal-user process; any future Windows maintenance service and the elevated installer/updater must be separate from it; any later local IPC must have an explicit per-session ACL and minimal command schema. A codec/GPU worker is a valuable future isolation candidate because it consumes hostile media and drives native providers, but it is `EXPERIMENT_REQUIRED` rather than a v0.1 process boundary.
4. **Secure unattended credential storage:** unattended access is excluded from v0.1. Later it should use a distinct, revocable, per-peer public-key credential—not a reusable password—whose private half remains in user-scoped OS storage (current-user CNG/DPAPI on Windows; Secret Service when available in the logged-in Linux session). No portable generic Linux unattended claim is justified until keyring and portal behavior are tested.
5. **Can central accounts be avoided?** Yes for v0.1 LAN pairing and identity: self-generated pinned device identities require neither product account nor public CA. This sacrifices password reset, cloud recovery, global device inventory, global revocation propagation, and convenient public discovery. A hosted public relay can avoid a human account only by accepting anonymous/time-limited capabilities, but then it still needs an operational admission and abuse-control mechanism; it is not cost-free anonymity.
6. **Minimal v0.1 security plan:** QR-only local pairing; pinned mTLS over full-1-RTT QUIC with 0-RTT disabled; fresh session authorization and local consent for view/input; unprivileged per-user agents; portal-scoped Linux permissions; user-scoped key storage; safe event-only logs; manually initiated signed installers/packages; and hard exclusion of relay, unattended access, clipboard, file transfer, audio, secure desktops, and automatic updates.

## Decisions

### D1 — Device identity and pairing bootstrap

Decision: Establish peer identity with locally generated, pinned device keys and QR-only out-of-band enrollment.

Current proposal: Locally generated cryptographic identity plus a short-lived pairing code **or** QR/out-of-band confirmation, then certificate/device-key pinning ([threat model](../../THREAT_MODEL.md)).

Verdict: MODIFY

Recommended solution: Generate one persistent per-user device identity using the selected TLS provider; represent it as a self-signed X.509 certificate/public key whose SHA-256 SPKI fingerprint is the stable device identifier. While a user is physically present at the host, display a QR invitation carrying: protocol/version, reachable candidate addresses, host SPKI fingerprint, one-use pairing ID, expiration, and a CSPRNG 128-bit-or-more pairing secret. The client generates/presents its own identity certificate during the full TLS handshake. It validates the pinned host fingerprint before sending a `PairRequest`; that request binds the pairing ID/secret and client public key to the authenticated channel. The host UI shows an untrusted device label plus client fingerprint, requires local acceptance, writes an active pair record, and irrevocably consumes the invitation. Reject any changed peer key until a new locally approved pairing completes.

Why: TLS provides endpoint authentication only once the application has chosen what identity to trust; a QR-pinned host key supplies that trust anchor without Web PKI or TOFU. TLS 1.3 supports certificate-based server and client authentication, while TLS/QUIC explicitly leaves application authentication requirements to the protocol designer ([RFC 9001 §2.1](https://www.rfc-editor.org/rfc/rfc9001.html#section-2.1), [§4.4](https://www.rfc-editor.org/rfc/rfc9001.html#section-4.4)). Security secrets must be unpredictable; a short human-memorable code is not interchangeable with a high-entropy QR bearer secret ([RFC 4086](https://www.rfc-editor.org/rfc/rfc4086.html)).

Alternative: A manually entered pairing code with a fully specified, audited PAKE and explicit short-authentication-string comparison. A raw code sent in a control message is rejected: it permits online guessing and makes the code a reusable bearer credential. RFC 9383 documents SPAKE2+ but is an augmented PAKE; its role/storage model must be chosen deliberately rather than copied into symmetric QR pairing ([RFC 9383](https://www.rfc-editor.org/rfc/rfc9383.html)).

Risk: A photographed QR, malicious local process, or tricked local user can still enroll an attacker. Expiry, one-time use, no log/copy path, and explicit local approval reduce but do not remove that risk. Device-key loss requires re-pairing; this is a product trade-off, not a transport failure.

Prototype required: EXPERIMENT_REQUIRED — can the selected QUIC/TLS implementation perform a full mTLS handshake with locally self-signed peer certificates and a custom pinned verifier on both Windows and Linux without enabling a public-CA fallback?

Evidence: [RFC 8446 §4.4](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.4), [RFC 9001 §2.1](https://www.rfc-editor.org/rfc/rfc9001.html#section-2.1), [RFC 4086](https://www.rfc-editor.org/rfc/rfc4086.html), [RFC 9383](https://www.rfc-editor.org/rfc/rfc9383.html).

### D2 — QUIC/TLS authentication, replay, and session authority

Decision: Use standard TLS 1.3 inside QUIC with pinned mutual authentication, full 1-RTT authorization, and no 0-RTT application data.

Current proposal: One TLS-authenticated QUIC connection; peer identity and local consent precede media/input; protocol epochs prevent stale application state ([protocol security invariants](../../PROTOCOL.md)).

Verdict: MODIFY

Recommended solution: Permit only TLS 1.3-or-newer versions supported by QUIC; configure mTLS/pinned identity verification before the application treats a peer as paired. Disable issuing/accepting 0-RTT for LatencyDesk v0.1. Resumption may later shorten a handshake only if all authorization messages, pairing actions, input enablement, and data-channel grants wait for a fresh 1-RTT session. On every successful connection, create a new unpredictable `session_id` and local `authorization_epoch`; bind every control request, input epoch, recovery state, and capability decision to them. Pairing IDs are one-use; existing `codec_epoch`/`input_epoch` validation remains necessary but is not a replacement for session authorization. Do not place pairing, grant, revoke, input, clipboard, or file-transfer semantics in QUIC DATAGRAMs; they belong on reliable control paths after approval. QUIC DATAGRAM is protected in the same crypto context but is deliberately unreliable ([RFC 9221 §1](https://www.rfc-editor.org/rfc/rfc9221.html#section-1), [§5](https://www.rfc-editor.org/rfc/rfc9221.html#section-5)).

Why: QUIC clients must not offer TLS versions older than 1.3 ([RFC 9001 §4.2](https://www.rfc-editor.org/rfc/rfc9001.html#section-4.2)). 0-RTT application data can be replayed, and RFC 9001 says disabling it entirely is the most effective replay defense ([RFC 9001 §9.2](https://www.rfc-editor.org/rfc/rfc9001.html#section-9.2)). A transport reconnect must never resurrect an old local capability merely because a TLS ticket is valid.

Alternative: Enable 0-RTT only for a future explicitly profiled, idempotent, non-authorizing request. This is rejected for v0.1 because all useful early messages here cause state, consume resources, or affect authorization.

Risk: Full handshakes cost latency during reconnect. That is acceptable before correctness/security measurement, and less harmful than replayed input enablement or stale consent.

Prototype required: No protocol experiment is needed to decide the default; implementation verification must demonstrate that 0-RTT is disabled and that resumed connections cannot send a media/input frame before fresh `session_id`/authorization issuance.

Evidence: [RFC 9001 §2.1](https://www.rfc-editor.org/rfc/rfc9001.html#section-2.1), [§4.2](https://www.rfc-editor.org/rfc/rfc9001.html#section-4.2), [§4.6.2](https://www.rfc-editor.org/rfc/rfc9001.html#section-4.6.2), [§9.2](https://www.rfc-editor.org/rfc/rfc9001.html#section-9.2), [RFC 9221 §5](https://www.rfc-editor.org/rfc/rfc9221.html#section-5).

### D3 — Content-blind relay and the role of Noise

Decision: Keep endpoint-to-endpoint QUIC/TLS through an opaque packet-forwarding relay; do not add Noise for v0.1 or to compensate for a TLS-terminating relay.

Current proposal: Relay forwarding does not terminate content encryption; an E2E-encrypted relay fallback is planned later ([protocol](../../PROTOCOL.md), [roadmap](../../ROADMAP.md)).

Verdict: MODIFY

Recommended solution: For future Internet operation, the host and client remain the QUIC endpoints. A TURN-compatible or equivalent relay allocates a bounded, short-lived forwarding path and forwards complete QUIC UDP payloads without terminating TLS, decoding media, reading control messages, holding device keys, or deciding host authorization. Pair-specific opaque rendezvous/allocation handles should be high entropy, short-lived, and rotated per connection; they are routing capabilities, not device identities. Rate limits, bandwidth quotas, allocation lifetimes, and abuse reports occur at the relay boundary before expensive work. State the product property precisely as **content-blind E2E relay**.

Why: TURN exists specifically for relaying packets when direct paths fail, and its security considerations explicitly include unauthorized allocation, anonymous malicious relaying, and DoS ([RFC 8656 §1](https://www.rfc-editor.org/rfc/rfc8656.html#section-1), [§21](https://www.rfc-editor.org/rfc/rfc8656.html#section-21)). End-to-end QUIC already provides the necessary confidentiality/integrity and peer authentication between the two devices. A malicious relay can drop, delay, reorder, and observe metadata, but it cannot turn accepted 1-RTT ciphertext into a new authorized action; QUIC/TLS does not solve availability or traffic analysis ([RFC 9000 §21](https://www.rfc-editor.org/rfc/rfc9000.html#section-21), [RFC 8446 §1](https://www.rfc-editor.org/rfc/rfc8446.html#section-1)).

Alternative: Terminate QUIC at the relay and add an application-layer Noise channel. Reject this for v0.1: it creates a second key lifecycle, transcript/channel-binding, replay, authorization, and recovery design without benefit when packet forwarding is available. Noise is a framework whose concrete security properties depend on the selected handshake pattern, static/ephemeral key knowledge, payload binding, and nonce discipline; it is not a generic “E2EE relay” switch ([Noise Framework rev. 34](https://noiseprotocol.org/noise.html)). If a terminating relay is ever unavoidable, it requires an independently reviewed E2EE protocol and does not inherit safety merely by naming Noise.

Risk: The relay still learns network metadata and can be abused as a bandwidth proxy. Hosted operation therefore needs admission control even if device identity remains decentralized. Opaque forwarding also needs careful UDP/MTU/path-validation testing.

Prototype required: EXPERIMENT_REQUIRED — does the chosen relay/TURN deployment preserve end-to-end QUIC peer authentication and reconnection across relay allocation renewal without the relay terminating or modifying application payloads?

Evidence: [RFC 8656](https://www.rfc-editor.org/rfc/rfc8656.html), [RFC 9000 §21.14](https://www.rfc-editor.org/rfc/rfc9000.html#section-21.14), [RFC 9001](https://www.rfc-editor.org/rfc/rfc9001.html), [Noise Framework](https://noiseprotocol.org/noise.html).

### D4 — Host approval, capability grants, and revocation

Decision: Make pairing, per-session consent, and capability grants three distinct host-local state transitions.

Current proposal: Explicit consent by default, separate view/input/clipboard/file/audio grants, visible activity, and immediate local revoke ([threat model](../../THREAT_MODEL.md)).

Verdict: MODIFY

Recommended solution: A pair record proves a device key only. Each new session must be locally approved by the interactive host agent and creates an in-memory capability set `{view, input}` tied to that fresh `session_id`, peer fingerprint, selected display, authorization epoch, and local expiry. `input` starts disabled and is never enabled by a reconnect, saved pairing label, portal restore token, relay, or remote request alone. Revoking any capability immediately stops the matching capture/input provider, sends best-effort reliable close/revocation, releases all pressed state, invalidates the authorization epoch, and destroys session media resources. Revoke-pair performs the same action plus deletes/marks the pinned peer record before accepting another handshake.

Why: Connection authentication is not authorization. The project already correctly treats authenticated peer messages as hostile and bounds them; that must include authorization messages ([threat model](../../THREAT_MODEL.md)). QUIC DATAGRAM shares QUIC’s authentication context but has no retransmission guarantee, so it cannot be the sole carrier of durable consent/revocation state ([RFC 9221 §1](https://www.rfc-editor.org/rfc/rfc9221.html#section-1)).

Alternative: Persist a broad `trusted device may always control` bit at pairing time. Reject for v0.1: it silently turns pairing into unattended access and makes a compromised paired device equivalent to a permanent remote-control credential.

Risk: A local user can still be socially engineered, and a process running under the same user can attack ordinary UI. Revocation cannot retract frames already viewed, protect a compromised endpoint, or propagate instantly to an offline host without a central service.

Prototype required: EXPERIMENT_REQUIRED — can the Windows and portal-backed Linux approval surface reject this agent’s own injected remote input while approval is pending, and does revocation release every key/button under packet loss and portal/session cancellation?

Evidence: [RFC 9221](https://www.rfc-editor.org/rfc/rfc9221.html), [RemoteDesktop portal](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.RemoteDesktop.html), [existing threat model](../../THREAT_MODEL.md).

### D5 — Windows privilege separation and local IPC

Decision: Eliminate a persistent privileged Windows service from v0.1; if a service is later necessary, make it a narrow maintenance broker with no desktop, content, or device secrets.

Current proposal: A service handles lifecycle, update policy, session discovery, and narrow IPC; an interactive agent owns capture, ordinary input, encoder/decoder, and consent UI ([Windows plan](../../PLATFORM_WINDOWS.md), [ADR 0006](../../adr/0006-service-agent-split.md)).

Verdict: MODIFY

Recommended solution: For logged-in LAN v0.1, run one per-user agent under the interactive user token. It owns device identity, pair records, QR UI, QUIC, DDA/WGC, normal input, and the user-visible session indicator. Do not install a `LocalSystem` listener merely to discover sessions or hold identity/update policy. Keep elevation at a separately invoked installer/package-management boundary.

If a future service is demonstrated necessary, it must not have a network listener, capture frames, arbitrary file paths, encoder/decoder input, injected-input commands, peer private keys, portal handles, or authority to approve a session. It may receive only a bounded fixed schema such as a service-owned update request or a session-discovery notification. Its named pipe must have an explicit DACL restricted to the expected per-logon SID/service identity and specific individual rights, reject non-local access, bind an operation to the caller’s session/token, and never rely on the default descriptor or generic write. Microsoft documents that a default named-pipe descriptor gives read access to Everyone and Anonymous, and that `FILE_GENERIC_WRITE` can enable pipe-instance creation ([Named Pipe Security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)). Service and updater object/file ACLs must deny untrusted users service-config replacement; changing a service configuration can otherwise permit execution under `LocalSystem` ([Service Security](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)).

Why: Windows services cannot directly interact with users after Vista; Microsoft explicitly cautions `LocalSystem` services not to create windows or access the interactive desktop ([Interactive Services](https://learn.microsoft.com/en-us/windows/win32/services/interactive-services)). A service is therefore not a capability shortcut for capture, consent, UAC, or secure desktop. Removing it from v0.1 shrinks the elevation boundary rather than trusting an untested local broker.

Alternative: Retain the baseline service as `LocalSystem` from day one and harden IPC later. Reject: the service becomes a high-value elevation target before it supplies a v0.1 feature.

Risk: Per-user startup is less convenient and does not provide login-screen access. That is aligned with the stated v0.1 exclusion; convenience is not a reason to enlarge a privilege boundary.

Prototype required: EXPERIMENT_REQUIRED — if a service is reintroduced, does an explicit per-logon-SID pipe ACL deny a different local user, a different terminal session, and a low-integrity process while preserving the intended agent operation?

Evidence: [Microsoft Interactive Services](https://learn.microsoft.com/en-us/windows/win32/services/interactive-services), [Microsoft Named Pipe Security](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights), [Microsoft Service Security](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights), [Windows plan](../../PLATFORM_WINDOWS.md).

### D6 — Linux permissions and unattended credential storage

Decision: Keep Linux standard operation user-session/portal scoped; exclude unattended access and persisted portal grants from v0.1, and store private device credentials only through user-scoped OS facilities.

Current proposal: Portable Linux support controls a logged-in, user-authorized Wayland session through RemoteDesktop/ScreenCast portals and explicitly defers generic unattended/login-screen control ([Linux plan](../../PLATFORM_LINUX.md)).

Verdict: KEEP

Recommended solution: On Linux, run no root daemon, setuid helper, Polkit action, system-bus broker, or `/dev/uinput` path in v0.1. The per-user agent obtains ScreenCast/RemoteDesktop handles in the logged-in session and treats portal closure, compositor restart, and authorization revocation as a hard session teardown. Request non-persistent portal sessions only; do not retain `restore_token` or request `persist_mode=2` for v0.1. The XDG interfaces explicitly permit persistent grants/restore tokens and say a portal may prompt again if permission was withdrawn, so a restore token is neither peer authentication nor a portable unattended-access guarantee ([ScreenCast](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.ScreenCast.html), [RemoteDesktop](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.RemoteDesktop.html)).

Store a Windows private identity as a current-user CNG key where the selected TLS provider can use it, or as a tightly ACLed application blob protected by **user-scoped** DPAPI. Never set `CRYPTPROTECT_LOCAL_MACHINE`: Microsoft states that any user on the machine can decrypt that scope. CNG supports current-user versus machine key persistence; optional VBS protection must be treated as a tested enhancement, not a portability claim ([DPAPI](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata), [NCryptCreatePersistedKey](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)). On Linux, use the logged-in user’s Secret Service collection if present; fail closed when it is locked/unavailable rather than silently falling back to a plaintext or merely mode-`0600` private-key file. The Secret Service API exposes separate collections, sessions, locking/unlocking, and secret retrieval, but it is an API capability—not proof that every desktop’s keyring has the desired lock behavior ([Secret Service API](https://specifications.freedesktop.org/secret-service/latest/)).

A later unattended design must require local enrollment of a distinct `unattended` capability for one specific pinned peer key, stored separately from ordinary pairing; local UI must show it as persistent and permit one-click revocation. The client private key is the remote credential; there is no shared static “permanent access password,” no key export/backup, and no generic login/secure-desktop capability. If a recovery password is ever added, it needs a dedicated threat model and memory-hard password handling such as Argon2id, not reuse of the pairing code ([RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html)).

Why: Portal grants are bounded by the desktop/portal policy and may support persistence in a vendor/compositor-specific way; they do not authorize a remote device by themselves. DPAPI’s user scope offers at-rest protection in the normal Windows account model, while machine scope intentionally expands decryptors. Neither platform facility protects against code running as the unlocked user.

Alternative: Store a portable encrypted key file with a hard-coded/application-derived key, or give a service machine-wide access to the user’s device key. Reject both: the first invents weak key management and the second defeats user-scope isolation.

Risk: Secret Service availability and lock semantics vary by desktop; Windows CNG key-provider and VBS behavior vary by provider/hardware. A lost client key requires manual re-pair, and an unlocked compromised user session can still use its own keys.

Prototype required: EXPERIMENT_REQUIRED — across supported GNOME and KDE versions, does the selected Secret Service/keyring remain inaccessible to the agent after a user lock event and fail closed on unlock/cancellation without making a persistent portal grant?

Evidence: [RemoteDesktop portal](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.RemoteDesktop.html), [ScreenCast portal](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.ScreenCast.html), [Microsoft DPAPI](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata), [Microsoft CNG](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey), [Secret Service API](https://specifications.freedesktop.org/secret-service/latest/), [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106.html).

### D7 — Clipboard and file-transfer boundaries

Decision: Keep clipboard and file transfer entirely excluded from v0.1; make both separate capability/security reviews rather than extensions of control media.

Current proposal: Clipboard and file transfer are explicit non-goals for v0.1 and later require separate authorization ([technical audit](../../TECHNICAL_AUDIT.md), [protocol](../../PROTOCOL.md)).

Verdict: KEEP

Recommended solution: Do not create channels, preferences, capability bits, or dormant parser paths for either feature in v0.1. If clipboard is later approved, separate read from write permission, require per-session visible enablement, start with bounded UTF-8 `text/plain` only, rate-limit transfers, never log contents, and exclude rich formats, images, file objects/URIs, history sync, and automatic overwrite. If file transfer is later approved, use a separately authorized reliable transfer protocol with per-transfer user confirmation, bounded sizes/quotas, explicit source selection and explicit save destination; never grant arbitrary remote paths, filesystem enumeration, directory synchronization, executable launch, device redirection, or automatic resume. On Linux, a file chooser is an appropriate user-mediated source/destination primitive: the portal presents a chooser and selected files may remain accessible through the Documents portal across sessions, so lifetime/revocation must be designed deliberately ([FileChooser portal](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.FileChooser.html)).

Why: End-to-end transport encryption protects bytes in transit; it cannot decide whether a plaintext is a password, sensitive clipboard content, a malicious document, or an unauthorized filesystem path. Both features add persistent data exfiltration and parser/storage surfaces beyond pointer/keyboard control.

Alternative: Add “clipboard/file streams” now but hide them in the UI. Reject: hidden protocol paths are still attack surface and collapse the explicit product boundary.

Risk: A later transfer that exposes persistent portal document grants, rich clipboard formats, or arbitrary paths would invalidate the lean user-session threat model.

Prototype required: No v0.1 prototype; any future proposal needs one scoped experiment per transfer/clipboard direction before design approval.

Evidence: [XDG FileChooser](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.FileChooser.html), [baseline non-goals](../../TECHNICAL_AUDIT.md), [future protocol mapping](../../PROTOCOL.md).

### D8 — Update signing and privileged update execution

Decision: Ship manually initiated, signed artifacts in v0.1; defer an automatic updater until it has TUF-grade metadata, key separation, rollback protection, and a separately reviewed privileged installer path.

Current proposal: Signed installers/packages and an update design are planned later; automatic update execution is a deferred high-risk feature ([roadmap](../../ROADMAP.md), [threat model](../../THREAT_MODEL.md)).

Verdict: MODIFY

Recommended solution: For v0.1, publish a manually invoked Windows installer signed with Authenticode and timestamped, and platform-native signed packages where an established package trust path is used. The installation flow verifies the artifact signature before elevation; the per-user remote-desktop agent cannot download, replace, or elevate an update on its own. Microsoft documents SignTool signing, verification, and timestamping, including hardware-backed certificate-key use ([Microsoft SignTool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/using-signtool-to-sign-a-file)).

For a future self-updater, adopt rather than invent a TUF-compatible client/metadata design: offline/threshold root keys, separately scoped targets keys, short-lived timestamp metadata, snapshot consistency, monotonically checked versions, explicit metadata expiry, and an installed-version/rollback state. TUF’s stated goals directly cover arbitrary-installation, freeze, mix-and-match, rollback, and single-key-compromise classes, but do not prevent a denial of service ([TUF §1.5.2](https://theupdateframework.github.io/specification/v1.0.33/#goals-for-protecting-against-specific-attacks)). SBOMs and build provenance are useful release evidence, but neither replaces client-side update authorization.

Why: A valid signature alone does not prevent an attacker from replaying an old valid installer or abusing a compromised online signer. The update manifest and installed-version state are security-critical protocol inputs, and the component that replaces privileged binaries must not be driven by the network-facing session agent.

Alternative: A single vendor-signed JSON manifest plus a background `LocalSystem` updater. Reject: it leaves rollback/freeze/key-compromise behavior undefined and turns an Internet-reachable product component into an elevation path.

Risk: Manual updates delay security patch uptake; automatic updates introduce a supply-chain and elevation boundary that needs independent review.

Prototype required: EXPERIMENT_REQUIRED — can a candidate update client reject a validly signed older target and expired/mix-and-match metadata while never invoking elevation before all verification succeeds?

Evidence: [Microsoft SignTool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/using-signtool-to-sign-a-file), [TUF specification](https://theupdateframework.github.io/specification/v1.0.33/), [baseline roadmap](../../ROADMAP.md).

### D9 — Central accounts, discovery, and revocation scope

Decision: Avoid central user accounts for v0.1 identity and pairing, while explicitly declining account-recovery, public discovery, and hosted-relay claims.

Current proposal: LAN first, Internet traversal/relay later, with locally generated device identity ([README](../../README.md), [roadmap](../../ROADMAP.md)).

Verdict: KEEP

Recommended solution: Treat device key pairs and host-local pair records as the sole v0.1 identity system. LAN discovery may be unauthenticated because the QR-pinned TLS key decides trust; do not put a stable device identifier or user name in unauthenticated broadcast. Do not offer password reset, cloud backup, email recovery, public host directory, or cross-host revocation synchronization. A lost device is revoked locally at each reachable host and re-paired manually. For a future hosted relay/rendezvous, use pair-scoped opaque handles and disclose that the service receives metadata; give public relay admission/quotas an explicit operations design rather than silently converting a device identifier into an account.

Why: Decentralized pinned keys answer peer authentication without a central account. They cannot, by themselves, deliver recovery, global revocation, abuse billing, or discovery. TURN’s relay model also requires an allocation/permission control plane and has explicit unauthorized/anonymous-relaying abuse concerns ([RFC 8656 §3](https://www.rfc-editor.org/rfc/rfc8656.html#section-3), [§21](https://www.rfc-editor.org/rfc/rfc8656.html#section-21)).

Alternative: Create central accounts now to make recovery and public relay convenient. Reject for v0.1: it adds credential recovery, account takeover, PII, service availability, and identity-linkability scope before the direct product path is proven.

Risk: Local-only revocation is not globally immediate, and self-hosted/anonymous relay operation may be impractical at scale without admission controls. These are product limitations that must be stated, not hidden behind “account-free.”

Prototype required: No v0.1 prototype. A hosted-relay proposal must separately measure whether its anonymous allocation/admission control resists abuse without exposing stable device identifiers.

Evidence: [RFC 8656](https://www.rfc-editor.org/rfc/rfc8656.html), [repository network scope](../../README.md), [roadmap](../../ROADMAP.md).

## Required boundary model

### Processes and authority

| Component | Runs as | May hold | Must not hold/do |
|---|---|---|---|
| Interactive host/client agent | Logged-in user | Per-user key handle/blob, pair records, QUIC endpoint, portal/DDA/WGC handles, visible consent state. | Elevate, capture Session 0, grant secure desktop/UAC access, run arbitrary installer actions. |
| Elevated installer/package action | Only during explicit local installation/update | Verified staged artifact and minimal install privilege. | Network session state, device private keys, capture/input/consent UI, automatic remote command channel. |
| Future maintenance service, if proven necessary | Least privileged service identity; not a generic `LocalSystem` broker. | Its narrowly defined maintenance state only. | Network listener, desktop capture, input injection, peer secrets, arbitrary paths/commands, UI/consent decisions. |
| Future codec/GPU worker | Restricted normal-user process, if platform capability tests permit. | Bounded encoded/decoded surfaces/Fds. | Pair database, key-store access, service control, arbitrary filesystem access. |
| Relay/rendezvous | Remote untrusted service | Short-lived forwarding/allocation metadata, quotas, operational logs. | TLS termination, plaintext media/control, device private keys, host authorization. |

The codec/GPU split is an `EXPERIMENT_REQUIRED` hardening path: it may conflict with capture/graphics resource sharing on particular Windows drivers and Wayland compositors. It must not be presented as sandboxing until an actual restricted-token/AppContainer or Linux sandbox design is shown to preserve the tested GPU path.

### Replay, revocation, and logging risk register

| Risk | Required control | Residual limitation |
|---|---|---|
| Replayed early data or old authorization request | Disable 0-RTT; consume pairing IDs once; create fresh session/authorization epochs after each full handshake. RFC 9001 assigns replay management to the application protocol and identifies disabling 0-RTT as the most effective defense ([RFC 9001 §9.2](https://www.rfc-editor.org/rfc/rfc9001.html#section-9.2)). | A malicious relay can delay/drop packets; it cannot provide availability. |
| Replayed/reordered UDP media or input | QUIC 1-RTT packet protection plus existing bounded input sequence/epoch checks; never make a DATAGRAM the sole durable authorization fact. | A compromised paired endpoint can generate fresh valid events until revoked. |
| QR invitation reuse or race | CSPRNG secret, short expiry, atomic one-use state, no logging/copy/paste, local host acceptance. | Physical QR exposure or local malware can still race the intended client. |
| Revoked peer reconnects via resumption/relay | Pair-record denylist/active-state check before application authorization; invalidate all active authorization epochs; close/release local input. | No central service means an offline host cannot be updated immediately; already viewed data cannot be recalled. |
| Portal permission outlives product consent | Do not request persistent/restore portal grants in v0.1; on portal closure/revocation tear down agent session. | Backend behavior is compositor/version-specific and needs the listed experiments. |
| Sensitive diagnostic data leaks | Normal logs contain only local event type, time, opaque/truncated peer key ID, capability decision, session outcome, bounded error class, and update key/version/result. Protect logs with user/service ACLs and retention bounds. | Local event logs are not tamper-proof forensic evidence. |
| Logs expose secrets or content | Never log screen pixels, audio, keystrokes, clipboard/file bytes or names, QR/pairing secrets, TLS tickets, private keys, raw control/media packets, full peer IP history, or unredacted crash dumps. | A user-authorized crash report needs a separate privacy policy and consent. |

## Minimum v0.1 release plan and hard exclusions

### Must ship before claiming secure LAN remote control

1. **Identity and pairing:** D1 QR-only pairing, locally generated/persisted per-user identity, pinned peer fingerprint, changed-key fail-closed behavior, pair revoke UI, and tests for expiry/race/re-pair.
2. **Transport:** TLS 1.3 QUIC with pinning/mTLS, 0-RTT disabled, full-handshake-first session authorization, bounded protocol parsing, and control/media/input epoch validation already required by the protocol proposal.
3. **Authority:** per-session local host approval, visible active indicator, default view-only until input is explicitly approved, release-all on every close/revoke/provider failure, and no durable unattended bit.
4. **OS boundary:** Windows/Linux per-user agents only; portal-scoped Linux sessions with no persistent restore grant; user-scoped secret storage; manual pair re-enrollment rather than key export.
5. **Data minimization:** event-only local audit logs, no sensitive content logging, and no optional data-channel parser paths.
6. **Distribution:** manually initiated signed installer/package verification; no automatic update service; document signing-key and manual upgrade provenance.

### Must remain excluded

- Any unattended access, wake-on-LAN implication, login-screen access, Windows secure desktop/UAC control, or generic Wayland persistent remote-control claim.
- Persistent portal grants/restore tokens, root/system Linux capture/input, `/dev/uinput`, Polkit helpers, setuid components, and an always-on `LocalSystem` remote-control broker.
- Public relay/rendezvous, NAT traversal, account recovery, public host discovery, cloud pair backup, and product claims of metadata-free/“zero-knowledge” operation.
- Clipboard, file transfer, audio capture, printer/device/drive redirection, remote shell, arbitrary file paths, file-object clipboard formats, and rich clipboard formats.
- Numeric-code-as-security pairing, TOFU changed-key acceptance, public-Web-PKI substitution for device pinning, shared permanent-access passwords, or device-key export.
- Noise/double encryption layered into end-to-end QUIC without a distinct reviewed need.
- Automatic self-update, remote-triggered installer execution, a single online signing key as the complete update trust model, and any release that treats an SBOM as a client-side verification mechanism.

## Sources

### Official

- [Microsoft — Interactive Services](https://learn.microsoft.com/en-us/windows/win32/services/interactive-services)
- [Microsoft — Named Pipe Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/ipc/named-pipe-security-and-access-rights)
- [Microsoft — Service Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)
- [Microsoft — CryptProtectData (DPAPI)](https://learn.microsoft.com/en-us/windows/win32/api/dpapi/nf-dpapi-cryptprotectdata)
- [Microsoft — NCryptCreatePersistedKey](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey)
- [Microsoft — Use SignTool to Sign a File](https://learn.microsoft.com/en-us/windows/win32/seccrypto/using-signtool-to-sign-a-file)
- [XDG Desktop Portal — ScreenCast, interface v6](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.ScreenCast.html)
- [XDG Desktop Portal — RemoteDesktop, interface v2](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.RemoteDesktop.html)
- [XDG Desktop Portal — FileChooser, interface v4](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.FileChooser.html)
- [Freedesktop — Secret Service API](https://specifications.freedesktop.org/secret-service/latest/)

### Upstream

- [The Update Framework Specification v1.0.33](https://theupdateframework.github.io/specification/v1.0.33/)
- [Noise Protocol Framework, revision 34](https://noiseprotocol.org/noise.html)

### Standards

- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html)
- [RFC 9000 — QUIC Transport](https://www.rfc-editor.org/rfc/rfc9000.html)
- [RFC 9001 — Using TLS to Secure QUIC](https://www.rfc-editor.org/rfc/rfc9001.html)
- [RFC 9221 — QUIC DATAGRAM](https://www.rfc-editor.org/rfc/rfc9221.html)
- [RFC 8656 — TURN](https://www.rfc-editor.org/rfc/rfc8656.html)
- [RFC 9383 — SPAKE2+](https://www.rfc-editor.org/rfc/rfc9383.html)
- [RFC 9106 — Argon2](https://www.rfc-editor.org/rfc/rfc9106.html)
- [RFC 4086 — Randomness Requirements for Security](https://www.rfc-editor.org/rfc/rfc4086.html)

### Other

- [Repository threat model](../../THREAT_MODEL.md)
- [Repository protocol design](../../PROTOCOL.md)
- [Repository technical audit](../../TECHNICAL_AUDIT.md)
- [Repository Windows platform plan](../../PLATFORM_WINDOWS.md)
- [Repository Linux platform plan](../../PLATFORM_LINUX.md)
- [Repository service-agent ADR](../../adr/0006-service-agent-split.md)
- [Repository roadmap](../../ROADMAP.md)

## Candidate experiments

- Can the selected QUIC library enforce pinned self-signed mTLS while disabling 0-RTT on both target operating systems?
- Can a pending local approval UI reject this product’s own injected input on Windows and each supported Wayland portal backend?
- Does an opaque relay path preserve endpoint-to-endpoint QUIC authentication after allocation renewal without TLS termination?
- Does the selected Linux Secret Service/keyring fail closed after user lock and across GNOME/KDE session cancellation?
- Can a reintroduced Windows service pipe deny cross-user, cross-session, and low-integrity clients with the intended explicit DACL?
- Can the candidate update client reject an older signed target and expired/mix-and-match metadata before any elevation occurs?
