# Security Policy

LatencyDesk is a secure alpha, not a production-supported unattended-access
service. The default product path is fail-closed TLS 1.3 mutual authentication
over QUIC; the old plaintext UDP path requires explicit `--unsafe-udp-lab`.

## Default product security boundary

The secure host and client require all three of these paths:

- `--identity-cert`: the local self-signed leaf certificate in DER format;
- `--identity-key`: its matching PKCS#8 private key in DER format;
- `--peer-cert`: the exact expected peer leaf certificate in DER format.

Both TLS configurations trust only the supplied peer certificate, and the
authenticated leaf is additionally compared byte-for-byte before an application
session is returned. TLS is restricted to 1.3, early data is disabled, and there
is no automatic downgrade to the legacy UDP path. Reliable input records carry
the authenticated product-session stamp; media travels in bounded QUIC
DATAGRAMs.

`latencydesk-identity generate` creates persistent `identity.cert.der` and
`identity.key.der` files and refuses to overwrite them. On Unix, new private-key
files are created with mode `0600`; on Windows, protection depends on the
directory's account ACLs. The private key is not password-encrypted or backed by
an OS hardware keystore. Keep it on its originating device, exclude it from
source control and backups shared with others, and never send it to a peer.

Certificate exchange is manual. Compare the SHA-256 fingerprints through an
independent trusted channel: transport security cannot detect that a user pinned
an attacker's certificate during a compromised exchange. There is not yet an
account service, certificate revocation/rotation workflow, recovery flow, or
supported unattended-access policy.

## Product limitations that still affect security

- secure hosting is implemented only for Linux X11; Windows and other hosts are
  rejected before a network socket is opened;
- the interactive viewer is Windows-only; other clients must use bounded
  `--frames` headless mode or `--inject-probe`;
- media is raw NV12, so the current path is appropriate only for a low-resolution
  trusted-LAN alpha preview despite QUIC encryption;
- there is no production rendezvous, NAT traversal, end-to-end relay, seamless
  reconnect, signed installer/updater, or operational audit service;
- exact-peer mTLS, product lanes, rogue-client rejection, and real X11 frame
  delivery have a retained single-machine Xvfb process-loopback result; a
  cross-machine Linux-host-to-Windows-client viewer result, visible input-effect
  test, and packet-capture review are still Pending;
- the project has not completed an independent security assessment.

An authenticated peer is still untrusted input. Dimensions, frame sizes,
fragments, queues, sequence numbers, session epochs, and native input actions
must remain bounded and validated. TLS protects data on the network; it does not
protect a compromised endpoint, an exposed desktop session, or a leaked private
key.

## Unsafe legacy UDP mode

`--unsafe-udp-lab` explicitly selects the compatibility protocol. Its known
limits include:

- desktop media and input datagrams are plaintext;
- the custom tag is not a secure cryptographic message authenticator;
- the client does not cryptographically authenticate the host;
- `--approve` / `--auto-approve` uses a public built-in fixed secret;
- `--device-fingerprint` is not proof of a persistent private key;
- supplying `--shared-secret` does not repair the protocol.

Use this mode only on `127.0.0.1` with disposable synthetic/test content. Never
bind it to an external interface, select the harness's `lan-bind` mode, forward
its port, or use it for privileged or sensitive desktop control.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/1122-gggggg/open_desk/security/advisories/new)
when available. If it is disabled, contact a maintainer through a private
channel before disclosing details. Do not open a public issue containing an
exploit, credential, private key, token, captured desktop data, or working
remote-control bypass.

Include the affected commit and platform, threat preconditions, a minimal safe
reproduction, security impact, and a suggested mitigation if known. State
whether the secure QUIC or unsafe legacy path is involved. Never paste live
credentials into a report; revoke any credential already exposed in a chat,
log, issue, or artifact.

## Supported versions and contribution baseline

No production version is supported. Security fixes target the latest `main`
branch until a tagged release documents a support period and passes
[`docs/PRODUCT_READINESS.md`](docs/PRODUCT_READINESS.md).

Contributions must follow `docs/THREAT_MODEL.md`, fail closed, and include
negative tests for wrong identities, replay, stale session stamps, malformed
messages, resource exhaustion, and native privilege boundaries.
