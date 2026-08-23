# LatencyDesk lab-preview package runbook

This runbook is for the binary archives. Except for Section 1, run commands
from the extracted archive root. Run Section 1 from the download directory
before extraction. Do not substitute the source-checkout `cargo run` commands
from the repository README.

> This is a lab preview, not a production release. It has no codec, rendezvous,
> NAT traversal, relay, reconnect, installer, updater, or demonstrated
> cross-machine release qualification. The intended secure preview topology is
> a Linux X11 Host and a Windows interactive Client on a trusted wired LAN.

Read `SECURITY.md` and `docs/PRODUCT_READINESS.md` before exchanging identity
files or opening a firewall port.

## 1. Verify the archive

Keep the archive and its adjacent `.sha256` file together. Verify it before
extracting.

The archive and checksum are not signed. This check detects corruption but
does not authenticate the publisher. Obtain both through an authenticated
release channel. Replace `<version>` below with the version in the downloaded
file name.

Windows PowerShell:

```powershell
$archive = "LatencyDesk-<version>-lab-preview-windows-x86_64.zip"
$expected = (Get-Content "$archive.sha256").Split()[0].ToLowerInvariant()
$actual = (Get-FileHash $archive -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actual -ne $expected) { throw "archive SHA-256 mismatch" }
```

Linux:

```bash
sha256sum --check LatencyDesk-<version>-lab-preview-linux-x86_64.tar.gz.sha256
```

The package manifest records `source_state.dirty`. A dirty lab build is
permitted, but its top-level `commit` is `null`; `source_state.git_head` is only
the base commit and the archive is attributed to the base plus worktree
changes. The `source_state.diff_sha256` recipe is:

1. Write `git diff --binary --full-index --no-ext-diff --no-color HEAD` to a
   file without transforming its bytes, then SHA-256 that file.
2. Enumerate `git -c core.quotePath=false ls-files --others
   --exclude-standard`, sort paths in ordinal order, and SHA-256 each raw file.
3. Create this UTF-8-without-BOM, LF-terminated descriptor (`<TAB>` means one
   literal tab byte):

   ```text
   format=latencydesk-source-diff-v1
   head=<full Git HEAD object id>
   tracked_diff_sha256=<tracked diff SHA-256>
   untracked=<repository-relative path><TAB>sha256=<raw file SHA-256>
   ```

   Repeat the last line for each sorted untracked file; omit it when there are
   none.
4. SHA-256 that descriptor. The result must equal the manifest value.

The exact recipe identifier is also stored in `source_state.diff_hash_format`.

## 2. Match the Linux and Windows builds

When using a Linux Host archive with a Windows Client archive, compare their
manifest `version`, `source_state.git_head`, `source_state.dirty`, and
`source_state.diff_sha256`. All four must match; otherwise do not combine them.

## 3. Create one persistent identity per device

The command creates `identity.cert.der` and `identity.key.der` and refuses to
overwrite an existing identity.

Linux X11 Host:

```bash
umask 077
install -d -m 700 "$HOME/.local/share/latencydesk/peers"

./latencydesk-identity generate \
  --name "Linux X11 host" \
  --out-dir "$HOME/.local/share/latencydesk/host"

./latencydesk-identity fingerprint \
  --cert "$HOME/.local/share/latencydesk/host/identity.cert.der"
```

Windows Client in PowerShell:

```powershell
New-Item -ItemType Directory -Force `
  "$env:LOCALAPPDATA\LatencyDesk\peers" | Out-Null

.\latencydesk-identity.exe generate `
  --name "Windows client" `
  --out-dir "$env:LOCALAPPDATA\LatencyDesk\client"

.\latencydesk-identity.exe fingerprint `
  --cert "$env:LOCALAPPDATA\LatencyDesk\client\identity.cert.der"
```

Exchange only `identity.cert.der` through a trusted channel. Never copy or
share `identity.key.der`. Compare both printed SHA-256 fingerprints over a
separate trusted channel. In the examples below:

- the Host stores the Client certificate as
  `$HOME/.local/share/latencydesk/peers/windows-client.cert.der`;
- the Client stores the Host certificate as
  `$env:LOCALAPPDATA\LatencyDesk\peers\linux-host.cert.der`.

For example, after receiving the renamed peer certificates through that
trusted channel:

```bash
install -m 600 /trusted-transfer/windows-client.cert.der \
  "$HOME/.local/share/latencydesk/peers/windows-client.cert.der"
```

```powershell
Copy-Item -LiteralPath "D:\trusted-transfer\linux-host.cert.der" `
  -Destination "$env:LOCALAPPDATA\LatencyDesk\peers\linux-host.cert.der"
```

Fingerprint the received certificate too and compare it with the value shown
on the device that generated it.

## 4. Start the Linux X11 Host

Run this as the user logged in to the intended X11 session. Allow inbound UDP
port 9000 only from the trusted Client network.

```bash
test -n "${DISPLAY:-}" || {
  echo "Run this from the logged-in X11 session; DISPLAY is unset." >&2
  exit 1
}

./latencydesk-host \
  --listen 0.0.0.0:9000 \
  --identity-cert "$HOME/.local/share/latencydesk/host/identity.cert.der" \
  --identity-key "$HOME/.local/share/latencydesk/host/identity.key.der" \
  --peer-cert "$HOME/.local/share/latencydesk/peers/windows-client.cert.der" \
  --pairing-timeout 300 \
  --max-width 640 \
  --max-height 360 \
  --fps 15
```

The Host accepts only the exact pinned Client certificate. Windows secure
hosting is unsupported and fails before opening a network socket. The packaged
Windows Host binary exists only for the explicit plaintext compatibility lab
mode described by `--unsafe-udp-lab`; do not use that mode on a LAN or WAN.

## 5. Start the Windows interactive Client

Replace `192.168.1.20` with the Linux Host address.

```powershell
.\latencydesk-client.exe `
  --connect 192.168.1.20:9000 `
  --identity-cert "$env:LOCALAPPDATA\LatencyDesk\client\identity.cert.der" `
  --identity-key "$env:LOCALAPPDATA\LatencyDesk\client\identity.key.der" `
  --peer-cert "$env:LOCALAPPDATA\LatencyDesk\peers\linux-host.cert.der" `
  --pairing-timeout 300
```

The Windows Client is a strict raw-NV12 D3D11 viewer. There is no H.264/AV1
decoder path in this package.

## 6. Optional Linux headless Client

Linux has no interactive viewer. It can perform a bounded headless receive
using a separate Client identity that the Host pins instead of the Windows
certificate. Generate that separate identity first:

```bash
./latencydesk-identity generate \
  --name "Linux headless client" \
  --out-dir "$HOME/.local/share/latencydesk/client"
```

Exchange and fingerprint this Client's certificate just as above. Store it on
the Host as
`$HOME/.local/share/latencydesk/peers/linux-headless-client.cert.der`, store the
Host certificate on the Client as
`$HOME/.local/share/latencydesk/peers/linux-host.cert.der`, then restart the
Host with `--peer-cert` pointing at `linux-headless-client.cert.der`. A Host
process currently pins exactly one peer certificate.

Run the bounded Client:

```bash
./latencydesk-client \
  --connect 192.168.1.20:9000 \
  --identity-cert "$HOME/.local/share/latencydesk/client/identity.cert.der" \
  --identity-key "$HOME/.local/share/latencydesk/client/identity.key.der" \
  --peer-cert "$HOME/.local/share/latencydesk/peers/linux-host.cert.der" \
  --frames 60
```

Any missing or wrong certificate, mixed secure/legacy flags, unsupported
platform role, or malformed identity must fail closed. Treat a fallback to
`--unsafe-udp-lab` as a failed secure test.
