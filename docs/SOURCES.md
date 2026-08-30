# Primary Technical Sources

Reviewed for the architecture on 2026-08-30. These links are implementation references, not blanket endorsements or performance proof.

## Windows

- Microsoft — Desktop Duplication API: https://learn.microsoft.com/en-us/windows/win32/direct3ddxgi/desktop-dup-api
- Microsoft — Windows screen capture: https://learn.microsoft.com/en-us/windows/apps/develop/media-authoring-processing/screen-capture
- Microsoft — Interactive services / Session 0 considerations: https://learn.microsoft.com/en-us/windows/win32/services/interactive-services
- Microsoft — `SendInput`: https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-sendinput

## Linux Wayland, PipeWire, input

- XDG Desktop Portal — ScreenCast: https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.ScreenCast.html
- XDG Desktop Portal — RemoteDesktop: https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.portal.RemoteDesktop.html
- PipeWire documentation: https://docs.pipewire.org/
- libei documentation: https://libinput.pages.freedesktop.org/libei/

## Network protocols

- IETF RFC 9000 — QUIC: https://www.rfc-editor.org/rfc/rfc9000
- IETF RFC 9001 — Using TLS to Secure QUIC: https://www.rfc-editor.org/rfc/rfc9001
- IETF RFC 9221 — QUIC DATAGRAM: https://www.rfc-editor.org/rfc/rfc9221
- Quinn 0.11.8 `SendStream::set_priority`: https://docs.rs/quinn/0.11.8/quinn/struct.SendStream.html#method.set_priority
- IETF RFC 8445 — ICE: https://www.rfc-editor.org/rfc/rfc8445
- IETF RFC 8656 — TURN: https://www.rfc-editor.org/rfc/rfc8656
- `is` 0.11.0 — focused Sans-I/O ICE agent extracted from str0m: https://docs.rs/is/0.11.0/is/
- str0m upstream and ICE design provenance: https://github.com/algesten/str0m

## Video acceleration/provider references

- NVIDIA Video Codec SDK documentation: https://docs.nvidia.com/video-technologies/video-codec-sdk/
- Intel oneVPL specification: https://oneapi-spec.uxlfoundation.org/specifications/oneapi/latest/elements/onevpl/source/index.html
- VA-API/libva upstream: https://github.com/intel/libva
- AMD Advanced Media Framework upstream: https://github.com/GPUOpen-LibrariesAndSDKs/AMF
- Cisco OpenH264 upstream and binary/patent notices: https://github.com/cisco/openh264

## Adjacent open-source projects — architecture/provenance review only

- RustDesk: https://github.com/rustdesk/rustdesk
- RustDesk video service: https://github.com/rustdesk/rustdesk/blob/master/src/server/video_service.rs
- RustDesk license boundary: https://github.com/rustdesk/rustdesk/blob/master/LICENCE
- Sunshine: https://github.com/LizardByte/Sunshine
- Sunshine low-latency encoder configuration: https://github.com/LizardByte/Sunshine/blob/master/docs/configuration.md
- Moonlight latency and frame-pacing FAQ: https://github.com/moonlight-stream/moonlight-docs/wiki/Frequently-Asked-Questions
- Moonlight common core: https://github.com/moonlight-stream/moonlight-common-c
- Selkies WebRTC/congestion-control FAQ: https://github.com/selkies-project/selkies/blob/main/docs/faq.md
- TigerVNC: https://github.com/TigerVNC/tigervnc
- FreeRDP: https://github.com/FreeRDP/FreeRDP

Before implementing a provider, re-check the current official API, SDK, platform, license, and distribution terms. This source list does not freeze them.
