# ADR 0002: Use Wayland portals/PipeWire/libei as the standard Linux backend

- Status: Accepted
- Date: 2026-08-13

## Decision

The portable Linux host targets logged-in, user-authorized Wayland sessions through XDG ScreenCast/RemoteDesktop portals, PipeWire, and libei where available. KMS/uinput/compositor-specific paths are later optional backends.

## Consequences

v0.1 cannot promise generic login-screen/unattended Wayland control. It gains a security-model-aligned GNOME/KDE route and avoids requiring root for the standard backend.
