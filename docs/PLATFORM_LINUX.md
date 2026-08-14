# Linux Wayland Platform Plan

## Supported security model

The portable reference backend controls a **logged-in, user-authorized Wayland session**. It does not promise generic login-screen or unattended capture/input.

```text
user selects/authorizes session
      ↓
XDG RemoteDesktop + ScreenCast portal
      ↓
PipeWire video stream + input connection/capability
      ↓
DMA-BUF import when compatible
or MemFd/CPU/GPU copy fallback
      ↓
encoder / renderer provider
```

## Portal state machine

Model every asynchronous portal step explicitly:

1. create session;
2. select sources/devices;
3. start session and receive PipeWire node(s);
4. connect PipeWire stream;
5. begin capture/input only after authorization;
6. respond to cancellation, close, compositor restart, and permission revocation;
7. release all input state and media resources.

Do not bury portal errors inside a generic “capture failed” message. Diagnostics include desktop environment, portal backend, negotiated memory type, format, modifier, and input capability without logging pixels or keystrokes.

## PipeWire buffers

- negotiate supported video formats and memory types;
- prefer DMA-BUF only when device/modifier/sync import is valid;
- support MemFd/CPU buffer fallback;
- never retain PipeWire-owned buffers across unbounded async work;
- import/copy synchronously into a bounded encoder-owned pool, then return buffer;
- handle format changes and renegotiation by incrementing display/codec epoch.

## Input

Use the RemoteDesktop session and libei path when exposed by the environment. Implement:

- keyboard physical usages and release reconciliation;
- relative and absolute pointer modes;
- buttons, high-resolution wheel, and focus loss;
- coordinate transforms for scale/rotation;
- explicit capability errors when compositor/backend cannot provide a requested device.

`/dev/uinput` is not the default portable Wayland path. A privileged appliance backend would require a separate security design.

## Client presentation

Use a native Wayland window and a hardware decode provider. Import decoder surfaces into Vulkan/EGL only when supported; retain a measured copy path. The compositor may impose presentation scheduling, so record decode completion and present submission and validate with optical measurement.

## Test matrix

At least:

- GNOME Wayland with its standard portal backend;
- KDE Plasma Wayland with its standard portal backend;
- NVIDIA reference path;
- one Intel and one AMD path during provider expansion;
- DMA-BUF enabled and forcibly disabled;
- fractional scale, rotation, multi-monitor selection;
- user cancellation, permission revoke, logout, compositor restart;
- screen lock behavior explicitly recorded;
- PipeWire reconnect and format changes;
- stuck-key tests under packet loss/disconnect.

X11 support follows as a compatibility provider and must use the same core contracts.
