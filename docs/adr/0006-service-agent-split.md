# ADR 0006: Separate privileged service from interactive user agent

- Status: Accepted
- Date: 2026-08-13

## Decision

On Windows, capture and normal input live in the logged-in user agent. A service is limited to lifecycle, session discovery, update policy, and narrowly scoped IPC. Linux standard operation remains user-session/portal scoped.

## Consequences

Secure-desktop/login-screen control is not inherited automatically and requires a later privilege-specific design. The attack surface of elevated code remains smaller.
