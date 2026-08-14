# ADR 0005: Keep host and client timing in separate monotonic clock domains

- Status: Accepted
- Date: 2026-08-13

## Decision

Software telemetry reports local stage durations. Clock synchronization produces only an estimate with uncertainty. Physical input-to-photon/screen-to-screen measurement is required for performance claims.

## Consequences

Dashboards cannot fabricate precise one-way latency by subtracting unrelated timestamps, but benchmark conclusions remain defensible.
