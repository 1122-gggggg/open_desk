# ADR 0004: Media freshness never overrides predictive-codec continuity

- Status: Accepted
- Date: 2026-08-13

## Decision

Encoded access units carry codec epoch, frame id, conservative dependency, and recovery-point metadata. Missing required data triggers a coalesced recovery request; dependent frames are not fed to the decoder.

## Consequences

The sender cannot blindly drop any late P-frame. Encoder queue-drop policy and transport scheduling must coordinate with IDR/intra-refresh recovery.
