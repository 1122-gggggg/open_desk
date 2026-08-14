# ADR 0001: Establish a full-frame H.264 baseline before hybrid refinement

- Status: Accepted
- Date: 2026-08-13

## Context

Per-region simultaneous codecs would make synchronization, rate allocation, packet-loss recovery, decoder composition, and performance attribution difficult before cross-platform capture/render works.

## Decision

Implement a complete low-delay H.264 stream first. Add independently discardable exact tiles and static refinements only after the baseline is frozen and benchmarked.

## Consequences

Initial text quality/bandwidth may not beat desktop-specific codecs. In return, recovery and cross-platform debugging remain tractable, and later refinements have a valid control baseline.
