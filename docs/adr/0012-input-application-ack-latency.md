# ADR 0012: Opt-in input application acknowledgments

**Status:** Accepted

**Date:** 2026-08-31

## Context

Input uses its own high-priority reliable QUIC lane, but the project had no
evidence for the interval between a Client submitting an event and the Linux
Host completing reconciliation plus XTEST injection. Network send completion
alone cannot prove that the Host applied the input, while cross-machine clocks
cannot be compared safely without a separate synchronization experiment.

## Decision

1. Version-1 input records may set one explicit `ACK_REQUESTED` flag. Ordinary
   input leaves it clear and pays no ACK traffic or waiting cost; unknown flags
   remain protocol errors.
2. The Linux Host creates `InputAppliedAck` only after epoch validation,
   duplicate suppression, reconciliation, every resulting XTEST call, and a
   subsequent X11 request/reply synchronization have returned. Platform or
   synchronization failure produces an `ApplyFailed` ACK before the input lane
   terminates; only a fully successful path produces `Applied`.
3. ACK payloads contain the complete ProductSession stamp, input epoch,
   original input sequence, a per-session ACK sequence, status, and only an
   action count. They never contain key codes, text, button identities, or
   snapshots.
4. The Client accepts an ACK only when the outer control lane and payload match
   the current full stamp, input sequence, ACK sequence, successful status, and
   expected action count. ACKs never grant permission or trigger input replay.
5. `--input-latency-probes N` is a bounded single-target diagnostic. It sends
   alternating relative pointer events one at a time and measures each local
   `Instant` from immediately before reliable send through receipt of the
   post-X11-sync ACK. It first receives one media frame so the complete product
   session is active.
6. Linux CI retains exactly 128 raw `{sequence, latency_us}` samples, recomputes
   nearest-rank p50/p95/p99 and mean, and uses a permissive 100 ms loopback p95
   sanity ceiling to detect stalls rather than market a competitive result.

## Consequences

- The resulting number is `application_ack_rtt`, not input-to-photon latency,
  display latency, or proof of superiority over another product.
- Sequential probes measure responsiveness without queue buildup; separate
  concurrent-load and physical keyboard-to-photon experiments remain required.
- Windows Host ACK production, interactive continuous telemetry, network
  shaping, and competitor baselines remain Pending.

## Sources

- QUIC streams and reliable application data:
  https://www.rfc-editor.org/rfc/rfc9000.html#section-2
- QUIC stream prioritization is application-defined:
  https://www.rfc-editor.org/rfc/rfc9000.html#section-2.3
