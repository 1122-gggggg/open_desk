# ADR 0025: Concurrent rendezvous with two-sided delivery commit

## Status

Accepted for the bounded exact-mTLS rendezvous daemon and local process gates.
Public trust/account operation and automatic desktop route creation remain
pending.

## Decision

One daemon may trust 2–32 unique exact client leaves and run at most eight
authentication/request admissions concurrently. Matching state remains
serialized in `RendezvousBroker`; pending, per-device, registration, match,
rejection, frame, and deadline bounds are explicit.

A reciprocal registration reserves a match but does not commit it. The wire
barrier is:

1. Delivery to both authenticated connections.
2. DeliveryAck from both connections.
3. Commit to both connections.
4. CommitAck from both connections.
5. Broker confirmation.
6. Complete to the clients.

Clients retain the peer offer internally but do not return it to the caller
before Complete. Failure before both CommitAck messages aborts the reservation,
closes both connections, and refunds exactly the two uncommitted registrations.
A disconnected or expired waiter refunds exactly one registration and leaves a
replay tombstone. After both CommitAck messages, Complete delivery failure does
not roll back a match both peers already committed.

`exchange_registration` returns `CommittedRendezvousDelivery`, not the raw
delivery. Its fields and constructor are private, it has no `into_inner`, and
only the validated Complete branch can create it. The token owns the exact
local and peer `DeviceId` plus both canonical registrations so a later route
coordinator need not duplicate secret-bearing registration state. Access is
read-only and Debug renders both registrations as redacted. The token is
same-process, non-serializable Rust type-state. It is not a durable
cryptographic attestation, a third-party proof, or a stable commit-instance
identity; callers that need those properties require a separately designed
signed protocol.

## Evidence and limits

The in-process fault gate disconnects the second peer after the first CommitAck
and proves the first cannot complete. Broker tests prove three disconnected
waiters do not exhaust a later legal pair. The native multi-process gate proves
two matches through four clients while a stranger is rejected, with exact
versions, DER validation, and live UDP socket ownership.

All evidence is same-machine loopback. It does not establish public service
availability, distributed persistence, account recovery, abuse resistance,
NAT traversal, route promotion, or competitor superiority.
