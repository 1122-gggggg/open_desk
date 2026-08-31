# Candidate exchange and rendezvous parser fuzz plan

## Scope

The targets are the three nested, peer-controlled decoding boundaries changed
by TURN-relayed candidate signaling:

1. `IceCandidate::decode`
2. `CandidateExchange::decode`
3. `RendezvousRegistration::decode`

The harness must call the public decoders exactly as the network paths do. It
must not bypass length checks or construct Rust values directly.

## Seed corpus

Retain canonical encodings for:

- one IPv4 and one IPv6 Host candidate;
- one IPv4 and one IPv6 server-reflexive candidate with related address;
- one IPv4 and one IPv6 UDP `Relayed`/`Turn` candidate;
- same-family Host plus TURN-relayed candidates;
- the maximum eight-candidate exchange;
- initiator and responder rendezvous registrations containing each exchange;
- exact maximum-size and minimum-size valid frames.

Every seed records the repository revision and SHA-256. No credentials or
private keys are corpus inputs.

## Mutations

The first implementation uses `cargo-fuzz`/libFuzzer with structure-aware
dictionary tokens for the wire version, address-family tags, candidate type,
relay provider, transport, lengths, count, generation, exchange ID, and match
ID. It must also retain raw byte mutation, truncation at every byte offset,
one-byte extension, declared-length drift, duplicate endpoint insertion,
candidate reordering, cross-family related addresses, zero/nonzero boundary
flips, and count values 0, 1, 8, 9, and 255.

## Invariants

For every input:

- decoding never panics, aborts, or performs unsafe code;
- a rejected input allocates no vector using an unchecked peer length;
- an accepted exchange has 1–8 candidates and one address family;
- an accepted relayed exchange entry is UDP, uses the exact
  `CandidateType::Relayed`/`RelayProvider::Turn` pair, and has RFC 8445 relay
  type preference plus a component-consistent low priority byte;
- TCP, DERP signaling, provider/type drift, duplicates, unusable addresses,
  trailing bytes, and nested length disagreement never decode successfully;
- `decode(encode(value)) == value` for accepted values;
- an accepted rendezvous registration stays within 4 KiB and has matching
  credential/candidate exchange IDs and generations;
- no accepted candidate grants allocation, nomination, consent, or route
  authority.

## Resource gates

Run each target with a 4 KiB maximum input, address-space and RSS reporting,
and a per-input timeout. The acceptance gate is:

- at least 10 million executions per target in a clean release build;
- at least one continuous 24-hour sanitizer run on Linux;
- zero crashes, hangs, sanitizer findings, or corpus cases that exceed parser
  bounds;
- every fixed finding becomes a minimized permanent regression seed.

CI will run a bounded smoke corpus on every protocol change. The long campaign
runs before a public rendezvous/TURN release and publishes engine version,
compiler/sanitizer versions, exact commands, duration, execution count, peak
RSS, corpus hashes, and minimized findings as retained artifacts. Until those
artifacts exist, release readiness remains **Partial** and no public parser
assurance claim is allowed.
