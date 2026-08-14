# M1 deterministic loopback laboratory

M1 establishes the first executable correctness boundary before native capture,
hardware codecs, sockets, or GUI integration are introduced.

## Scope

The laboratory exercises this complete path:

```text
FakeCapture
  → exact bounded test codec
  → 44-byte media protocol
  → path-MTU fragmentation
  → deterministic hostile network
  → bounded out-of-order reassembly
  → decoder continuity decision
  → exact decode and checksum comparison
```

Input uses a separate fixed-size datagram format. Low-latency events are repaired
by periodic complete state snapshots. `InputReconciler` ignores stale messages and
produces an explicit release plan on disconnect, preventing stuck keys or pointer
buttons.

## Security and resource invariants

- Peer-controlled frame, fragment, packet, control, and input sizes are checked
  before allocation.
- Reassembly reserves the complete declared frame size under a global byte cap.
- Both fragments per frame and total fragment entries are capped, because a byte
  limit alone does not bound map/vector metadata overhead.
- Exact duplicate fragments are idempotent.
- Any partial overlap, conflicting payload, or inconsistent metadata invalidates
  the entire in-flight frame.
- Incomplete frames expire; deadline-expired packets never reach the application.
- The exact test codec checks decompressed size and checksum, so malformed streams
  cannot become decompression bombs.
- This codec is a laboratory instrument, not the production desktop codec.

## Executable gates

Bootstrap environments without Rust can run:

```bash
./scripts/bootstrap_verify.sh
```

`scripts/reference_lab.py` is an independent Python reference implementation of
the fixed wire format, exact codec, fragmentation/reassembly rules, hostile
network behavior, input reconciliation, and Rust workspace structural checks.
It produces `artifacts/reference-lab.json`. The schema records the Git commit,
seed, hostile-network probabilities, exact/rejected access units, silent corruption
count, maximum reservation, and final cleanup state.

The authoritative Rust gates remain:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets
```

Use the executable applications after building:

```bash
cargo run -p latencydesk-lab -- \
  --frames 300 --width 320 --height 180 \
  --loss-ppm 10000 --reorder-ppm 50000 \
  --json artifacts/lab-trace.json \
  --csv artifacts/lab-trace.csv \
  --report artifacts/lab-report.json

cargo run -p latencydesk-stress -- \
  --iterations 1000000 --max-len 4096 \
  --output artifacts/parser-stress.json
```

## Exit criteria

M1 is complete only when:

1. clean loopback reconstructs every configured frame byte-for-byte;
2. hostile profiles never produce a silently corrupted accepted frame;
3. all queues, reassembly reservations, fragment entries, and decoded sizes stay
   within configured caps;
4. loss/reorder/duplication cannot panic parsers or leave input pressed;
5. the Rust fmt, Clippy, and test gates pass on Linux and Windows CI;
6. generated JSON artifacts include the exact commit, parameters, and random seed.

The Python reference can validate items 1–4 independently. Item 5 cannot be
claimed until an actual Rust toolchain executes CI.
