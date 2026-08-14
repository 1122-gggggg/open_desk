## Problem and scope

## Design and rejected alternatives

## Resource, latency, security, and privilege impact

## Platform/GPU/driver matrix

## Buffer ownership / queue bounds / recovery semantics

## Tests and benchmark evidence

## Provenance and license review

- [ ] I did not copy incompatible GPL/AGPL implementation code into the permissive core.
- [ ] All peer-controlled sizes are bounded before allocation.
- [ ] Zero-copy work includes a tested copy fallback where applicable.
- [ ] Predictive-media dropping preserves decoder continuity or triggers recovery.
- [ ] Host and client clocks are not directly subtracted.
- [ ] Documentation/ADR is updated.
