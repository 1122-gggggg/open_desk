# ADR 0021: Two-phase route promotion with monotonic rollback epochs

**Status:** Accepted

## Decision

Do not use `ConnectionRouter::record_check_result(true)` as product authority.
A future product route must pass ICE nomination, exact-mTLS, transcript binding,
and fresh consent, then complete peer prepare before local commit. The active
route remains unchanged until commit. Commit increments an independent
`route_epoch`, retains the prior validated route for a bounded stability window,
and accepts application data only on the exact active `(route_epoch, path)`.

Post-commit health observations are not a substitute for deadline proof and
are not remembered as continuous health. At the stability deadline,
`tick(now, candidate_proof, previous_proof)` is deterministic regardless of
call order: a complete current-candidate proof finalizes the candidate; if it
is incomplete, only a complete fresh previous-route proof may restore the
previous route and increment the route epoch. If neither proof is complete,
the controller returns `NoVerifiedRoute` and revokes active route authority;
it never reactivates an unverified route. Promotion and rollback never rewrite `SessionStamp`,
authorization, display, codec, input sequence, or controller-lease state.

## Consequences

- Returning to the same path still uses a new route epoch; delayed packets from
  its earlier lifetime remain stale.
- Only one transition may exist per session, and stale/wrong tokens do not
  mutate state.
- Product integration still requires route-epoch wire fields, authenticated
  prepare/commit messages, retained parallel exact-mTLS connections, continuous
  consent, and media/input dispatch fencing.

## Sources

- ICE consent freshness: https://www.rfc-editor.org/rfc/rfc7675.html
- QUIC path validation is a distinct mechanism:
  https://www.rfc-editor.org/rfc/rfc9000.html#section-8.2
