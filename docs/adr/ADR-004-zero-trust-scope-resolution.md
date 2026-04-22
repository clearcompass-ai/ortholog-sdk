# ADR-004: Zero-Trust Scope Resolution via AuthorizedSetAtPosition

**Status:** Accepted (Decision 52, shipped in v7.5)
**Supersedes:** pre-v7.5 scope-at-current-tip semantics in
  `processPathC` and `EvaluateConditions`.
**Related:** ADR-003 (explicit non-member: EvaluateConditions moves
  out of caller-provides-SDK-validates).

## Context

The SDK's target domains — notarization, judicial, medical,
credentialing — require that authorizations valid at signing time
remain valid retrospectively. A retired judge's prior rulings do
not become invalid when the judge retires. A physician's
attestations from before they lost privileges do not become invalid.
A Board member's cosignature signed before their term ended does not
become invalid.

This contradicts the CA-style "current state, current validity"
model used by PKI and typical revocation systems. In notarization
precedent, authorization is evaluated at the time of the act, not
at the time of inspection.

Pre-v7.5 the SDK had a subtle bug: both `processPathC` (admission)
and `EvaluateConditions` (verification) resolved the governing
`AuthoritySet` by reading the scope leaf's `OriginTip` — i.e., the
*current* scope state. That meant a scope amendment instantly
invalidated every historical cosignature signed under the prior
scope. The domain invariant was silently violated.

## Decision

The SDK exposes exactly one scope-resolution primitive:

```go
func AuthorizedSetAtPosition(
    scope types.LogPosition,
    pos   types.LogPosition,
    fetcher types.EntryFetcher,
    leafReader smt.LeafReader,
) (map[string]struct{}, error)
```

Returns the `AuthoritySet` governing `scope` as of log position `pos`.

Callers choose the position that matches their question:

- Admission-time evaluation — the pending entry's `Prior_Authority`.
- Historical audit — the target entry's own admission position.
- Fraud-proof replay — the target entry's admission position.
- Governance retrospective — the position of interest.

Scope amendments take effect forward from their admission position.
Entries signed against pre-amendment observations remain valid for
those observations, evaluated via their `Prior_Authority` reference.
The historical record preserves authorization-at-signing-time.

## Architectural placement

The primitive lives at `core/scope/`. Imports only `core/envelope`,
`core/smt`, `types`, stdlib. Both `builder` (write path) and
`verifier` (read path) import it; neither imports the other through
it. No cycles.

`EntryFetcher` was relocated from `builder/` to `types/` so
`core/scope/` could depend on it without reintroducing the cycle.

## Security posture — fail closed

The primitive fails closed on every error mode. Eight typed errors
give callers structural-vs-transient discrimination:

- `ErrScopeLeafMissing` — scope's SMT leaf not present (transient).
- `ErrScopeEntryMissing` — fetcher returned nil for a walked
  position (transient).
- `ErrScopeEntryMalformed` — deserialize failed (structural).
- `ErrScopeCycle` — visited-set collision (structural corruption).
- `ErrScopeEmptySet` — governing entry's AuthoritySet is empty
  (structural; empty is never a legitimate governance state).
- `ErrScopeWalkTooDeep` — exceeded `MaxHistoryDepth = 4096`
  (structural; defense against corrupted chains).
- `ErrScopePositionUnknown` — queried position predates scope
  creation (structural; the signer is asserting observation of a
  state that never existed).
- `ErrCrossLogScopeHistory` — walk touched a foreign log
  (structural; Decision 47 locality is enforced here, not assumed
  by callers).

Cross-log enforcement is **fail-fast**: a query whose position is
on a foreign log returns `ErrCrossLogScopeHistory` **before any
fetcher call**. Verified by a counting-fetcher stub in the scope
regression tests.

## Consumer semantics

**`processPathC` (write path).** Resolves set at
`h.PriorAuthority`. Structural errors → `PathResultRejected`;
transient → `PathD`. Scope-creation entries have no
`Prior_Authority` and are handled as a distinct branch (no primitive
call).

**`EvaluateConditions` (read path).** Resolves set at
`pendingEntry.Header.PriorAuthority`. Any primitive error fails the
entire evaluation with a typed wrap. The pre-v7.5
caller-supplied `AuthorizedSet` field was removed — the SDK, not
the caller, is the trust boundary for cosignature authority
membership.

**`EvaluateAuthority` (read path, defense-in-depth).** Each walked
constraint entry is verified through the primitive at the entry's
admission position; non-members are reclassified as `Overridden`.
Catches entries that bypassed admission validation via a corrupted
store.

## Domain guarantees this enables

- A 2050 verifier auditing a 2025 credential uses the same primitive
  the 2025 admission path used; results are identical.
- A Tennessee Medical Board cosignature signed in the 60-day
  contest window remains valid after Board turnover in day 61.
- Institutional closure preserves historical authorizations: the
  scope no longer accepts new entries, but past entries remain
  evaluable against their historical scope state.

These become structural properties of the SDK, not aspirations
documented in prose.

## Deferred (not part of Decision 52)

Operator-side optimisation of `AuthorizedSetAtPosition` via a
scope-history index. Walk cost is O(amendments between pos and
current tip). Optimisation is additive, not semantic. Defer until
measurement shows the walk is hot.
