# ADR-003: Caller-Provides, SDK-Validates — Pattern and Boundaries

**Status:** Accepted (predates v7.5; codified here)
**Related:** ADR-004 (zero-trust scope resolution explicitly departs from this pattern)

## Context

Several SDK entry points follow a "caller provides a hint, SDK
validates" pattern:

- `builder.GrantAuthSealed` — caller supplies the grant's authorized
  set; SDK verifies every supplied DID is live and in-policy.
- `builder.AssemblePathB` — caller supplies candidate delegation
  positions; SDK walks them, checks liveness, and refuses any chain
  that doesn't connect.
- `verifier.WalkDelegationTree` — caller supplies the root
  delegation; SDK traverses and reports the per-hop liveness.

The pattern is appropriate when the caller has information the SDK
could not efficiently discover on its own (a set of candidate
positions from an external index, a grant's intended scope, a
traversal starting point). The SDK's role is to validate that the
hint is consistent with log state — not to re-derive it.

## Decision

The pattern is retained for these three call surfaces. Callers pass
hints; the SDK validates. A validation failure is a fail-closed
rejection, never a silent fallback.

## Explicit non-members

**`EvaluateConditions` is NOT in this pattern post-v7.5.**

v7 QW-4 added `AuthorizedSet map[string]struct{}` to
`EvaluateConditionsParams` as a caller-supplied Sybil defense. That
was a "caller provides, SDK validates" shape — and the SDK could not
in fact validate the supplied set.

Decision 52 (v7.5) replaces the field with `LeafReader`. The SDK now
**derives** the authorised set cryptographically from the pending
entry's `Prior_Authority` observation time via
`core/scope.AuthorizedSetAtPosition`. The caller cannot supply a
permissive override — the trust boundary is inside the SDK.

**Why the difference:** the cosignature authority set is not a hint
(the SDK could discover it from `Prior_Authority` and the scope
leaf). Making it caller-supplied created an unvalidated trust input
that the SDK had no way to check against log state. Decision 52
eliminated the trust boundary by eliminating the input.

## Rule of thumb

Ask: could the SDK have discovered this value on its own from log
state? If yes, the SDK derives it. If no (because the value comes
from an external index, an out-of-band intent, or an intermediate
result the caller computed), the caller provides it and the SDK
validates. A value that the SDK could derive but currently accepts
from the caller is a Decision-52-shaped bug — fix it at source.
