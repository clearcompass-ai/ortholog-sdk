// Package scope — history.go implements AuthorizedSetAtPosition, the
// single scope-resolution primitive shared by the write path (builder)
// and the read path (verifier). Introduced in Decision 52.
//
// Semantics. AuthorizedSetAtPosition(scope, pos) returns the
// AuthoritySet governing `scope` as of log position `pos`. Callers
// choose the position that matches their question:
//
//   - Admission-time evaluation:   pending entry's Prior_Authority.
//   - Historical audit queries:    target entry's admission position.
//   - Fraud-proof replay:          target entry's admission position.
//   - Governance retrospective:    the position of interest.
//
// Scope amendments take effect forward from their admission position.
// Entries signed against pre-amendment observations remain valid for
// those observations, evaluated via their Prior_Authority reference.
// The historical record preserves authorization-at-signing-time. This
// is the policy the domain (notarization, judicial, medical) requires
// and rejects the current-tip-only CA-style model as inappropriate.
//
// Architectural placement. This package lives at core/scope/ so both
// builder and verifier can import it without creating a cycle.
// Imports only core/envelope, core/smt, and types. No upward imports.
//
// Cross-log safety. The primitive fails closed on any attempt to
// traverse scope history across log boundaries — Decision 47 locality
// is enforced at this layer, not assumed by callers.
package scope

import (
	"errors"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// MaxHistoryDepth bounds the scope-history walk. Reaching this depth
// without finding the governing amendment returns ErrScopeWalkTooDeep.
// The bound is generous — real scopes rarely exceed a few dozen
// amendments — and exists purely to defend against corrupted chains.
const MaxHistoryDepth = 4096

// Typed errors. Every failure mode of AuthorizedSetAtPosition has its
// own sentinel so callers (builder processPathC, verifier
// EvaluateConditions, audit tooling) can distinguish transient-store
// errors from structural violations and make policy decisions.
var (
	// ErrScopeLeafMissing — no SMT leaf exists for the scope
	// pointer. Either the scope was never created or the SMT is
	// out of sync with the caller's view.
	ErrScopeLeafMissing = errors.New("scope: no leaf for scope pointer")

	// ErrScopeEntryMissing — the fetcher returned (nil, nil) for a
	// position the scope history references. Distinguishable from
	// transport errors, which are wrapped and propagated as-is.
	ErrScopeEntryMissing = errors.New("scope: scope-history entry not in fetcher")

	// ErrScopeEntryMalformed — an entry in the scope history failed
	// to deserialize. Treated as a chain-corruption signal; the walk
	// halts rather than silently skipping.
	ErrScopeEntryMalformed = errors.New("scope: scope-history entry malformed")

	// ErrScopeCycle — the walk visited the same position twice.
	// Indicates corrupted Prior_Authority pointers. Distinct from
	// ErrScopeWalkTooDeep so chain-integrity tooling can triage.
	ErrScopeCycle = errors.New("scope: cycle in scope-history chain")

	// ErrScopeEmptySet — the governing scope entry has an empty
	// AuthoritySet. An empty set grants no authority and is never a
	// legitimate governance state; surfaced so callers can flag the
	// corruption rather than silently admitting a set no one is in.
	ErrScopeEmptySet = errors.New("scope: governing scope has empty authority set")

	// ErrScopeWalkTooDeep — the walk exceeded MaxHistoryDepth
	// without finding a governing amendment. See constant docstring.
	ErrScopeWalkTooDeep = errors.New("scope: history walk exceeded MaxHistoryDepth")

	// ErrScopePositionUnknown — the queried position precedes the
	// earliest scope entry reachable from the current tip. The
	// caller asked about a scope state that never existed.
	ErrScopePositionUnknown = errors.New("scope: queried position precedes scope creation")

	// ErrCrossLogScopeHistory — the walk encountered a position on
	// a foreign log. Enforces Decision 47 at the primitive layer:
	// the query position, the scope pointer, the SMT leaf's tip,
	// any visited entry's position, or any followed Prior_Authority
	// must all share the scope's LogDID. A cross-log pointer is
	// never legitimate — scope history cannot cross log boundaries
	// without a separate cross-log-proof entry type, which this
	// primitive deliberately refuses to follow.
	ErrCrossLogScopeHistory = errors.New("scope: cross-log scope history traversal refused")

	// ErrScopePointerEmpty — the scope pointer passed to the
	// primitive was the zero LogPosition. Callers must supply a
	// real scope pointer; the primitive does not invent one.
	ErrScopePointerEmpty = errors.New("scope: scope pointer is empty")
)

// AuthorizedSetAtPosition returns the AuthoritySet governing `scope`
// as of log position `pos`. See package doc for semantics and the
// Decision 52 spec for policy rationale.
//
// Walk algorithm. Start from the scope's leaf in the SMT (via
// leafReader). The leaf's OriginTip names the most-recent scope entry
// — creation or amendment. If that entry's position ≤ pos, return
// its AuthoritySet. Otherwise follow Prior_Authority backward until
// the first entry whose position ≤ pos is found, or the chain
// terminates.
//
// All walked positions must share the scope's LogDID. A mismatch at
// any step — the query, a visited entry, a followed pointer — halts
// with ErrCrossLogScopeHistory.
//
// The returned map is a fresh copy; callers are free to mutate it
// without affecting the underlying entry.
func AuthorizedSetAtPosition(
	scope types.LogPosition,
	pos types.LogPosition,
	fetcher types.EntryFetcher,
	leafReader smt.LeafReader,
) (map[string]struct{}, error) {
	if scope.LogDID == "" && scope.Sequence == 0 {
		return nil, ErrScopePointerEmpty
	}
	if fetcher == nil {
		return nil, errors.New("scope: fetcher required")
	}
	if leafReader == nil {
		return nil, errors.New("scope: leafReader required")
	}

	// Cross-log enforcement: the query position must share the
	// scope's log. This is the earliest possible check — verified
	// before any fetcher or leaf-reader interaction.
	if pos.LogDID != scope.LogDID {
		return nil, fmt.Errorf("%w: query position on %q, scope on %q",
			ErrCrossLogScopeHistory, pos.LogDID, scope.LogDID)
	}

	leafKey := smt.DeriveKey(scope)
	leaf, err := leafReader.Get(leafKey)
	if err != nil {
		return nil, fmt.Errorf("scope: read scope leaf: %w", err)
	}
	if leaf == nil {
		return nil, ErrScopeLeafMissing
	}

	// The scope leaf's OriginTip names the latest scope-governing
	// entry (creation or amendment). Amendments advance OriginTip;
	// enforcements advance AuthorityTip and are NOT governance
	// events for the scope itself.
	if leaf.OriginTip.LogDID != scope.LogDID {
		return nil, fmt.Errorf("%w: scope leaf OriginTip on %q, scope on %q",
			ErrCrossLogScopeHistory, leaf.OriginTip.LogDID, scope.LogDID)
	}

	current := leaf.OriginTip
	visited := make(map[types.LogPosition]bool)

	for depth := 0; depth < MaxHistoryDepth; depth++ {
		if current.LogDID != scope.LogDID {
			return nil, fmt.Errorf("%w: walk reached %q, scope on %q",
				ErrCrossLogScopeHistory, current.LogDID, scope.LogDID)
		}
		if visited[current] {
			return nil, fmt.Errorf("%w at %s", ErrScopeCycle, current)
		}
		visited[current] = true

		meta, fErr := fetcher.Fetch(current)
		if fErr != nil {
			return nil, fmt.Errorf("scope: fetch %s: %w", current, fErr)
		}
		if meta == nil {
			return nil, fmt.Errorf("%w: %s", ErrScopeEntryMissing, current)
		}
		entry, dErr := envelope.Deserialize(meta.CanonicalBytes)
		if dErr != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrScopeEntryMalformed, current, dErr)
		}

		// This entry governs `pos` iff `pos` is at or after the
		// entry's admission position. Positions on the same log
		// are ordered by Sequence (already validated as same log).
		if current.Sequence <= pos.Sequence {
			set := entry.Header.AuthoritySet
			if len(set) == 0 {
				return nil, fmt.Errorf("%w at %s", ErrScopeEmptySet, current)
			}
			// Return a defensive copy so the caller cannot mutate
			// the deserialized entry's map.
			out := make(map[string]struct{}, len(set))
			for did := range set {
				out[did] = struct{}{}
			}
			return out, nil
		}

		// current is after pos. Follow Prior_Authority back.
		if entry.Header.PriorAuthority == nil {
			return nil, fmt.Errorf("%w: earliest entry is at %s, query was at %s",
				ErrScopePositionUnknown, current, pos)
		}
		next := *entry.Header.PriorAuthority
		if next.LogDID != scope.LogDID {
			return nil, fmt.Errorf("%w: Prior_Authority from %s points to %q, scope on %q",
				ErrCrossLogScopeHistory, current, next.LogDID, scope.LogDID)
		}
		current = next
	}
	return nil, ErrScopeWalkTooDeep
}
