/*
Package verifier — authority_evaluator.go reads the Authority lane of an
SMT leaf and verifies delegation chain provenance.

Two exported functions:

EvaluateAuthority(leafKey, fetcher, extractor):

	Walks the Prior_Authority chain backward from AuthorityTip. Each entry
	is classified as active, pending (within activation delay per
	SchemaParameterExtractor), or overridden. Handles authority snapshots
	(O(active constraints) shortcut via Evidence_Pointers). v7.5 removed
	the Authority_Skip reader — every walk now follows Prior_Authority.
	Returns AuthorityEvaluation{ActiveConstraints, PendingCount}.

VerifyDelegationProvenance(delegationPointers, fetcher, leafReader):

	Walks Delegation_Pointers checking liveness at each hop. Same logic
	the builder uses for Path B but returns structured provenance data
	instead of pass/fail.
	Returns []DelegationHop{Position, SignerDID, DelegateDID, IsLive, RevokedAt}.

Consumed by:
  - verification/delegation_chain.go in the judicial network
  - Domain verification flows (authority history queries)
*/
package verifier

import (
	"errors"
	"fmt"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/scope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/schema"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// Authority Evaluation Types
// ─────────────────────────────────────────────────────────────────────

// ConstraintState classifies one authority entry in the chain.
//
// Group 8.1 Defect 1 — the zero value is ConstraintUnclassified, NOT
// ConstraintActive. Pre-shift the enum placed ConstraintActive at 0,
// which made the classification loop's `State != 0` skip-guard
// silently dead: the guard never fired for snapshot-harvested entries
// pre-marked ConstraintActive. The loop correctly re-ran
// scopeMembershipValid on those entries, but for the wrong reason —
// a future "guard fix" that matched the guard's stated comment would
// have silently reintroduced the constraint-laundering exploit
// (Defect 2). The structural fix is the distinct zero value declared
// here; the guard now reads `State != ConstraintUnclassified` and is
// load-bearing in exactly the intended direction.
type ConstraintState uint8

const (
	// ConstraintUnclassified is the zero value. Every ConstraintEntry
	// emitted by the walk (snapshot-harvested or chain-walked) begins
	// life at this state; the classification loop is the only path
	// that transitions it to Active/Pending/Overridden.
	ConstraintUnclassified ConstraintState = iota
	// ConstraintActive means the constraint is in effect.
	ConstraintActive
	// ConstraintPending means the constraint is within activation delay.
	ConstraintPending
	// ConstraintOverridden means a later constraint supersedes this one.
	ConstraintOverridden
)

// ConstraintEntry describes one entry in the authority chain.
type ConstraintEntry struct {
	Position types.LogPosition
	State    ConstraintState
	Entry    *envelope.Entry
	LogTime  time.Time
}

// AuthorityEvaluation is the result of walking the authority chain.
type AuthorityEvaluation struct {
	// ActiveConstraints is the ordered list of currently active authority
	// entries (most recent first). Each has been verified as not pending
	// and not overridden.
	ActiveConstraints []ConstraintEntry

	// PendingCount is the number of authority entries within their
	// activation delay window (not yet effective).
	PendingCount int

	// ChainLength is the total number of entries walked in the chain.
	ChainLength int

	// UsedSnapshot is true if an authority snapshot shortcut was used.
	UsedSnapshot bool
}

// ─────────────────────────────────────────────────────────────────────
// Delegation Provenance Types
// ─────────────────────────────────────────────────────────────────────

// DelegationHop describes one hop in a delegation chain.
type DelegationHop struct {
	// Position is the LogPosition of the delegation entry.
	Position types.LogPosition

	// SignerDID is who created (and can revoke) this delegation.
	SignerDID string

	// DelegateDID is who received delegated authority.
	DelegateDID string

	// IsLive is true if the delegation leaf's OriginTip still equals
	// Position (not revoked, not amended).
	IsLive bool

	// RevokedAt is the OriginTip position if the delegation was revoked.
	// Zero value if still live.
	RevokedAt types.LogPosition
}

// ─────────────────────────────────────────────────────────────────────
// Authority Evaluation Defaults
// ─────────────────────────────────────────────────────────────────────

// maxAuthorityChainDepth prevents infinite loops from corrupt chains.
const maxAuthorityChainDepth = 1000

// ─────────────────────────────────────────────────────────────────────
// EvaluateAuthority — O(A) authority chain walker
// ─────────────────────────────────────────────────────────────────────

// EvaluateAuthority walks the Prior_Authority chain backward from the
// leaf's AuthorityTip and classifies each entry.
//
// The walk terminates when:
//  1. An entry has no PriorAuthority (end of chain).
//  2. PriorAuthority equals the entity position (base case).
//  3. An authority snapshot is encountered (shortcut via Evidence_Pointers).
//  4. Maximum chain depth is reached (safety guard).
//
// Each entry is classified using the activation delay from the
// SchemaParameterExtractor (if available). Entries within the delay
// window are Pending; entries superseded by a later entry are Overridden;
// the rest are Active.
func EvaluateAuthority(
	leafKey [32]byte,
	leafReader smt.LeafReader,
	fetcher types.EntryFetcher,
	extractor schema.SchemaParameterExtractor,
) (*AuthorityEvaluation, error) {
	leaf, err := leafReader.Get(leafKey)
	if err != nil {
		return nil, fmt.Errorf("verifier/authority: read leaf: %w", err)
	}
	if leaf == nil {
		return nil, ErrLeafNotFound
	}

	eval := &AuthorityEvaluation{}

	// If AuthorityTip == OriginTip at the entity's creation position,
	// there are no authority constraints. The entity position is the base.
	// We can detect this: if the entry at AuthorityTip has no PriorAuthority
	// and no TargetRoot for enforcement, it's the base entity entry.
	if leaf.AuthorityTip.Equal(leaf.OriginTip) {
		// AuthorityTip hasn't diverged from OriginTip — check if this is
		// the base case (no enforcement) or if both advanced together.
		// If the tip entry has no PriorAuthority and AuthorityPath is
		// not ScopeAuthority, there are no constraints.
		return eval, nil
	}

	// Walk the chain backward from AuthorityTip.
	current := leaf.AuthorityTip
	var allEntries []ConstraintEntry
	visited := make(map[types.LogPosition]bool)

	for depth := 0; depth < maxAuthorityChainDepth; depth++ {
		// Gate: muEnableAuthorityChainCycleGuard. Off relies on
		// maxAuthorityChainDepth alone to terminate a corrupted
		// chain; on, a repeat position terminates the loop
		// immediately (catching cycles before the depth cap).
		if muEnableAuthorityChainCycleGuard && visited[current] {
			break // Cycle detected.
		}
		visited[current] = true

		meta, fetchErr := fetcher.Fetch(current)
		if fetchErr != nil || meta == nil {
			break // Chain terminates (entry not found).
		}

		entry, desErr := envelope.Deserialize(meta.CanonicalBytes)
		if desErr != nil {
			break
		}

		ce := ConstraintEntry{
			Position: current,
			Entry:    entry,
			LogTime:  meta.LogTime,
		}

		// Check for authority snapshot shortcut.
		// Gate: muEnableSnapshotShapeCheck. Off admits every entry
		// into the shortcut branch — walked Path A/B entries would
		// be treated as snapshots, erasing chain-walk and membership
		// checks. On, only entries whose shape matches
		// (Path C + TargetRoot + PriorAuthority + non-empty
		// EvidencePointers) enter the shortcut.
		isSnapshot := isAuthoritySnapshotEntry(entry)
		if !muEnableSnapshotShapeCheck {
			isSnapshot = true
		}
		if isSnapshot {
			eval.UsedSnapshot = true
			// Snapshot: Evidence_Pointers contain the active constraints.
			// Walk them instead of continuing the chain.
			//
			// Group 8.1 Defect 3 — the admission-time exemption from
			// MaxEvidencePointers leaves this walk length at attacker
			// discretion. MaxSnapshotEvidencePointers is the verifier-
			// side cap. Binding test:
			// TestEvaluateAuthority_SnapshotEvidenceCapEnforced.
			for i, evPtr := range entry.Header.EvidencePointers {
				if muEnableSnapshotEvidenceCap && i >= MaxSnapshotEvidencePointers {
					break
				}
				evMeta, evErr := fetcher.Fetch(evPtr)
				if evErr != nil || evMeta == nil {
					continue
				}
				evEntry, evDesErr := envelope.Deserialize(evMeta.CanonicalBytes)
				if evDesErr != nil {
					continue
				}
				// Group 8.1 Defect 2 — harvested entries arrive at
				// ConstraintUnclassified (zero value) so the
				// classification loop runs scopeMembershipValid on
				// them on equal footing with chain-walked entries.
				// An entry whose signer was not authorized in the
				// governing scope at the entry's admission position
				// drops from the active set.
				allEntries = append(allEntries, ConstraintEntry{
					Position: evPtr,
					Entry:    evEntry,
					LogTime:  evMeta.LogTime,
				})
			}
			break
		}

		allEntries = append(allEntries, ce)
		eval.ChainLength++

		// Follow Prior_Authority chain. v7.5 Phase B1 removed the
		// AuthoritySkip reader — skip pointers were a "trust me, I
		// validated the skipped range" claim from an untrusted party
		// and were never validatable at this layer. Every walk now
		// follows the single Prior_Authority edge.
		if entry.Header.PriorAuthority == nil {
			break // End of chain.
		}
		current = *entry.Header.PriorAuthority
	}

	// Classify entries: newest first (allEntries[0] is the most recent).
	//
	// Decision 52 adds a defense-in-depth layer here: for each walked
	// Path C enforcement entry, verify the signer was authorised in
	// the governing scope at the entry's admission position. The
	// shared primitive core/scope.AuthorizedSetAtPosition answers
	// that question directly. An entry whose signer fails the check
	// is reclassified as Overridden so it does not contribute to the
	// active constraint set.
	//
	// Admission-time enforcement in processPathC already catches the
	// common case; this check guards against a corrupted store
	// surfacing entries that were never properly admitted (or were
	// admitted against a pre-Decision-52 builder).
	classifyAllEntries(allEntries, extractor, fetcher, leafReader, time.Now().UTC())

	// Separate active, pending, overridden.
	// The most recent non-pending entry is active; older entries at the
	// same level are overridden unless they're from a snapshot.
	seenActive := false
	for i := range allEntries {
		switch allEntries[i].State {
		case ConstraintPending:
			eval.PendingCount++
		case ConstraintActive:
			if !seenActive || eval.UsedSnapshot {
				eval.ActiveConstraints = append(eval.ActiveConstraints, allEntries[i])
				seenActive = true
			} else {
				allEntries[i].State = ConstraintOverridden
			}
		}
	}

	return eval, nil
}

// classifyAllEntries is the inner loop of EvaluateAuthority's
// classification pass. Factored into a named helper so the Group 8.1
// binding tests can exercise the guard and membership-validation
// behaviour without rebuilding a full envelope+SMT fixture for every
// case.
//
// The helper mutates `allEntries` in place. Each entry begins at its
// incoming State value; entries at ConstraintUnclassified are
// classified (Active/Pending) by classifyConstraint and then run
// through scopeMembershipValid when Active. Entries already at any
// non-zero state are left alone under the classification guard.
func classifyAllEntries(
	allEntries []ConstraintEntry,
	extractor schema.SchemaParameterExtractor,
	fetcher types.EntryFetcher,
	leafReader smt.LeafReader,
	now time.Time,
) {
	for i := range allEntries {
		// Gate: muEnableClassificationGuard. Skip entries that are
		// already classified by upstream logic (reserved for future
		// pre-classification paths; today every entry the walk emits
		// sits at ConstraintUnclassified). Off removes the guard and
		// lets the classification loop overwrite every entry's State
		// on each iteration.
		if muEnableClassificationGuard && allEntries[i].State != ConstraintUnclassified {
			continue
		}
		state := classifyConstraint(allEntries[i], extractor, fetcher, now)

		// Gate: muEnableSnapshotMembershipValidation. Group 8.1
		// Defect 2 — harvested snapshot entries and chain-walked
		// entries both pass through this check on equal footing.
		// An entry whose signer was not authorized in the governing
		// scope at the entry's admission position is reclassified
		// as ConstraintOverridden and drops from the active set.
		// Off re-opens the constraint-laundering exploit: a
		// malicious authorized signer publishing a snapshot whose
		// EvidencePointers reference fraudulent or historically
		// rejected entries could have them treated as active
		// constraints.
		if muEnableSnapshotMembershipValidation &&
			state == ConstraintActive &&
			!scopeMembershipValid(allEntries[i], fetcher, leafReader) {
			state = ConstraintOverridden
		}
		allEntries[i].State = state
	}
}

// classifyConstraint determines if a constraint entry is active or pending
// based on the activation delay from the schema parameters.
func classifyConstraint(
	ce ConstraintEntry,
	extractor schema.SchemaParameterExtractor,
	fetcher types.EntryFetcher,
	now time.Time,
) ConstraintState {
	if extractor == nil || ce.Entry == nil {
		return ConstraintActive
	}

	// Read activation delay from schema parameters.
	var activationDelay time.Duration
	if ce.Entry.Header.SchemaRef != nil {
		schemaMeta, err := fetcher.Fetch(*ce.Entry.Header.SchemaRef)
		if err == nil && schemaMeta != nil {
			schemaEntry, desErr := envelope.Deserialize(schemaMeta.CanonicalBytes)
			if desErr == nil {
				params, extErr := extractor.Extract(schemaEntry)
				if extErr == nil && params != nil {
					activationDelay = params.ActivationDelay
				}
			}
		}
	}

	if activationDelay <= 0 {
		return ConstraintActive
	}

	// Check if the entry's LogTime + activation delay has elapsed.
	effectiveAt := ce.LogTime.Add(activationDelay)
	if now.Before(effectiveAt) {
		return ConstraintPending
	}
	return ConstraintActive
}

// scopeMembershipValid reports whether a walked constraint entry's
// signer was a member of the governing scope's AuthoritySet at the
// entry's admission position, resolved via the Decision 52 primitive.
//
// Returns true for entries that carry no ScopePointer (non-scope
// constraints are out of this check's scope), for entries whose
// scope resolution fails in a transient way (missing leaf, missing
// entry), and for entries whose signer is in the resolved set.
//
// Returns false only when the set is resolved successfully AND the
// signer is not a member. Structural chain errors (cycle, cross-log,
// malformed, too-deep, position-unknown) also mark the entry as
// un-trustworthy — an entry that cannot resolve its own scope
// authority cannot be counted as active.
func scopeMembershipValid(
	ce ConstraintEntry,
	fetcher types.EntryFetcher,
	leafReader smt.LeafReader,
) bool {
	if ce.Entry == nil || ce.Entry.Header.ScopePointer == nil {
		return true
	}
	set, err := scope.AuthorizedSetAtPosition(
		*ce.Entry.Header.ScopePointer,
		ce.Position,
		fetcher,
		leafReader,
	)
	if err != nil {
		// Transient lookup failure (missing leaf, missing entry) —
		// decline to penalise an entry we cannot verify. Structural
		// errors flag the entry as un-trustworthy.
		if errors.Is(err, scope.ErrScopeLeafMissing) ||
			errors.Is(err, scope.ErrScopeEntryMissing) {
			return true
		}
		return false
	}
	_, ok := set[ce.Entry.Header.SignerDID]
	return ok
}

// isAuthoritySnapshotEntry detects an authority snapshot entry by shape.
// A snapshot is a Path C entry that references a prior authority constraint
// AND carries evidence pointers justifying the update. Regular enforcement
// entries share the shape but carry no evidence pointers.
//
// The envelope writer grants these entries an exemption from MaxEvidencePointers
// (isAuthoritySnapshotShape in core/envelope/serialize.go); the verifier treats
// them as snapshot shortcuts for authority chain walking.
func isAuthoritySnapshotEntry(entry *envelope.Entry) bool {
	h := &entry.Header
	if h.AuthorityPath == nil || *h.AuthorityPath != envelope.AuthorityScopeAuthority {
		return false
	}
	if h.TargetRoot == nil || h.PriorAuthority == nil {
		return false
	}
	return len(h.EvidencePointers) > 0
}

// ─────────────────────────────────────────────────────────────────────
// VerifyDelegationProvenance — delegation chain liveness check
// ─────────────────────────────────────────────────────────────────────

// VerifyDelegationProvenance walks a delegation chain specified by
// Delegation_Pointers and checks liveness at each hop. Returns structured
// provenance data for each hop.
//
// Same liveness logic as the builder's Path B but returns detailed
// per-hop results instead of pass/fail. A delegation is "live" when
// its leaf's OriginTip still equals the delegation position (not
// revoked, not amended).
//
// The chain connects signer → delegate across hops:
//
//	hop[0]: delegate = action signer
//	hop[0].signer → hop[1].delegate (chain link)
//	hop[N-1].signer must equal the root entity signer (chain terminates)
//
// Consumed by judicial network's verification/delegation_chain.go.
func VerifyDelegationProvenance(
	delegationPointers []types.LogPosition,
	fetcher types.EntryFetcher,
	leafReader smt.LeafReader,
) ([]DelegationHop, error) {
	if len(delegationPointers) == 0 {
		return nil, nil
	}

	hops := make([]DelegationHop, 0, len(delegationPointers))

	for _, ptr := range delegationPointers {
		hop := DelegationHop{
			Position: ptr,
		}

		// Fetch the delegation entry.
		meta, err := fetcher.Fetch(ptr)
		if err != nil || meta == nil {
			hop.IsLive = false
			hops = append(hops, hop)
			continue
		}

		entry, err := envelope.Deserialize(meta.CanonicalBytes)
		if err != nil {
			hop.IsLive = false
			hops = append(hops, hop)
			continue
		}

		hop.SignerDID = entry.Header.SignerDID
		if entry.Header.DelegateDID != nil {
			hop.DelegateDID = *entry.Header.DelegateDID
		}

		// Check liveness: delegation leaf's OriginTip == delegation position.
		delegLeafKey := smt.DeriveKey(ptr)
		delegLeaf, leafErr := leafReader.Get(delegLeafKey)
		if leafErr != nil || delegLeaf == nil {
			hop.IsLive = false
			hops = append(hops, hop)
			continue
		}

		if delegLeaf.OriginTip.Equal(ptr) {
			hop.IsLive = true
		} else {
			hop.IsLive = false
			hop.RevokedAt = delegLeaf.OriginTip
		}

		hops = append(hops, hop)
	}

	return hops, nil
}
