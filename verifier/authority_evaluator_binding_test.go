// Package verifier — authority_evaluator_binding_test.go holds the
// Group 8.1 binding tests for the five mutation-audit switches
// declared in authority_evaluator_mutation_switches.go.
//
// Scope, in order:
//
//   1. muEnableClassificationGuard
//        → TestEvaluateAuthority_ClassificationLoopGuardIsLoadBearing
//        Exercises classifyAllEntries directly with one pre-classified
//        entry (ConstraintPending) and one unclassified entry. On, the
//        pre-classified entry is left alone and the unclassified one
//        gets classified. Off, the loop overwrites every entry's
//        State — the pre-classification is lost.
//
//   2. muEnableSnapshotMembershipValidation
//        → TestEvaluateAuthority_SnapshotEvidenceMembershipValidated
//        Builds a snapshot whose EvidencePointers reference an
//        enforcement entry signed by a DID NOT in the scope
//        AuthoritySet at the enforcement admission position. On, the
//        entry is reclassified Overridden and drops from the active
//        set. Off, the laundering succeeds — the entry is counted
//        as active.
//
//   3. muEnableSnapshotEvidenceCap
//        → TestEvaluateAuthority_SnapshotEvidenceCapEnforced
//        Builds a snapshot whose EvidencePointers length exceeds
//        MaxSnapshotEvidencePointers. On, the walk terminates at the
//        cap. Off, it walks every pointer.
//
//   4. muEnableSnapshotShapeCheck
//        → TestEvaluateAuthority_SnapshotShapeCheck_Binding
//        Builds a chain-walk-shaped entry (no EvidencePointers) and
//        exercises isAuthoritySnapshotEntry directly. On, the predicate
//        refuses the entry. Off, the predicate admits it — wrapped in
//        a helper that observes the shortcut branch is taken.
//
//   5. muEnableAuthorityChainCycleGuard
//        → TestEvaluateAuthority_CycleGuardIsLoadBearing
//        Builds a two-entry PriorAuthority cycle and asserts the walk
//        terminates in ≤ 2 iterations (existing behaviour under the
//        guard) rather than falling through to maxAuthorityChainDepth.

package verifier

import (
	"testing"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// muEnableClassificationGuard
// ─────────────────────────────────────────────────────────────────────

// TestEvaluateAuthority_ClassificationLoopGuardIsLoadBearing exercises
// classifyAllEntries directly. The guard's invariant: entries with a
// non-ConstraintUnclassified incoming State are left alone. With the
// gate off, the pre-classification is lost because the loop overwrites
// every entry's State on each iteration.
func TestEvaluateAuthority_ClassificationLoopGuardIsLoadBearing(t *testing.T) {
	// Two entries. The first is synthetically pre-classified as
	// ConstraintPending (a state the production walk cannot emit
	// today, but the invariant the guard protects is "pre-classified
	// entries are respected"). The second is at ConstraintUnclassified
	// and expects the loop to re-classify it to ConstraintActive
	// (no ScopePointer → scopeMembershipValid is a no-op; no
	// activation delay → classifyConstraint returns ConstraintActive).
	entries := []ConstraintEntry{
		{
			Position: types.LogPosition{LogDID: "did:test:log", Sequence: 1},
			State:    ConstraintPending,
		},
		{
			Position: types.LogPosition{LogDID: "did:test:log", Sequence: 2},
			State:    ConstraintUnclassified,
		},
	}
	// classifyConstraint's happy path for an entry with no extractor
	// and no activation delay returns ConstraintActive.
	classifyAllEntries(entries, nil, nopFetcher{}, nopLeafReader{}, time.Now().UTC())

	if entries[0].State != ConstraintPending {
		t.Fatalf("pre-classified entry was overwritten: got State=%v, want ConstraintPending (muEnableClassificationGuard not load-bearing?)", entries[0].State)
	}
	if entries[1].State != ConstraintActive {
		t.Fatalf("unclassified entry was not classified: got State=%v, want ConstraintActive", entries[1].State)
	}
}

// ─────────────────────────────────────────────────────────────────────
// muEnableSnapshotMembershipValidation
// ─────────────────────────────────────────────────────────────────────

// TestEvaluateAuthority_SnapshotEvidenceMembershipValidated exercises
// classifyAllEntries with a harvested-from-snapshot ConstraintEntry
// whose signer is NOT in the governing scope's AuthoritySet. On,
// scopeMembershipValid returns false and the entry is reclassified to
// ConstraintOverridden — the constraint-laundering exploit is closed.
// Off, the membership check short-circuits and the entry stays Active.
func TestEvaluateAuthority_SnapshotEvidenceMembershipValidated(t *testing.T) {
	fetcher := aeFetcher{}
	store := smt.NewInMemoryLeafStore()

	// Scope whose AuthoritySet includes only judge, not impostor.
	scopePos := aePos(5)
	aeBuild(t, fetcher, scopePos, envelope.ControlHeader{
		Destination:   aeTestDestination,
		SignerDID:     "did:example:governor",
		AuthorityPath: aeSameSigner(),
		AuthoritySet:  aeAuthSet("did:example:judge"),
	})
	scopeKey := smt.DeriveKey(scopePos)
	if err := store.Set(scopeKey, types.SMTLeaf{Key: scopeKey, OriginTip: scopePos, AuthorityTip: scopePos}); err != nil {
		t.Fatalf("seed scope leaf: %v", err)
	}

	entityPos := aePos(10)
	aeBuild(t, fetcher, entityPos, envelope.ControlHeader{
		Destination:   aeTestDestination,
		SignerDID:     "did:example:entity",
		AuthorityPath: aeSameSigner(),
	})

	// A walked-or-harvested enforcement entry signed by the impostor,
	// referencing the same scope. scopeMembershipValid will resolve
	// the scope, look up the signer, and return false.
	enfPos := aePos(20)
	aeBuild(t, fetcher, enfPos, envelope.ControlHeader{
		Destination:   aeTestDestination,
		SignerDID:     "did:example:impostor",
		TargetRoot:    &entityPos,
		AuthorityPath: aeScopeAuth(),
		ScopePointer:  &scopePos,
	})
	enfEntry, err := envelope.Deserialize(fetcher[enfPos].CanonicalBytes)
	if err != nil {
		t.Fatalf("deserialize enfEntry: %v", err)
	}

	entries := []ConstraintEntry{{
		Position: enfPos,
		State:    ConstraintUnclassified,
		Entry:    enfEntry,
	}}
	classifyAllEntries(entries, nil, fetcher, store, time.Now().UTC())

	if entries[0].State != ConstraintOverridden {
		t.Fatalf("impostor entry not reclassified Overridden: got State=%v, want ConstraintOverridden (muEnableSnapshotMembershipValidation not load-bearing?)", entries[0].State)
	}
}

// ─────────────────────────────────────────────────────────────────────
// muEnableSnapshotEvidenceCap
// ─────────────────────────────────────────────────────────────────────

// TestEvaluateAuthority_SnapshotEvidenceCapEnforced builds a snapshot
// whose EvidencePointers length exceeds MaxSnapshotEvidencePointers
// and asserts the walk terminates at the cap. With the gate off the
// loop walks every pointer and the eval returns more active
// constraints than the cap permits.
func TestEvaluateAuthority_SnapshotEvidenceCapEnforced(t *testing.T) {
	fetcher := aeFetcher{}
	store := smt.NewInMemoryLeafStore()

	// Permissive scope so every harvested entry is Active.
	scopePos := aePos(5)
	aeBuild(t, fetcher, scopePos, envelope.ControlHeader{
		Destination:   aeTestDestination,
		SignerDID:     "did:example:governor",
		AuthorityPath: aeSameSigner(),
		AuthoritySet:  aeAuthSet("did:example:judge"),
	})
	scopeKey := smt.DeriveKey(scopePos)
	if err := store.Set(scopeKey, types.SMTLeaf{Key: scopeKey, OriginTip: scopePos, AuthorityTip: scopePos}); err != nil {
		t.Fatalf("seed scope leaf: %v", err)
	}

	entityPos := aePos(10)
	aeBuild(t, fetcher, entityPos, envelope.ControlHeader{
		Destination:   aeTestDestination,
		SignerDID:     "did:example:entity",
		AuthorityPath: aeSameSigner(),
	})

	// 2 × cap evidence pointers. Each points at an enforcement entry
	// signed by an in-scope authority.
	overshoot := MaxSnapshotEvidencePointers * 2
	evidencePointers := make([]types.LogPosition, 0, overshoot)
	for i := 0; i < overshoot; i++ {
		p := aePos(uint64(1000 + i))
		aeBuild(t, fetcher, p, envelope.ControlHeader{
			Destination:   aeTestDestination,
			SignerDID:     "did:example:judge",
			TargetRoot:    &entityPos,
			AuthorityPath: aeScopeAuth(),
			ScopePointer:  &scopePos,
		})
		evidencePointers = append(evidencePointers, p)
	}

	// Snapshot entry: Path C, TargetRoot, PriorAuthority, with an
	// oversized EvidencePointers slice.
	snapPos := aePos(900)
	aeBuild(t, fetcher, snapPos, envelope.ControlHeader{
		Destination:       aeTestDestination,
		SignerDID:         "did:example:judge",
		TargetRoot:        &entityPos,
		AuthorityPath:     aeScopeAuth(),
		ScopePointer:      &scopePos,
		PriorAuthority:    &entityPos,
		EvidencePointers:  evidencePointers,
	})

	leafKey := smt.DeriveKey(entityPos)
	if err := store.Set(leafKey, types.SMTLeaf{
		Key: leafKey, OriginTip: entityPos, AuthorityTip: snapPos,
	}); err != nil {
		t.Fatalf("seed entity leaf: %v", err)
	}

	eval, err := EvaluateAuthority(leafKey, store, fetcher, nil)
	if err != nil {
		t.Fatalf("EvaluateAuthority: %v", err)
	}
	if !eval.UsedSnapshot {
		t.Fatal("walk did not enter the snapshot shortcut")
	}
	if len(eval.ActiveConstraints) > MaxSnapshotEvidencePointers {
		t.Fatalf("active constraints = %d > cap %d (muEnableSnapshotEvidenceCap not load-bearing?)",
			len(eval.ActiveConstraints), MaxSnapshotEvidencePointers)
	}
}

// ─────────────────────────────────────────────────────────────────────
// muEnableSnapshotShapeCheck
// ─────────────────────────────────────────────────────────────────────

// TestEvaluateAuthority_SnapshotShapeCheck_Binding constructs a
// chain-walk-shaped Path C entry (no EvidencePointers) at
// AuthorityTip and asserts the walk treats it as a regular walked
// entry (UsedSnapshot=false). With the gate off, the callsite in
// EvaluateAuthority forces isSnapshot=true for every walked entry,
// which pushes the fixture into the shortcut branch and sets
// UsedSnapshot=true — the load-bearing signal.
func TestEvaluateAuthority_SnapshotShapeCheck_Binding(t *testing.T) {
	fetcher := aeFetcher{}
	store := smt.NewInMemoryLeafStore()

	scopePos := aePos(5)
	aeBuild(t, fetcher, scopePos, envelope.ControlHeader{
		Destination:   aeTestDestination,
		SignerDID:     "did:example:governor",
		AuthorityPath: aeSameSigner(),
		AuthoritySet:  aeAuthSet("did:example:judge"),
	})
	scopeKey := smt.DeriveKey(scopePos)
	if err := store.Set(scopeKey, types.SMTLeaf{Key: scopeKey, OriginTip: scopePos, AuthorityTip: scopePos}); err != nil {
		t.Fatalf("seed scope leaf: %v", err)
	}

	entityPos := aePos(10)
	aeBuild(t, fetcher, entityPos, envelope.ControlHeader{
		Destination:   aeTestDestination,
		SignerDID:     "did:example:entity",
		AuthorityPath: aeSameSigner(),
	})

	// Chain-walk-shaped entry: TargetRoot + PriorAuthority but
	// deliberately NO EvidencePointers. Production semantics: this is
	// a regular enforcement entry, NOT a snapshot. isAuthoritySnapshotEntry
	// returns false → the walk continues through PriorAuthority.
	//
	// With muEnableSnapshotShapeCheck off, the callsite forces
	// isSnapshot=true; the shortcut branch fires; the empty
	// EvidencePointers slice produces no active constraints AND
	// UsedSnapshot=true — a flag the regular walk never sets.
	enfPos := aePos(20)
	aeBuild(t, fetcher, enfPos, envelope.ControlHeader{
		Destination:    aeTestDestination,
		SignerDID:      "did:example:judge",
		TargetRoot:     &entityPos,
		AuthorityPath:  aeScopeAuth(),
		ScopePointer:   &scopePos,
		PriorAuthority: &entityPos,
		// No EvidencePointers.
	})

	leafKey := smt.DeriveKey(entityPos)
	if err := store.Set(leafKey, types.SMTLeaf{
		Key: leafKey, OriginTip: entityPos, AuthorityTip: enfPos,
	}); err != nil {
		t.Fatalf("seed entity leaf: %v", err)
	}

	eval, err := EvaluateAuthority(leafKey, store, fetcher, nil)
	if err != nil {
		t.Fatalf("EvaluateAuthority: %v", err)
	}
	if eval.UsedSnapshot {
		t.Fatal("walked entry without EvidencePointers took the snapshot shortcut (muEnableSnapshotShapeCheck not load-bearing?)")
	}

	// Direct predicate sanity — a chain-walk entry without
	// EvidencePointers is not a snapshot, and adding EvidencePointers
	// makes it one. Locks the predicate against future refactors
	// that would change its boundary.
	enfEntry, err := envelope.Deserialize(fetcher[enfPos].CanonicalBytes)
	if err != nil {
		t.Fatalf("deserialize enfEntry: %v", err)
	}
	if isAuthoritySnapshotEntry(enfEntry) {
		t.Fatal("predicate admitted entry without EvidencePointers — fixture drift")
	}
	enfEntry.Header.EvidencePointers = []types.LogPosition{entityPos}
	if !isAuthoritySnapshotEntry(enfEntry) {
		t.Fatal("predicate refused a well-formed snapshot — fixture drift")
	}
}

// ─────────────────────────────────────────────────────────────────────
// muEnableAuthorityChainCycleGuard
// ─────────────────────────────────────────────────────────────────────

// TestEvaluateAuthority_CycleGuardIsLoadBearing asserts a 2-entry
// PriorAuthority cycle terminates the walk at ≤ 2 iterations. With the
// gate off the walk falls through to maxAuthorityChainDepth (1000).
// The test runs fast either way but the observable ChainLength
// distinguishes guard-on from guard-off.
func TestEvaluateAuthority_CycleGuardIsLoadBearing(t *testing.T) {
	fetcher := aeFetcher{}
	store := smt.NewInMemoryLeafStore()

	scopePos := aePos(5)
	aeBuild(t, fetcher, scopePos, envelope.ControlHeader{
		Destination:   aeTestDestination,
		SignerDID:     "did:example:governor",
		AuthorityPath: aeSameSigner(),
		AuthoritySet:  aeAuthSet("did:example:judge"),
	})
	scopeKey := smt.DeriveKey(scopePos)
	if err := store.Set(scopeKey, types.SMTLeaf{Key: scopeKey, OriginTip: scopePos, AuthorityTip: scopePos}); err != nil {
		t.Fatalf("seed scope leaf: %v", err)
	}

	entityPos := aePos(10)
	aeBuild(t, fetcher, entityPos, envelope.ControlHeader{
		Destination:   aeTestDestination,
		SignerDID:     "did:example:entity",
		AuthorityPath: aeSameSigner(),
	})

	a := aePos(20)
	b := aePos(30)
	aeBuild(t, fetcher, a, envelope.ControlHeader{
		Destination:    aeTestDestination,
		SignerDID:      "did:example:judge",
		TargetRoot:     &entityPos,
		AuthorityPath:  aeScopeAuth(),
		ScopePointer:   &scopePos,
		PriorAuthority: &b,
	})
	aeBuild(t, fetcher, b, envelope.ControlHeader{
		Destination:    aeTestDestination,
		SignerDID:      "did:example:judge",
		TargetRoot:     &entityPos,
		AuthorityPath:  aeScopeAuth(),
		ScopePointer:   &scopePos,
		PriorAuthority: &a,
	})

	leafKey := smt.DeriveKey(entityPos)
	if err := store.Set(leafKey, types.SMTLeaf{
		Key: leafKey, OriginTip: entityPos, AuthorityTip: a,
	}); err != nil {
		t.Fatalf("seed entity leaf: %v", err)
	}

	eval, err := EvaluateAuthority(leafKey, store, fetcher, nil)
	if err != nil {
		t.Fatalf("EvaluateAuthority: %v", err)
	}
	if eval.ChainLength > 2 {
		t.Fatalf("cycle walk = %d, want <= 2 (muEnableAuthorityChainCycleGuard not load-bearing?)", eval.ChainLength)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Test-local no-op interfaces
// ─────────────────────────────────────────────────────────────────────

// nopFetcher satisfies types.EntryFetcher without any backing data —
// every Fetch returns nil, nil. Used by the classification-guard
// binding test where the entries under test have no ScopePointer or
// SchemaRef, so no Fetch is actually called on the fetcher.
type nopFetcher struct{}

func (nopFetcher) Fetch(types.LogPosition) (*types.EntryWithMetadata, error) {
	return nil, nil
}

type nopLeafReader struct{}

func (nopLeafReader) Get([32]byte) (*types.SMTLeaf, error) { return nil, nil }
