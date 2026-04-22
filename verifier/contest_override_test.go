/*
FILE PATH: verifier/contest_override_test.go

DESCRIPTION:

	Migrated from tests/phase5_part_b_test.go (TestContest_* suite, 7
	tests). These tests exercise verifier.EvaluateContest end-to-end:
	contest detection, supermajority override evaluation, the witness
	requirement, and below-threshold rejection. Shared helpers live in
	p5b_helpers_test.go.

	BUG-016 FIX COMPATIBILITY (preserved from the original suite header):
	three contest-override positive-path tests use evidence entries that
	cosign the contest (CosignatureOf=&contestPos), reflecting the
	post-BUG-016 semantic that "authority approving the override" means
	the authority cosigns the contest.
*/
package verifier

import (
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/schema"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

func TestContest_NoContest_Unblocked(t *testing.T) {
	h := newP5BHarness()

	entityPos := p5bPos(1)
	h.addEntity(t, entityPos, "did:example:entity")
	scopePos := p5bPos(2)
	h.addEntityWithPayload(t, scopePos, "did:example:judge", nil)

	pendingPos := p5bPos(3)
	pendingEntry := p5bBuildEntry(t, envelope.ControlHeader{
		Destination:   p5bTestDestinationDID,
		SignerDID:     "did:example:judge",
		TargetRoot:    p5bPtr(entityPos),
		AuthorityPath: p5bScopeAuth(),
		ScopePointer:  p5bPtr(scopePos),
	}, nil)
	h.storeEntry(t, pendingPos, pendingEntry)
	h.advanceAuthorityTip(t, entityPos, pendingPos)

	result, err := EvaluateContest(pendingPos, h.fetcher, h.leaves, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if result.OperationBlocked {
		t.Fatal("no contest should mean unblocked")
	}
	if result.ContestPos != nil {
		t.Fatal("ContestPos should be nil")
	}
}

func TestContest_Contested_Blocked(t *testing.T) {
	h := newP5BHarness()

	entityPos := p5bPos(1)
	h.addEntity(t, entityPos, "did:example:entity")
	scopePos := p5bPos(2)
	scopeEntry := p5bBuildEntry(t, envelope.ControlHeader{
		Destination:   p5bTestDestinationDID,
		SignerDID:     "did:example:admin",
		AuthorityPath: p5bSameSigner(),
		AuthoritySet:  map[string]struct{}{"did:example:admin": {}, "did:example:judge": {}, "did:example:clerk": {}},
	}, nil)
	h.storeEntry(t, scopePos, scopeEntry)
	h.setLeaf(t, smt.DeriveKey(scopePos), types.SMTLeaf{
		Key: smt.DeriveKey(scopePos), OriginTip: scopePos, AuthorityTip: scopePos,
	})

	pendingPos := p5bPos(3)
	pendingEntry := p5bBuildEntry(t, envelope.ControlHeader{
		Destination:   p5bTestDestinationDID,
		SignerDID:     "did:example:judge",
		TargetRoot:    p5bPtr(entityPos),
		AuthorityPath: p5bScopeAuth(),
		ScopePointer:  p5bPtr(scopePos),
	}, nil)
	h.storeEntry(t, pendingPos, pendingEntry)

	contestPos := p5bPos(4)
	contestEntry := p5bBuildEntry(t, envelope.ControlHeader{
		Destination:    p5bTestDestinationDID,
		SignerDID:      "did:example:clerk",
		TargetRoot:     p5bPtr(entityPos),
		AuthorityPath:  p5bScopeAuth(),
		ScopePointer:   p5bPtr(scopePos),
		CosignatureOf:  p5bPtr(pendingPos),
		PriorAuthority: p5bPtr(pendingPos),
	}, nil)
	h.storeEntry(t, contestPos, contestEntry)
	h.advanceAuthorityTip(t, entityPos, contestPos)

	result, err := EvaluateContest(pendingPos, h.fetcher, h.leaves, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !result.OperationBlocked {
		t.Fatal("contested operation should be blocked")
	}
	if result.ContestPos == nil {
		t.Fatal("ContestPos should be set")
	}
	if !result.ContestPos.Equal(contestPos) {
		t.Fatalf("ContestPos: %s", result.ContestPos)
	}
}

func TestContest_OverriddenWithSupermajority_Unblocked(t *testing.T) {
	h := newP5BHarness()

	entityPos := p5bPos(1)
	h.addEntity(t, entityPos, "did:example:entity")
	scopePos := p5bPos(2)
	scopeEntry := p5bBuildEntry(t, envelope.ControlHeader{
		Destination:   p5bTestDestinationDID,
		SignerDID:     "did:example:admin",
		AuthorityPath: p5bSameSigner(),
		AuthoritySet:  map[string]struct{}{"did:example:a": {}, "did:example:b": {}, "did:example:c": {}},
	}, nil)
	h.storeEntry(t, scopePos, scopeEntry)
	h.setLeaf(t, smt.DeriveKey(scopePos), types.SMTLeaf{
		Key: smt.DeriveKey(scopePos), OriginTip: scopePos, AuthorityTip: scopePos,
	})

	pendingPos := p5bPos(3)
	h.storeEntry(t, pendingPos, p5bBuildEntry(t, envelope.ControlHeader{
		Destination:   p5bTestDestinationDID,
		SignerDID:     "did:example:a",
		TargetRoot:    p5bPtr(entityPos),
		AuthorityPath: p5bScopeAuth(),
		ScopePointer:  p5bPtr(scopePos),
	}, nil))

	contestPos := p5bPos(4)
	h.storeEntry(t, contestPos, p5bBuildEntry(t, envelope.ControlHeader{
		Destination:    p5bTestDestinationDID,
		SignerDID:      "did:example:b",
		TargetRoot:     p5bPtr(entityPos),
		AuthorityPath:  p5bScopeAuth(),
		ScopePointer:   p5bPtr(scopePos),
		CosignatureOf:  p5bPtr(pendingPos),
		PriorAuthority: p5bPtr(pendingPos),
	}, nil))

	ev1 := p5bPos(5)
	h.storeEntry(t, ev1, p5bBuildEntry(t, envelope.ControlHeader{
		Destination:   p5bTestDestinationDID,
		SignerDID:     "did:example:a",
		CosignatureOf: p5bPtr(contestPos),
	}, nil))
	ev2 := p5bPos(6)
	h.storeEntry(t, ev2, p5bBuildEntry(t, envelope.ControlHeader{
		Destination:   p5bTestDestinationDID,
		SignerDID:     "did:example:c",
		CosignatureOf: p5bPtr(contestPos),
	}, nil))

	overridePos := p5bPos(7)
	h.storeEntry(t, overridePos, p5bBuildEntry(t, envelope.ControlHeader{
		Destination:      p5bTestDestinationDID,
		SignerDID:        "did:example:b",
		TargetRoot:       p5bPtr(entityPos),
		AuthorityPath:    p5bScopeAuth(),
		ScopePointer:     p5bPtr(scopePos),
		EvidencePointers: []types.LogPosition{contestPos, ev1, ev2},
		PriorAuthority:   p5bPtr(contestPos),
	}, nil))
	h.advanceAuthorityTip(t, entityPos, overridePos)

	result, err := EvaluateContest(pendingPos, h.fetcher, h.leaves, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if result.OperationBlocked {
		t.Fatal("overridden contest should unblock")
	}
	if result.ContestPos == nil || result.OverridePos == nil {
		t.Fatal("both positions should be set")
	}
}

func TestContest_OverrideBelowThreshold_StillBlocked(t *testing.T) {
	h := newP5BHarness()

	entityPos := p5bPos(1)
	h.addEntity(t, entityPos, "did:example:entity")
	scopePos := p5bPos(2)
	scopeEntry := p5bBuildEntry(t, envelope.ControlHeader{
		Destination:   p5bTestDestinationDID,
		SignerDID:     "did:example:admin",
		AuthorityPath: p5bSameSigner(),
		AuthoritySet: map[string]struct{}{
			"did:example:a": {}, "did:example:b": {}, "did:example:c": {},
			"did:example:d": {}, "did:example:e": {}, "did:example:f": {},
		},
	}, nil)
	h.storeEntry(t, scopePos, scopeEntry)
	h.setLeaf(t, smt.DeriveKey(scopePos), types.SMTLeaf{
		Key: smt.DeriveKey(scopePos), OriginTip: scopePos, AuthorityTip: scopePos,
	})

	pendingPos := p5bPos(3)
	h.storeEntry(t, pendingPos, p5bBuildEntry(t, envelope.ControlHeader{
		Destination: p5bTestDestinationDID,
		SignerDID:   "did:example:a", TargetRoot: p5bPtr(entityPos),
		AuthorityPath: p5bScopeAuth(), ScopePointer: p5bPtr(scopePos),
	}, nil))

	contestPos := p5bPos(4)
	h.storeEntry(t, contestPos, p5bBuildEntry(t, envelope.ControlHeader{
		Destination: p5bTestDestinationDID,
		SignerDID:   "did:example:b", TargetRoot: p5bPtr(entityPos),
		AuthorityPath: p5bScopeAuth(), ScopePointer: p5bPtr(scopePos),
		CosignatureOf: p5bPtr(pendingPos), PriorAuthority: p5bPtr(pendingPos),
	}, nil))

	ev1 := p5bPos(5)
	h.storeEntry(t, ev1, p5bBuildEntry(t, envelope.ControlHeader{
		Destination:   p5bTestDestinationDID,
		SignerDID:     "did:example:c",
		CosignatureOf: p5bPtr(contestPos),
	}, nil))

	overridePos := p5bPos(6)
	h.storeEntry(t, overridePos, p5bBuildEntry(t, envelope.ControlHeader{
		Destination: p5bTestDestinationDID,
		SignerDID:   "did:example:a", TargetRoot: p5bPtr(entityPos),
		AuthorityPath: p5bScopeAuth(), ScopePointer: p5bPtr(scopePos),
		EvidencePointers: []types.LogPosition{contestPos, ev1},
		PriorAuthority:   p5bPtr(contestPos),
	}, nil))
	h.advanceAuthorityTip(t, entityPos, overridePos)

	result, err := EvaluateContest(pendingPos, h.fetcher, h.leaves, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !result.OperationBlocked {
		t.Fatal("override below threshold should stay blocked")
	}
}

func TestContest_OverrideWithoutRequiredWitness_Blocked(t *testing.T) {
	h := newP5BHarness()

	entityPos := p5bPos(1)
	h.addEntity(t, entityPos, "did:example:entity")
	scopePos := p5bPos(2)
	h.storeEntry(t, scopePos, p5bBuildEntry(t, envelope.ControlHeader{
		Destination: p5bTestDestinationDID,
		SignerDID:   "did:example:admin", AuthorityPath: p5bSameSigner(),
		AuthoritySet: map[string]struct{}{"did:example:a": {}, "did:example:b": {}, "did:example:c": {}},
	}, nil))
	h.setLeaf(t, smt.DeriveKey(scopePos), types.SMTLeaf{
		Key: smt.DeriveKey(scopePos), OriginTip: scopePos, AuthorityTip: scopePos,
	})

	schemaPos := p5bPos(10)
	h.storeEntry(t, schemaPos, p5bBuildEntry(t, envelope.ControlHeader{
		Destination: p5bTestDestinationDID,
		SignerDID:   "did:example:schema", AuthorityPath: p5bSameSigner(),
	}, p5bMustJSON(map[string]any{"override_requires_witness": true})))

	pendingPos := p5bPos(3)
	h.storeEntry(t, pendingPos, p5bBuildEntry(t, envelope.ControlHeader{
		Destination: p5bTestDestinationDID,
		SignerDID:   "did:example:a", TargetRoot: p5bPtr(entityPos),
		AuthorityPath: p5bScopeAuth(), ScopePointer: p5bPtr(scopePos),
		SchemaRef: p5bPtr(schemaPos),
	}, nil))

	contestPos := p5bPos(4)
	h.storeEntry(t, contestPos, p5bBuildEntry(t, envelope.ControlHeader{
		Destination: p5bTestDestinationDID,
		SignerDID:   "did:example:b", TargetRoot: p5bPtr(entityPos),
		AuthorityPath: p5bScopeAuth(), ScopePointer: p5bPtr(scopePos),
		CosignatureOf: p5bPtr(pendingPos), PriorAuthority: p5bPtr(pendingPos),
	}, nil))

	ev1 := p5bPos(5)
	h.storeEntry(t, ev1, p5bBuildEntry(t, envelope.ControlHeader{
		Destination:   p5bTestDestinationDID,
		SignerDID:     "did:example:a",
		CosignatureOf: p5bPtr(contestPos),
	}, nil))
	ev2 := p5bPos(6)
	h.storeEntry(t, ev2, p5bBuildEntry(t, envelope.ControlHeader{
		Destination:   p5bTestDestinationDID,
		SignerDID:     "did:example:c",
		CosignatureOf: p5bPtr(contestPos),
	}, nil))

	overridePos := p5bPos(7)
	h.storeEntry(t, overridePos, p5bBuildEntry(t, envelope.ControlHeader{
		Destination: p5bTestDestinationDID,
		SignerDID:   "did:example:b", TargetRoot: p5bPtr(entityPos),
		AuthorityPath: p5bScopeAuth(), ScopePointer: p5bPtr(scopePos),
		EvidencePointers: []types.LogPosition{contestPos, ev1, ev2},
		PriorAuthority:   p5bPtr(contestPos),
	}, nil))
	h.advanceAuthorityTip(t, entityPos, overridePos)

	extractor := schema.NewJSONParameterExtractor()
	result, err := EvaluateContest(pendingPos, h.fetcher, h.leaves, extractor)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !result.OperationBlocked {
		t.Fatal("override without required witness should stay blocked")
	}
}

func TestContest_OverrideWithWitnessCosig_Unblocked(t *testing.T) {
	h := newP5BHarness()

	entityPos := p5bPos(1)
	h.addEntity(t, entityPos, "did:example:entity")
	scopePos := p5bPos(2)
	h.storeEntry(t, scopePos, p5bBuildEntry(t, envelope.ControlHeader{
		Destination: p5bTestDestinationDID,
		SignerDID:   "did:example:admin", AuthorityPath: p5bSameSigner(),
		AuthoritySet: map[string]struct{}{"did:example:a": {}, "did:example:b": {}, "did:example:c": {}},
	}, nil))
	h.setLeaf(t, smt.DeriveKey(scopePos), types.SMTLeaf{
		Key: smt.DeriveKey(scopePos), OriginTip: scopePos, AuthorityTip: scopePos,
	})

	schemaPos := p5bPos(10)
	h.storeEntry(t, schemaPos, p5bBuildEntry(t, envelope.ControlHeader{
		Destination: p5bTestDestinationDID,
		SignerDID:   "did:example:schema", AuthorityPath: p5bSameSigner(),
	}, p5bMustJSON(map[string]any{"override_requires_witness": true})))

	pendingPos := p5bPos(3)
	h.storeEntry(t, pendingPos, p5bBuildEntry(t, envelope.ControlHeader{
		Destination: p5bTestDestinationDID,
		SignerDID:   "did:example:a", TargetRoot: p5bPtr(entityPos),
		AuthorityPath: p5bScopeAuth(), ScopePointer: p5bPtr(scopePos),
		SchemaRef: p5bPtr(schemaPos),
	}, nil))

	contestPos := p5bPos(4)
	h.storeEntry(t, contestPos, p5bBuildEntry(t, envelope.ControlHeader{
		Destination: p5bTestDestinationDID,
		SignerDID:   "did:example:b", TargetRoot: p5bPtr(entityPos),
		AuthorityPath: p5bScopeAuth(), ScopePointer: p5bPtr(scopePos),
		CosignatureOf: p5bPtr(pendingPos), PriorAuthority: p5bPtr(pendingPos),
	}, nil))

	ev1 := p5bPos(5)
	h.storeEntry(t, ev1, p5bBuildEntry(t, envelope.ControlHeader{
		Destination:   p5bTestDestinationDID,
		SignerDID:     "did:example:a",
		CosignatureOf: p5bPtr(contestPos),
	}, nil))
	ev2 := p5bPos(6)
	h.storeEntry(t, ev2, p5bBuildEntry(t, envelope.ControlHeader{
		Destination:   p5bTestDestinationDID,
		SignerDID:     "did:example:c",
		CosignatureOf: p5bPtr(contestPos),
	}, nil))

	witnessCosig := p5bPos(8)
	h.storeEntry(t, witnessCosig, p5bBuildEntry(t, envelope.ControlHeader{
		Destination:   p5bTestDestinationDID,
		SignerDID:     "did:example:independent-witness",
		CosignatureOf: p5bPtr(contestPos),
	}, nil))

	overridePos := p5bPos(7)
	h.storeEntry(t, overridePos, p5bBuildEntry(t, envelope.ControlHeader{
		Destination: p5bTestDestinationDID,
		SignerDID:   "did:example:b", TargetRoot: p5bPtr(entityPos),
		AuthorityPath: p5bScopeAuth(), ScopePointer: p5bPtr(scopePos),
		EvidencePointers: []types.LogPosition{contestPos, ev1, ev2, witnessCosig},
		PriorAuthority:   p5bPtr(contestPos),
	}, nil))
	h.advanceAuthorityTip(t, entityPos, overridePos)

	extractor := schema.NewJSONParameterExtractor()
	result, err := EvaluateContest(pendingPos, h.fetcher, h.leaves, extractor)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if result.OperationBlocked {
		t.Fatal("override with witness cosig should unblock")
	}
	if result.OverridePos == nil {
		t.Fatal("OverridePos should be set")
	}
}

func TestContest_NonExistentPending_Error(t *testing.T) {
	h := newP5BHarness()
	_, err := EvaluateContest(p5bPos(999), h.fetcher, h.leaves, nil)
	if err == nil {
		t.Fatal("non-existent pending entry should error")
	}
}
