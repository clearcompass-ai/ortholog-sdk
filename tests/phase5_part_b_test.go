/*
FILE PATH: tests/phase5_part_b_test.go

Phase 5 Part B: 20 tests covering:
  - Contest/override evaluation (7 tests)
  - Key rotation tier classification (6 tests)
  - Fraud proof verification (7 tests)

All tests use in-memory infrastructure. No Postgres required.
*/
package tests

import (
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/schema"
	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/verifier"
)

// ═════════════════════════════════════════════════════════════════════
// Part B helpers
// ═════════════════════════════════════════════════════════════════════

// pbHarness extends p5Harness with authority chain construction helpers.
type pbHarness struct {
	p5Harness
}

func newPBHarness() *pbHarness {
	leaves := smt.NewInMemoryLeafStore()
	return &pbHarness{
		p5Harness: p5Harness{
			tree:    smt.NewTree(leaves, smt.NewInMemoryNodeCache()),
			leaves:  leaves,
			fetcher: NewMockFetcher(),
		},
	}
}

// advanceAuthorityTip sets a leaf's AuthorityTip to a new position.
func (h *pbHarness) advanceAuthorityTip(t *testing.T, entityPos, newTip types.LogPosition) {
	t.Helper()
	key := smt.DeriveKey(entityPos)
	leaf, _ := h.leaves.Get(key)
	if leaf == nil {
		t.Fatalf("leaf not found for %s", entityPos)
	}
	updated := *leaf
	updated.AuthorityTip = newTip
	h.setLeaf(t, key, updated)
}

// ═════════════════════════════════════════════════════════════════════
// 1. Contest/Override Evaluation (7 tests)
// ═════════════════════════════════════════════════════════════════════

func TestContest_NoContest_Unblocked(t *testing.T) {
	h := newPBHarness()

	// Entity + scope.
	entityPos := p5pos(1)
	h.addEntity(t, entityPos, "did:example:entity")
	scopePos := p5pos(2)
	h.addEntityWithPayload(t, scopePos, "did:example:judge", nil)

	// Pending operation (scope enforcement targeting entity).
	pendingPos := p5pos(3)
	pendingEntry := p5makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:     "did:example:judge",
		TargetRoot:    p5ptrTo(entityPos),
		AuthorityPath: scopeAuth(),
		ScopePointer:  p5ptrTo(scopePos),
	}, nil)
	h.storeEntry(t, pendingPos, pendingEntry)
	h.advanceAuthorityTip(t, entityPos, pendingPos)

	result, err := verifier.EvaluateContest(pendingPos, h.fetcher, h.leaves, nil)
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
	h := newPBHarness()

	entityPos := p5pos(1)
	h.addEntity(t, entityPos, "did:example:entity")
	scopePos := p5pos(2)
	scopeEntry := p5makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:     "did:example:admin",
		AuthorityPath: sameSigner(),
		AuthoritySet:  map[string]struct{}{"did:example:admin": {}, "did:example:judge": {}, "did:example:clerk": {}},
	}, nil)
	h.storeEntry(t, scopePos, scopeEntry)
	h.setLeaf(t, smt.DeriveKey(scopePos), types.SMTLeaf{
		Key: smt.DeriveKey(scopePos), OriginTip: scopePos, AuthorityTip: scopePos,
	})

	// Pending operation.
	pendingPos := p5pos(3)
	pendingEntry := p5makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:     "did:example:judge",
		TargetRoot:    p5ptrTo(entityPos),
		AuthorityPath: scopeAuth(),
		ScopePointer:  p5ptrTo(scopePos),
	}, nil)
	h.storeEntry(t, pendingPos, pendingEntry)

	// Contest entry: CosignatureOf == pendingPos, in authority chain.
	contestPos := p5pos(4)
	contestEntry := p5makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:      "did:example:clerk",
		TargetRoot:     p5ptrTo(entityPos),
		AuthorityPath:  scopeAuth(),
		ScopePointer:   p5ptrTo(scopePos),
		CosignatureOf:  p5ptrTo(pendingPos),
		PriorAuthority: p5ptrTo(pendingPos),
	}, nil)
	h.storeEntry(t, contestPos, contestEntry)
	h.advanceAuthorityTip(t, entityPos, contestPos)

	result, err := verifier.EvaluateContest(pendingPos, h.fetcher, h.leaves, nil)
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
	h := newPBHarness()

	entityPos := p5pos(1)
	h.addEntity(t, entityPos, "did:example:entity")
	scopePos := p5pos(2)
	scopeEntry := p5makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:     "did:example:admin",
		AuthorityPath: sameSigner(),
		AuthoritySet:  map[string]struct{}{"did:example:a": {}, "did:example:b": {}, "did:example:c": {}},
	}, nil)
	h.storeEntry(t, scopePos, scopeEntry)
	h.setLeaf(t, smt.DeriveKey(scopePos), types.SMTLeaf{
		Key: smt.DeriveKey(scopePos), OriginTip: scopePos, AuthorityTip: scopePos,
	})

	// Pending.
	pendingPos := p5pos(3)
	h.storeEntry(t, pendingPos, p5makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:     "did:example:a",
		TargetRoot:    p5ptrTo(entityPos),
		AuthorityPath: scopeAuth(),
		ScopePointer:  p5ptrTo(scopePos),
	}, nil))

	// Contest.
	contestPos := p5pos(4)
	h.storeEntry(t, contestPos, p5makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:      "did:example:b",
		TargetRoot:     p5ptrTo(entityPos),
		AuthorityPath:  scopeAuth(),
		ScopePointer:   p5ptrTo(scopePos),
		CosignatureOf:  p5ptrTo(pendingPos),
		PriorAuthority: p5ptrTo(pendingPos),
	}, nil))

	// Evidence entries for override (distinct signers).
	ev1 := p5pos(5)
	h.storeEntry(t, ev1, p5makeEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:a"}, nil))
	ev2 := p5pos(6)
	h.storeEntry(t, ev2, p5makeEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:c"}, nil))

	// Override entry referencing contest in EvidencePointers.
	// ⌈2*3/3⌉ = 2 needed. Override signer + 2 evidence = 3 distinct → passes.
	overridePos := p5pos(7)
	h.storeEntry(t, overridePos, p5makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:        "did:example:b",
		TargetRoot:       p5ptrTo(entityPos),
		AuthorityPath:    scopeAuth(),
		ScopePointer:     p5ptrTo(scopePos),
		EvidencePointers: []types.LogPosition{contestPos, ev1, ev2},
		PriorAuthority:   p5ptrTo(contestPos),
	}, nil))
	h.advanceAuthorityTip(t, entityPos, overridePos)

	result, err := verifier.EvaluateContest(pendingPos, h.fetcher, h.leaves, nil)
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
	h := newPBHarness()

	entityPos := p5pos(1)
	h.addEntity(t, entityPos, "did:example:entity")
	// Scope with 6 members → ⌈2*6/3⌉ = 4 needed.
	scopePos := p5pos(2)
	scopeEntry := p5makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:     "did:example:admin",
		AuthorityPath: sameSigner(),
		AuthoritySet: map[string]struct{}{
			"did:example:a": {}, "did:example:b": {}, "did:example:c": {},
			"did:example:d": {}, "did:example:e": {}, "did:example:f": {},
		},
	}, nil)
	h.storeEntry(t, scopePos, scopeEntry)
	h.setLeaf(t, smt.DeriveKey(scopePos), types.SMTLeaf{
		Key: smt.DeriveKey(scopePos), OriginTip: scopePos, AuthorityTip: scopePos,
	})

	pendingPos := p5pos(3)
	h.storeEntry(t, pendingPos, p5makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID: "did:example:a", TargetRoot: p5ptrTo(entityPos),
		AuthorityPath: scopeAuth(), ScopePointer: p5ptrTo(scopePos),
	}, nil))

	contestPos := p5pos(4)
	h.storeEntry(t, contestPos, p5makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID: "did:example:b", TargetRoot: p5ptrTo(entityPos),
		AuthorityPath: scopeAuth(), ScopePointer: p5ptrTo(scopePos),
		CosignatureOf: p5ptrTo(pendingPos), PriorAuthority: p5ptrTo(pendingPos),
	}, nil))

	// Override with only 2 distinct signers (need 4).
	ev1 := p5pos(5)
	h.storeEntry(t, ev1, p5makeEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:c"}, nil))

	overridePos := p5pos(6)
	h.storeEntry(t, overridePos, p5makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID: "did:example:a", TargetRoot: p5ptrTo(entityPos),
		AuthorityPath: scopeAuth(), ScopePointer: p5ptrTo(scopePos),
		EvidencePointers: []types.LogPosition{contestPos, ev1},
		PriorAuthority:   p5ptrTo(contestPos),
	}, nil))
	h.advanceAuthorityTip(t, entityPos, overridePos)

	result, err := verifier.EvaluateContest(pendingPos, h.fetcher, h.leaves, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !result.OperationBlocked {
		t.Fatal("override below threshold should stay blocked")
	}
}

func TestContest_OverrideWithoutRequiredWitness_Blocked(t *testing.T) {
	h := newPBHarness()

	entityPos := p5pos(1)
	h.addEntity(t, entityPos, "did:example:entity")
	scopePos := p5pos(2)
	h.storeEntry(t, scopePos, p5makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID: "did:example:admin", AuthorityPath: sameSigner(),
		AuthoritySet: map[string]struct{}{"did:example:a": {}, "did:example:b": {}, "did:example:c": {}},
	}, nil))
	h.setLeaf(t, smt.DeriveKey(scopePos), types.SMTLeaf{
		Key: smt.DeriveKey(scopePos), OriginTip: scopePos, AuthorityTip: scopePos,
	})

	// Schema requiring witness cosig.
	schemaPos := p5pos(10)
	h.storeEntry(t, schemaPos, p5makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID: "did:example:schema", AuthorityPath: sameSigner(),
	}, mustJSON(map[string]any{"override_requires_witness": true})))

	pendingPos := p5pos(3)
	h.storeEntry(t, pendingPos, p5makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID: "did:example:a", TargetRoot: p5ptrTo(entityPos),
		AuthorityPath: scopeAuth(), ScopePointer: p5ptrTo(scopePos),
		SchemaRef: p5ptrTo(schemaPos),
	}, nil))

	contestPos := p5pos(4)
	h.storeEntry(t, contestPos, p5makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID: "did:example:b", TargetRoot: p5ptrTo(entityPos),
		AuthorityPath: scopeAuth(), ScopePointer: p5ptrTo(scopePos),
		CosignatureOf: p5ptrTo(pendingPos), PriorAuthority: p5ptrTo(pendingPos),
	}, nil))

	// Override with enough signers but NO witness cosig.
	ev1 := p5pos(5)
	h.storeEntry(t, ev1, p5makeEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:a"}, nil))
	ev2 := p5pos(6)
	h.storeEntry(t, ev2, p5makeEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:c"}, nil))

	overridePos := p5pos(7)
	h.storeEntry(t, overridePos, p5makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID: "did:example:b", TargetRoot: p5ptrTo(entityPos),
		AuthorityPath: scopeAuth(), ScopePointer: p5ptrTo(scopePos),
		EvidencePointers: []types.LogPosition{contestPos, ev1, ev2},
		PriorAuthority:   p5ptrTo(contestPos),
	}, nil))
	h.advanceAuthorityTip(t, entityPos, overridePos)

	extractor := schema.NewJSONParameterExtractor()
	result, err := verifier.EvaluateContest(pendingPos, h.fetcher, h.leaves, extractor)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !result.OperationBlocked {
		t.Fatal("override without required witness should stay blocked")
	}
}

func TestContest_OverrideWithWitnessCosig_Unblocked(t *testing.T) {
	h := newPBHarness()

	entityPos := p5pos(1)
	h.addEntity(t, entityPos, "did:example:entity")
	scopePos := p5pos(2)
	h.storeEntry(t, scopePos, p5makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID: "did:example:admin", AuthorityPath: sameSigner(),
		AuthoritySet: map[string]struct{}{"did:example:a": {}, "did:example:b": {}, "did:example:c": {}},
	}, nil))
	h.setLeaf(t, smt.DeriveKey(scopePos), types.SMTLeaf{
		Key: smt.DeriveKey(scopePos), OriginTip: scopePos, AuthorityTip: scopePos,
	})

	schemaPos := p5pos(10)
	h.storeEntry(t, schemaPos, p5makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID: "did:example:schema", AuthorityPath: sameSigner(),
	}, mustJSON(map[string]any{"override_requires_witness": true})))

	pendingPos := p5pos(3)
	h.storeEntry(t, pendingPos, p5makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID: "did:example:a", TargetRoot: p5ptrTo(entityPos),
		AuthorityPath: scopeAuth(), ScopePointer: p5ptrTo(scopePos),
		SchemaRef: p5ptrTo(schemaPos),
	}, nil))

	contestPos := p5pos(4)
	h.storeEntry(t, contestPos, p5makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID: "did:example:b", TargetRoot: p5ptrTo(entityPos),
		AuthorityPath: scopeAuth(), ScopePointer: p5ptrTo(scopePos),
		CosignatureOf: p5ptrTo(pendingPos), PriorAuthority: p5ptrTo(pendingPos),
	}, nil))

	// Evidence + independent witness cosignature.
	ev1 := p5pos(5)
	h.storeEntry(t, ev1, p5makeEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:a"}, nil))
	ev2 := p5pos(6)
	h.storeEntry(t, ev2, p5makeEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:c"}, nil))
	// Witness cosig: signer NOT in authority set, has CosignatureOf.
	witnessCosig := p5pos(8)
	h.storeEntry(t, witnessCosig, p5makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:     "did:example:independent-witness",
		CosignatureOf: p5ptrTo(pendingPos),
	}, nil))

	overridePos := p5pos(7)
	h.storeEntry(t, overridePos, p5makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID: "did:example:b", TargetRoot: p5ptrTo(entityPos),
		AuthorityPath: scopeAuth(), ScopePointer: p5ptrTo(scopePos),
		EvidencePointers: []types.LogPosition{contestPos, ev1, ev2, witnessCosig},
		PriorAuthority:   p5ptrTo(contestPos),
	}, nil))
	h.advanceAuthorityTip(t, entityPos, overridePos)

	extractor := schema.NewJSONParameterExtractor()
	result, err := verifier.EvaluateContest(pendingPos, h.fetcher, h.leaves, extractor)
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
	h := newPBHarness()
	_, err := verifier.EvaluateContest(p5pos(999), h.fetcher, h.leaves, nil)
	if err == nil {
		t.Fatal("non-existent pending entry should error")
	}
}

// ═════════════════════════════════════════════════════════════════════
// 2. Key Rotation Tier Classification (6 tests)
// ═════════════════════════════════════════════════════════════════════

func setupRotationHarness(t *testing.T, maturationSecs, activationDelaySecs int64, nextKeyHash string) (*pbHarness, types.LogPosition, types.LogPosition, types.LogPosition) {
	t.Helper()
	h := newPBHarness()

	// Schema with maturation epoch and activation delay.
	schemaPos := p5pos(1)
	h.addEntityWithPayload(t, schemaPos, "did:example:schema", mustJSON(map[string]any{
		"maturation_epoch": maturationSecs,
		"activation_delay": activationDelaySecs,
	}))

	// DID profile entity with optional next_key_hash.
	profilePos := p5pos(2)
	var profilePayload []byte
	if nextKeyHash != "" {
		profilePayload = mustJSON(map[string]any{"next_key_hash": nextKeyHash})
	}
	h.addEntityWithPayload(t, profilePos, "did:example:holder", profilePayload)

	return h, schemaPos, profilePos, p5pos(0) // rotationPos set by caller
}

func TestRotation_Tier2_MaturedPrecommitment(t *testing.T) {
	h := newPBHarness()

	schemaPos := p5pos(1)
	h.addEntityWithPayload(t, schemaPos, "did:example:schema", mustJSON(map[string]any{
		"maturation_epoch": 1, // 1 second maturation.
	}))

	keyHash := fmt.Sprintf("%x", sha256.Sum256([]byte("new-public-key-bytes")))
	profilePos := p5pos(2)
	profileEntry := p5makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID: "did:example:holder", AuthorityPath: sameSigner(),
	}, mustJSON(map[string]any{"next_key_hash": keyHash}))
	h.storeEntry(t, profilePos, profileEntry)
	h.setLeaf(t, smt.DeriveKey(profilePos), types.SMTLeaf{
		Key: smt.DeriveKey(profilePos), OriginTip: profilePos, AuthorityTip: profilePos,
	})
	// Backdate the profile entry LogTime so maturation has passed.
	h.fetcher.entries[profilePos].LogTime = time.Now().Add(-1 * time.Hour)

	rotPos := p5pos(3)
	rotEntry := p5makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID: "did:example:holder", TargetRoot: p5ptrTo(profilePos),
		AuthorityPath: sameSigner(), SchemaRef: p5ptrTo(schemaPos),
	}, mustJSON(map[string]any{"new_key_hash": keyHash}))
	h.storeEntry(t, rotPos, rotEntry)

	eval, err := verifier.EvaluateKeyRotation(rotPos, h.fetcher, h.leaves, schema.NewJSONParameterExtractor())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if eval.Tier != verifier.RotationTier2 {
		t.Fatalf("expected Tier 2, got %d", eval.Tier)
	}
	if !eval.Matured {
		t.Fatal("should be matured")
	}
	if eval.ContestResult != nil {
		t.Fatal("Tier 2 should have nil ContestResult")
	}
}

func TestRotation_Tier3_ImmaturePrecommitment(t *testing.T) {
	h := newPBHarness()

	schemaPos := p5pos(1)
	h.addEntityWithPayload(t, schemaPos, "did:example:schema", mustJSON(map[string]any{
		"maturation_epoch": 999999, // Very long maturation.
		"activation_delay": 3600,
	}))

	keyHash := fmt.Sprintf("%x", sha256.Sum256([]byte("new-key")))
	profilePos := p5pos(2)
	h.storeEntry(t, profilePos, p5makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID: "did:example:holder", AuthorityPath: sameSigner(),
	}, mustJSON(map[string]any{"next_key_hash": keyHash})))
	h.setLeaf(t, smt.DeriveKey(profilePos), types.SMTLeaf{
		Key: smt.DeriveKey(profilePos), OriginTip: profilePos, AuthorityTip: profilePos,
	})

	rotPos := p5pos(3)
	h.storeEntry(t, rotPos, p5makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID: "did:example:holder", TargetRoot: p5ptrTo(profilePos),
		AuthorityPath: sameSigner(), SchemaRef: p5ptrTo(schemaPos),
	}, mustJSON(map[string]any{"new_key_hash": keyHash})))

	eval, err := verifier.EvaluateKeyRotation(rotPos, h.fetcher, h.leaves, schema.NewJSONParameterExtractor())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if eval.Tier != verifier.RotationTier3 {
		t.Fatalf("expected Tier 3, got %d", eval.Tier)
	}
	if eval.EffectiveAt == nil {
		t.Fatal("Tier 3 should have EffectiveAt")
	}
}

func TestRotation_Tier3_NoPrecommitment(t *testing.T) {
	h := newPBHarness()

	schemaPos := p5pos(1)
	h.addEntityWithPayload(t, schemaPos, "did:example:schema", mustJSON(map[string]any{
		"activation_delay": 7200,
	}))

	profilePos := p5pos(2)
	h.addEntityWithPayload(t, profilePos, "did:example:holder", nil) // No next_key_hash.

	rotPos := p5pos(3)
	h.storeEntry(t, rotPos, p5makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID: "did:example:holder", TargetRoot: p5ptrTo(profilePos),
		AuthorityPath: sameSigner(), SchemaRef: p5ptrTo(schemaPos),
	}, mustJSON(map[string]any{"new_public_key": "some-key"})))

	eval, err := verifier.EvaluateKeyRotation(rotPos, h.fetcher, h.leaves, schema.NewJSONParameterExtractor())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if eval.Tier != verifier.RotationTier3 {
		t.Fatalf("expected Tier 3 (no precommitment), got %d", eval.Tier)
	}
	if eval.Matured {
		t.Fatal("should not be matured without precommitment")
	}
}

func TestRotation_Tier3_ContestedBlocked(t *testing.T) {
	h := newPBHarness()

	schemaPos := p5pos(1)
	h.addEntityWithPayload(t, schemaPos, "did:example:schema", mustJSON(map[string]any{
		"activation_delay": 3600,
	}))

	profilePos := p5pos(2)
	h.addEntityWithPayload(t, profilePos, "did:example:holder", nil)

	rotPos := p5pos(3)
	h.storeEntry(t, rotPos, p5makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID: "did:example:holder", TargetRoot: p5ptrTo(profilePos),
		AuthorityPath: sameSigner(), SchemaRef: p5ptrTo(schemaPos),
	}, nil))

	// Add contest.
	contestPos := p5pos(4)
	h.storeEntry(t, contestPos, p5makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID: "did:example:escrow", TargetRoot: p5ptrTo(profilePos),
		AuthorityPath: scopeAuth(), ScopePointer: p5ptrTo(p5pos(10)),
		CosignatureOf: p5ptrTo(rotPos), PriorAuthority: p5ptrTo(rotPos),
	}, nil))
	h.advanceAuthorityTip(t, profilePos, contestPos)

	eval, err := verifier.EvaluateKeyRotation(rotPos, h.fetcher, h.leaves, schema.NewJSONParameterExtractor())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if eval.Tier != verifier.RotationTier3 {
		t.Fatalf("expected Tier 3, got %d", eval.Tier)
	}
	if eval.ContestResult == nil {
		t.Fatal("ContestResult should be set for Tier 3")
	}
	if !eval.ContestResult.OperationBlocked {
		t.Fatal("contested rotation should be blocked")
	}
}

func TestRotation_Tier3_ContestedThenOverridden(t *testing.T) {
	h := newPBHarness()

	schemaPos := p5pos(1)
	h.addEntityWithPayload(t, schemaPos, "did:example:schema", mustJSON(map[string]any{
		"activation_delay": 3600,
	}))

	profilePos := p5pos(2)
	h.addEntityWithPayload(t, profilePos, "did:example:holder", nil)

	scopePos := p5pos(10)
	h.storeEntry(t, scopePos, p5makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID: "did:example:admin", AuthorityPath: sameSigner(),
		AuthoritySet: map[string]struct{}{"did:example:a": {}, "did:example:b": {}, "did:example:c": {}},
	}, nil))
	h.setLeaf(t, smt.DeriveKey(scopePos), types.SMTLeaf{
		Key: smt.DeriveKey(scopePos), OriginTip: scopePos, AuthorityTip: scopePos,
	})

	rotPos := p5pos(3)
	h.storeEntry(t, rotPos, p5makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID: "did:example:holder", TargetRoot: p5ptrTo(profilePos),
		AuthorityPath: sameSigner(), SchemaRef: p5ptrTo(schemaPos),
		ScopePointer: p5ptrTo(scopePos),
	}, nil))

	contestPos := p5pos(4)
	h.storeEntry(t, contestPos, p5makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID: "did:example:b", TargetRoot: p5ptrTo(profilePos),
		AuthorityPath: scopeAuth(), ScopePointer: p5ptrTo(scopePos),
		CosignatureOf: p5ptrTo(rotPos), PriorAuthority: p5ptrTo(rotPos),
	}, nil))

	ev1 := p5pos(5)
	h.storeEntry(t, ev1, p5makeEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:a"}, nil))
	ev2 := p5pos(6)
	h.storeEntry(t, ev2, p5makeEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:c"}, nil))

	overridePos := p5pos(7)
	h.storeEntry(t, overridePos, p5makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID: "did:example:a", TargetRoot: p5ptrTo(profilePos),
		AuthorityPath: scopeAuth(), ScopePointer: p5ptrTo(scopePos),
		EvidencePointers: []types.LogPosition{contestPos, ev1, ev2},
		PriorAuthority:   p5ptrTo(contestPos),
	}, nil))
	h.advanceAuthorityTip(t, profilePos, overridePos)

	eval, err := verifier.EvaluateKeyRotation(rotPos, h.fetcher, h.leaves, schema.NewJSONParameterExtractor())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if eval.ContestResult == nil {
		t.Fatal("ContestResult should be set")
	}
	if eval.ContestResult.OperationBlocked {
		t.Fatal("overridden contest should unblock rotation")
	}
}

func TestRotation_MaturationBoundary(t *testing.T) {
	h := newPBHarness()

	schemaPos := p5pos(1)
	h.addEntityWithPayload(t, schemaPos, "did:example:schema", mustJSON(map[string]any{
		"maturation_epoch": 100,
	}))

	keyHash := fmt.Sprintf("%x", sha256.Sum256([]byte("boundary-key")))
	profilePos := p5pos(2)
	h.storeEntry(t, profilePos, p5makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID: "did:example:holder", AuthorityPath: sameSigner(),
	}, mustJSON(map[string]any{"next_key_hash": keyHash})))
	h.setLeaf(t, smt.DeriveKey(profilePos), types.SMTLeaf{
		Key: smt.DeriveKey(profilePos), OriginTip: profilePos, AuthorityTip: profilePos,
	})

	baseTime := time.Now().UTC()
	h.fetcher.entries[profilePos].LogTime = baseTime

	// Rotation exactly at epoch boundary → Tier 2.
	rotAtPos := p5pos(3)
	h.storeEntry(t, rotAtPos, p5makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID: "did:example:holder", TargetRoot: p5ptrTo(profilePos),
		AuthorityPath: sameSigner(), SchemaRef: p5ptrTo(schemaPos),
	}, mustJSON(map[string]any{"new_key_hash": keyHash})))
	h.fetcher.entries[rotAtPos].LogTime = baseTime.Add(100 * time.Second)

	evalAt, _ := verifier.EvaluateKeyRotation(rotAtPos, h.fetcher, h.leaves, schema.NewJSONParameterExtractor())
	if evalAt.Tier != verifier.RotationTier2 {
		t.Fatal("exactly at epoch should be Tier 2")
	}

	// Rotation 1 second before epoch → Tier 3.
	rotBeforePos := p5pos(4)
	h.storeEntry(t, rotBeforePos, p5makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID: "did:example:holder", TargetRoot: p5ptrTo(profilePos),
		AuthorityPath: sameSigner(), SchemaRef: p5ptrTo(schemaPos),
	}, mustJSON(map[string]any{"new_key_hash": keyHash})))
	h.fetcher.entries[rotBeforePos].LogTime = baseTime.Add(99 * time.Second)

	evalBefore, _ := verifier.EvaluateKeyRotation(rotBeforePos, h.fetcher, h.leaves, schema.NewJSONParameterExtractor())
	if evalBefore.Tier != verifier.RotationTier3 {
		t.Fatal("1 second before epoch should be Tier 3")
	}
}

// ═════════════════════════════════════════════════════════════════════
// 3. Fraud Proofs (7 tests)
// ═════════════════════════════════════════════════════════════════════

// buildCommitmentFixture creates entries, processes them, and returns
// the commitment + fetcher for fraud proof testing.
func buildCommitmentFixture(t *testing.T, n int) (types.SMTDerivationCommitment, *MockFetcher) {
	t.Helper()
	tree := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeCache())
	fetcher := NewMockFetcher()
	buf := builder.NewDeltaWindowBuffer(10)

	entries := make([]*envelope.Entry, n)
	positions := make([]types.LogPosition, n)
	for i := 0; i < n; i++ {
		e, _ := makeEntry(t, envelope.ControlHeader{
			Destination: testDestinationDID,
			SignerDID:     fmt.Sprintf("did:example:fp-signer%d", i),
			AuthorityPath: sameSigner(),
		}, []byte(fmt.Sprintf("fp-payload-%d", i)))
		entries[i] = e
		positions[i] = p5pos(uint64(i + 1))
		fetcher.Store(positions[i], e)
	}

	rootBefore, _ := tree.Root()
	result, err := builder.ProcessBatch(tree, entries, positions, fetcher, nil, testLogDID, buf)
	if err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}

	commitment := builder.GenerateBatchCommitment(positions[0], positions[len(positions)-1], rootBefore, result)
	return commitment, fetcher
}

func TestFraud_ValidCommitment(t *testing.T) {
	commitment, fetcher := buildCommitmentFixture(t, 5)

	result, err := verifier.VerifyDerivationCommitment(commitment, fetcher, nil, testLogDID)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !result.Valid {
		t.Fatalf("valid commitment should pass, got %d proofs", len(result.Proofs))
	}
	if len(result.Proofs) != 0 {
		t.Fatal("valid commitment should have no proofs")
	}
}

func TestFraud_SingleCorruptMutation(t *testing.T) {
	commitment, fetcher := buildCommitmentFixture(t, 3)

	// Corrupt one mutation's NewOriginTip.
	if len(commitment.Mutations) > 0 {
		commitment.Mutations[0].NewOriginTip = p5pos(9999)
	}

	result, err := verifier.VerifyDerivationCommitment(commitment, fetcher, nil, testLogDID)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if result.Valid {
		t.Fatal("corrupt mutation should be detected")
	}
	if len(result.Proofs) < 1 {
		t.Fatal("should have at least 1 fraud proof")
	}
	// Verify the proof identifies the correct leaf.
	found := false
	for _, p := range result.Proofs {
		if p.ClaimedNewOriginTip.Equal(p5pos(9999)) {
			found = true
		}
	}
	if !found {
		t.Fatal("fraud proof should reference the corrupt claimed tip")
	}
}

func TestFraud_MultipleCorruptMutations(t *testing.T) {
	commitment, fetcher := buildCommitmentFixture(t, 5)

	// Corrupt multiple mutations.
	for i := range commitment.Mutations {
		if i < 2 {
			commitment.Mutations[i].NewOriginTip = p5pos(uint64(8000 + i))
		}
	}

	result, err := verifier.VerifyDerivationCommitment(commitment, fetcher, nil, testLogDID)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if result.Valid {
		t.Fatal("multiple corrupt mutations should be detected")
	}
	if len(result.Proofs) < 2 {
		t.Fatalf("expected at least 2 fraud proofs, got %d", len(result.Proofs))
	}
}

func TestFraud_EmptyCommitment_Valid(t *testing.T) {
	commitment := types.SMTDerivationCommitment{
		MutationCount: 0,
		Mutations:     nil,
	}
	fetcher := NewMockFetcher()

	result, err := verifier.VerifyDerivationCommitment(commitment, fetcher, nil, testLogDID)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !result.Valid {
		t.Fatal("empty commitment should be valid")
	}
}

func TestFraud_WrongPreRoot(t *testing.T) {
	commitment, fetcher := buildCommitmentFixture(t, 3)

	// Change PriorSMTRoot → seeded tree will have different starting state.
	commitment.PriorSMTRoot = [32]byte{0xFF}

	result, err := verifier.VerifyDerivationCommitment(commitment, fetcher, nil, testLogDID)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	// With wrong pre-root, the seeded state is the same (we seed from mutations'
	// old tips, not from the root). But PostSMTRoot won't match.
	if result.Valid {
		t.Fatal("wrong PriorSMTRoot should cause PostSMTRoot mismatch → invalid")
	}
}

func TestFraud_CorrectMutationsWrongPostRoot(t *testing.T) {
	commitment, fetcher := buildCommitmentFixture(t, 3)

	// Keep mutations correct but corrupt PostSMTRoot.
	commitment.PostSMTRoot = [32]byte{0xAA}

	result, err := verifier.VerifyDerivationCommitment(commitment, fetcher, nil, testLogDID)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if result.Valid {
		t.Fatal("wrong PostSMTRoot should be detected")
	}
}

func TestFraud_CommitmentClaimsExtraMutation(t *testing.T) {
	commitment, fetcher := buildCommitmentFixture(t, 3)

	// Add a phantom mutation that the replay won't produce.
	phantom := types.LeafMutation{
		LeafKey:         smt.DeriveKey(p5pos(777)),
		OldOriginTip:    types.LogPosition{}, // null — "new leaf" claim
		NewOriginTip:    p5pos(778),
		OldAuthorityTip: types.LogPosition{}, // null — "new leaf" claim
		NewAuthorityTip: p5pos(778),
	}
	commitment.Mutations = append(commitment.Mutations, phantom)
	commitment.MutationCount++

	result, err := verifier.VerifyDerivationCommitment(commitment, fetcher, nil, testLogDID)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if result.Valid {
		t.Fatal("phantom mutation should be detected as fraud")
	}
	// Should have a proof for the phantom leaf.
	found := false
	for _, p := range result.Proofs {
		if p.LeafKey == smt.DeriveKey(p5pos(777)) {
			found = true
		}
	}
	if !found {
		t.Fatal("fraud proof should reference the phantom leaf key")
	}
}
