/*
FILE PATH: verifier/key_rotation_test.go

DESCRIPTION:

	Migrated from tests/phase5_part_b_test.go (TestRotation_* suite, 6
	tests). These tests exercise verifier.EvaluateKeyRotation: tier
	classification (2 vs 3), maturity boundaries, the precommitment
	requirement, and the contest/override interaction with rotations.
	Shared helpers live in p5b_helpers_test.go.

	BUG-016 FIX COMPATIBILITY (preserved from the original suite header):
	TestRotation_Tier3_ContestedThenOverridden uses evidence entries that
	cosign the contest, reflecting the post-BUG-016 semantic.
*/
package verifier

import (
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/schema"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

func TestRotation_Tier2_MaturedPrecommitment(t *testing.T) {
	h := newP5BHarness()

	schemaPos := p5bPos(1)
	h.addEntityWithPayload(t, schemaPos, "did:example:schema", p5bMustJSON(map[string]any{
		"maturation_epoch": 1,
	}))

	keyHash := fmt.Sprintf("%x", sha256.Sum256([]byte("new-public-key-bytes")))
	profilePos := p5bPos(2)
	profileEntry := p5bBuildEntry(t, envelope.ControlHeader{
		Destination: p5bTestDestinationDID,
		SignerDID:   "did:example:holder", AuthorityPath: p5bSameSigner(),
	}, p5bMustJSON(map[string]any{"next_key_hash": keyHash}))
	h.storeEntry(t, profilePos, profileEntry)
	h.setLeaf(t, smt.DeriveKey(profilePos), types.SMTLeaf{
		Key: smt.DeriveKey(profilePos), OriginTip: profilePos, AuthorityTip: profilePos,
	})
	h.fetcher.entries[profilePos].LogTime = time.Now().Add(-1 * time.Hour)

	rotPos := p5bPos(3)
	rotEntry := p5bBuildEntry(t, envelope.ControlHeader{
		Destination: p5bTestDestinationDID,
		SignerDID:   "did:example:holder", TargetRoot: p5bPtr(profilePos),
		AuthorityPath: p5bSameSigner(), SchemaRef: p5bPtr(schemaPos),
	}, p5bMustJSON(map[string]any{"new_key_hash": keyHash}))
	h.storeEntry(t, rotPos, rotEntry)

	eval, err := EvaluateKeyRotation(rotPos, h.fetcher, h.leaves, schema.NewJSONParameterExtractor())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if eval.Tier != RotationTier2 {
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
	h := newP5BHarness()

	schemaPos := p5bPos(1)
	h.addEntityWithPayload(t, schemaPos, "did:example:schema", p5bMustJSON(map[string]any{
		"maturation_epoch": 999999,
		"activation_delay": 3600,
	}))

	keyHash := fmt.Sprintf("%x", sha256.Sum256([]byte("new-key")))
	profilePos := p5bPos(2)
	h.storeEntry(t, profilePos, p5bBuildEntry(t, envelope.ControlHeader{
		Destination: p5bTestDestinationDID,
		SignerDID:   "did:example:holder", AuthorityPath: p5bSameSigner(),
	}, p5bMustJSON(map[string]any{"next_key_hash": keyHash})))
	h.setLeaf(t, smt.DeriveKey(profilePos), types.SMTLeaf{
		Key: smt.DeriveKey(profilePos), OriginTip: profilePos, AuthorityTip: profilePos,
	})

	rotPos := p5bPos(3)
	h.storeEntry(t, rotPos, p5bBuildEntry(t, envelope.ControlHeader{
		Destination: p5bTestDestinationDID,
		SignerDID:   "did:example:holder", TargetRoot: p5bPtr(profilePos),
		AuthorityPath: p5bSameSigner(), SchemaRef: p5bPtr(schemaPos),
	}, p5bMustJSON(map[string]any{"new_key_hash": keyHash})))

	eval, err := EvaluateKeyRotation(rotPos, h.fetcher, h.leaves, schema.NewJSONParameterExtractor())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if eval.Tier != RotationTier3 {
		t.Fatalf("expected Tier 3, got %d", eval.Tier)
	}
	if eval.EffectiveAt == nil {
		t.Fatal("Tier 3 should have EffectiveAt")
	}
}

func TestRotation_Tier3_NoPrecommitment(t *testing.T) {
	h := newP5BHarness()

	schemaPos := p5bPos(1)
	h.addEntityWithPayload(t, schemaPos, "did:example:schema", p5bMustJSON(map[string]any{
		"activation_delay": 7200,
	}))

	profilePos := p5bPos(2)
	h.addEntityWithPayload(t, profilePos, "did:example:holder", nil)

	rotPos := p5bPos(3)
	h.storeEntry(t, rotPos, p5bBuildEntry(t, envelope.ControlHeader{
		Destination: p5bTestDestinationDID,
		SignerDID:   "did:example:holder", TargetRoot: p5bPtr(profilePos),
		AuthorityPath: p5bSameSigner(), SchemaRef: p5bPtr(schemaPos),
	}, p5bMustJSON(map[string]any{"new_public_key": "some-key"})))

	eval, err := EvaluateKeyRotation(rotPos, h.fetcher, h.leaves, schema.NewJSONParameterExtractor())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if eval.Tier != RotationTier3 {
		t.Fatalf("expected Tier 3 (no precommitment), got %d", eval.Tier)
	}
	if eval.Matured {
		t.Fatal("should not be matured without precommitment")
	}
}

func TestRotation_Tier3_ContestedBlocked(t *testing.T) {
	h := newP5BHarness()

	schemaPos := p5bPos(1)
	h.addEntityWithPayload(t, schemaPos, "did:example:schema", p5bMustJSON(map[string]any{
		"activation_delay": 3600,
	}))

	profilePos := p5bPos(2)
	h.addEntityWithPayload(t, profilePos, "did:example:holder", nil)

	rotPos := p5bPos(3)
	h.storeEntry(t, rotPos, p5bBuildEntry(t, envelope.ControlHeader{
		Destination: p5bTestDestinationDID,
		SignerDID:   "did:example:holder", TargetRoot: p5bPtr(profilePos),
		AuthorityPath: p5bSameSigner(), SchemaRef: p5bPtr(schemaPos),
	}, nil))

	contestPos := p5bPos(4)
	h.storeEntry(t, contestPos, p5bBuildEntry(t, envelope.ControlHeader{
		Destination: p5bTestDestinationDID,
		SignerDID:   "did:example:escrow", TargetRoot: p5bPtr(profilePos),
		AuthorityPath: p5bScopeAuth(), ScopePointer: p5bPtr(p5bPos(10)),
		CosignatureOf: p5bPtr(rotPos), PriorAuthority: p5bPtr(rotPos),
	}, nil))
	h.advanceAuthorityTip(t, profilePos, contestPos)

	eval, err := EvaluateKeyRotation(rotPos, h.fetcher, h.leaves, schema.NewJSONParameterExtractor())
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if eval.Tier != RotationTier3 {
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
	h := newP5BHarness()

	schemaPos := p5bPos(1)
	h.addEntityWithPayload(t, schemaPos, "did:example:schema", p5bMustJSON(map[string]any{
		"activation_delay": 3600,
	}))

	profilePos := p5bPos(2)
	h.addEntityWithPayload(t, profilePos, "did:example:holder", nil)

	scopePos := p5bPos(10)
	h.storeEntry(t, scopePos, p5bBuildEntry(t, envelope.ControlHeader{
		Destination: p5bTestDestinationDID,
		SignerDID:   "did:example:admin", AuthorityPath: p5bSameSigner(),
		AuthoritySet: map[string]struct{}{"did:example:a": {}, "did:example:b": {}, "did:example:c": {}},
	}, nil))
	h.setLeaf(t, smt.DeriveKey(scopePos), types.SMTLeaf{
		Key: smt.DeriveKey(scopePos), OriginTip: scopePos, AuthorityTip: scopePos,
	})

	rotPos := p5bPos(3)
	h.storeEntry(t, rotPos, p5bBuildEntry(t, envelope.ControlHeader{
		Destination: p5bTestDestinationDID,
		SignerDID:   "did:example:holder", TargetRoot: p5bPtr(profilePos),
		AuthorityPath: p5bSameSigner(), SchemaRef: p5bPtr(schemaPos),
		ScopePointer: p5bPtr(scopePos),
	}, nil))

	contestPos := p5bPos(4)
	h.storeEntry(t, contestPos, p5bBuildEntry(t, envelope.ControlHeader{
		Destination: p5bTestDestinationDID,
		SignerDID:   "did:example:b", TargetRoot: p5bPtr(profilePos),
		AuthorityPath: p5bScopeAuth(), ScopePointer: p5bPtr(scopePos),
		CosignatureOf: p5bPtr(rotPos), PriorAuthority: p5bPtr(rotPos),
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
		SignerDID:   "did:example:a", TargetRoot: p5bPtr(profilePos),
		AuthorityPath: p5bScopeAuth(), ScopePointer: p5bPtr(scopePos),
		EvidencePointers: []types.LogPosition{contestPos, ev1, ev2},
		PriorAuthority:   p5bPtr(contestPos),
	}, nil))
	h.advanceAuthorityTip(t, profilePos, overridePos)

	eval, err := EvaluateKeyRotation(rotPos, h.fetcher, h.leaves, schema.NewJSONParameterExtractor())
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
	h := newP5BHarness()

	schemaPos := p5bPos(1)
	h.addEntityWithPayload(t, schemaPos, "did:example:schema", p5bMustJSON(map[string]any{
		"maturation_epoch": 100,
	}))

	keyHash := fmt.Sprintf("%x", sha256.Sum256([]byte("boundary-key")))
	profilePos := p5bPos(2)
	h.storeEntry(t, profilePos, p5bBuildEntry(t, envelope.ControlHeader{
		Destination: p5bTestDestinationDID,
		SignerDID:   "did:example:holder", AuthorityPath: p5bSameSigner(),
	}, p5bMustJSON(map[string]any{"next_key_hash": keyHash})))
	h.setLeaf(t, smt.DeriveKey(profilePos), types.SMTLeaf{
		Key: smt.DeriveKey(profilePos), OriginTip: profilePos, AuthorityTip: profilePos,
	})

	baseTime := time.Now().UTC()
	h.fetcher.entries[profilePos].LogTime = baseTime

	rotAtPos := p5bPos(3)
	h.storeEntry(t, rotAtPos, p5bBuildEntry(t, envelope.ControlHeader{
		Destination: p5bTestDestinationDID,
		SignerDID:   "did:example:holder", TargetRoot: p5bPtr(profilePos),
		AuthorityPath: p5bSameSigner(), SchemaRef: p5bPtr(schemaPos),
	}, p5bMustJSON(map[string]any{"new_key_hash": keyHash})))
	h.fetcher.entries[rotAtPos].LogTime = baseTime.Add(100 * time.Second)

	evalAt, _ := EvaluateKeyRotation(rotAtPos, h.fetcher, h.leaves, schema.NewJSONParameterExtractor())
	if evalAt.Tier != RotationTier2 {
		t.Fatal("exactly at epoch should be Tier 2")
	}

	rotBeforePos := p5bPos(4)
	h.storeEntry(t, rotBeforePos, p5bBuildEntry(t, envelope.ControlHeader{
		Destination: p5bTestDestinationDID,
		SignerDID:   "did:example:holder", TargetRoot: p5bPtr(profilePos),
		AuthorityPath: p5bSameSigner(), SchemaRef: p5bPtr(schemaPos),
	}, p5bMustJSON(map[string]any{"new_key_hash": keyHash})))
	h.fetcher.entries[rotBeforePos].LogTime = baseTime.Add(99 * time.Second)

	evalBefore, _ := EvaluateKeyRotation(rotBeforePos, h.fetcher, h.leaves, schema.NewJSONParameterExtractor())
	if evalBefore.Tier != RotationTier3 {
		t.Fatal("1 second before epoch should be Tier 3")
	}
}
