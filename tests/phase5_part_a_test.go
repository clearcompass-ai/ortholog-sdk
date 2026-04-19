/*
FILE PATH: tests/phase5_part_a_test.go

Phase 5 Part A: ~30 tests covering:
  - JSON parameter extraction (10 well-known fields, defaults, errors)
  - Origin evaluator (Original, Amended, Revoked, path compression)
  - Authority evaluator (chain walking, pending, snapshots, delegation)
  - Schema succession (chain building, migration policies)

All tests use in-memory infrastructure. No Postgres required.
*/
package tests

import (
	"testing"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/schema"
	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/verifier"
)

// ═════════════════════════════════════════════════════════════════════
// Helpers
// ═════════════════════════════════════════════════════════════════════

func p5pos(seq uint64) types.LogPosition {
	return types.LogPosition{LogDID: testLogDID, Sequence: seq}
}

func p5ptrTo[T any](v T) *T { return &v }

func p5makeEntry(t *testing.T, h envelope.ControlHeader, payload []byte) *envelope.Entry {
	t.Helper()
	entry, err := envelope.NewUnsignedEntry(h, payload)
	if err != nil {
		t.Fatalf("NewEntry: %v", err)
	}
	return entry
}

// p5Harness wraps tree + fetcher for Phase 5 tests.
type p5Harness struct {
	tree    *smt.Tree
	leaves  *smt.InMemoryLeafStore
	fetcher *MockFetcher
}

func newP5Harness() *p5Harness {
	leaves := smt.NewInMemoryLeafStore()
	return &p5Harness{
		tree:    smt.NewTree(leaves, smt.NewInMemoryNodeCache()),
		leaves:  leaves,
		fetcher: NewMockFetcher(),
	}
}

func (h *p5Harness) addEntity(t *testing.T, p types.LogPosition, signerDID string) {
	t.Helper()
	entry := p5makeEntry(t, envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     signerDID,
		AuthorityPath: sameSigner(),
	}, nil)
	h.fetcher.Store(p, entry)
	key := smt.DeriveKey(p)
	leaf := types.SMTLeaf{Key: key, OriginTip: p, AuthorityTip: p}
	if err := h.tree.SetLeaf(key, leaf); err != nil {
		t.Fatal(err)
	}
}

func (h *p5Harness) addEntityWithPayload(t *testing.T, p types.LogPosition, signerDID string, payload []byte) {
	t.Helper()
	entry := p5makeEntry(t, envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     signerDID,
		AuthorityPath: sameSigner(),
	}, payload)
	h.fetcher.Store(p, entry)
	key := smt.DeriveKey(p)
	leaf := types.SMTLeaf{Key: key, OriginTip: p, AuthorityTip: p}
	if err := h.tree.SetLeaf(key, leaf); err != nil {
		t.Fatal(err)
	}
}

func (h *p5Harness) storeEntry(t *testing.T, p types.LogPosition, entry *envelope.Entry) {
	t.Helper()
	h.fetcher.Store(p, entry)
}

func (h *p5Harness) setLeaf(t *testing.T, key [32]byte, leaf types.SMTLeaf) {
	t.Helper()
	if err := h.tree.SetLeaf(key, leaf); err != nil {
		t.Fatal(err)
	}
}

// ═════════════════════════════════════════════════════════════════════
// 1. Parameters Extraction (8 tests)
// ═════════════════════════════════════════════════════════════════════

func TestParamsJSON_AllFields(t *testing.T) {
	payload := mustJSON(map[string]any{
		"activation_delay":           3600,
		"cosignature_threshold":      3,
		"maturation_epoch":           2592000,
		"credential_validity_period": 31536000,
		"override_requires_witness":  true,
		"migration_policy":           "forward",
		"predecessor_schema":         map[string]any{"log_did": "did:ortholog:schema", "sequence": 5},
		"artifact_encryption":        "umbral_pre",
		"grant_entry_required":       true,
		"re_encryption_threshold":    map[string]any{"m": 3, "n": 5},
	})

	entry := p5makeEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:schema-author"}, payload)
	extractor := schema.NewJSONParameterExtractor()
	params, err := extractor.Extract(entry)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}

	if params.ActivationDelay != 3600*time.Second {
		t.Fatalf("ActivationDelay: %s", params.ActivationDelay)
	}
	if params.CosignatureThreshold != 3 {
		t.Fatalf("CosignatureThreshold: %d", params.CosignatureThreshold)
	}
	if params.MaturationEpoch != 2592000*time.Second {
		t.Fatalf("MaturationEpoch: %s", params.MaturationEpoch)
	}
	if params.CredentialValidityPeriod == nil || *params.CredentialValidityPeriod != 31536000*time.Second {
		t.Fatal("CredentialValidityPeriod mismatch")
	}
	if !params.OverrideRequiresIndependentWitness {
		t.Fatal("OverrideRequiresIndependentWitness should be true")
	}
	if params.MigrationPolicy != types.MigrationForward {
		t.Fatalf("MigrationPolicy: %d", params.MigrationPolicy)
	}
	if params.PredecessorSchema == nil {
		t.Fatal("PredecessorSchema should not be nil")
	}
	if params.PredecessorSchema.LogDID != "did:ortholog:schema" || params.PredecessorSchema.Sequence != 5 {
		t.Fatalf("PredecessorSchema: %s", params.PredecessorSchema)
	}
	if params.ArtifactEncryption != types.EncryptionUmbralPRE {
		t.Fatalf("ArtifactEncryption: %d", params.ArtifactEncryption)
	}
	if !params.GrantEntryRequired {
		t.Fatal("GrantEntryRequired should be true")
	}
	if params.ReEncryptionThreshold == nil || params.ReEncryptionThreshold.M != 3 || params.ReEncryptionThreshold.N != 5 {
		t.Fatal("ReEncryptionThreshold mismatch")
	}
}

func TestParamsJSON_MissingOptionalFieldsDefault(t *testing.T) {
	// Only required-ish fields set. Artifact fields should default.
	payload := mustJSON(map[string]any{
		"activation_delay":      60,
		"cosignature_threshold": 1,
	})

	entry := p5makeEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:minimal"}, payload)
	params, err := schema.NewJSONParameterExtractor().Extract(entry)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}

	if params.ActivationDelay != 60*time.Second {
		t.Fatalf("ActivationDelay: %s", params.ActivationDelay)
	}
	// Defaults for missing fields.
	if params.CredentialValidityPeriod != nil {
		t.Fatal("CredentialValidityPeriod should be nil")
	}
	if params.OverrideRequiresIndependentWitness {
		t.Fatal("OverrideRequiresIndependentWitness should be false")
	}
	if params.PredecessorSchema != nil {
		t.Fatal("PredecessorSchema should be nil")
	}
	if params.ArtifactEncryption != types.EncryptionAESGCM {
		t.Fatalf("ArtifactEncryption should default to aes_gcm, got %d", params.ArtifactEncryption)
	}
	if params.GrantEntryRequired {
		t.Fatal("GrantEntryRequired should default to false")
	}
	if params.ReEncryptionThreshold != nil {
		t.Fatal("ReEncryptionThreshold should default to nil")
	}
}

func TestParamsJSON_UnknownFieldsIgnored(t *testing.T) {
	payload := mustJSON(map[string]any{
		"activation_delay":     30,
		"future_unknown_field": "some value",
		"another_unknown":      42,
	})

	entry := p5makeEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:forward"}, payload)
	params, err := schema.NewJSONParameterExtractor().Extract(entry)
	if err != nil {
		t.Fatalf("unknown fields should be silently ignored: %v", err)
	}
	if params.ActivationDelay != 30*time.Second {
		t.Fatalf("known field should still parse: %s", params.ActivationDelay)
	}
}

func TestParamsJSON_MalformedJSONError(t *testing.T) {
	entry := p5makeEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:bad"}, []byte("{not valid json"))
	_, err := schema.NewJSONParameterExtractor().Extract(entry)
	if err == nil {
		t.Fatal("malformed JSON should produce error")
	}
}

func TestParamsJSON_EmptyPayloadError(t *testing.T) {
	entry := p5makeEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:empty"}, nil)
	_, err := schema.NewJSONParameterExtractor().Extract(entry)
	if err == nil {
		t.Fatal("empty payload should produce error")
	}
}

func TestParamsJSON_AESGCMDefault(t *testing.T) {
	// artifact_encryption not set → defaults to aes_gcm.
	payload := mustJSON(map[string]any{"cosignature_threshold": 2})
	entry := p5makeEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:gcm"}, payload)
	params, _ := schema.NewJSONParameterExtractor().Extract(entry)
	if params.ArtifactEncryption != types.EncryptionAESGCM {
		t.Fatalf("should default to aes_gcm, got %d", params.ArtifactEncryption)
	}
}

func TestParamsJSON_UmbralPREExplicit(t *testing.T) {
	payload := mustJSON(map[string]any{"artifact_encryption": "umbral_pre"})
	entry := p5makeEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:pre"}, payload)
	params, _ := schema.NewJSONParameterExtractor().Extract(entry)
	if params.ArtifactEncryption != types.EncryptionUmbralPRE {
		t.Fatalf("should be umbral_pre, got %d", params.ArtifactEncryption)
	}
}

func TestParamsJSON_ReEncryptionThresholdParsing(t *testing.T) {
	payload := mustJSON(map[string]any{
		"re_encryption_threshold": map[string]any{"m": 2, "n": 7},
	})
	entry := p5makeEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:thresh"}, payload)
	params, _ := schema.NewJSONParameterExtractor().Extract(entry)
	if params.ReEncryptionThreshold == nil {
		t.Fatal("ReEncryptionThreshold should not be nil")
	}
	if params.ReEncryptionThreshold.M != 2 || params.ReEncryptionThreshold.N != 7 {
		t.Fatalf("threshold: M=%d N=%d", params.ReEncryptionThreshold.M, params.ReEncryptionThreshold.N)
	}
}

// ═════════════════════════════════════════════════════════════════════
// 2. Origin Evaluator (6 tests)
// ═════════════════════════════════════════════════════════════════════

func TestOrigin_OriginalUntouched(t *testing.T) {
	h := newP5Harness()
	entityPos := p5pos(1)
	h.addEntity(t, entityPos, "did:example:alice")
	key := smt.DeriveKey(entityPos)

	eval, err := verifier.EvaluateOrigin(key, h.leaves, h.fetcher)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if eval.State != verifier.OriginOriginal {
		t.Fatalf("expected Original, got %d", eval.State)
	}
	if eval.TipEntry == nil {
		t.Fatal("TipEntry should not be nil")
	}
	if !eval.TipPosition.Equal(entityPos) {
		t.Fatalf("TipPosition: %s", eval.TipPosition)
	}
}

func TestOrigin_AmendedEntity(t *testing.T) {
	h := newP5Harness()
	entityPos := p5pos(1)
	h.addEntity(t, entityPos, "did:example:alice")

	// Create an amendment entry (Path A: same signer, targets root).
	amendPos := p5pos(2)
	amendEntry := p5makeEntry(t, envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     "did:example:alice",
		TargetRoot:    p5ptrTo(entityPos),
		AuthorityPath: sameSigner(),
	}, []byte("amended content"))
	h.storeEntry(t, amendPos, amendEntry)

	// Advance OriginTip to the amendment.
	key := smt.DeriveKey(entityPos)
	leaf, _ := h.leaves.Get(key)
	updated := *leaf
	updated.OriginTip = amendPos
	h.setLeaf(t, key, updated)

	eval, err := verifier.EvaluateOrigin(key, h.leaves, h.fetcher)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if eval.State != verifier.OriginAmended {
		t.Fatalf("expected Amended, got %d", eval.State)
	}
	if !eval.TipPosition.Equal(amendPos) {
		t.Fatalf("TipPosition should be amendment: %s", eval.TipPosition)
	}
}

func TestOrigin_RevokedEntity(t *testing.T) {
	h := newP5Harness()
	entityPos := p5pos(1)
	h.addEntity(t, entityPos, "did:example:owner")

	// Simulate revocation: advance OriginTip to a position that doesn't
	// have a valid entry (or targets a different entity).
	revokePos := p5pos(99)
	// Store an entry at revokePos that targets a DIFFERENT entity.
	revokeEntry := p5makeEntry(t, envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     "did:example:admin",
		TargetRoot:    p5ptrTo(p5pos(999)), // Different entity.
		AuthorityPath: scopeAuth(),
		ScopePointer:  p5ptrTo(p5pos(50)),
	}, nil)
	h.storeEntry(t, revokePos, revokeEntry)

	key := smt.DeriveKey(entityPos)
	leaf, _ := h.leaves.Get(key)
	updated := *leaf
	updated.OriginTip = revokePos
	h.setLeaf(t, key, updated)

	eval, err := verifier.EvaluateOrigin(key, h.leaves, h.fetcher)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if eval.State != verifier.OriginRevoked {
		t.Fatalf("expected Revoked, got %d", eval.State)
	}
}

func TestOrigin_RevokedMissingEntry(t *testing.T) {
	h := newP5Harness()
	entityPos := p5pos(1)
	h.addEntity(t, entityPos, "did:example:owner")

	// Advance OriginTip to a position with no entry.
	key := smt.DeriveKey(entityPos)
	leaf, _ := h.leaves.Get(key)
	updated := *leaf
	updated.OriginTip = p5pos(9999) // No entry stored here.
	h.setLeaf(t, key, updated)

	eval, err := verifier.EvaluateOrigin(key, h.leaves, h.fetcher)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if eval.State != verifier.OriginRevoked {
		t.Fatalf("expected Revoked for missing tip entry, got %d", eval.State)
	}
}

func TestOrigin_PathCompression(t *testing.T) {
	h := newP5Harness()
	rootPos := p5pos(1)
	intPos := p5pos(2)
	h.addEntity(t, rootPos, "did:example:alice")
	h.addEntity(t, intPos, "did:example:alice")

	// Amendment with path compression: targets root with intermediate.
	amendPos := p5pos(3)
	amendEntry := p5makeEntry(t, envelope.ControlHeader{
		Destination:        testDestinationDID,
		SignerDID:          "did:example:alice",
		TargetRoot:         p5ptrTo(rootPos),
		TargetIntermediate: p5ptrTo(intPos),
		AuthorityPath:      sameSigner(),
	}, nil)
	h.storeEntry(t, amendPos, amendEntry)

	// Advance root's OriginTip.
	rootKey := smt.DeriveKey(rootPos)
	rootLeaf, _ := h.leaves.Get(rootKey)
	updatedRoot := *rootLeaf
	updatedRoot.OriginTip = amendPos
	h.setLeaf(t, rootKey, updatedRoot)

	eval, err := verifier.EvaluateOrigin(rootKey, h.leaves, h.fetcher)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if eval.State != verifier.OriginAmended {
		t.Fatalf("expected Amended, got %d", eval.State)
	}
	if eval.IntermediatePosition == nil {
		t.Fatal("IntermediatePosition should be set for path compression")
	}
	if !eval.IntermediatePosition.Equal(intPos) {
		t.Fatalf("IntermediatePosition: %s", eval.IntermediatePosition)
	}
}

func TestOrigin_NonExistentLeafError(t *testing.T) {
	h := newP5Harness()
	key := smt.DeriveKey(p5pos(999))
	_, err := verifier.EvaluateOrigin(key, h.leaves, h.fetcher)
	if err == nil {
		t.Fatal("non-existent leaf should return error")
	}
}

// ═════════════════════════════════════════════════════════════════════
// 3. Authority Evaluator (8 tests)
// ═════════════════════════════════════════════════════════════════════

func TestAuthority_NoConstraints(t *testing.T) {
	h := newP5Harness()
	entityPos := p5pos(1)
	h.addEntity(t, entityPos, "did:example:entity")
	key := smt.DeriveKey(entityPos)

	eval, err := verifier.EvaluateAuthority(key, h.leaves, h.fetcher, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if len(eval.ActiveConstraints) != 0 {
		t.Fatalf("expected 0 constraints, got %d", len(eval.ActiveConstraints))
	}
	if eval.PendingCount != 0 {
		t.Fatalf("pending: %d", eval.PendingCount)
	}
}

func TestAuthority_SingleActiveConstraint(t *testing.T) {
	h := newP5Harness()
	entityPos := p5pos(1)
	h.addEntity(t, entityPos, "did:example:entity")
	scopePos := p5pos(2)
	h.addEntity(t, scopePos, "did:example:judge")

	// Create enforcement entry (Path C).
	enfPos := p5pos(3)
	enfEntry := p5makeEntry(t, envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     "did:example:judge",
		TargetRoot:    p5ptrTo(entityPos),
		AuthorityPath: scopeAuth(),
		ScopePointer:  p5ptrTo(scopePos),
	}, []byte("seal"))
	h.storeEntry(t, enfPos, enfEntry)

	// Advance AuthorityTip.
	key := smt.DeriveKey(entityPos)
	leaf, _ := h.leaves.Get(key)
	updated := *leaf
	updated.AuthorityTip = enfPos
	h.setLeaf(t, key, updated)

	eval, err := verifier.EvaluateAuthority(key, h.leaves, h.fetcher, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if len(eval.ActiveConstraints) != 1 {
		t.Fatalf("expected 1 active constraint, got %d", len(eval.ActiveConstraints))
	}
	if !eval.ActiveConstraints[0].Position.Equal(enfPos) {
		t.Fatalf("constraint position: %s", eval.ActiveConstraints[0].Position)
	}
}

func TestAuthority_MultipleConstraintsWithPriorChain(t *testing.T) {
	h := newP5Harness()
	entityPos := p5pos(1)
	h.addEntity(t, entityPos, "did:example:entity")

	// First enforcement.
	enf1Pos := p5pos(3)
	enf1 := p5makeEntry(t, envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     "did:example:judge",
		TargetRoot:    p5ptrTo(entityPos),
		AuthorityPath: scopeAuth(),
		ScopePointer:  p5ptrTo(p5pos(2)),
	}, nil)
	h.storeEntry(t, enf1Pos, enf1)

	// Second enforcement with Prior_Authority → first.
	enf2Pos := p5pos(4)
	enf2 := p5makeEntry(t, envelope.ControlHeader{
		Destination:    testDestinationDID,
		SignerDID:      "did:example:judge",
		TargetRoot:     p5ptrTo(entityPos),
		AuthorityPath:  scopeAuth(),
		ScopePointer:   p5ptrTo(p5pos(2)),
		PriorAuthority: p5ptrTo(enf1Pos),
	}, nil)
	h.storeEntry(t, enf2Pos, enf2)

	key := smt.DeriveKey(entityPos)
	leaf, _ := h.leaves.Get(key)
	updated := *leaf
	updated.AuthorityTip = enf2Pos
	h.setLeaf(t, key, updated)

	eval, err := verifier.EvaluateAuthority(key, h.leaves, h.fetcher, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if eval.ChainLength < 2 {
		t.Fatalf("chain should have at least 2 entries, got %d", eval.ChainLength)
	}
	// Most recent should be active; older should be overridden.
	if len(eval.ActiveConstraints) != 1 {
		t.Fatalf("expected 1 active (most recent wins), got %d", len(eval.ActiveConstraints))
	}
}

func TestAuthority_PendingWithinActivationDelay(t *testing.T) {
	h := newP5Harness()
	entityPos := p5pos(1)
	h.addEntity(t, entityPos, "did:example:entity")

	// Create a schema with a long activation delay.
	schemaPos := p5pos(10)
	schemaPayload := mustJSON(map[string]any{
		"activation_delay": 999999, // Very long delay.
	})
	schemaEntry := p5makeEntry(t, envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     "did:example:schema-author",
		AuthorityPath: sameSigner(),
	}, schemaPayload)
	h.storeEntry(t, schemaPos, schemaEntry)

	// Enforcement entry referencing this schema.
	enfPos := p5pos(3)
	enfEntry := p5makeEntry(t, envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     "did:example:judge",
		TargetRoot:    p5ptrTo(entityPos),
		AuthorityPath: scopeAuth(),
		ScopePointer:  p5ptrTo(p5pos(2)),
		SchemaRef:     p5ptrTo(schemaPos),
	}, nil)
	h.storeEntry(t, enfPos, enfEntry)
	// The entry's LogTime is set to now by the mock fetcher.

	key := smt.DeriveKey(entityPos)
	leaf, _ := h.leaves.Get(key)
	updated := *leaf
	updated.AuthorityTip = enfPos
	h.setLeaf(t, key, updated)

	extractor := schema.NewJSONParameterExtractor()
	eval, err := verifier.EvaluateAuthority(key, h.leaves, h.fetcher, extractor)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if eval.PendingCount < 1 {
		t.Fatalf("expected at least 1 pending, got %d", eval.PendingCount)
	}
}

func TestAuthority_SnapshotShortcut(t *testing.T) {
	h := newP5Harness()
	entityPos := p5pos(1)
	h.addEntity(t, entityPos, "did:example:entity")

	// Create several enforcement entries that Evidence_Pointers reference.
	ev1Pos := p5pos(10)
	ev1 := p5makeEntry(t, envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     "did:example:judge",
		TargetRoot:    p5ptrTo(entityPos),
		AuthorityPath: scopeAuth(),
		ScopePointer:  p5ptrTo(p5pos(2)),
	}, nil)
	h.storeEntry(t, ev1Pos, ev1)

	ev2Pos := p5pos(11)
	ev2 := p5makeEntry(t, envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     "did:example:judge2",
		TargetRoot:    p5ptrTo(entityPos),
		AuthorityPath: scopeAuth(),
		ScopePointer:  p5ptrTo(p5pos(2)),
	}, nil)
	h.storeEntry(t, ev2Pos, ev2)

	// Build authority snapshot: >10 Evidence_Pointers to trigger snapshot detection.
	pointers := make([]types.LogPosition, 11)
	pointers[0] = ev1Pos
	pointers[1] = ev2Pos
	for i := 2; i < 11; i++ {
		pointers[i] = p5pos(uint64(20 + i))
		h.storeEntry(t, pointers[i], p5makeEntry(t, envelope.ControlHeader{
			Destination:   testDestinationDID,
			SignerDID:     "did:example:judge",
			TargetRoot:    p5ptrTo(entityPos),
			AuthorityPath: scopeAuth(),
			ScopePointer:  p5ptrTo(p5pos(2)),
		}, nil))
	}

	snapPos := p5pos(50)
	snapEntry := p5makeEntry(t, envelope.ControlHeader{
		Destination:      testDestinationDID,
		SignerDID:        "did:example:judge",
		TargetRoot:       p5ptrTo(entityPos),
		AuthorityPath:    scopeAuth(),
		ScopePointer:     p5ptrTo(p5pos(2)),
		PriorAuthority:   p5ptrTo(p5pos(9)),
		EvidencePointers: pointers,
	}, nil)
	h.storeEntry(t, snapPos, snapEntry)

	key := smt.DeriveKey(entityPos)
	leaf, _ := h.leaves.Get(key)
	updated := *leaf
	updated.AuthorityTip = snapPos
	h.setLeaf(t, key, updated)

	eval, err := verifier.EvaluateAuthority(key, h.leaves, h.fetcher, nil)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !eval.UsedSnapshot {
		t.Fatal("expected UsedSnapshot=true")
	}
	if len(eval.ActiveConstraints) == 0 {
		t.Fatal("snapshot should produce active constraints from Evidence_Pointers")
	}
}

func TestDelegation_ThreeDeepAllLive(t *testing.T) {
	h := newP5Harness()

	// Owner → mid → leaf delegation chain.
	d1Pos := p5pos(10)
	d1 := p5makeEntry(t, envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     "did:example:owner",
		AuthorityPath: sameSigner(),
		DelegateDID:   p5ptrTo("did:example:mid"),
	}, nil)
	h.storeEntry(t, d1Pos, d1)
	h.setLeaf(t, smt.DeriveKey(d1Pos), types.SMTLeaf{
		Key: smt.DeriveKey(d1Pos), OriginTip: d1Pos, AuthorityTip: d1Pos,
	})

	d2Pos := p5pos(11)
	d2 := p5makeEntry(t, envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     "did:example:mid",
		AuthorityPath: sameSigner(),
		DelegateDID:   p5ptrTo("did:example:leaf"),
	}, nil)
	h.storeEntry(t, d2Pos, d2)
	h.setLeaf(t, smt.DeriveKey(d2Pos), types.SMTLeaf{
		Key: smt.DeriveKey(d2Pos), OriginTip: d2Pos, AuthorityTip: d2Pos,
	})

	d3Pos := p5pos(12)
	d3 := p5makeEntry(t, envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     "did:example:leaf",
		AuthorityPath: sameSigner(),
		DelegateDID:   p5ptrTo("did:example:deputy"),
	}, nil)
	h.storeEntry(t, d3Pos, d3)
	h.setLeaf(t, smt.DeriveKey(d3Pos), types.SMTLeaf{
		Key: smt.DeriveKey(d3Pos), OriginTip: d3Pos, AuthorityTip: d3Pos,
	})

	hops, err := verifier.VerifyDelegationProvenance(
		[]types.LogPosition{d3Pos, d2Pos, d1Pos},
		h.fetcher, h.leaves,
	)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(hops) != 3 {
		t.Fatalf("expected 3 hops, got %d", len(hops))
	}
	for i, hop := range hops {
		if !hop.IsLive {
			t.Fatalf("hop %d should be live", i)
		}
	}
	if hops[0].DelegateDID != "did:example:deputy" {
		t.Fatalf("hop[0] delegate: %s", hops[0].DelegateDID)
	}
	if hops[2].SignerDID != "did:example:owner" {
		t.Fatalf("hop[2] signer: %s", hops[2].SignerDID)
	}
}

func TestDelegation_RevokedMiddleHop(t *testing.T) {
	h := newP5Harness()

	d1Pos := p5pos(10)
	d1 := p5makeEntry(t, envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     "did:example:owner",
		AuthorityPath: sameSigner(),
		DelegateDID:   p5ptrTo("did:example:mid"),
	}, nil)
	h.storeEntry(t, d1Pos, d1)
	h.setLeaf(t, smt.DeriveKey(d1Pos), types.SMTLeaf{
		Key: smt.DeriveKey(d1Pos), OriginTip: d1Pos, AuthorityTip: d1Pos,
	})

	d2Pos := p5pos(11)
	d2 := p5makeEntry(t, envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     "did:example:mid",
		AuthorityPath: sameSigner(),
		DelegateDID:   p5ptrTo("did:example:leaf"),
	}, nil)
	h.storeEntry(t, d2Pos, d2)
	// Revoke d2: OriginTip advanced to pos(99).
	revokedTip := p5pos(99)
	h.setLeaf(t, smt.DeriveKey(d2Pos), types.SMTLeaf{
		Key: smt.DeriveKey(d2Pos), OriginTip: revokedTip, AuthorityTip: d2Pos,
	})

	hops, err := verifier.VerifyDelegationProvenance(
		[]types.LogPosition{d2Pos, d1Pos},
		h.fetcher, h.leaves,
	)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(hops) != 2 {
		t.Fatalf("expected 2 hops, got %d", len(hops))
	}
	// d2 (index 0) should be revoked.
	if hops[0].IsLive {
		t.Fatal("revoked delegation should not be live")
	}
	if !hops[0].RevokedAt.Equal(revokedTip) {
		t.Fatalf("RevokedAt: %s", hops[0].RevokedAt)
	}
	// d1 (index 1) should still be live.
	if !hops[1].IsLive {
		t.Fatal("d1 should still be live")
	}
}

func TestDelegation_ExpiredDelegation(t *testing.T) {
	h := newP5Harness()

	// Delegation with no entry at position → treated as not live.
	missingPos := p5pos(777)

	hops, err := verifier.VerifyDelegationProvenance(
		[]types.LogPosition{missingPos},
		h.fetcher, h.leaves,
	)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(hops))
	}
	if hops[0].IsLive {
		t.Fatal("missing delegation entry should not be live")
	}
}

// ═════════════════════════════════════════════════════════════════════
// 4. Schema Succession (8 tests)
// ═════════════════════════════════════════════════════════════════════

func TestSchema_SingleNoPredecessor(t *testing.T) {
	h := newP5Harness()
	schemaPos := p5pos(1)
	payload := mustJSON(map[string]any{
		"activation_delay": 60,
		"migration_policy": "strict",
	})
	h.addEntityWithPayload(t, schemaPos, "did:example:schema-author", payload)

	chain, err := verifier.WalkSchemaChain(schemaPos, h.fetcher, schema.NewJSONParameterExtractor())
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(chain.Versions) != 1 {
		t.Fatalf("expected 1 version, got %d", len(chain.Versions))
	}
	if chain.Versions[0].ChainIndex != 0 {
		t.Fatalf("ChainIndex: %d", chain.Versions[0].ChainIndex)
	}
	if chain.MigrationPolicy != "strict" {
		t.Fatalf("policy: %s", chain.MigrationPolicy)
	}
}

func TestSchema_ThreeVersionChain(t *testing.T) {
	h := newP5Harness()
	extractor := schema.NewJSONParameterExtractor()

	// v1: root schema, no predecessor.
	v1Pos := p5pos(1)
	v1Payload := mustJSON(map[string]any{
		"activation_delay": 30,
		"migration_policy": "strict",
	})
	h.addEntityWithPayload(t, v1Pos, "did:example:schema", v1Payload)

	// v2: predecessor → v1.
	v2Pos := p5pos(2)
	v2Payload := mustJSON(map[string]any{
		"activation_delay":   60,
		"migration_policy":   "forward",
		"predecessor_schema": map[string]any{"log_did": testLogDID, "sequence": 1},
	})
	h.addEntityWithPayload(t, v2Pos, "did:example:schema", v2Payload)

	// v3: predecessor → v2.
	v3Pos := p5pos(3)
	v3Payload := mustJSON(map[string]any{
		"activation_delay":   120,
		"migration_policy":   "forward",
		"predecessor_schema": map[string]any{"log_did": testLogDID, "sequence": 2},
	})
	h.addEntityWithPayload(t, v3Pos, "did:example:schema", v3Payload)

	chain, err := verifier.WalkSchemaChain(v3Pos, h.fetcher, extractor)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(chain.Versions) != 3 {
		t.Fatalf("expected 3 versions, got %d", len(chain.Versions))
	}
	// Oldest first.
	if !chain.Versions[0].Position.Equal(v1Pos) {
		t.Fatalf("versions[0] should be v1: %s", chain.Versions[0].Position)
	}
	if !chain.Versions[2].Position.Equal(v3Pos) {
		t.Fatalf("versions[2] should be v3: %s", chain.Versions[2].Position)
	}
	if chain.MigrationPolicy != "forward" {
		t.Fatalf("policy should be from newest version: %s", chain.MigrationPolicy)
	}
	// Chain indices.
	if chain.Versions[0].ChainIndex != 0 || chain.Versions[1].ChainIndex != 1 || chain.Versions[2].ChainIndex != 2 {
		t.Fatal("chain indices wrong")
	}
}

func TestSchema_StrictRejectsCrossVersion(t *testing.T) {
	h := newP5Harness()
	extractor := schema.NewJSONParameterExtractor()

	v1Pos := p5pos(1)
	h.addEntityWithPayload(t, v1Pos, "did:example:schema", mustJSON(map[string]any{
		"migration_policy": "strict",
	}))

	v2Pos := p5pos(2)
	h.addEntityWithPayload(t, v2Pos, "did:example:schema", mustJSON(map[string]any{
		"migration_policy":   "strict",
		"predecessor_schema": map[string]any{"log_did": testLogDID, "sequence": 1},
	}))

	chain, _ := verifier.WalkSchemaChain(v2Pos, h.fetcher, extractor)
	result := verifier.EvaluateMigration(chain, v2Pos, v1Pos)
	if result.Allowed {
		t.Fatal("strict policy should reject cross-version references")
	}
	if result.Policy != "strict" {
		t.Fatalf("policy: %s", result.Policy)
	}
}

func TestSchema_ForwardAllowsNewerToOlder(t *testing.T) {
	h := newP5Harness()
	extractor := schema.NewJSONParameterExtractor()

	v1Pos := p5pos(1)
	h.addEntityWithPayload(t, v1Pos, "did:example:schema", mustJSON(map[string]any{
		"migration_policy": "forward",
	}))

	v2Pos := p5pos(2)
	h.addEntityWithPayload(t, v2Pos, "did:example:schema", mustJSON(map[string]any{
		"migration_policy":   "forward",
		"predecessor_schema": map[string]any{"log_did": testLogDID, "sequence": 1},
	}))

	chain, _ := verifier.WalkSchemaChain(v2Pos, h.fetcher, extractor)

	// Newer → older: allowed.
	result := verifier.EvaluateMigration(chain, v2Pos, v1Pos)
	if !result.Allowed {
		t.Fatalf("forward policy should allow newer→older: %s", result.Reason)
	}

	// Older → newer: rejected.
	result2 := verifier.EvaluateMigration(chain, v1Pos, v2Pos)
	if result2.Allowed {
		t.Fatal("forward policy should reject older→newer")
	}
}

func TestSchema_AmendmentPolicy(t *testing.T) {
	h := newP5Harness()
	extractor := schema.NewJSONParameterExtractor()

	v1Pos := p5pos(1)
	h.addEntityWithPayload(t, v1Pos, "did:example:schema", mustJSON(map[string]any{
		"migration_policy": "amendment",
	}))

	v2Pos := p5pos(2)
	h.addEntityWithPayload(t, v2Pos, "did:example:schema", mustJSON(map[string]any{
		"migration_policy":   "amendment",
		"predecessor_schema": map[string]any{"log_did": testLogDID, "sequence": 1},
	}))

	chain, _ := verifier.WalkSchemaChain(v2Pos, h.fetcher, extractor)
	result := verifier.EvaluateMigration(chain, v2Pos, v1Pos)
	if !result.Allowed {
		t.Fatal("amendment policy should allow with migration requirement")
	}
	if result.Reason != "amendment_required" {
		t.Fatalf("reason should be amendment_required: %s", result.Reason)
	}
}

func TestSchema_BrokenChainPredecessorNotFound(t *testing.T) {
	h := newP5Harness()
	extractor := schema.NewJSONParameterExtractor()

	// Schema references a predecessor that doesn't exist.
	schemaPos := p5pos(5)
	h.addEntityWithPayload(t, schemaPos, "did:example:schema", mustJSON(map[string]any{
		"migration_policy":   "forward",
		"predecessor_schema": map[string]any{"log_did": testLogDID, "sequence": 999},
	}))

	_, err := verifier.WalkSchemaChain(schemaPos, h.fetcher, extractor)
	if err == nil {
		t.Fatal("broken chain should return error")
	}
}

func TestSchema_SameVersionAlwaysAllowed(t *testing.T) {
	h := newP5Harness()
	extractor := schema.NewJSONParameterExtractor()

	v1Pos := p5pos(1)
	h.addEntityWithPayload(t, v1Pos, "did:example:schema", mustJSON(map[string]any{
		"migration_policy": "strict",
	}))

	chain, _ := verifier.WalkSchemaChain(v1Pos, h.fetcher, extractor)
	result := verifier.EvaluateMigration(chain, v1Pos, v1Pos)
	if !result.Allowed {
		t.Fatal("same version should always be allowed even under strict")
	}
	if result.Reason != "same version" {
		t.Fatalf("reason: %s", result.Reason)
	}
}

func TestSchema_NilChainRejectsAll(t *testing.T) {
	result := verifier.EvaluateMigration(nil, p5pos(1), p5pos(2))
	if result.Allowed {
		t.Fatal("nil chain should reject")
	}
}
