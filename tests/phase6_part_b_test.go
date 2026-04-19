/*
FILE PATH: tests/phase6_part_b_test.go

Phase 6 Part B: 42 tests covering:
  - VerifyShare / VerifyShareSet (3 tests)
  - ProcessWithRetry OCC retry (5 tests)
  - EvaluateConditions condition evaluator (6 tests)
  - WalkDelegationTree delegation tree (5 tests)
  - GrantArtifactAccess + VerifyAndDecryptArtifact (6 tests)
  - GenerateAdmissionStamp / VerifyAdmissionStamp (3 tests)
  - ProvisionThreeLogs (4 tests)
  - InitiateRecovery / CollectShares / ExecuteRecovery (5 tests)
  - ProposeAmendment / CollectApprovals / ExecuteAmendment / ExecuteRemoval (5 tests)

All tests use in-memory infrastructure. No Postgres. No HTTP.
*/
package tests

import (
	"crypto/elliptic"
	"testing"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/admission" // ← add this
	"github.com/clearcompass-ai/ortholog-sdk/crypto/artifact"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/escrow"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/lifecycle"
	"github.com/clearcompass-ai/ortholog-sdk/schema"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/verifier"
)

// ═════════════════════════════════════════════════════════════════════
// 1. VerifyShare / VerifyShareSet (3 tests)
// ═════════════════════════════════════════════════════════════════════

func TestVerifyShare_ValidShare(t *testing.T) {
	share := escrow.Share{FieldTag: 0x01, Index: 1, Value: make([]byte, 32)}
	if err := escrow.VerifyShare(share); err != nil {
		t.Fatalf("valid share should pass: %v", err)
	}
}

func TestVerifyShare_WrongFieldTag(t *testing.T) {
	share := escrow.Share{FieldTag: 0x02, Index: 1, Value: make([]byte, 32)}
	if err := escrow.VerifyShare(share); err == nil {
		t.Fatal("wrong field tag should be rejected")
	}
}

func TestVerifyShareSet_DuplicateIndex(t *testing.T) {
	shares := []escrow.Share{
		{FieldTag: 0x01, Index: 1, Value: make([]byte, 32)},
		{FieldTag: 0x01, Index: 1, Value: make([]byte, 32)},
	}
	if err := escrow.VerifyShareSet(shares); err == nil {
		t.Fatal("duplicate indices should be rejected")
	}
}

// ═════════════════════════════════════════════════════════════════════
// 2. ProcessWithRetry (5 tests)
// ═════════════════════════════════════════════════════════════════════

func TestRetry_SucceedsFirstAttempt(t *testing.T) {
	h := newHarness()
	entry, _ := makeEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:alice", AuthorityPath: sameSigner()}, nil)
	h.fetcher.Store(pos(1), entry)

	result, err := builder.ProcessWithRetry(builder.ProcessWithRetryParams{
		Tree:        h.tree,
		Entries:     []*envelope.Entry{entry},
		Positions:   []types.LogPosition{pos(1)},
		Fetcher:     h.fetcher,
		LocalLogDID: testLogDID,
		DeltaBuffer: h.buffer,
		Config:      builder.DefaultRetryConfig(),
	})
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if result.Attempts != 1 {
		t.Fatalf("expected 1 attempt, got %d", result.Attempts)
	}
	if result.FinalRejections != 0 {
		t.Fatalf("expected 0 rejections, got %d", result.FinalRejections)
	}
}

func TestRetry_EmptyBatch(t *testing.T) {
	h := newHarness()
	result, err := builder.ProcessWithRetry(builder.ProcessWithRetryParams{
		Tree:        h.tree,
		Entries:     nil,
		Positions:   nil,
		Fetcher:     h.fetcher,
		LocalLogDID: testLogDID,
		DeltaBuffer: h.buffer,
		Config:      builder.DefaultRetryConfig(),
	})
	if err != nil {
		t.Fatalf("empty: %v", err)
	}
	if result.Attempts != 1 {
		t.Fatalf("empty should be 1 attempt, got %d", result.Attempts)
	}
}

func TestRetry_RespectsMaxAttempts(t *testing.T) {
	h := newHarness()
	rootPos := pos(1)
	h.addRootEntity(t, rootPos, "did:example:entity")
	scopePos := pos(2)
	h.addScopeEntity(t, scopePos, "did:example:judge", map[string]struct{}{"did:example:judge": {}})

	// Entry with wrong PriorAuthority → will be rejected every attempt.
	entry, _ := makeEntry(t, envelope.ControlHeader{
		Destination:    testDestinationDID,
		SignerDID:      "did:example:judge",
		TargetRoot:     ptrTo(rootPos),
		AuthorityPath:  scopeAuth(),
		ScopePointer:   ptrTo(scopePos),
		PriorAuthority: ptrTo(pos(999)),
	}, nil)
	h.fetcher.Store(pos(3), entry)

	cfg := builder.RetryConfig{MaxAttempts: 3, BaseDelay: 1 * time.Millisecond, MaxDelay: 5 * time.Millisecond}
	result, err := builder.ProcessWithRetry(builder.ProcessWithRetryParams{
		Tree:        h.tree,
		Entries:     []*envelope.Entry{entry},
		Positions:   []types.LogPosition{pos(3)},
		Fetcher:     h.fetcher,
		LocalLogDID: testLogDID,
		DeltaBuffer: h.buffer,
		Config:      cfg,
	})
	if err != nil {
		t.Fatalf("retry: %v", err)
	}
	if result.Attempts != 3 {
		t.Fatalf("expected 3 attempts, got %d", result.Attempts)
	}
	if result.FinalRejections == 0 {
		t.Fatal("should still have rejections after max attempts")
	}
}

func TestRetry_DefaultConfig(t *testing.T) {
	cfg := builder.DefaultRetryConfig()
	if cfg.MaxAttempts != 5 {
		t.Fatalf("default MaxAttempts: %d", cfg.MaxAttempts)
	}
	if cfg.BaseDelay != 50*time.Millisecond {
		t.Fatalf("default BaseDelay: %s", cfg.BaseDelay)
	}
}

func TestRetry_BatchConfig(t *testing.T) {
	cfg := builder.BatchRetryConfig()
	if cfg.MaxAttempts != 10 {
		t.Fatalf("batch MaxAttempts: %d", cfg.MaxAttempts)
	}
	if !cfg.AcceptPartialSuccess {
		t.Fatal("batch should accept partial success")
	}
}

// ═════════════════════════════════════════════════════════════════════
// 3. EvaluateConditions (6 tests)
// ═════════════════════════════════════════════════════════════════════

func p6bSchemaEntry(t *testing.T, payload []byte) *envelope.Entry {
	t.Helper()
	e, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     "did:example:schema-author",
		AuthorityPath: sameSigner(),
	}, payload)

	if err != nil {
		t.Fatal(err)
	}
	return e
}

func TestConditions_AllMet(t *testing.T) {
	fetcher := NewMockFetcher()
	schemaPos := pos(10)
	fetcher.Store(schemaPos, p6bSchemaEntry(t, mustJSON(map[string]any{
		"activation_delay":      1,
		"cosignature_threshold": 1,
	})))

	pendingEntry, _ := makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:   "did:example:judge",
		SchemaRef:   ptrTo(schemaPos),
	}, nil)
	pendingPos := pos(1)
	fetcher.Store(pendingPos, pendingEntry)
	// Backdate so delay has elapsed.
	fetcher.entries[pendingPos].LogTime = time.Now().Add(-1 * time.Hour)

	// One cosignature.
	cosigEntry, _ := makeEntry(t, envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     "did:example:clerk",
		CosignatureOf: ptrTo(pendingPos),
	}, nil)
	cosigMeta := types.EntryWithMetadata{
		CanonicalBytes: envelope.Serialize(cosigEntry),
		Position:       pos(2),
		LogTime:        time.Now(),
	}

	result, err := verifier.EvaluateConditions(verifier.EvaluateConditionsParams{
		PendingPos:   pendingPos,
		Fetcher:      fetcher,
		Extractor:    schema.NewJSONParameterExtractor(),
		Cosignatures: []types.EntryWithMetadata{cosigMeta},
		Now:          time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if !result.AllMet {
		t.Fatal("all conditions should be met")
	}
	if result.CosignatureCount != 1 {
		t.Fatalf("cosig count: %d", result.CosignatureCount)
	}
}

func TestConditions_ActivationDelayPending(t *testing.T) {
	fetcher := NewMockFetcher()
	schemaPos := pos(10)
	fetcher.Store(schemaPos, p6bSchemaEntry(t, mustJSON(map[string]any{
		"activation_delay": 999999,
	})))

	pendingEntry, _ := makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:   "did:example:judge",
		SchemaRef:   ptrTo(schemaPos),
	}, nil)
	pendingPos := pos(1)
	fetcher.Store(pendingPos, pendingEntry)

	result, err := verifier.EvaluateConditions(verifier.EvaluateConditionsParams{
		PendingPos: pendingPos,
		Fetcher:    fetcher,
		Extractor:  schema.NewJSONParameterExtractor(),
		Now:        time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if result.AllMet {
		t.Fatal("activation delay should be pending")
	}
	if result.EarliestActivation == nil {
		t.Fatal("EarliestActivation should be set")
	}
}

func TestConditions_CosignatureThresholdNotMet(t *testing.T) {
	fetcher := NewMockFetcher()
	schemaPos := pos(10)
	fetcher.Store(schemaPos, p6bSchemaEntry(t, mustJSON(map[string]any{
		"cosignature_threshold": 3,
	})))

	pendingEntry, _ := makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:   "did:example:judge",
		SchemaRef:   ptrTo(schemaPos),
	}, nil)
	pendingPos := pos(1)
	fetcher.Store(pendingPos, pendingEntry)

	result, _ := verifier.EvaluateConditions(verifier.EvaluateConditionsParams{
		PendingPos:   pendingPos,
		Fetcher:      fetcher,
		Extractor:    schema.NewJSONParameterExtractor(),
		Cosignatures: nil,
		Now:          time.Now().UTC(),
	})
	if result.AllMet {
		t.Fatal("cosig threshold should not be met with 0 sigs")
	}
}

func TestConditions_CredentialExpired(t *testing.T) {
	fetcher := NewMockFetcher()
	schemaPos := pos(10)
	fetcher.Store(schemaPos, p6bSchemaEntry(t, mustJSON(map[string]any{
		"credential_validity_period": 1,
	})))

	pendingEntry, _ := makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:   "did:example:issuer",
		SchemaRef:   ptrTo(schemaPos),
	}, nil)
	pendingPos := pos(1)
	fetcher.Store(pendingPos, pendingEntry)
	fetcher.entries[pendingPos].LogTime = time.Now().Add(-1 * time.Hour)

	result, _ := verifier.EvaluateConditions(verifier.EvaluateConditionsParams{
		PendingPos: pendingPos,
		Fetcher:    fetcher,
		Extractor:  schema.NewJSONParameterExtractor(),
		Now:        time.Now().UTC(),
	})
	if result.AllMet {
		t.Fatal("expired credential should not pass")
	}
}

func TestConditions_NoSchema(t *testing.T) {
	fetcher := NewMockFetcher()
	pendingEntry, _ := makeEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:actor"}, nil)
	pendingPos := pos(1)
	fetcher.Store(pendingPos, pendingEntry)

	result, _ := verifier.EvaluateConditions(verifier.EvaluateConditionsParams{
		PendingPos: pendingPos,
		Fetcher:    fetcher,
		Now:        time.Now().UTC(),
	})
	if !result.AllMet {
		t.Fatal("no schema → all conditions N/A → all met")
	}
}

func TestConditions_CheckActivationReady(t *testing.T) {
	fetcher := NewMockFetcher()
	pendingEntry, _ := makeEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:actor"}, nil)
	pendingPos := pos(1)
	fetcher.Store(pendingPos, pendingEntry)

	ready, err := verifier.CheckActivationReady(verifier.EvaluateConditionsParams{
		PendingPos: pendingPos,
		Fetcher:    fetcher,
		Now:        time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !ready {
		t.Fatal("should be ready")
	}
}

// ═════════════════════════════════════════════════════════════════════
// 4. WalkDelegationTree (5 tests)
// ═════════════════════════════════════════════════════════════════════

// mockDelegationQuerier returns stored entries by signer DID.
type mockDelegationQuerier struct {
	entries map[string][]types.EntryWithMetadata
}

func newMockQuerier() *mockDelegationQuerier {
	return &mockDelegationQuerier{entries: make(map[string][]types.EntryWithMetadata)}
}
func (q *mockDelegationQuerier) QueryBySignerDID(did string) ([]types.EntryWithMetadata, error) {
	return q.entries[did], nil
}
func (q *mockDelegationQuerier) addDelegation(t *testing.T, p types.LogPosition, signerDID, delegateDID string) {
	t.Helper()
	entry, _ := makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:   signerDID, AuthorityPath: sameSigner(), DelegateDID: &delegateDID,
	}, nil)
	meta := types.EntryWithMetadata{
		CanonicalBytes: envelope.Serialize(entry), Position: p, LogTime: time.Now(),
	}
	q.entries[signerDID] = append(q.entries[signerDID], meta)
}

func TestDelegationTree_SingleLevel(t *testing.T) {
	fetcher := NewMockFetcher()
	store := smt.NewInMemoryLeafStore()
	querier := newMockQuerier()

	rootPos := pos(1)
	rootEntry, _ := makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:   "did:example:court", AuthorityPath: sameSigner(),
	}, nil)
	fetcher.Store(rootPos, rootEntry)

	d1 := pos(10)
	querier.addDelegation(t, d1, "did:example:court", "did:example:judge")
	key := smt.DeriveKey(d1)
	store.Set(key, types.SMTLeaf{Key: key, OriginTip: d1, AuthorityTip: d1})

	tree, err := verifier.WalkDelegationTree(verifier.WalkDelegationTreeParams{
		RootEntityPos: rootPos, Fetcher: fetcher, LeafReader: store, Querier: querier,
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if tree.TotalNodes != 2 {
		t.Fatalf("total: %d", tree.TotalNodes)
	}
	if tree.LiveCount != 1 {
		t.Fatalf("live: %d", tree.LiveCount)
	}
}

func TestDelegationTree_ThreeDeep(t *testing.T) {
	fetcher := NewMockFetcher()
	store := smt.NewInMemoryLeafStore()
	querier := newMockQuerier()

	rootPos := pos(1)
	rootEntry, _ := makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:   "did:example:court", AuthorityPath: sameSigner(),
	}, nil)
	fetcher.Store(rootPos, rootEntry)

	d1, d2, d3 := pos(10), pos(11), pos(12)
	querier.addDelegation(t, d1, "did:example:court", "did:example:judge")
	querier.addDelegation(t, d2, "did:example:judge", "did:example:clerk")
	querier.addDelegation(t, d3, "did:example:clerk", "did:example:deputy")
	for _, p := range []types.LogPosition{d1, d2, d3} {
		k := smt.DeriveKey(p)
		store.Set(k, types.SMTLeaf{Key: k, OriginTip: p, AuthorityTip: p})
	}

	tree, _ := verifier.WalkDelegationTree(verifier.WalkDelegationTreeParams{
		RootEntityPos: rootPos, Fetcher: fetcher, LeafReader: store, Querier: querier,
	})
	if tree.TotalNodes != 4 {
		t.Fatalf("total: %d", tree.TotalNodes)
	}
	if tree.MaxDepthReached != 3 {
		t.Fatalf("depth: %d", tree.MaxDepthReached)
	}
}

func TestDelegationTree_RevokedMarked(t *testing.T) {
	fetcher := NewMockFetcher()
	store := smt.NewInMemoryLeafStore()
	querier := newMockQuerier()

	rootPos := pos(1)
	rootEntry, _ := makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:   "did:example:court", AuthorityPath: sameSigner(),
	}, nil)
	fetcher.Store(rootPos, rootEntry)

	d1 := pos(10)
	querier.addDelegation(t, d1, "did:example:court", "did:example:judge")
	k := smt.DeriveKey(d1)
	store.Set(k, types.SMTLeaf{Key: k, OriginTip: pos(99), AuthorityTip: d1})

	tree, _ := verifier.WalkDelegationTree(verifier.WalkDelegationTreeParams{
		RootEntityPos: rootPos, Fetcher: fetcher, LeafReader: store, Querier: querier,
	})
	if tree.LiveCount != 0 {
		t.Fatalf("live: %d (revoked should be 0)", tree.LiveCount)
	}
	nodes := verifier.FlattenTree(tree)
	if nodes[1].IsLive {
		t.Fatal("delegation should not be live")
	}
}

func TestDelegationTree_FlattenAndLive(t *testing.T) {
	fetcher := NewMockFetcher()
	store := smt.NewInMemoryLeafStore()
	querier := newMockQuerier()

	rootPos := pos(1)
	rootEntry, _ := makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:   "did:example:court", AuthorityPath: sameSigner(),
	}, nil)
	fetcher.Store(rootPos, rootEntry)

	d1, d2 := pos(10), pos(11)
	querier.addDelegation(t, d1, "did:example:court", "did:example:a")
	querier.addDelegation(t, d2, "did:example:court", "did:example:b")
	for _, p := range []types.LogPosition{d1, d2} {
		k := smt.DeriveKey(p)
		store.Set(k, types.SMTLeaf{Key: k, OriginTip: p, AuthorityTip: p})
	}

	tree, _ := verifier.WalkDelegationTree(verifier.WalkDelegationTreeParams{
		RootEntityPos: rootPos, Fetcher: fetcher, LeafReader: store, Querier: querier,
	})
	flat := verifier.FlattenTree(tree)
	if len(flat) != 3 {
		t.Fatalf("flat: %d", len(flat))
	}
	live := verifier.LiveDelegations(tree)
	if len(live) != 2 {
		t.Fatalf("live: %d", len(live))
	}
}

func TestDelegationTree_RootNotFound(t *testing.T) {
	_, err := verifier.WalkDelegationTree(verifier.WalkDelegationTreeParams{
		RootEntityPos: pos(999),
		Fetcher:       NewMockFetcher(),
		LeafReader:    smt.NewInMemoryLeafStore(),
		Querier:       newMockQuerier(),
	})
	if err == nil {
		t.Fatal("missing root should error")
	}
}

// ═════════════════════════════════════════════════════════════════════
// 5. Artifact access (6 tests)
// ═════════════════════════════════════════════════════════════════════

func TestArtifactAccess_AESGCM_GrantRoundTrip(t *testing.T) {
	plaintext := []byte("court evidence document")
	ct, artKey, _ := artifact.EncryptArtifact(plaintext)
	artCID := storage.Compute(ct)
	contentDigest := storage.Compute(plaintext)

	keyStore := lifecycle.NewInMemoryKeyStore()
	keyStore.Store(artCID, artKey)

	recipientKey, _ := signatures.GenerateKey()
	recipientPK := elliptic.Marshal(signatures.Secp256k1(), recipientKey.PublicKey.X, recipientKey.PublicKey.Y)

	result, err := lifecycle.GrantArtifactAccess(lifecycle.GrantArtifactAccessParams{
		Destination:       testDestinationDID,
		ArtifactCID:       artCID,
		ContentDigest:     contentDigest,
		RecipientPubKey:   recipientPK,
		KeyStore:          keyStore,
		RetrievalProvider: storage.NewInMemoryRetrievalProvider(),
		SchemaParams:      &types.SchemaParameters{ArtifactEncryption: types.EncryptionAESGCM},
	})
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	if result.Method != "aes_gcm" {
		t.Fatalf("method: %s", result.Method)
	}
	if result.Credential == nil {
		t.Fatal("credential should be set")
	}
	if len(result.WrappedKey) == 0 {
		t.Fatal("wrapped key should be set")
	}
}

func TestArtifactAccess_GrantEntryRequired(t *testing.T) {
	plaintext := []byte("artifact with grant entry")
	ct, artKey, _ := artifact.EncryptArtifact(plaintext)
	artCID := storage.Compute(ct)

	keyStore := lifecycle.NewInMemoryKeyStore()
	keyStore.Store(artCID, artKey)

	recipientKey, _ := signatures.GenerateKey()
	recipientPK := elliptic.Marshal(signatures.Secp256k1(), recipientKey.PublicKey.X, recipientKey.PublicKey.Y)

	result, err := lifecycle.GrantArtifactAccess(lifecycle.GrantArtifactAccessParams{
		Destination:       testDestinationDID,
		ArtifactCID:       artCID,
		RecipientPubKey:   recipientPK,
		KeyStore:          keyStore,
		RetrievalProvider: storage.NewInMemoryRetrievalProvider(),
		SchemaParams:      &types.SchemaParameters{ArtifactEncryption: types.EncryptionAESGCM, GrantEntryRequired: true},
		GranterDID:        "did:example:exchange",
		RecipientDID:      "did:example:board",
	})
	if err != nil {
		t.Fatalf("grant: %v", err)
	}
	if result.GrantEntry == nil {
		t.Fatal("grant entry should be built when GrantEntryRequired")
	}
}

func TestArtifactAccess_VerifyAndDecryptArtifact_AESGCM(t *testing.T) {
	plaintext := []byte("decryption test payload")
	ct, artKey, _ := artifact.EncryptArtifact(plaintext)
	artCID := storage.Compute(ct)
	contentDigest := storage.Compute(plaintext)

	recovered, err := lifecycle.VerifyAndDecryptArtifact(lifecycle.VerifyAndDecryptArtifactParams{
		Ciphertext:    ct,
		ArtifactCID:   artCID,
		ContentDigest: contentDigest,
		SchemaParams:  &types.SchemaParameters{ArtifactEncryption: types.EncryptionAESGCM},
		Key:           &artKey,
	})
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if string(recovered) != string(plaintext) {
		t.Fatal("plaintext mismatch")
	}
}

func TestArtifactAccess_ReEncryptRoundTrip(t *testing.T) {
	plaintext := []byte("re-encryption test")
	ct, artKey, _ := artifact.EncryptArtifact(plaintext)
	artCID := storage.Compute(ct)

	keyStore := lifecycle.NewInMemoryKeyStore()
	keyStore.Store(artCID, artKey)
	contentStore := storage.NewInMemoryContentStore()
	contentStore.Push(artCID, ct)

	result, err := lifecycle.ReEncryptWithGrant(lifecycle.ReEncryptWithGrantParams{
		OldCID:       artCID,
		KeyStore:     keyStore,
		ContentStore: contentStore,
	})
	if err != nil {
		t.Fatalf("re-encrypt: %v", err)
	}
	if result.NewCID.Equal(artCID) {
		t.Fatal("new CID should differ from old")
	}

	// Verify new key works.
	newCT, _ := contentStore.Fetch(result.NewCID)
	recovered, err := artifact.DecryptArtifact(newCT, result.NewKey)
	if err != nil {
		t.Fatalf("decrypt new: %v", err)
	}
	if string(recovered) != string(plaintext) {
		t.Fatal("re-encrypted plaintext mismatch")
	}

	// Old key should be deleted.
	oldKey, _ := keyStore.Get(artCID)
	if oldKey != nil {
		t.Fatal("old key should be deleted after re-encryption")
	}
}

func TestArtifactAccess_InMemoryKeyStore(t *testing.T) {
	ks := lifecycle.NewInMemoryKeyStore()
	cid := storage.Compute([]byte("test"))
	key := artifact.ArtifactKey{}
	key.Key[0] = 0x42

	ks.Store(cid, key)
	got, _ := ks.Get(cid)
	if got == nil || got.Key[0] != 0x42 {
		t.Fatal("key should be retrievable")
	}

	ks.Delete(cid)
	got, _ = ks.Get(cid)
	if got != nil {
		t.Fatal("deleted key should be nil")
	}
}

func TestArtifactAccess_NilSchemaParams_Error(t *testing.T) {
	_, err := lifecycle.GrantArtifactAccess(lifecycle.GrantArtifactAccessParams{
		Destination:  testDestinationDID,
		SchemaParams: nil,
	})
	if err == nil {
		t.Fatal("nil schema params should error")
	}
}

// ═════════════════════════════════════════════════════════════════════
// 6. Difficulty (3 tests)
// ═════════════════════════════════════════════════════════════════════
func TestDifficulty_GenerateAndVerify(t *testing.T) {
	entryHash := [32]byte{1, 2, 3, 4}
	cfg := lifecycle.DefaultDifficultyConfig("did:ortholog:testlog")
	// Lower difficulty for test speed; default is 16.
	cfg.Difficulty = 8

	proof, err := lifecycle.GenerateAdmissionStamp(entryHash, cfg, nil)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if proof.Mode != types.AdmissionModeB {
		t.Fatalf("mode: %d", proof.Mode)
	}
	if proof.TargetLog != "did:ortholog:testlog" {
		t.Fatalf("target: %s", proof.TargetLog)
	}

	if err := lifecycle.VerifyAdmissionStamp(entryHash, proof, cfg); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestDifficulty_WrongLogDIDRejected(t *testing.T) {
	entryHash := [32]byte{5, 6, 7}
	cfg := lifecycle.DefaultDifficultyConfig("did:ortholog:correct")
	cfg.Difficulty = 8
	proof, err := lifecycle.GenerateAdmissionStamp(entryHash, cfg, nil)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	wrongCfg := lifecycle.DefaultDifficultyConfig("did:ortholog:wrong")
	wrongCfg.Difficulty = 8
	if err := lifecycle.VerifyAdmissionStamp(entryHash, proof, wrongCfg); err == nil {
		t.Fatal("wrong log DID should be rejected")
	}
}

func TestDifficulty_BelowMinimum(t *testing.T) {
	entryHash := [32]byte{8, 9}
	lowCfg := lifecycle.DifficultyConfig{
		TargetLogDID: "did:test:log",
		Difficulty:   8,
		HashFunc:     admission.HashSHA256,
	}
	proof, err := lifecycle.GenerateAdmissionStamp(entryHash, lowCfg, nil)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	highCfg := lifecycle.DifficultyConfig{
		TargetLogDID: "did:test:log",
		Difficulty:   24,
		HashFunc:     admission.HashSHA256,
	}
	if err := lifecycle.VerifyAdmissionStamp(entryHash, proof, highCfg); err == nil {
		t.Fatal("difficulty below minimum should be rejected")
	}
}

// ═════════════════════════════════════════════════════════════════════
// 7. Provision (1 test)
// ═════════════════════════════════════════════════════════════════════
//
// Wave 3: ProvisionThreeLogs and its court-specific validation moved to
// the judicial-network repo. The SDK keeps only ProvisionSingleLog,
// which is domain-agnostic. Multi-log provisioning (judicial, physician
// credentialing, insurance) composes this single-log primitive in the
// downstream repo.

func TestProvision_SingleLog(t *testing.T) {
	result, err := lifecycle.ProvisionSingleLog(lifecycle.SingleLogConfig{
		Destination:  testDestinationDID,
		SignerDID:    "did:web:hospital.example.com",
		LogDID:       "did:web:hospital.example.com:credentials",
		AuthoritySet: map[string]struct{}{"did:web:hospital.example.com": {}},
	})
	if err != nil {
		t.Fatalf("single: %v", err)
	}
	if result.ScopeEntry == nil {
		t.Fatal("scope should exist")
	}
}

// ═════════════════════════════════════════════════════════════════════
// 8. Recovery (5 tests)
// ═════════════════════════════════════════════════════════════════════

func TestRecovery_InitiateProducesCommentary(t *testing.T) {
	result, err := lifecycle.InitiateRecovery(lifecycle.InitiateRecoveryParams{
		Destination:      testDestinationDID,
		NewExchangeDID:   "did:example:new-exchange",
		HolderDID:        "did:example:holder",
		Reason:           "exchange failure",
		EscrowPackageCID: storage.Compute([]byte("package")),
	})
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	if result.RequestEntry == nil {
		t.Fatal("entry should be built")
	}
	if result.RequestEntry.Header.TargetRoot != nil {
		t.Fatal("recovery request should be commentary (no TargetRoot)")
	}
}

func TestRecovery_CollectSharesValidates(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	shares, _ := escrow.SplitGF256(secret, 3, 5)

	collected, err := lifecycle.CollectShares(lifecycle.CollectSharesParams{
		DecryptedShares:   shares[:4],
		RequiredThreshold: 3,
	})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(collected.ValidShares) != 4 {
		t.Fatalf("valid: %d", len(collected.ValidShares))
	}
	if !collected.SufficientForRecovery {
		t.Fatal("4 of 3 should be sufficient")
	}
}

func TestRecovery_CollectSharesRejectsBadTag(t *testing.T) {
	badShare := escrow.Share{FieldTag: 0xFF, Index: 1, Value: make([]byte, 32)}
	collected, _ := lifecycle.CollectShares(lifecycle.CollectSharesParams{
		DecryptedShares:   []escrow.Share{badShare},
		RequiredThreshold: 1,
	})
	if collected.InvalidCount != 1 {
		t.Fatalf("invalid: %d", collected.InvalidCount)
	}
	if collected.SufficientForRecovery {
		t.Fatal("should not be sufficient with only invalid shares")
	}
}

func TestRecovery_ExecuteRoundTrip(t *testing.T) {
	plaintext := []byte("recovery target artifact data!!!")
	ct, artKey, _ := artifact.EncryptArtifact(plaintext)
	artCID := storage.Compute(ct)

	contentStore := storage.NewInMemoryContentStore()
	contentStore.Push(artCID, ct)

	// Shamir-split the key material.
	keyMaterial := make([]byte, artifact.KeySize+artifact.NonceSize)
	copy(keyMaterial[:artifact.KeySize], artKey.Key[:])
	copy(keyMaterial[artifact.KeySize:], artKey.Nonce[:])
	shares, _ := escrow.SplitGF256(keyMaterial, 3, 5)

	keyStore := lifecycle.NewInMemoryKeyStore()
	result, err := lifecycle.ExecuteRecovery(lifecycle.ExecuteRecoveryParams{
		Destination:  testDestinationDID,
		Shares:       shares[:3],
		ArtifactCIDs: []storage.CID{artCID},
		ContentStore: contentStore,
		KeyStore:     keyStore,
	})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(result.ReEncryptedArtifacts) != 1 {
		t.Fatalf("re-encrypted: %d", len(result.ReEncryptedArtifacts))
	}
}

func TestRecovery_ArbitrationBelowThreshold(t *testing.T) {
	result, err := lifecycle.EvaluateArbitration(lifecycle.ArbitrationParams{
		RecoveryRequestPos: pos(1),
		EscrowApprovals:    nil,
		TotalEscrowNodes:   5,
	})
	if err != nil {
		t.Fatalf("arb: %v", err)
	}
	if result.OverrideAuthorized {
		t.Fatal("0 approvals should not authorize override")
	}
	if result.RequiredCount != 4 {
		t.Fatalf("required: %d (expected ⌈2×5/3⌉=4)", result.RequiredCount)
	}
}

// ═════════════════════════════════════════════════════════════════════
// 9. Scope Governance (5 tests)
// ═════════════════════════════════════════════════════════════════════

func TestScope_ProposeAmendment(t *testing.T) {
	proposal, err := lifecycle.ProposeAmendment(lifecycle.AmendmentProposalParams{
		Destination:  testDestinationDID,
		ProposerDID:  "did:example:authority-a",
		ProposalType: lifecycle.ProposalAddAuthority,
		TargetDID:    "did:example:new-member",
	})
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if proposal.Entry == nil {
		t.Fatal("entry should be built")
	}
	if !proposal.RequiresUnanimity {
		t.Fatal("add_authority requires unanimity")
	}
}

func TestScope_ProposeRemovalNoUnanimity(t *testing.T) {
	proposal, err := lifecycle.ProposeAmendment(lifecycle.AmendmentProposalParams{
		Destination:  testDestinationDID,
		ProposerDID:  "did:example:authority-a",
		ProposalType: lifecycle.ProposalRemoveAuthority,
		TargetDID:    "did:example:rogue",
	})
	if err != nil {
		t.Fatal(err)
	}
	if proposal.RequiresUnanimity {
		t.Fatal("remove_authority should NOT require unanimity")
	}
}

// mockCosigQuerier returns stored cosignature entries.
type mockCosigQuerier struct {
	entries []types.EntryWithMetadata
}

func (q *mockCosigQuerier) QueryByCosignatureOf(pos types.LogPosition) ([]types.EntryWithMetadata, error) {
	return q.entries, nil
}

func TestScope_CollectApprovals(t *testing.T) {
	proposalPos := pos(1)
	auth := map[string]struct{}{
		"did:example:a": {}, "did:example:b": {}, "did:example:c": {},
	}

	cosigA, _ := makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:   "did:example:b", CosignatureOf: ptrTo(proposalPos),
	}, nil)
	cosigB, _ := makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:   "did:example:c", CosignatureOf: ptrTo(proposalPos),
	}, nil)

	querier := &mockCosigQuerier{entries: []types.EntryWithMetadata{
		{CanonicalBytes: envelope.Serialize(cosigA), Position: pos(2)},
		{CanonicalBytes: envelope.Serialize(cosigB), Position: pos(3)},
	}}

	status, err := lifecycle.CollectApprovals(lifecycle.CollectApprovalsParams{
		ProposalPos:         proposalPos,
		CurrentAuthoritySet: auth,
		Querier:             querier,
		RequiresUnanimity:   true,
		ProposerDID:         "did:example:a",
	})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if status.ApprovalCount != 2 {
		t.Fatalf("approvals: %d", status.ApprovalCount)
	}
	if !status.Sufficient {
		t.Fatal("2 of 2 required (3 total minus proposer) should be sufficient")
	}
}

func TestScope_ExecuteRemovalTimeLock(t *testing.T) {
	result, err := lifecycle.ExecuteRemoval(lifecycle.RemovalParams{
		Destination: testDestinationDID,
		ExecutorDID: "did:example:authority-a",
		ScopePos:    pos(1),
		TargetDID:   "did:example:rogue",
	})
	if err != nil {
		t.Fatalf("remove: %v", err)
	}
	if result.TimeLock != lifecycle.DefaultRemovalTimeLock {
		t.Fatalf("time-lock: %s", result.TimeLock)
	}
	if result.HasObjectiveTrigger {
		t.Fatal("should not have objective trigger without evidence")
	}
}

func TestScope_ExecuteRemovalReducedTimeLock(t *testing.T) {
	result, err := lifecycle.ExecuteRemoval(lifecycle.RemovalParams{
		Destination:       testDestinationDID,
		ExecutorDID:       "did:example:authority-a",
		ScopePos:          pos(1),
		TargetDID:         "did:example:rogue",
		ObjectiveTriggers: []types.LogPosition{pos(100)},
		TriggerType:       lifecycle.TriggerEquivocation,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.TimeLock != lifecycle.ReducedRemovalTimeLock {
		t.Fatalf("time-lock: %s (expected 7 days)", result.TimeLock)
	}
	if !result.HasObjectiveTrigger {
		t.Fatal("should have objective trigger")
	}
}
