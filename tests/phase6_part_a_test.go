/*
FILE PATH: tests/phase6_part_a_test.go

Phase 6 Part A: 50 tests covering:
  - Entry builders (29 tests): one per builder + constraint violations
  - AssemblePathB (7 tests): chain depth, cycles, liveness, disconnection
  - ClassifyEntry (10 tests): each path + edge cases
  - Delegation Key Isolation (4 tests): generate, unwrap, rejection, full PRE flow

All tests use in-memory infrastructure. No Postgres required.
*/
package tests

import (
	"bytes"
	"crypto/elliptic"
	"errors"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/artifact"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/lifecycle"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ═════════════════════════════════════════════════════════════════════
// Phase 6A helpers
// ═════════════════════════════════════════════════════════════════════

func p6leafStore() *smt.InMemoryLeafStore { return smt.NewInMemoryLeafStore() }

func p6setLeaf(t *testing.T, store *smt.InMemoryLeafStore, p types.LogPosition) {
	t.Helper()
	key := smt.DeriveKey(p)
	if err := store.Set(key, types.SMTLeaf{Key: key, OriginTip: p, AuthorityTip: p}); err != nil {
		t.Fatal(err)
	}
}

func p6storeDelegation(t *testing.T, fetcher *MockFetcher, store *smt.InMemoryLeafStore, p types.LogPosition, signerDID, delegateDID string) {
	t.Helper()
	entry := buildTestEntry(t, envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     signerDID,
		AuthorityPath: sameSigner(),
		DelegateDID:   &delegateDID,
	}, nil)
	fetcher.Store(p, entry)
	p6setLeaf(t, store, p)
}

func padSecretKeyTo32(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}

// ═════════════════════════════════════════════════════════════════════
// 1. Entry Builder Tests (29 tests)
// ═════════════════════════════════════════════════════════════════════

func TestBuild_RootEntity_Valid(t *testing.T) {
	entry, err := builder.BuildRootEntity(builder.RootEntityParams{
		Destination: testDestinationDID,
		SignerDID:   "did:example:alice",
		Payload:     []byte("entity-data"),
		EventTime:   1700000000,
	})
	if err != nil {
		t.Fatalf("BuildRootEntity: %v", err)
	}
	if entry.Header.SignerDID != "did:example:alice" {
		t.Fatalf("SignerDID: %s", entry.Header.SignerDID)
	}
	if entry.Header.AuthorityPath == nil || *entry.Header.AuthorityPath != envelope.AuthoritySameSigner {
		t.Fatal("AuthorityPath should be SameSigner")
	}
	if entry.Header.TargetRoot != nil {
		t.Fatal("TargetRoot should be nil for root entity")
	}
	if string(entry.DomainPayload) != "entity-data" {
		t.Fatalf("payload: %s", entry.DomainPayload)
	}
}

func TestBuild_RootEntity_MissingSignerDID_Error(t *testing.T) {
	_, err := builder.BuildRootEntity(builder.RootEntityParams{Destination: testDestinationDID, Payload: []byte("x")})
	if !errors.Is(err, builder.ErrEmptySignerDID) {
		t.Fatalf("expected ErrEmptySignerDID, got: %v", err)
	}
}

func TestBuild_Amendment_Valid(t *testing.T) {
	target := pos(1)
	entry, err := builder.BuildAmendment(builder.AmendmentParams{
		Destination: testDestinationDID,
		SignerDID:   "did:example:alice",
		TargetRoot:  target,
		Payload:     []byte("amended"),
		EventTime:   1700000001,
	})
	if err != nil {
		t.Fatalf("BuildAmendment: %v", err)
	}
	if entry.Header.TargetRoot == nil || !entry.Header.TargetRoot.Equal(target) {
		t.Fatal("TargetRoot mismatch")
	}
	if *entry.Header.AuthorityPath != envelope.AuthoritySameSigner {
		t.Fatal("AuthorityPath should be SameSigner")
	}
}

func TestBuild_Amendment_MissingTargetRoot_Error(t *testing.T) {
	_, err := builder.BuildAmendment(builder.AmendmentParams{
		Destination: testDestinationDID,
		SignerDID:   "did:example:alice",
	})
	if !errors.Is(err, builder.ErrMissingTargetRoot) {
		t.Fatalf("expected ErrMissingTargetRoot, got: %v", err)
	}
}

func TestBuild_Delegation_Valid(t *testing.T) {
	entry, err := builder.BuildDelegation(builder.DelegationParams{
		Destination: testDestinationDID,
		SignerDID:   "did:example:owner",
		DelegateDID: "did:example:delegate",
		EventTime:   1700000002,
	})
	if err != nil {
		t.Fatalf("BuildDelegation: %v", err)
	}
	if entry.Header.DelegateDID == nil || *entry.Header.DelegateDID != "did:example:delegate" {
		t.Fatal("DelegateDID mismatch")
	}
}

func TestBuild_Delegation_MissingDelegateDID_Error(t *testing.T) {
	_, err := builder.BuildDelegation(builder.DelegationParams{
		Destination: testDestinationDID,
		SignerDID:   "did:example:owner",
	})
	if !errors.Is(err, builder.ErrMissingDelegateDID) {
		t.Fatalf("expected ErrMissingDelegateDID, got: %v", err)
	}
}

func TestBuild_Succession_Valid(t *testing.T) {
	entry, err := builder.BuildSuccession(builder.SuccessionParams{
		Destination: testDestinationDID,
		SignerDID:   "did:example:alice",
		TargetRoot:  pos(1),
		Payload:     []byte("succession"),
	})
	if err != nil {
		t.Fatalf("BuildSuccession: %v", err)
	}
	if entry.Header.TargetRoot == nil {
		t.Fatal("TargetRoot should be set")
	}
}

func TestBuild_Enforcement_Valid(t *testing.T) {
	entry, err := builder.BuildEnforcement(builder.EnforcementParams{
		Destination:  testDestinationDID,
		SignerDID:    "did:example:judge",
		TargetRoot:   pos(1),
		ScopePointer: pos(2),
		Payload:      []byte("seal"),
		EventTime:    1700000003,
	})
	if err != nil {
		t.Fatalf("BuildEnforcement: %v", err)
	}
	if *entry.Header.AuthorityPath != envelope.AuthorityScopeAuthority {
		t.Fatal("AuthorityPath should be ScopeAuthority")
	}
	if entry.Header.ScopePointer == nil {
		t.Fatal("ScopePointer should be set")
	}
}

func TestBuild_Enforcement_MissingScopePointer_Error(t *testing.T) {
	_, err := builder.BuildEnforcement(builder.EnforcementParams{
		Destination: testDestinationDID,
		SignerDID:   "did:example:judge",
		TargetRoot:  pos(1),
	})
	if !errors.Is(err, builder.ErrMissingScopePointer) {
		t.Fatalf("expected ErrMissingScopePointer, got: %v", err)
	}
}

func TestBuild_ScopeCreation_Valid(t *testing.T) {
	entry, err := builder.BuildScopeCreation(builder.ScopeCreationParams{
		Destination:  testDestinationDID,
		SignerDID:    "did:example:admin",
		AuthoritySet: map[string]struct{}{"did:example:admin": {}, "did:example:judge": {}},
		Payload:      []byte("scope"),
	})
	if err != nil {
		t.Fatalf("BuildScopeCreation: %v", err)
	}
	if len(entry.Header.AuthoritySet) != 2 {
		t.Fatalf("AuthoritySet size: %d", len(entry.Header.AuthoritySet))
	}
}

func TestBuild_ScopeCreation_EmptyAuthoritySet_Error(t *testing.T) {
	_, err := builder.BuildScopeCreation(builder.ScopeCreationParams{
		Destination:  testDestinationDID,
		SignerDID:    "did:example:admin",
		AuthoritySet: map[string]struct{}{},
	})
	if !errors.Is(err, builder.ErrEmptyAuthoritySet) {
		t.Fatalf("expected ErrEmptyAuthoritySet, got: %v", err)
	}
}

func TestBuild_ScopeAmendment_Valid(t *testing.T) {
	scopePos := pos(1)
	entry, err := builder.BuildScopeAmendment(builder.ScopeAmendmentParams{
		Destination:     testDestinationDID,
		SignerDID:       "did:example:admin",
		TargetRoot:      scopePos,
		ScopePointer:    scopePos,
		NewAuthoritySet: map[string]struct{}{"did:example:admin": {}, "did:example:new": {}},
	})
	if err != nil {
		t.Fatalf("BuildScopeAmendment: %v", err)
	}
	if *entry.Header.AuthorityPath != envelope.AuthorityScopeAuthority {
		t.Fatal("AuthorityPath should be ScopeAuthority")
	}
	if !entry.Header.ScopePointer.Equal(scopePos) {
		t.Fatal("ScopePointer should equal TargetRoot for amendment")
	}
}

func TestBuild_Commentary_Valid_ZeroSMTImpact(t *testing.T) {
	entry, err := builder.BuildCommentary(builder.CommentaryParams{
		Destination: testDestinationDID,
		SignerDID:   "did:example:witness",
		Payload:     []byte("attestation"),
	})
	if err != nil {
		t.Fatalf("BuildCommentary: %v", err)
	}
	if entry.Header.TargetRoot != nil {
		t.Fatal("commentary should have nil TargetRoot")
	}
	if entry.Header.AuthorityPath != nil {
		t.Fatal("commentary should have nil AuthorityPath")
	}
}

func TestBuild_Cosignature_Valid(t *testing.T) {
	cosigOf := pos(42)
	entry, err := builder.BuildCosignature(builder.CosignatureParams{
		Destination:   testDestinationDID,
		SignerDID:     "did:example:cosigner",
		CosignatureOf: cosigOf,
	})
	if err != nil {
		t.Fatalf("BuildCosignature: %v", err)
	}
	if entry.Header.CosignatureOf == nil || !entry.Header.CosignatureOf.Equal(cosigOf) {
		t.Fatal("CosignatureOf mismatch")
	}
}

func TestBuild_Cosignature_MissingCosignatureOf_Error(t *testing.T) {
	_, err := builder.BuildCosignature(builder.CosignatureParams{
		Destination: testDestinationDID,
		SignerDID:   "did:example:cosigner",
	})
	if !errors.Is(err, builder.ErrMissingCosignatureOf) {
		t.Fatalf("expected ErrMissingCosignatureOf, got: %v", err)
	}
}

func TestBuild_KeyRotation_Valid(t *testing.T) {
	entry, err := builder.BuildKeyRotation(builder.KeyRotationParams{
		Destination:  testDestinationDID,
		SignerDID:    "did:example:holder",
		TargetRoot:   pos(1),
		NewPublicKey: []byte{0x04, 0x01, 0x02},
	})
	if err != nil {
		t.Fatalf("BuildKeyRotation: %v", err)
	}
	if entry.Header.TargetRoot == nil {
		t.Fatal("TargetRoot should be set")
	}
	if len(entry.DomainPayload) == 0 {
		t.Fatal("payload should be auto-constructed from NewPublicKey")
	}
}

func TestBuild_KeyPrecommit_Valid(t *testing.T) {
	entry, err := builder.BuildKeyPrecommit(builder.KeyPrecommitParams{
		Destination: testDestinationDID,
		SignerDID:   "did:example:holder",
		TargetRoot:  pos(1),
		NextKeyHash: "abcdef0123456789",
	})
	if err != nil {
		t.Fatalf("BuildKeyPrecommit: %v", err)
	}
	if len(entry.DomainPayload) == 0 {
		t.Fatal("payload should be auto-constructed from NextKeyHash")
	}
}

func TestBuild_PathBEntry_Valid(t *testing.T) {
	entry, err := builder.BuildPathBEntry(builder.PathBParams{
		Destination:        testDestinationDID,
		SignerDID:          "did:example:delegate",
		TargetRoot:         pos(1),
		DelegationPointers: []types.LogPosition{pos(10)},
		Payload:            []byte("delegated-action"),
	})
	if err != nil {
		t.Fatalf("BuildPathBEntry: %v", err)
	}
	if *entry.Header.AuthorityPath != envelope.AuthorityDelegation {
		t.Fatal("AuthorityPath should be Delegation")
	}
	if len(entry.Header.DelegationPointers) != 1 {
		t.Fatal("DelegationPointers should have 1 entry")
	}
}

func TestBuild_Revocation_Valid(t *testing.T) {
	entry, err := builder.BuildRevocation(builder.RevocationParams{
		Destination: testDestinationDID,
		SignerDID:   "did:example:owner",
		TargetRoot:  pos(1),
		Payload:     []byte("revoke-delegation"),
		EventTime:   1700000010,
	})
	if err != nil {
		t.Fatalf("BuildRevocation: %v", err)
	}
	if entry.Header.TargetRoot == nil || !entry.Header.TargetRoot.Equal(pos(1)) {
		t.Fatal("TargetRoot mismatch")
	}
	if *entry.Header.AuthorityPath != envelope.AuthoritySameSigner {
		t.Fatal("AuthorityPath should be SameSigner")
	}
}

func TestBuild_Revocation_MissingSignerDID_Error(t *testing.T) {
	_, err := builder.BuildRevocation(builder.RevocationParams{
		Destination: testDestinationDID,
		TargetRoot:  pos(1),
	})
	if !errors.Is(err, builder.ErrEmptySignerDID) {
		t.Fatalf("expected ErrEmptySignerDID, got: %v", err)
	}
}

func TestBuild_Revocation_MissingTargetRoot_Error(t *testing.T) {
	_, err := builder.BuildRevocation(builder.RevocationParams{
		Destination: testDestinationDID,
		SignerDID:   "did:example:owner",
	})
	if !errors.Is(err, builder.ErrMissingTargetRoot) {
		t.Fatalf("expected ErrMissingTargetRoot, got: %v", err)
	}
}

func TestBuild_ScopeRemoval_Valid(t *testing.T) {
	entry, err := builder.BuildScopeRemoval(builder.ScopeRemovalParams{
		Destination:  testDestinationDID,
		SignerDID:    "did:example:judge",
		ScopePointer: pos(2),
		TargetRoot:   pos(1),
		EventTime:    1700000011,
	})
	if err != nil {
		t.Fatalf("BuildScopeRemoval: %v", err)
	}
	if *entry.Header.AuthorityPath != envelope.AuthorityScopeAuthority {
		t.Fatal("AuthorityPath should be ScopeAuthority")
	}
	if entry.Header.ScopePointer == nil || !entry.Header.ScopePointer.Equal(pos(2)) {
		t.Fatal("ScopePointer mismatch")
	}
	if entry.Header.TargetRoot == nil || !entry.Header.TargetRoot.Equal(pos(1)) {
		t.Fatal("TargetRoot mismatch")
	}
}

func TestBuild_ScopeRemoval_MissingScopePointer_Error(t *testing.T) {
	_, err := builder.BuildScopeRemoval(builder.ScopeRemovalParams{
		Destination: testDestinationDID,
		SignerDID:   "did:example:judge",
		TargetRoot:  pos(1),
	})
	if !errors.Is(err, builder.ErrMissingScopePointer) {
		t.Fatalf("expected ErrMissingScopePointer, got: %v", err)
	}
}

func TestBuild_RecoveryRequest_Valid(t *testing.T) {
	entry, err := builder.BuildRecoveryRequest(builder.RecoveryRequestParams{
		Destination: testDestinationDID,
		SignerDID:   "did:example:recovery-agent",
		Payload:     []byte("recovery-params"),
		EventTime:   1700000012,
	})
	if err != nil {
		t.Fatalf("BuildRecoveryRequest: %v", err)
	}
	if entry.Header.SignerDID != "did:example:recovery-agent" {
		t.Fatalf("SignerDID: %s", entry.Header.SignerDID)
	}
	if entry.Header.TargetRoot != nil {
		t.Fatal("recovery request should have nil TargetRoot")
	}
	if entry.Header.AuthorityPath != nil {
		t.Fatal("recovery request should have nil AuthorityPath")
	}
}

func TestBuild_AnchorEntry_Valid(t *testing.T) {
	entry, err := builder.BuildAnchorEntry(builder.AnchorParams{
		Destination:  testDestinationDID,
		SignerDID:    "did:example:operator",
		SourceLogDID: "did:ortholog:foreign-log",
		TreeHeadRef:  "abcdef0123456789",
		TreeSize:     1000,
		EventTime:    1700000013,
	})
	if err != nil {
		t.Fatalf("BuildAnchorEntry: %v", err)
	}
	if entry.Header.SignerDID != "did:example:operator" {
		t.Fatalf("SignerDID: %s", entry.Header.SignerDID)
	}
	if entry.Header.TargetRoot != nil {
		t.Fatal("anchor should have nil TargetRoot")
	}
	if entry.Header.AuthorityPath != nil {
		t.Fatal("anchor should have nil AuthorityPath")
	}
	if len(entry.DomainPayload) == 0 {
		t.Fatal("anchor payload should be auto-constructed")
	}
}

func TestBuild_AnchorEntry_MissingSourceLogDID_Error(t *testing.T) {
	_, err := builder.BuildAnchorEntry(builder.AnchorParams{
		Destination: testDestinationDID,
		SignerDID:   "did:example:operator",
		TreeHeadRef: "abcdef",
	})
	if !errors.Is(err, builder.ErrMissingSourceLogDID) {
		t.Fatalf("expected ErrMissingSourceLogDID, got: %v", err)
	}
}

func TestBuild_MirrorEntry_Valid(t *testing.T) {
	entry, err := builder.BuildMirrorEntry(builder.MirrorParams{
		Destination:  testDestinationDID,
		SignerDID:    "did:example:relay",
		SourceLogDID: "did:ortholog:foreign-court",
		Payload:      []byte("mirror-proof"),
		EventTime:    1700000014,
	})
	if err != nil {
		t.Fatalf("BuildMirrorEntry: %v", err)
	}
	if entry.Header.SignerDID != "did:example:relay" {
		t.Fatalf("SignerDID: %s", entry.Header.SignerDID)
	}
	if entry.Header.TargetRoot != nil {
		t.Fatal("mirror should have nil TargetRoot")
	}
}

func TestBuild_MirrorEntry_MissingSourceLogDID_Error(t *testing.T) {
	_, err := builder.BuildMirrorEntry(builder.MirrorParams{
		Destination: testDestinationDID,
		SignerDID:   "did:example:relay",
		Payload:     []byte("mirror-proof"),
	})
	if !errors.Is(err, builder.ErrMissingSourceLogDID) {
		t.Fatalf("expected ErrMissingSourceLogDID, got: %v", err)
	}
}

func TestBuild_SchemaEntry_Valid(t *testing.T) {
	entry, err := builder.BuildSchemaEntry(builder.SchemaEntryParams{
		Destination:           testDestinationDID,
		SignerDID:             "did:example:schema-author",
		Payload:               []byte(`{"activation_delay":100}`),
		CommutativeOperations: []uint32{1, 2},
		EventTime:             1700000015,
	})
	if err != nil {
		t.Fatalf("BuildSchemaEntry: %v", err)
	}
	if *entry.Header.AuthorityPath != envelope.AuthoritySameSigner {
		t.Fatal("AuthorityPath should be SameSigner")
	}
	if len(entry.Header.CommutativeOperations) != 2 {
		t.Fatalf("CommutativeOperations: %d", len(entry.Header.CommutativeOperations))
	}
}

// ═════════════════════════════════════════════════════════════════════
// 2. AssemblePathB Tests (7 tests)
// ═════════════════════════════════════════════════════════════════════

func TestAssemblePathB_ThreeDeep_Valid(t *testing.T) {
	fetcher := NewMockFetcher()
	store := p6leafStore()

	rootPos := pos(1)
	rootEntry := buildTestEntry(t, envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     "did:example:owner",
		AuthorityPath: sameSigner(),
	}, nil)
	fetcher.Store(rootPos, rootEntry)
	p6setLeaf(t, store, rootPos)

	d1 := pos(10)
	p6storeDelegation(t, fetcher, store, d1, "did:example:owner", "did:example:mid")
	d2 := pos(11)
	p6storeDelegation(t, fetcher, store, d2, "did:example:mid", "did:example:leaf")
	d3 := pos(12)
	p6storeDelegation(t, fetcher, store, d3, "did:example:leaf", "did:example:deputy")

	assembly, err := builder.AssemblePathB(builder.AssemblePathBParams{
		DelegateDID:        "did:example:deputy",
		TargetRoot:         rootPos,
		LeafReader:         store,
		Fetcher:            fetcher,
		CandidatePositions: []types.LogPosition{d3, d2, d1},
	})
	if err != nil {
		t.Fatalf("AssemblePathB: %v", err)
	}
	if len(assembly.Hops) != 3 {
		t.Fatalf("expected 3 hops, got %d", len(assembly.Hops))
	}
	if len(assembly.DelegationPointers) != 3 {
		t.Fatalf("expected 3 pointers, got %d", len(assembly.DelegationPointers))
	}
	if assembly.Hops[0].DelegateDID != "did:example:deputy" {
		t.Fatalf("hop[0] delegate: %s", assembly.Hops[0].DelegateDID)
	}
	if assembly.Hops[2].SignerDID != "did:example:owner" {
		t.Fatalf("hop[2] signer: %s", assembly.Hops[2].SignerDID)
	}
}

func TestAssemblePathB_SingleHop_Valid(t *testing.T) {
	fetcher := NewMockFetcher()
	store := p6leafStore()

	rootPos := pos(1)
	rootEntry := buildTestEntry(t, envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     "did:example:owner",
		AuthorityPath: sameSigner(),
	}, nil)
	fetcher.Store(rootPos, rootEntry)

	d1 := pos(10)
	p6storeDelegation(t, fetcher, store, d1, "did:example:owner", "did:example:delegate")

	assembly, err := builder.AssemblePathB(builder.AssemblePathBParams{
		DelegateDID:        "did:example:delegate",
		TargetRoot:         rootPos,
		LeafReader:         store,
		Fetcher:            fetcher,
		CandidatePositions: []types.LogPosition{d1},
	})
	if err != nil {
		t.Fatalf("AssemblePathB: %v", err)
	}
	if len(assembly.Hops) != 1 {
		t.Fatalf("expected 1 hop, got %d", len(assembly.Hops))
	}
}

func TestAssemblePathB_ExceedsMaxDepth_Error(t *testing.T) {
	fetcher := NewMockFetcher()
	store := p6leafStore()

	rootPos := pos(1)
	rootEntry := buildTestEntry(t, envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     "did:example:owner",
		AuthorityPath: sameSigner(),
	}, nil)
	fetcher.Store(rootPos, rootEntry)

	candidates := make([]types.LogPosition, 4)
	for i := 0; i < 4; i++ {
		candidates[i] = pos(uint64(10 + i))
		p6storeDelegation(t, fetcher, store, candidates[i],
			"did:example:d"+intToStr(i), "did:example:d"+intToStr(i+1))
	}

	_, err := builder.AssemblePathB(builder.AssemblePathBParams{
		DelegateDID:        "did:example:d4",
		TargetRoot:         rootPos,
		LeafReader:         store,
		Fetcher:            fetcher,
		CandidatePositions: candidates,
	})
	if !errors.Is(err, builder.ErrChainTooDeep) {
		t.Fatalf("expected ErrChainTooDeep, got: %v", err)
	}
}

func TestAssemblePathB_CycleDetected_Error(t *testing.T) {
	fetcher := NewMockFetcher()
	store := p6leafStore()

	rootPos := pos(1)
	rootEntry := buildTestEntry(t, envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     "did:example:owner",
		AuthorityPath: sameSigner(),
	}, nil)
	fetcher.Store(rootPos, rootEntry)

	d1 := pos(10)
	p6storeDelegation(t, fetcher, store, d1, "did:example:a", "did:example:b")
	d2 := pos(11)
	p6storeDelegation(t, fetcher, store, d2, "did:example:b", "did:example:a")

	_, err := builder.AssemblePathB(builder.AssemblePathBParams{
		DelegateDID:        "did:example:a",
		TargetRoot:         rootPos,
		LeafReader:         store,
		Fetcher:            fetcher,
		CandidatePositions: []types.LogPosition{d2, d1},
	})
	if !errors.Is(err, builder.ErrChainCycle) {
		t.Fatalf("expected ErrChainCycle, got: %v", err)
	}
}

func TestAssemblePathB_DeadDelegation_MarkedNotLive(t *testing.T) {
	fetcher := NewMockFetcher()
	store := p6leafStore()

	rootPos := pos(1)
	rootEntry := buildTestEntry(t, envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     "did:example:owner",
		AuthorityPath: sameSigner(),
	}, nil)
	fetcher.Store(rootPos, rootEntry)

	d1 := pos(10)
	delegEntry := buildTestEntry(t, envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     "did:example:owner",
		AuthorityPath: sameSigner(),
		DelegateDID:   ptrTo("did:example:delegate"),
	}, nil)
	fetcher.Store(d1, delegEntry)
	key := smt.DeriveKey(d1)
	store.Set(key, types.SMTLeaf{Key: key, OriginTip: pos(99), AuthorityTip: d1})

	assembly, err := builder.AssemblePathB(builder.AssemblePathBParams{
		DelegateDID:        "did:example:delegate",
		TargetRoot:         rootPos,
		LeafReader:         store,
		Fetcher:            fetcher,
		CandidatePositions: []types.LogPosition{d1},
	})
	if err != nil {
		t.Fatalf("AssemblePathB: %v", err)
	}
	if assembly.Hops[0].IsLive {
		t.Fatal("revoked delegation should be marked not live")
	}
}

func TestAssemblePathB_RootEntityNotFound_Error(t *testing.T) {
	fetcher := NewMockFetcher()
	store := p6leafStore()

	d1 := pos(10)
	p6storeDelegation(t, fetcher, store, d1, "did:example:owner", "did:example:delegate")

	_, err := builder.AssemblePathB(builder.AssemblePathBParams{
		DelegateDID:        "did:example:delegate",
		TargetRoot:         pos(1),
		LeafReader:         store,
		Fetcher:            fetcher,
		CandidatePositions: []types.LogPosition{d1},
	})
	if !errors.Is(err, builder.ErrRootNotFound) {
		t.Fatalf("expected ErrRootNotFound, got: %v", err)
	}
}

func TestValidateChainLiveness_FirstDeadLink(t *testing.T) {
	store := p6leafStore()

	livePos := pos(10)
	p6setLeaf(t, store, livePos)

	deadPos := pos(11)
	key := smt.DeriveKey(deadPos)
	store.Set(key, types.SMTLeaf{Key: key, OriginTip: pos(99), AuthorityTip: deadPos})

	result, err := builder.ValidateChainLiveness(builder.ValidateChainParams{
		DelegationPointers: []types.LogPosition{livePos, deadPos},
		LeafReader:         store,
	})
	if err != nil {
		t.Fatalf("ValidateChainLiveness: %v", err)
	}
	if result.AllLive {
		t.Fatal("should not be all live")
	}
	if result.FirstDead == nil || !result.FirstDead.Equal(deadPos) {
		t.Fatal("FirstDead should point to deadPos")
	}
}

// ═════════════════════════════════════════════════════════════════════
// 3. ClassifyEntry Tests (10 tests)
// ═════════════════════════════════════════════════════════════════════

func TestClassify_RootEntity_NewLeaf(t *testing.T) {
	entry := buildTestEntry(t, envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     "did:example:alice",
		AuthorityPath: sameSigner(),
	}, nil)
	store := p6leafStore()
	fetcher := NewMockFetcher()

	result, err := builder.ClassifyEntry(builder.ClassifyParams{
		Entry:       entry,
		Position:    pos(1),
		LeafReader:  store,
		Fetcher:     fetcher,
		LocalLogDID: testLogDID,
	})
	if err != nil {
		t.Fatalf("ClassifyEntry: %v", err)
	}
	if result.Path != builder.PathResultNewLeaf {
		t.Fatalf("expected NewLeaf, got %d", result.Path)
	}
}

func TestClassify_Amendment_PathA(t *testing.T) {
	store := p6leafStore()
	fetcher := NewMockFetcher()

	rootPos := pos(1)
	rootEntry := buildTestEntry(t, envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     "did:example:alice",
		AuthorityPath: sameSigner(),
	}, nil)
	fetcher.Store(rootPos, rootEntry)
	p6setLeaf(t, store, rootPos)

	amendment := buildTestEntry(t, envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     "did:example:alice",
		TargetRoot:    ptrTo(rootPos),
		AuthorityPath: sameSigner(),
	}, []byte("amended"))

	result, err := builder.ClassifyEntry(builder.ClassifyParams{
		Entry:       amendment,
		Position:    pos(2),
		LeafReader:  store,
		Fetcher:     fetcher,
		LocalLogDID: testLogDID,
	})
	if err != nil {
		t.Fatalf("ClassifyEntry: %v", err)
	}
	if result.Path != builder.PathResultPathA {
		t.Fatalf("expected PathA, got %d (%s)", result.Path, result.Reason)
	}
}

func TestClassify_DelegatedFiling_PathB(t *testing.T) {
	store := p6leafStore()
	fetcher := NewMockFetcher()

	rootPos := pos(1)
	rootEntry := buildTestEntry(t, envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     "did:example:owner",
		AuthorityPath: sameSigner(),
	}, nil)
	fetcher.Store(rootPos, rootEntry)
	p6setLeaf(t, store, rootPos)

	delegPos := pos(10)
	p6storeDelegation(t, fetcher, store, delegPos, "did:example:owner", "did:example:delegate")

	pathBEntry := buildTestEntry(t, envelope.ControlHeader{
		Destination:        testDestinationDID,
		SignerDID:          "did:example:delegate",
		TargetRoot:         ptrTo(rootPos),
		AuthorityPath:      delegation(),
		DelegationPointers: []types.LogPosition{delegPos},
	}, nil)

	result, err := builder.ClassifyEntry(builder.ClassifyParams{
		Entry:       pathBEntry,
		Position:    pos(20),
		LeafReader:  store,
		Fetcher:     fetcher,
		LocalLogDID: testLogDID,
	})
	if err != nil {
		t.Fatalf("ClassifyEntry: %v", err)
	}
	if result.Path != builder.PathResultPathB {
		t.Fatalf("expected PathB, got %d (%s)", result.Path, result.Reason)
	}
	if result.Details.DelegationDepth != 1 {
		t.Fatalf("DelegationDepth: %d", result.Details.DelegationDepth)
	}
}

func TestClassify_Enforcement_PathC(t *testing.T) {
	store := p6leafStore()
	fetcher := NewMockFetcher()

	entityPos := pos(1)
	entityEntry := buildTestEntry(t, envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     "did:example:entity",
		AuthorityPath: sameSigner(),
	}, nil)
	fetcher.Store(entityPos, entityEntry)
	p6setLeaf(t, store, entityPos)

	scopePos := pos(2)
	scopeEntry := buildTestEntry(t, envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     "did:example:judge",
		AuthorityPath: sameSigner(),
		AuthoritySet:  map[string]struct{}{"did:example:judge": {}},
	}, nil)
	fetcher.Store(scopePos, scopeEntry)
	p6setLeaf(t, store, scopePos)

	enforcement := buildTestEntry(t, envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     "did:example:judge",
		TargetRoot:    ptrTo(entityPos),
		AuthorityPath: scopeAuth(),
		ScopePointer:  ptrTo(scopePos),
	}, []byte("seal"))

	result, err := builder.ClassifyEntry(builder.ClassifyParams{
		Entry:       enforcement,
		Position:    pos(3),
		LeafReader:  store,
		Fetcher:     fetcher,
		LocalLogDID: testLogDID,
	})
	if err != nil {
		t.Fatalf("ClassifyEntry: %v", err)
	}
	if result.Path != builder.PathResultPathC {
		t.Fatalf("expected PathC, got %d (%s)", result.Path, result.Reason)
	}
}

func TestClassify_Commentary_ZeroImpact(t *testing.T) {
	entry := buildTestEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:   "did:example:witness",
	}, []byte("attestation"))

	result, err := builder.ClassifyEntry(builder.ClassifyParams{
		Entry:       entry,
		Position:    pos(1),
		LeafReader:  p6leafStore(),
		Fetcher:     NewMockFetcher(),
		LocalLogDID: testLogDID,
	})
	if err != nil {
		t.Fatalf("ClassifyEntry: %v", err)
	}
	if result.Path != builder.PathResultCommentary {
		t.Fatalf("expected Commentary, got %d", result.Path)
	}
	if !result.Details.IsCommentary {
		t.Fatal("IsCommentary should be true")
	}
}

func TestClassify_ForeignTarget_PathD(t *testing.T) {
	entry := buildTestEntry(t, envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     "did:example:alice",
		TargetRoot:    ptrTo(foreignPos(1)),
		AuthorityPath: sameSigner(),
	}, nil)

	result, _ := builder.ClassifyEntry(builder.ClassifyParams{
		Entry:       entry,
		Position:    pos(1),
		LeafReader:  p6leafStore(),
		Fetcher:     NewMockFetcher(),
		LocalLogDID: testLogDID,
	})
	if result.Path != builder.PathResultPathD {
		t.Fatalf("expected PathD for foreign target, got %d", result.Path)
	}
}

func TestClassify_RevokedDelegation_PathD(t *testing.T) {
	store := p6leafStore()
	fetcher := NewMockFetcher()

	rootPos := pos(1)
	rootEntry := buildTestEntry(t, envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     "did:example:owner",
		AuthorityPath: sameSigner(),
	}, nil)
	fetcher.Store(rootPos, rootEntry)
	p6setLeaf(t, store, rootPos)

	delegPos := pos(10)
	delegEntry := buildTestEntry(t, envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     "did:example:owner",
		AuthorityPath: sameSigner(),
		DelegateDID:   ptrTo("did:example:delegate"),
	}, nil)
	fetcher.Store(delegPos, delegEntry)
	key := smt.DeriveKey(delegPos)
	store.Set(key, types.SMTLeaf{Key: key, OriginTip: pos(99), AuthorityTip: delegPos})

	pathBEntry := buildTestEntry(t, envelope.ControlHeader{
		Destination:        testDestinationDID,
		SignerDID:          "did:example:delegate",
		TargetRoot:         ptrTo(rootPos),
		AuthorityPath:      delegation(),
		DelegationPointers: []types.LogPosition{delegPos},
	}, nil)

	result, _ := builder.ClassifyEntry(builder.ClassifyParams{
		Entry:       pathBEntry,
		Position:    pos(20),
		LeafReader:  store,
		Fetcher:     fetcher,
		LocalLogDID: testLogDID,
	})
	if result.Path != builder.PathResultPathD {
		t.Fatalf("revoked delegation should classify as PathD, got %d (%s)", result.Path, result.Reason)
	}
}

func TestClassify_EvidenceCapExceeded_Error(t *testing.T) {
	store := p6leafStore()
	fetcher := NewMockFetcher()

	rootPos := pos(1)
	rootEntry := buildTestEntry(t, envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     "did:example:alice",
		AuthorityPath: sameSigner(),
	}, nil)
	fetcher.Store(rootPos, rootEntry)
	p6setLeaf(t, store, rootPos)

	// Construct an entry that exceeds the evidence cap without the
	// authority-snapshot shape exemption. MaxEvidencePointers+1 pointers
	// on a Path A entry (SameSigner, no PriorAuthority) must be rejected.
	pointers := make([]types.LogPosition, envelope.MaxEvidencePointers+1)
	for i := range pointers {
		pointers[i] = pos(uint64(100 + i))
	}
	ap := envelope.AuthoritySameSigner
	entry := &envelope.Entry{
		Header: envelope.ControlHeader{
			Destination:      testDestinationDID,
			ProtocolVersion:  5,
			SignerDID:        "did:example:alice",
			TargetRoot:       ptrTo(rootPos),
			AuthorityPath:    &ap,
			EvidencePointers: pointers,
		},
	}

	result, _ := builder.ClassifyEntry(builder.ClassifyParams{
		Entry:       entry,
		Position:    pos(2),
		LeafReader:  store,
		Fetcher:     fetcher,
		LocalLogDID: testLogDID,
	})
	if result.Path != builder.PathResultRejected {
		t.Fatalf("expected Rejected for evidence cap (%d pointers), got %d (%s)",
			len(pointers), result.Path, result.Reason)
	}
}

func TestClassify_SnapshotExempt_PathC(t *testing.T) {
	store := p6leafStore()
	fetcher := NewMockFetcher()

	entityPos := pos(1)
	entityEntry := buildTestEntry(t, envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     "did:example:entity",
		AuthorityPath: sameSigner(),
	}, nil)
	fetcher.Store(entityPos, entityEntry)
	enfPos := pos(5)
	key := smt.DeriveKey(entityPos)
	store.Set(key, types.SMTLeaf{Key: key, OriginTip: entityPos, AuthorityTip: enfPos})

	scopePos := pos(2)
	scopeEntry := buildTestEntry(t, envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     "did:example:judge",
		AuthorityPath: sameSigner(),
		AuthoritySet:  map[string]struct{}{"did:example:judge": {}},
	}, nil)
	fetcher.Store(scopePos, scopeEntry)
	p6setLeaf(t, store, scopePos)

	pointers := make([]types.LogPosition, 11)
	for i := range pointers {
		pointers[i] = pos(uint64(100 + i))
	}
	snapshot := buildTestEntry(t, envelope.ControlHeader{
		Destination:      testDestinationDID,
		SignerDID:        "did:example:judge",
		TargetRoot:       ptrTo(entityPos),
		AuthorityPath:    scopeAuth(),
		ScopePointer:     ptrTo(scopePos),
		PriorAuthority:   ptrTo(enfPos),
		EvidencePointers: pointers,
	}, nil)

	result, _ := builder.ClassifyEntry(builder.ClassifyParams{
		Entry:       snapshot,
		Position:    pos(3),
		LeafReader:  store,
		Fetcher:     fetcher,
		LocalLogDID: testLogDID,
	})
	if result.Path != builder.PathResultPathC {
		t.Fatalf("snapshot should be exempt from evidence cap, got %d (%s)", result.Path, result.Reason)
	}
}

func TestClassifyBatch_MixedPaths(t *testing.T) {
	store := p6leafStore()
	fetcher := NewMockFetcher()

	rootPos := pos(1)
	rootEntry := buildTestEntry(t, envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     "did:example:alice",
		AuthorityPath: sameSigner(),
	}, nil)
	fetcher.Store(rootPos, rootEntry)
	p6setLeaf(t, store, rootPos)

	commentary := buildTestEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:   "did:example:witness",
	}, nil)
	amendment := buildTestEntry(t, envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     "did:example:alice",
		TargetRoot:    ptrTo(rootPos),
		AuthorityPath: sameSigner(),
	}, nil)
	foreign := buildTestEntry(t, envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     "did:example:bob",
		TargetRoot:    ptrTo(foreignPos(99)),
		AuthorityPath: sameSigner(),
	}, nil)

	entries := []*envelope.Entry{commentary, amendment, foreign}
	positions := []types.LogPosition{pos(10), pos(11), pos(12)}

	results, err := builder.ClassifyBatch(entries, positions, store, fetcher, nil, testLogDID)
	if err != nil {
		t.Fatalf("ClassifyBatch: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	if results[0].Path != builder.PathResultCommentary {
		t.Fatalf("results[0]: expected Commentary, got %d", results[0].Path)
	}
	if results[1].Path != builder.PathResultPathA {
		t.Fatalf("results[1]: expected PathA, got %d", results[1].Path)
	}
	if results[2].Path != builder.PathResultPathD {
		t.Fatalf("results[2]: expected PathD, got %d", results[2].Path)
	}
}

// ═════════════════════════════════════════════════════════════════════
// 4. Delegation Key Tests (4 tests)
// ═════════════════════════════════════════════════════════════════════

func TestDelegationKey_GenerateUnwrapRoundTrip(t *testing.T) {
	// Generate owner master key
	ownerPriv, _ := signatures.GenerateKey()
	ownerPubBytes := signatures.PubKeyBytes(&ownerPriv.PublicKey)
	ownerSecretBytes := padSecretKeyTo32(ownerPriv.D.Bytes())

	// Generate delegation key
	pkDel, wrappedSkDel, err := lifecycle.GenerateDelegationKey(ownerPubBytes)
	if err != nil {
		t.Fatalf("GenerateDelegationKey: %v", err)
	}

	// Unwrap
	skDel, err := lifecycle.UnwrapDelegationKey(wrappedSkDel, ownerSecretBytes)
	if err != nil {
		t.Fatalf("UnwrapDelegationKey: %v", err)
	}

	// Verify unwrapped scalar produces the same public key
	c := signatures.Secp256k1()
	x, y := c.ScalarBaseMult(skDel)
	expectedPkDel := elliptic.Marshal(c, x, y)

	if !bytes.Equal(pkDel, expectedPkDel) {
		t.Fatal("unwrapped sk_del does not match original pk_del")
	}
}

func TestDelegationKey_WrongMasterKey_FailsUnwrap(t *testing.T) {
	ownerA, _ := signatures.GenerateKey()
	ownerB, _ := signatures.GenerateKey()

	ownerAPubBytes := signatures.PubKeyBytes(&ownerA.PublicKey)
	ownerBSecretBytes := padSecretKeyTo32(ownerB.D.Bytes())

	_, wrappedSkDel, err := lifecycle.GenerateDelegationKey(ownerAPubBytes)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	_, err = lifecycle.UnwrapDelegationKey(wrappedSkDel, ownerBSecretBytes)
	if err == nil {
		t.Fatal("UnwrapDelegationKey should fail with wrong master key")
	}
}

func TestDelegationKey_GrantWithDelegationKey_Works(t *testing.T) {
	// Owner setup
	ownerPriv, _ := signatures.GenerateKey()
	ownerPubBytes := signatures.PubKeyBytes(&ownerPriv.PublicKey)
	ownerSecretBytes := padSecretKeyTo32(ownerPriv.D.Bytes())

	// Recipient setup
	recipientPriv, _ := signatures.GenerateKey()
	recipientPubBytes := signatures.PubKeyBytes(&recipientPriv.PublicKey)
	recipientSecretBytes := padSecretKeyTo32(recipientPriv.D.Bytes())

	plaintext := []byte("delegated PRE artifact content")

	// 1. Generate Delegation Key
	pkDel, wrappedSkDel, err := lifecycle.GenerateDelegationKey(ownerPubBytes)
	if err != nil {
		t.Fatalf("GenerateDelegationKey: %v", err)
	}

	// 2. Encrypt artifact using pkDel (NOT ownerPubBytes)
	capsule, ciphertext, err := artifact.PRE_Encrypt(pkDel, plaintext)
	if err != nil {
		t.Fatalf("PRE_Encrypt: %v", err)
	}

	// 3. Grant: Unwrap skDel using Master Key
	skDel, err := lifecycle.UnwrapDelegationKey(wrappedSkDel, ownerSecretBytes)
	if err != nil {
		t.Fatalf("UnwrapDelegationKey: %v", err)
	}

	// 4. Generate KFrags using skDel (no ephPub — rejected proposal)
	kfrags, err := artifact.PRE_GenerateKFrags(skDel, recipientPubBytes, 3, 5)
	if err != nil {
		t.Fatalf("PRE_GenerateKFrags: %v", err)
	}

	// 5. Re-Encrypt (simulated Escrow Nodes)
	cfrags := make([]*artifact.CFrag, 3)
	for i := 0; i < 3; i++ {
		cfrags[i], err = artifact.PRE_ReEncrypt(kfrags[i], capsule)
		if err != nil {
			t.Fatalf("PRE_ReEncrypt: %v", err)
		}
	}

	// 6. Decrypt (Recipient side — no ephPub parameter)
	recovered, err := artifact.PRE_DecryptFrags(recipientSecretBytes, cfrags, capsule, ciphertext, pkDel)
	if err != nil {
		t.Fatalf("PRE_DecryptFrags: %v", err)
	}

	if !bytes.Equal(recovered, plaintext) {
		t.Fatal("recovered plaintext does not match original")
	}
}

func TestDelegationKey_ExtractedKeyCannotSignEntries(t *testing.T) {
	// Shows that the extracted key (skDel) is mathematically different from the master key.
	ownerPriv, _ := signatures.GenerateKey()
	ownerPubBytes := signatures.PubKeyBytes(&ownerPriv.PublicKey)
	ownerSecretBytes := padSecretKeyTo32(ownerPriv.D.Bytes())

	_, wrappedSkDel, _ := lifecycle.GenerateDelegationKey(ownerPubBytes)
	skDel, _ := lifecycle.UnwrapDelegationKey(wrappedSkDel, ownerSecretBytes)

	if bytes.Equal(skDel, ownerSecretBytes) {
		t.Fatal("CRITICAL: Delegation key is identical to Master Identity Key!")
	}
}
