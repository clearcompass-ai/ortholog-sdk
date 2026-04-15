/*
FILE PATH: tests/phase6_part_a_test.go

Phase 6 Part A: 35 tests covering:
  - Entry builders (18 tests): one per builder + constraint violations
  - AssemblePathB (7 tests): chain depth, cycles, liveness, disconnection
  - ClassifyEntry (10 tests): each path + edge cases

All tests use in-memory infrastructure. No Postgres required.
*/
package tests

import (
	"errors"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ═════════════════════════════════════════════════════════════════════
// Phase 6A helpers
// ═════════════════════════════════════════════════════════════════════

// p6leafStore creates an InMemoryLeafStore that satisfies smt.LeafReader.
func p6leafStore() *smt.InMemoryLeafStore { return smt.NewInMemoryLeafStore() }

// p6setLeaf sets a leaf with OriginTip=pos, AuthorityTip=pos.
func p6setLeaf(t *testing.T, store *smt.InMemoryLeafStore, p types.LogPosition) {
	t.Helper()
	key := smt.DeriveKey(p)
	if err := store.Set(key, types.SMTLeaf{Key: key, OriginTip: p, AuthorityTip: p}); err != nil {
		t.Fatal(err)
	}
}

// p6storeDelegation stores a delegation entry and creates its live leaf.
func p6storeDelegation(t *testing.T, fetcher *MockFetcher, store *smt.InMemoryLeafStore, p types.LogPosition, signerDID, delegateDID string) {
	t.Helper()
	entry, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:     signerDID,
		AuthorityPath: sameSigner(),
		DelegateDID:   &delegateDID,
	}, nil)
	fetcher.Store(p, entry)
	p6setLeaf(t, store, p)
}

// ═════════════════════════════════════════════════════════════════════
// 1. Entry Builder Tests (18 tests)
// ═════════════════════════════════════════════════════════════════════

func TestBuild_RootEntity_Valid(t *testing.T) {
	entry, err := builder.BuildRootEntity(builder.RootEntityParams{
		SignerDID: "did:example:alice",
		Payload:   []byte("entity-data"),
		EventTime: 1700000000,
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
	_, err := builder.BuildRootEntity(builder.RootEntityParams{Payload: []byte("x")})
	if !errors.Is(err, builder.ErrEmptySignerDID) {
		t.Fatalf("expected ErrEmptySignerDID, got: %v", err)
	}
}

func TestBuild_Amendment_Valid(t *testing.T) {
	target := pos(1)
	entry, err := builder.BuildAmendment(builder.AmendmentParams{
		SignerDID:  "did:example:alice",
		TargetRoot: target,
		Payload:    []byte("amended"),
		EventTime:  1700000001,
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
		SignerDID: "did:example:alice",
	})
	if !errors.Is(err, builder.ErrMissingTargetRoot) {
		t.Fatalf("expected ErrMissingTargetRoot, got: %v", err)
	}
}

func TestBuild_Delegation_Valid(t *testing.T) {
	entry, err := builder.BuildDelegation(builder.DelegationParams{
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
		SignerDID: "did:example:owner",
	})
	if !errors.Is(err, builder.ErrMissingDelegateDID) {
		t.Fatalf("expected ErrMissingDelegateDID, got: %v", err)
	}
}

func TestBuild_Succession_Valid(t *testing.T) {
	entry, err := builder.BuildSuccession(builder.SuccessionParams{
		SignerDID:  "did:example:alice",
		TargetRoot: pos(1),
		Payload:    []byte("succession"),
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
		SignerDID:  "did:example:judge",
		TargetRoot: pos(1),
	})
	if !errors.Is(err, builder.ErrMissingScopePointer) {
		t.Fatalf("expected ErrMissingScopePointer, got: %v", err)
	}
}

func TestBuild_ScopeCreation_Valid(t *testing.T) {
	entry, err := builder.BuildScopeCreation(builder.ScopeCreationParams{
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
		SignerDID: "did:example:witness",
		Payload:   []byte("attestation"),
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
		SignerDID: "did:example:cosigner",
	})
	if !errors.Is(err, builder.ErrMissingCosignatureOf) {
		t.Fatalf("expected ErrMissingCosignatureOf, got: %v", err)
	}
}

func TestBuild_KeyRotation_Valid(t *testing.T) {
	entry, err := builder.BuildKeyRotation(builder.KeyRotationParams{
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

// ═════════════════════════════════════════════════════════════════════
// 2. AssemblePathB Tests (7 tests)
// ═════════════════════════════════════════════════════════════════════

func TestAssemblePathB_ThreeDeep_Valid(t *testing.T) {
	fetcher := NewMockFetcher()
	store := p6leafStore()

	// Root entity at pos(1), signer=owner.
	rootPos := pos(1)
	rootEntry, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:     "did:example:owner",
		AuthorityPath: sameSigner(),
	}, nil)
	fetcher.Store(rootPos, rootEntry)
	p6setLeaf(t, store, rootPos)

	// owner → mid → leaf chain.
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
	// First hop should be from deputy (DelegateDID=deputy).
	if assembly.Hops[0].DelegateDID != "did:example:deputy" {
		t.Fatalf("hop[0] delegate: %s", assembly.Hops[0].DelegateDID)
	}
	// Last hop should be signed by owner (connects to root).
	if assembly.Hops[2].SignerDID != "did:example:owner" {
		t.Fatalf("hop[2] signer: %s", assembly.Hops[2].SignerDID)
	}
}

func TestAssemblePathB_SingleHop_Valid(t *testing.T) {
	fetcher := NewMockFetcher()
	store := p6leafStore()

	rootPos := pos(1)
	rootEntry, _ := makeEntry(t, envelope.ControlHeader{
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
	rootEntry, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:     "did:example:owner",
		AuthorityPath: sameSigner(),
	}, nil)
	fetcher.Store(rootPos, rootEntry)

	// Create 4 delegations (exceeds MaxDelegationPointers=3).
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
	rootEntry, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:     "did:example:owner",
		AuthorityPath: sameSigner(),
	}, nil)
	fetcher.Store(rootPos, rootEntry)

	// A delegates to B, B delegates to A → cycle.
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

func TestAssemblePathB_DeadDelegation_Error(t *testing.T) {
	fetcher := NewMockFetcher()
	store := p6leafStore()

	rootPos := pos(1)
	rootEntry, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:     "did:example:owner",
		AuthorityPath: sameSigner(),
	}, nil)
	fetcher.Store(rootPos, rootEntry)

	// Delegation entry exists but leaf OriginTip advanced (revoked).
	d1 := pos(10)
	delegEntry, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:     "did:example:owner",
		AuthorityPath: sameSigner(),
		DelegateDID:   ptrTo("did:example:delegate"),
	}, nil)
	fetcher.Store(d1, delegEntry)
	// Set leaf with OriginTip != d1 (simulates revocation).
	key := smt.DeriveKey(d1)
	store.Set(key, types.SMTLeaf{Key: key, OriginTip: pos(99), AuthorityTip: d1})

	// AssemblePathB should still succeed (it marks liveness but doesn't reject).
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

	// No root entity stored at pos(1).
	d1 := pos(10)
	p6storeDelegation(t, fetcher, store, d1, "did:example:owner", "did:example:delegate")

	_, err := builder.AssemblePathB(builder.AssemblePathBParams{
		DelegateDID:        "did:example:delegate",
		TargetRoot:         pos(1), // Not stored.
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

	// Live delegation.
	livePos := pos(10)
	p6setLeaf(t, store, livePos)

	// Dead delegation (OriginTip advanced).
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
	entry, _ := makeEntry(t, envelope.ControlHeader{
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

	// Create root entity.
	rootPos := pos(1)
	rootEntry, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:     "did:example:alice",
		AuthorityPath: sameSigner(),
	}, nil)
	fetcher.Store(rootPos, rootEntry)
	p6setLeaf(t, store, rootPos)

	// Amendment by same signer.
	amendment, _ := makeEntry(t, envelope.ControlHeader{
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

	// Root entity.
	rootPos := pos(1)
	rootEntry, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:     "did:example:owner",
		AuthorityPath: sameSigner(),
	}, nil)
	fetcher.Store(rootPos, rootEntry)
	p6setLeaf(t, store, rootPos)

	// Live delegation: owner → delegate.
	delegPos := pos(10)
	p6storeDelegation(t, fetcher, store, delegPos, "did:example:owner", "did:example:delegate")

	// Path B entry by delegate.
	pathBEntry, _ := makeEntry(t, envelope.ControlHeader{
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

	// Entity.
	entityPos := pos(1)
	entityEntry, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:     "did:example:entity",
		AuthorityPath: sameSigner(),
	}, nil)
	fetcher.Store(entityPos, entityEntry)
	p6setLeaf(t, store, entityPos)

	// Scope with authority set containing the judge.
	scopePos := pos(2)
	scopeEntry, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:     "did:example:judge",
		AuthorityPath: sameSigner(),
		AuthoritySet:  map[string]struct{}{"did:example:judge": {}},
	}, nil)
	fetcher.Store(scopePos, scopeEntry)
	p6setLeaf(t, store, scopePos)

	// Enforcement entry.
	enforcement, _ := makeEntry(t, envelope.ControlHeader{
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
	entry, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID: "did:example:witness",
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
	entry, _ := makeEntry(t, envelope.ControlHeader{
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

	// Root entity.
	rootPos := pos(1)
	rootEntry, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:     "did:example:owner",
		AuthorityPath: sameSigner(),
	}, nil)
	fetcher.Store(rootPos, rootEntry)
	p6setLeaf(t, store, rootPos)

	// Delegation entry exists but leaf OriginTip advanced (revoked).
	delegPos := pos(10)
	delegEntry, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:     "did:example:owner",
		AuthorityPath: sameSigner(),
		DelegateDID:   ptrTo("did:example:delegate"),
	}, nil)
	fetcher.Store(delegPos, delegEntry)
	key := smt.DeriveKey(delegPos)
	store.Set(key, types.SMTLeaf{Key: key, OriginTip: pos(99), AuthorityTip: delegPos})

	// Try to use the revoked delegation.
	pathBEntry, _ := makeEntry(t, envelope.ControlHeader{
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
	rootEntry, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:     "did:example:alice",
		AuthorityPath: sameSigner(),
	}, nil)
	fetcher.Store(rootPos, rootEntry)
	p6setLeaf(t, store, rootPos)

	// 11 evidence pointers on a non-snapshot entry → rejected.
	// Construct Entry directly — NewEntry itself rejects >10 on non-snapshot.
	pointers := make([]types.LogPosition, 11)
	for i := range pointers {
		pointers[i] = pos(uint64(100 + i))
	}
	ap := envelope.AuthoritySameSigner
	entry := &envelope.Entry{
		Header: envelope.ControlHeader{
			ProtocolVersion:  3,
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
		t.Fatalf("expected Rejected for evidence cap, got %d (%s)", result.Path, result.Reason)
	}
}

func TestClassify_SnapshotExempt_PathC(t *testing.T) {
	store := p6leafStore()
	fetcher := NewMockFetcher()

	entityPos := pos(1)
	entityEntry, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:     "did:example:entity",
		AuthorityPath: sameSigner(),
	}, nil)
	fetcher.Store(entityPos, entityEntry)
	// Entity with enforcement history: AuthorityTip advanced to enfPos.
	enfPos := pos(5)
	key := smt.DeriveKey(entityPos)
	store.Set(key, types.SMTLeaf{Key: key, OriginTip: entityPos, AuthorityTip: enfPos})

	scopePos := pos(2)
	scopeEntry, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:     "did:example:judge",
		AuthorityPath: sameSigner(),
		AuthoritySet:  map[string]struct{}{"did:example:judge": {}},
	}, nil)
	fetcher.Store(scopePos, scopeEntry)
	p6setLeaf(t, store, scopePos)

	// Authority snapshot: >10 evidence + ScopeAuthority + TargetRoot + PriorAuthority.
	// PriorAuthority must match current AuthorityTip (enfPos) for OCC to pass.
	pointers := make([]types.LogPosition, 11)
	for i := range pointers {
		pointers[i] = pos(uint64(100 + i))
	}
	snapshot, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:        "did:example:judge",
		TargetRoot:       ptrTo(entityPos),
		AuthorityPath:    scopeAuth(),
		ScopePointer:     ptrTo(scopePos),
		PriorAuthority:   ptrTo(enfPos), // Matches current AuthorityTip.
		EvidencePointers: pointers,
	}, nil)

	result, _ := builder.ClassifyEntry(builder.ClassifyParams{
		Entry:       snapshot,
		Position:    pos(3),
		LeafReader:  store,
		Fetcher:     fetcher,
		LocalLogDID: testLogDID,
	})
	// Snapshot entries are exempt from evidence cap → should pass through to Path C.
	if result.Path != builder.PathResultPathC {
		t.Fatalf("snapshot should be exempt from evidence cap, got %d (%s)", result.Path, result.Reason)
	}
}

func TestClassifyBatch_MixedPaths(t *testing.T) {
	store := p6leafStore()
	fetcher := NewMockFetcher()

	// Root entity.
	rootPos := pos(1)
	rootEntry, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:     "did:example:alice",
		AuthorityPath: sameSigner(),
	}, nil)
	fetcher.Store(rootPos, rootEntry)
	p6setLeaf(t, store, rootPos)

	// Three entries: commentary, amendment (Path A), foreign target (Path D).
	commentary, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID: "did:example:witness",
	}, nil)
	amendment, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:     "did:example:alice",
		TargetRoot:    ptrTo(rootPos),
		AuthorityPath: sameSigner(),
	}, nil)
	foreign, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:     "did:example:bob",
		TargetRoot:    ptrTo(foreignPos(99)),
		AuthorityPath: sameSigner(),
	}, nil)

	entries := []*envelope.Entry{commentary, amendment, foreign}
	positions := []types.LogPosition{pos(10), pos(11), pos(12)}

	results, err := builder.ClassifyBatch(entries, positions, store, fetcher, testLogDID)
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
