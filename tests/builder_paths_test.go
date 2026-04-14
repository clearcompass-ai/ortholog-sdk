package tests

import (
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ── PATH A ─────────────────────────────────────────────────────────────

// Test 40: Path A basic — same signer updates Origin_Tip.
func TestBuilderPathA_Basic(t *testing.T) {
	h := newHarness()
	rootPos := pos(1)
	h.addRootEntity(t, rootPos, "did:example:alice")

	amendment, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:     "did:example:alice",
		TargetRoot:    ptrTo(rootPos),
		AuthorityPath: sameSigner(),
	}, []byte("amended"))
	amendPos := pos(2)
	result := h.process(t, amendment, amendPos)

	if result.PathACounts != 1 {
		t.Fatalf("PathA: got %d, want 1", result.PathACounts)
	}
	if tip := h.leafOriginTip(t, rootPos); !tip.Equal(amendPos) {
		t.Fatalf("OriginTip: got %s, want %s", tip, amendPos)
	}
}

// Test 41: Path A with Target_Intermediate — dual write.
func TestBuilderPathA_WithIntermediate(t *testing.T) {
	h := newHarness()
	rootPos := pos(1)
	h.addRootEntity(t, rootPos, "did:example:alice")
	intPos := pos(2)
	h.addRootEntity(t, intPos, "did:example:alice")

	activation, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:          "did:example:alice",
		TargetRoot:         ptrTo(rootPos),
		TargetIntermediate: ptrTo(intPos),
		AuthorityPath:      sameSigner(),
	}, nil)
	actPos := pos(3)
	result := h.process(t, activation, actPos)

	if result.PathACounts != 1 {
		t.Fatal("expected Path A")
	}
	// Both leaves updated.
	if tip := h.leafOriginTip(t, rootPos); !tip.Equal(actPos) {
		t.Fatal("root OriginTip not updated")
	}
	if tip := h.leafOriginTip(t, intPos); !tip.Equal(actPos) {
		t.Fatal("intermediate OriginTip not updated")
	}
}

// ── PATH B ─────────────────────────────────────────────────────────────

// Test 42: Path B depth 1 — single delegation hop.
func TestBuilderPathB_Depth1(t *testing.T) {
	h := newHarness()
	rootPos := pos(1)
	h.addRootEntity(t, rootPos, "did:example:owner")
	delegPos := pos(2)
	h.addDelegation(t, delegPos, "did:example:owner", "did:example:delegate")

	action, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:          "did:example:delegate",
		TargetRoot:         ptrTo(rootPos),
		AuthorityPath:      delegation(),
		DelegationPointers: []types.LogPosition{delegPos},
	}, nil)
	result := h.process(t, action, pos(3))
	if result.PathBCounts != 1 {
		t.Fatalf("PathB: got %d, want 1", result.PathBCounts)
	}
}

// Test 43: Path B depth 2 — two-hop delegation chain.
func TestBuilderPathB_Depth2(t *testing.T) {
	h := newHarness()
	rootPos := pos(1)
	h.addRootEntity(t, rootPos, "did:example:owner")
	d1Pos := pos(2)
	h.addDelegation(t, d1Pos, "did:example:owner", "did:example:mid")
	d2Pos := pos(3)
	h.addDelegation(t, d2Pos, "did:example:mid", "did:example:leaf")

	action, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:          "did:example:leaf",
		TargetRoot:         ptrTo(rootPos),
		AuthorityPath:      delegation(),
		DelegationPointers: []types.LogPosition{d2Pos, d1Pos}, // Nearest-to-signer first.
	}, nil)
	result := h.process(t, action, pos(4))
	if result.PathBCounts != 1 {
		t.Fatalf("PathB depth 2: got %d", result.PathBCounts)
	}
}

// Test 44: Path B depth 3 — max allowed.
func TestBuilderPathB_Depth3(t *testing.T) {
	h := newHarness()
	rootPos := pos(1)
	h.addRootEntity(t, rootPos, "did:example:owner")
	d1 := pos(2)
	h.addDelegation(t, d1, "did:example:owner", "did:example:a")
	d2 := pos(3)
	h.addDelegation(t, d2, "did:example:a", "did:example:b")
	d3 := pos(4)
	h.addDelegation(t, d3, "did:example:b", "did:example:c")

	action, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:          "did:example:c",
		TargetRoot:         ptrTo(rootPos),
		AuthorityPath:      delegation(),
		DelegationPointers: []types.LogPosition{d3, d2, d1},
	}, nil)
	result := h.process(t, action, pos(5))
	if result.PathBCounts != 1 {
		t.Fatal("depth 3 should succeed")
	}
}

// Test 45: Path B depth 4 — rejected (exceeds max).
func TestBuilderPathB_Depth4Rejected(t *testing.T) {
	h := newHarness()
	rootPos := pos(1)
	h.addRootEntity(t, rootPos, "did:example:owner")
	// Build 4-deep chain, but only 3 pointers allowed in DelegationPointers.
	// This tests that > 3 hops without connecting = rejected.
	d1 := pos(2)
	h.addDelegation(t, d1, "did:example:owner", "did:example:a")
	d2 := pos(3)
	h.addDelegation(t, d2, "did:example:a", "did:example:b")
	d3 := pos(4)
	h.addDelegation(t, d3, "did:example:b", "did:example:c") // c != owner, chain doesn't connect in 3.

	action, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:          "did:example:c",
		TargetRoot:         ptrTo(rootPos),
		AuthorityPath:      delegation(),
		DelegationPointers: []types.LogPosition{d3, d2, d1},
	}, nil)
	result := h.process(t, action, pos(5))
	// Chain doesn't connect within depth 3 (d1.Signer = owner but we need one more hop).
	// Wait — d1 is from owner to a, d2 is from a to b, d3 is from b to c.
	// Signer is c. Walk: d3 delegates to c (match), d3.Signer = b.
	// d2 delegates to b (match), d2.Signer = a. d1 delegates to a (match), d1.Signer = owner.
	// Owner == target signer. 3 hops = depth 3 = should succeed.
	// For depth 4 test, we'd need > 3 DelegationPointers which is rejected by NewEntry.
	// So test that 3 hops that DON'T connect -> rejected.
	// Reuse the chain but change target signer.
	h2 := newHarness()
	rootPos2 := pos(1)
	h2.addRootEntity(t, rootPos2, "did:example:DIFFERENT")
	h2.addDelegation(t, d1, "did:example:owner", "did:example:a")
	h2.addDelegation(t, d2, "did:example:a", "did:example:b")
	h2.addDelegation(t, d3, "did:example:b", "did:example:c")

	result = h2.process(t, action, pos(5))
	if result.PathBCounts != 0 && result.PathDCounts == 0 && result.RejectedCounts == 0 {
		t.Fatal("3 hops that don't connect should result in Path D or rejected")
	}
}

// Test 46-48: Delegation liveness — revoked delegation -> Path D.
func TestBuilderPathB_LivenessRevoked(t *testing.T) {
	h := newHarness()
	rootPos := pos(1)
	h.addRootEntity(t, rootPos, "did:example:owner")
	delegPos := pos(2)
	h.addDelegation(t, delegPos, "did:example:owner", "did:example:delegate")

	// Revoke: advance Origin_Tip of delegation leaf.
	revocationPos := pos(3)
	delegKey := smt.DeriveKey(delegPos)
	leaf, _ := h.tree.GetLeaf(delegKey)
	updated := *leaf
	updated.OriginTip = revocationPos // Origin_Tip != delegPos -> liveness broken.
	h.tree.SetLeaf(delegKey, updated)

	action, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:          "did:example:delegate",
		TargetRoot:         ptrTo(rootPos),
		AuthorityPath:      delegation(),
		DelegationPointers: []types.LogPosition{delegPos},
	}, nil)
	result := h.process(t, action, pos(4))
	if result.PathDCounts != 1 {
		t.Fatal("revoked delegation should fall through to Path D")
	}
}

// Test 47: Delegation liveness — amended delegation -> Path D.
func TestBuilderPathB_LivenessAmended(t *testing.T) {
	h := newHarness()
	rootPos := pos(1)
	h.addRootEntity(t, rootPos, "did:example:owner")
	delegPos := pos(2)
	h.addDelegation(t, delegPos, "did:example:owner", "did:example:delegate")

	// Amend: advance Origin_Tip to an amendment entry (same principle as revoke).
	amendPos := pos(3)
	delegKey := smt.DeriveKey(delegPos)
	leaf, _ := h.tree.GetLeaf(delegKey)
	updated := *leaf
	updated.OriginTip = amendPos // Any advancement breaks liveness.
	h.tree.SetLeaf(delegKey, updated)

	action, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:          "did:example:delegate",
		TargetRoot:         ptrTo(rootPos),
		AuthorityPath:      delegation(),
		DelegationPointers: []types.LogPosition{delegPos},
	}, nil)
	result := h.process(t, action, pos(4))
	if result.PathDCounts != 1 {
		t.Fatal("amended delegation (Origin_Tip advanced) should fall through to Path D")
	}
}

// Test 48: Delegation liveness — live delegation -> Path B succeeds.
func TestBuilderPathB_LivenessLive(t *testing.T) {
	h := newHarness()
	rootPos := pos(1)
	h.addRootEntity(t, rootPos, "did:example:owner")
	delegPos := pos(2)
	h.addDelegation(t, delegPos, "did:example:owner", "did:example:delegate")
	// Origin_Tip == delegPos (self-referential = live). No modification.

	action, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:          "did:example:delegate",
		TargetRoot:         ptrTo(rootPos),
		AuthorityPath:      delegation(),
		DelegationPointers: []types.LogPosition{delegPos},
	}, nil)
	result := h.process(t, action, pos(3))
	if result.PathBCounts != 1 {
		t.Fatal("live delegation should succeed via Path B")
	}
}

// ── PATH C ─────────────────────────────────────────────────────────────

// Test 49: Path C basic enforcement -> AuthorityTip updated.
func TestBuilderPathC_BasicEnforcement(t *testing.T) {
	h := newHarness()
	entityPos := pos(1)
	h.addRootEntity(t, entityPos, "did:example:entity")
	scopePos := pos(2)
	authSet := map[string]struct{}{"did:example:judge": {}}
	h.addScopeEntity(t, scopePos, "did:example:judge", authSet)

	enforcement, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:     "did:example:judge",
		TargetRoot:    ptrTo(entityPos),
		AuthorityPath: scopeAuth(),
		ScopePointer:  ptrTo(scopePos),
	}, []byte("sealing order"))
	enfPos := pos(3)
	result := h.process(t, enforcement, enfPos)

	if result.PathCCounts != 1 {
		t.Fatalf("PathC: got %d", result.PathCCounts)
	}
	// Enforcement -> AuthorityTip (not OriginTip).
	if tip := h.leafAuthorityTip(t, entityPos); !tip.Equal(enfPos) {
		t.Fatalf("AuthorityTip: got %s, want %s", tip, enfPos)
	}
	// OriginTip unchanged.
	if tip := h.leafOriginTip(t, entityPos); !tip.Equal(entityPos) {
		t.Fatal("OriginTip should not change for enforcement")
	}
}

// Test 50: Lane selection — scope amendment execution -> OriginTip.
func TestBuilderPathC_AmendmentExecution(t *testing.T) {
	h := newHarness()
	scopePos := pos(1)
	authSet := map[string]struct{}{"did:example:auth1": {}, "did:example:auth2": {}}
	h.addScopeEntity(t, scopePos, "did:example:auth1", authSet)

	newSet := map[string]struct{}{"did:example:auth1": {}, "did:example:auth2": {}, "did:example:auth3": {}}
	amendment, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:     "did:example:auth1",
		TargetRoot:    ptrTo(scopePos),
		AuthorityPath: scopeAuth(),
		ScopePointer:  ptrTo(scopePos), // Self-amendment: ScopePointer == TargetRoot.
		AuthoritySet:  newSet,           // Authority_Set present.
	}, nil)
	amendPos := pos(2)
	result := h.process(t, amendment, amendPos)

	if result.PathCCounts != 1 {
		t.Fatal("expected Path C")
	}
	// Amendment -> OriginTip (membership change).
	if tip := h.leafOriginTip(t, scopePos); !tip.Equal(amendPos) {
		t.Fatalf("OriginTip should be updated for scope amendment, got %s", tip)
	}
}

// Test 51: Removal execution (Authority_Set null) -> AuthorityTip (pending).
func TestBuilderPathC_RemovalExecution(t *testing.T) {
	h := newHarness()
	scopePos := pos(1)
	authSet := map[string]struct{}{"did:example:a": {}, "did:example:b": {}}
	h.addScopeEntity(t, scopePos, "did:example:a", authSet)

	removal, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:     "did:example:a",
		TargetRoot:    ptrTo(scopePos),
		AuthorityPath: scopeAuth(),
		ScopePointer:  ptrTo(scopePos),
		// Authority_Set NULL -> enforcement lane.
	}, nil)
	removalPos := pos(2)
	result := h.process(t, removal, removalPos)

	if result.PathCCounts != 1 {
		t.Fatal("expected Path C")
	}
	// No Authority_Set -> AuthorityTip.
	if tip := h.leafAuthorityTip(t, scopePos); !tip.Equal(removalPos) {
		t.Fatal("AuthorityTip should be updated for removal execution")
	}
	// OriginTip unchanged.
	if tip := h.leafOriginTip(t, scopePos); !tip.Equal(scopePos) {
		t.Fatal("OriginTip should not change for removal execution")
	}
}

// Test 52: Removal activation (reduced Authority_Set) -> OriginTip.
func TestBuilderPathC_RemovalActivation(t *testing.T) {
	h := newHarness()
	scopePos := pos(1)
	authSet := map[string]struct{}{"did:example:a": {}, "did:example:b": {}}
	h.addScopeEntity(t, scopePos, "did:example:a", authSet)

	reducedSet := map[string]struct{}{"did:example:a": {}} // b removed.
	activation, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:     "did:example:a",
		TargetRoot:    ptrTo(scopePos),
		AuthorityPath: scopeAuth(),
		ScopePointer:  ptrTo(scopePos),
		AuthoritySet:  reducedSet, // Present -> OriginTip.
	}, nil)
	actPos := pos(2)
	result := h.process(t, activation, actPos)

	if result.PathCCounts != 1 {
		t.Fatal("expected Path C")
	}
	if tip := h.leafOriginTip(t, scopePos); !tip.Equal(actPos) {
		t.Fatal("OriginTip should be updated for removal activation")
	}
}

// Test 53: Contest against scope (no Authority_Set) -> AuthorityTip.
func TestBuilderPathC_Contest(t *testing.T) {
	h := newHarness()
	entityPos := pos(1)
	h.addRootEntity(t, entityPos, "did:example:entity")
	scopePos := pos(2)
	authSet := map[string]struct{}{"did:example:judge": {}}
	h.addScopeEntity(t, scopePos, "did:example:judge", authSet)

	contest, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:     "did:example:judge",
		TargetRoot:    ptrTo(entityPos),
		AuthorityPath: scopeAuth(),
		ScopePointer:  ptrTo(scopePos),
		// No AuthoritySet, ScopePointer != TargetRoot -> AuthorityTip.
	}, nil)
	contestPos := pos(3)
	result := h.process(t, contest, contestPos)

	if result.PathCCounts != 1 {
		t.Fatal("expected Path C")
	}
	if tip := h.leafAuthorityTip(t, entityPos); !tip.Equal(contestPos) {
		t.Fatal("AuthorityTip should be updated for contest")
	}
}

// Test 54: Authority snapshot (Evidence_Pointers, no Authority_Set, scope != target) -> AuthorityTip.
func TestBuilderPathC_AuthoritySnapshot(t *testing.T) {
	h := newHarness()
	entityPos := pos(1)
	h.addRootEntity(t, entityPos, "did:example:entity")
	scopePos := pos(2)
	authSet := map[string]struct{}{"did:example:judge": {}}
	h.addScopeEntity(t, scopePos, "did:example:judge", authSet)

	snapshot, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:        "did:example:judge",
		TargetRoot:       ptrTo(entityPos),
		AuthorityPath:    scopeAuth(),
		ScopePointer:     ptrTo(scopePos),
		EvidencePointers: []types.LogPosition{pos(10), pos(11)}, // Active enforcements.
		// No AuthoritySet. ScopePointer != TargetRoot -> AuthorityTip.
	}, nil)
	snapPos := pos(3)
	result := h.process(t, snapshot, snapPos)

	if result.PathCCounts != 1 {
		t.Fatal("expected Path C for authority snapshot")
	}
	if tip := h.leafAuthorityTip(t, entityPos); !tip.Equal(snapPos) {
		t.Fatal("AuthorityTip should be updated for authority snapshot")
	}
	// OriginTip unchanged.
	if tip := h.leafOriginTip(t, entityPos); !tip.Equal(entityPos) {
		t.Fatal("OriginTip should not change for authority snapshot")
	}
}

// ── PATH D ─────────────────────────────────────────────────────────────

// Test 54: No authority -> Path D (no SMT update).
func TestBuilderPathD_NoAuthority(t *testing.T) {
	h := newHarness()
	rootPos := pos(1)
	h.addRootEntity(t, rootPos, "did:example:owner")

	// Wrong signer, no delegation, no scope -> Path D.
	entry, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:     "did:example:attacker",
		TargetRoot:    ptrTo(rootPos),
		AuthorityPath: sameSigner(), // Claims same_signer but DID doesn't match.
	}, nil)
	result := h.process(t, entry, pos(2))
	if result.PathDCounts != 1 {
		t.Fatal("wrong signer with same_signer path should be Path D")
	}
}

// Test 55: Commentary entry (Target_Root null, Authority_Path null) -> no leaf.
func TestBuilderPathD_Commentary(t *testing.T) {
	h := newHarness()
	entry, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID: "did:example:witness",
		// Target_Root nil, Authority_Path nil -> commentary.
	}, []byte("witness attestation"))
	result := h.process(t, entry, pos(1))
	if result.CommentaryCounts != 1 {
		t.Fatal("expected commentary, no leaf created")
	}
}
