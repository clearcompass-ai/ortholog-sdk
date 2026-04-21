package tests

import (
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

func TestBuilderPathA_Basic(t *testing.T) {
	h := newHarness()
	rootPos := pos(1)
	h.addRootEntity(t, rootPos, "did:example:alice")
	amendment := buildTestEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:alice", TargetRoot: ptrTo(rootPos), AuthorityPath: sameSigner()}, []byte("amended"))
	amendPos := pos(2)
	result := h.process(t, amendment, amendPos)
	if result.PathACounts != 1 {
		t.Fatalf("PathA: got %d", result.PathACounts)
	}
	if tip := h.leafOriginTip(t, rootPos); !tip.Equal(amendPos) {
		t.Fatalf("OriginTip: got %s", tip)
	}
}

func TestBuilderPathA_WithIntermediate(t *testing.T) {
	h := newHarness()
	rootPos := pos(1)
	h.addRootEntity(t, rootPos, "did:example:alice")
	intPos := pos(2)
	h.addRootEntity(t, intPos, "did:example:alice")
	act := buildTestEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:alice", TargetRoot: ptrTo(rootPos), TargetIntermediate: ptrTo(intPos), AuthorityPath: sameSigner()}, nil)
	actPos := pos(3)
	result := h.process(t, act, actPos)
	if result.PathACounts != 1 {
		t.Fatal("expected Path A")
	}
	if tip := h.leafOriginTip(t, rootPos); !tip.Equal(actPos) {
		t.Fatal("root OriginTip not updated")
	}
	if tip := h.leafOriginTip(t, intPos); !tip.Equal(actPos) {
		t.Fatal("intermediate OriginTip not updated")
	}
}

func TestBuilderPathB_Depth1(t *testing.T) {
	h := newHarness()
	rootPos := pos(1)
	h.addRootEntity(t, rootPos, "did:example:owner")
	delegPos := pos(2)
	h.addDelegation(t, delegPos, "did:example:owner", "did:example:delegate")
	action := buildTestEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:delegate", TargetRoot: ptrTo(rootPos), AuthorityPath: delegation(), DelegationPointers: []types.LogPosition{delegPos}}, nil)
	result := h.process(t, action, pos(3))
	if result.PathBCounts != 1 {
		t.Fatalf("PathB: got %d", result.PathBCounts)
	}
}

func TestBuilderPathB_Depth2(t *testing.T) {
	h := newHarness()
	rootPos := pos(1)
	h.addRootEntity(t, rootPos, "did:example:owner")
	d1 := pos(2)
	h.addDelegation(t, d1, "did:example:owner", "did:example:mid")
	d2 := pos(3)
	h.addDelegation(t, d2, "did:example:mid", "did:example:leaf")
	action := buildTestEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:leaf", TargetRoot: ptrTo(rootPos), AuthorityPath: delegation(), DelegationPointers: []types.LogPosition{d2, d1}}, nil)
	if result := h.process(t, action, pos(4)); result.PathBCounts != 1 {
		t.Fatal("depth 2 should succeed")
	}
}

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
	action := buildTestEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:c", TargetRoot: ptrTo(rootPos), AuthorityPath: delegation(), DelegationPointers: []types.LogPosition{d3, d2, d1}}, nil)
	if result := h.process(t, action, pos(5)); result.PathBCounts != 1 {
		t.Fatal("depth 3 should succeed")
	}
}

func TestBuilderPathB_DoesNotConnect(t *testing.T) {
	h := newHarness()
	rootPos := pos(1)
	h.addRootEntity(t, rootPos, "did:example:DIFFERENT")
	d1 := pos(2)
	h.addDelegation(t, d1, "did:example:owner", "did:example:a")
	d2 := pos(3)
	h.addDelegation(t, d2, "did:example:a", "did:example:b")
	d3 := pos(4)
	h.addDelegation(t, d3, "did:example:b", "did:example:c")
	action := buildTestEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:c", TargetRoot: ptrTo(rootPos), AuthorityPath: delegation(), DelegationPointers: []types.LogPosition{d3, d2, d1}}, nil)
	result := h.process(t, action, pos(5))
	if result.PathBCounts != 0 && result.PathDCounts == 0 && result.RejectedCounts == 0 {
		t.Fatal("chain that doesn't connect should be Path D or rejected")
	}
}

func TestBuilderPathB_LivenessRevoked(t *testing.T) {
	h := newHarness()
	rootPos := pos(1)
	h.addRootEntity(t, rootPos, "did:example:owner")
	delegPos := pos(2)
	h.addDelegation(t, delegPos, "did:example:owner", "did:example:delegate")
	delegKey := smt.DeriveKey(delegPos)
	leaf, _ := h.tree.GetLeaf(delegKey)
	updated := *leaf
	updated.OriginTip = pos(3)
	h.tree.SetLeaf(delegKey, updated)
	action := buildTestEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:delegate", TargetRoot: ptrTo(rootPos), AuthorityPath: delegation(), DelegationPointers: []types.LogPosition{delegPos}}, nil)
	if result := h.process(t, action, pos(4)); result.PathDCounts != 1 {
		t.Fatal("revoked delegation should fall to Path D")
	}
}

func TestBuilderPathB_LivenessAmended(t *testing.T) {
	h := newHarness()
	rootPos := pos(1)
	h.addRootEntity(t, rootPos, "did:example:owner")
	delegPos := pos(2)
	h.addDelegation(t, delegPos, "did:example:owner", "did:example:delegate")
	delegKey := smt.DeriveKey(delegPos)
	leaf, _ := h.tree.GetLeaf(delegKey)
	updated := *leaf
	updated.OriginTip = pos(3)
	h.tree.SetLeaf(delegKey, updated)
	action := buildTestEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:delegate", TargetRoot: ptrTo(rootPos), AuthorityPath: delegation(), DelegationPointers: []types.LogPosition{delegPos}}, nil)
	if result := h.process(t, action, pos(4)); result.PathDCounts != 1 {
		t.Fatal("amended delegation should fall to Path D")
	}
}

func TestBuilderPathB_LivenessLive(t *testing.T) {
	h := newHarness()
	rootPos := pos(1)
	h.addRootEntity(t, rootPos, "did:example:owner")
	delegPos := pos(2)
	h.addDelegation(t, delegPos, "did:example:owner", "did:example:delegate")
	action := buildTestEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:delegate", TargetRoot: ptrTo(rootPos), AuthorityPath: delegation(), DelegationPointers: []types.LogPosition{delegPos}}, nil)
	if result := h.process(t, action, pos(3)); result.PathBCounts != 1 {
		t.Fatal("live delegation should succeed")
	}
}

func TestBuilderPathC_BasicEnforcement(t *testing.T) {
	h := newHarness()
	entityPos := pos(1)
	h.addRootEntity(t, entityPos, "did:example:entity")
	scopePos := pos(2)
	h.addScopeEntity(t, scopePos, "did:example:judge", map[string]struct{}{"did:example:judge": {}})
	enf := buildTestEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:judge", TargetRoot: ptrTo(entityPos), AuthorityPath: scopeAuth(), ScopePointer: ptrTo(scopePos)}, []byte("sealing"))
	enfPos := pos(3)
	result := h.process(t, enf, enfPos)
	if result.PathCCounts != 1 {
		t.Fatal("expected Path C")
	}
	if tip := h.leafAuthorityTip(t, entityPos); !tip.Equal(enfPos) {
		t.Fatal("AuthorityTip not updated")
	}
	if tip := h.leafOriginTip(t, entityPos); !tip.Equal(entityPos) {
		t.Fatal("OriginTip should not change")
	}
}

func TestBuilderPathC_AmendmentExecution(t *testing.T) {
	h := newHarness()
	scopePos := pos(1)
	h.addScopeEntity(t, scopePos, "did:example:auth1", map[string]struct{}{"did:example:auth1": {}, "did:example:auth2": {}})
	newSet := map[string]struct{}{"did:example:auth1": {}, "did:example:auth2": {}, "did:example:auth3": {}}
	amend := buildTestEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:auth1", TargetRoot: ptrTo(scopePos), AuthorityPath: scopeAuth(), ScopePointer: ptrTo(scopePos), AuthoritySet: newSet}, nil)
	amendPos := pos(2)
	result := h.process(t, amend, amendPos)
	if result.PathCCounts != 1 {
		t.Fatal("expected Path C")
	}
	if tip := h.leafOriginTip(t, scopePos); !tip.Equal(amendPos) {
		t.Fatal("OriginTip should be updated for amendment")
	}
}

func TestBuilderPathC_RemovalExecution(t *testing.T) {
	h := newHarness()
	scopePos := pos(1)
	h.addScopeEntity(t, scopePos, "did:example:a", map[string]struct{}{"did:example:a": {}, "did:example:b": {}})
	removal := buildTestEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:a", TargetRoot: ptrTo(scopePos), AuthorityPath: scopeAuth(), ScopePointer: ptrTo(scopePos)}, nil)
	removalPos := pos(2)
	h.process(t, removal, removalPos)
	if tip := h.leafAuthorityTip(t, scopePos); !tip.Equal(removalPos) {
		t.Fatal("AuthorityTip should update for removal")
	}
	if tip := h.leafOriginTip(t, scopePos); !tip.Equal(scopePos) {
		t.Fatal("OriginTip should not change")
	}
}

func TestBuilderPathC_RemovalActivation(t *testing.T) {
	h := newHarness()
	scopePos := pos(1)
	h.addScopeEntity(t, scopePos, "did:example:a", map[string]struct{}{"did:example:a": {}, "did:example:b": {}})
	activation := buildTestEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:a", TargetRoot: ptrTo(scopePos), AuthorityPath: scopeAuth(), ScopePointer: ptrTo(scopePos), AuthoritySet: map[string]struct{}{"did:example:a": {}}}, nil)
	actPos := pos(2)
	h.process(t, activation, actPos)
	if tip := h.leafOriginTip(t, scopePos); !tip.Equal(actPos) {
		t.Fatal("OriginTip should update for removal activation")
	}
}

func TestBuilderPathC_Contest(t *testing.T) {
	h := newHarness()
	entityPos := pos(1)
	h.addRootEntity(t, entityPos, "did:example:entity")
	scopePos := pos(2)
	h.addScopeEntity(t, scopePos, "did:example:judge", map[string]struct{}{"did:example:judge": {}})
	contest := buildTestEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:judge", TargetRoot: ptrTo(entityPos), AuthorityPath: scopeAuth(), ScopePointer: ptrTo(scopePos)}, nil)
	contestPos := pos(3)
	h.process(t, contest, contestPos)
	if tip := h.leafAuthorityTip(t, entityPos); !tip.Equal(contestPos) {
		t.Fatal("AuthorityTip should update")
	}
}

func TestBuilderPathC_AuthoritySnapshot(t *testing.T) {
	h := newHarness()
	entityPos := pos(1)
	h.addRootEntity(t, entityPos, "did:example:entity")
	scopePos := pos(2)
	h.addScopeEntity(t, scopePos, "did:example:judge", map[string]struct{}{"did:example:judge": {}})
	snap := buildTestEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:judge", TargetRoot: ptrTo(entityPos), AuthorityPath: scopeAuth(), ScopePointer: ptrTo(scopePos), EvidencePointers: []types.LogPosition{pos(10), pos(11)}}, nil)
	snapPos := pos(3)
	h.process(t, snap, snapPos)
	if tip := h.leafAuthorityTip(t, entityPos); !tip.Equal(snapPos) {
		t.Fatal("AuthorityTip should update for snapshot")
	}
	if tip := h.leafOriginTip(t, entityPos); !tip.Equal(entityPos) {
		t.Fatal("OriginTip should not change")
	}
}

func TestBuilderPathD_NoAuthority(t *testing.T) {
	h := newHarness()
	rootPos := pos(1)
	h.addRootEntity(t, rootPos, "did:example:owner")
	entry := buildTestEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:attacker", TargetRoot: ptrTo(rootPos), AuthorityPath: sameSigner()}, nil)
	if result := h.process(t, entry, pos(2)); result.PathDCounts != 1 {
		t.Fatal("wrong signer should be Path D")
	}
}

func TestBuilderPathD_Commentary(t *testing.T) {
	h := newHarness()
	entry := buildTestEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:witness"}, []byte("attestation"))
	if result := h.process(t, entry, pos(1)); result.CommentaryCounts != 1 {
		t.Fatal("expected commentary")
	}
}
