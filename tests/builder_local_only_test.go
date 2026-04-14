package tests

import (
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// Test 56: Foreign Target_Root -> Path D.
func TestBuilderLocal_ForeignTargetRoot(t *testing.T) {
	h := newHarness()
	entry, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:     "did:example:alice",
		TargetRoot:    ptrTo(foreignPos(1)),
		AuthorityPath: sameSigner(),
	}, nil)
	result := h.process(t, entry, pos(1))
	if result.PathDCounts != 1 {
		t.Fatal("foreign Target_Root should fall to Path D")
	}
}

// Test 57: Foreign Delegation_Pointer -> Path D.
func TestBuilderLocal_ForeignDelegationPointer(t *testing.T) {
	h := newHarness()
	rootPos := pos(1)
	h.addRootEntity(t, rootPos, "did:example:owner")

	entry, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:          "did:example:delegate",
		TargetRoot:         ptrTo(rootPos),
		AuthorityPath:      delegation(),
		DelegationPointers: []types.LogPosition{foreignPos(2)},
	}, nil)
	result := h.process(t, entry, pos(3))
	if result.PathDCounts != 1 {
		t.Fatal("foreign Delegation_Pointer should fall to Path D")
	}
}

// Test 58: Foreign Scope_Pointer -> Path D.
func TestBuilderLocal_ForeignScopePointer(t *testing.T) {
	h := newHarness()
	rootPos := pos(1)
	h.addRootEntity(t, rootPos, "did:example:entity")

	entry, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:     "did:example:judge",
		TargetRoot:    ptrTo(rootPos),
		AuthorityPath: scopeAuth(),
		ScopePointer:  ptrTo(foreignPos(2)),
	}, nil)
	result := h.process(t, entry, pos(3))
	if result.PathDCounts != 1 {
		t.Fatal("foreign Scope_Pointer should fall to Path D")
	}
}

// Test 59: Local positions -> proceed normally.
func TestBuilderLocal_LocalPositions(t *testing.T) {
	h := newHarness()
	rootPos := pos(1)
	h.addRootEntity(t, rootPos, "did:example:alice")

	entry, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:     "did:example:alice",
		TargetRoot:    ptrTo(rootPos),
		AuthorityPath: sameSigner(),
	}, nil)
	result := h.process(t, entry, pos(2))
	if result.PathACounts != 1 {
		t.Fatal("local positions should proceed normally")
	}
}
