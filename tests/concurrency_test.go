package tests

import (
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

type mockSchemaResolver struct{ commutative bool }

func (r *mockSchemaResolver) Resolve(ref types.LogPosition, fetcher builder.EntryFetcher) (*builder.SchemaResolution, error) {
	return &builder.SchemaResolution{IsCommutative: r.commutative, DeltaWindowSize: 10}, nil
}

func setupOCCHarness(t *testing.T) (*testHarness, types.LogPosition, types.LogPosition) {
	t.Helper()
	h := newHarness()
	entityPos := pos(1)
	h.addRootEntity(t, entityPos, "did:example:entity")
	scopePos := pos(2)
	h.addScopeEntity(t, scopePos, "did:example:judge", map[string]struct{}{"did:example:judge": {}})
	return h, entityPos, scopePos
}

func TestOCC_StrictMatch(t *testing.T) {
	h, entityPos, scopePos := setupOCCHarness(t)
	e1 := buildTestEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:judge", TargetRoot: ptrTo(entityPos), AuthorityPath: scopeAuth(), ScopePointer: ptrTo(scopePos)}, nil)
	e1Pos := pos(3)
	h.process(t, e1, e1Pos)
	e2 := buildTestEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:judge", TargetRoot: ptrTo(entityPos), AuthorityPath: scopeAuth(), ScopePointer: ptrTo(scopePos), PriorAuthority: ptrTo(e1Pos)}, nil)
	if r := h.process(t, e2, pos(4)); r.PathCCounts != 1 {
		t.Fatal("strict OCC match should succeed")
	}
}

func TestOCC_StrictMismatch(t *testing.T) {
	h, entityPos, scopePos := setupOCCHarness(t)
	e1 := buildTestEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:judge", TargetRoot: ptrTo(entityPos), AuthorityPath: scopeAuth(), ScopePointer: ptrTo(scopePos)}, nil)
	h.process(t, e1, pos(3))
	e2 := buildTestEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:judge", TargetRoot: ptrTo(entityPos), AuthorityPath: scopeAuth(), ScopePointer: ptrTo(scopePos), PriorAuthority: ptrTo(pos(999))}, nil)
	if r := h.process(t, e2, pos(4)); len(r.RejectedPositions) != 1 {
		t.Fatal("strict OCC mismatch should reject")
	}
}

func TestOCC_CommutativeWithinWindow(t *testing.T) {
	h, entityPos, scopePos := setupOCCHarness(t)
	h.schema = &mockSchemaResolver{commutative: true}
	schemaPos := pos(10)
	schemaEntry := buildTestEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:schema-author", AuthorityPath: sameSigner(), CommutativeOperations: []uint32{1, 2}}, nil)
	h.fetcher.Store(schemaPos, schemaEntry)
	e1 := buildTestEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:judge", TargetRoot: ptrTo(entityPos), AuthorityPath: scopeAuth(), ScopePointer: ptrTo(scopePos), SchemaRef: ptrTo(schemaPos)}, nil)
	e1Pos := pos(3)
	h.process(t, e1, e1Pos)
	e2 := buildTestEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:judge", TargetRoot: ptrTo(entityPos), AuthorityPath: scopeAuth(), ScopePointer: ptrTo(scopePos), SchemaRef: ptrTo(schemaPos), PriorAuthority: ptrTo(e1Pos)}, nil)
	if r := h.process(t, e2, pos(4)); r.PathCCounts != 1 {
		t.Fatal("commutative within window should succeed")
	}
}

func TestOCC_CommutativeOutsideWindow(t *testing.T) {
	h, entityPos, scopePos := setupOCCHarness(t)
	h.schema = &mockSchemaResolver{commutative: true}
	h.buffer = builder.NewDeltaWindowBuffer(2)
	prevPos := types.LogPosition{}
	for i := uint64(3); i <= 7; i++ {
		hdr := envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:judge", TargetRoot: ptrTo(entityPos), AuthorityPath: scopeAuth(), ScopePointer: ptrTo(scopePos)}
		if !prevPos.IsNull() {
			hdr.PriorAuthority = &prevPos
		}
		e := buildTestEntry(t, hdr, nil)
		h.process(t, e, pos(i))
		prevPos = pos(i)
	}
	e := buildTestEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:judge", TargetRoot: ptrTo(entityPos), AuthorityPath: scopeAuth(), ScopePointer: ptrTo(scopePos), PriorAuthority: ptrTo(pos(3))}, nil)
	if r := h.process(t, e, pos(8)); len(r.RejectedPositions) != 1 {
		t.Fatal("outside window should reject")
	}
}

func TestOCC_ColdStart(t *testing.T) {
	h, entityPos, scopePos := setupOCCHarness(t)
	h.schema = &mockSchemaResolver{commutative: true}
	h.buffer = builder.NewDeltaWindowBuffer(10)
	e1 := buildTestEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:judge", TargetRoot: ptrTo(entityPos), AuthorityPath: scopeAuth(), ScopePointer: ptrTo(scopePos)}, nil)
	e1Pos := pos(3)
	h.process(t, e1, e1Pos)
	e2 := buildTestEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:judge", TargetRoot: ptrTo(entityPos), AuthorityPath: scopeAuth(), ScopePointer: ptrTo(scopePos), PriorAuthority: ptrTo(e1Pos)}, nil)
	if r := h.process(t, e2, pos(4)); r.PathCCounts != 1 {
		t.Fatal("cold start with current tip should succeed")
	}
}

func TestOCC_NullSchemaRef(t *testing.T) {
	h, entityPos, scopePos := setupOCCHarness(t)
	e1 := buildTestEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:judge", TargetRoot: ptrTo(entityPos), AuthorityPath: scopeAuth(), ScopePointer: ptrTo(scopePos)}, nil)
	e1Pos := pos(3)
	h.process(t, e1, e1Pos)
	e2 := buildTestEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:judge", TargetRoot: ptrTo(entityPos), AuthorityPath: scopeAuth(), ScopePointer: ptrTo(scopePos), PriorAuthority: ptrTo(e1Pos)}, nil)
	if r := h.process(t, e2, pos(4)); r.PathCCounts != 1 {
		t.Fatal("null Schema_Ref should use strict OCC")
	}
}

func TestOCC_DeterministicFlush(t *testing.T) {
	buf := builder.NewDeltaWindowBuffer(10)
	leafKey := smt.DeriveKey(pos(1))
	buf.Record(leafKey, pos(10))
	buf.Record(leafKey, pos(11))
	buf.Record(leafKey, pos(12))
	if !buf.Contains(leafKey, pos(10)) {
		t.Fatal("should contain")
	}
	if !buf.Contains(leafKey, pos(12)) {
		t.Fatal("should contain")
	}
	if buf.Contains(leafKey, pos(99)) {
		t.Fatal("should not contain")
	}
}

func TestOCC_BufferPersistence(t *testing.T) {
	buf := builder.NewDeltaWindowBuffer(10)
	leafKey := smt.DeriveKey(pos(1))
	buf.Record(leafKey, pos(10))
	buf.Record(leafKey, pos(11))
	history := buf.History(leafKey)
	if len(history) != 2 {
		t.Fatal("should have 2")
	}
	buf2 := builder.NewDeltaWindowBuffer(10)
	buf2.SetHistory(leafKey, history)
	if !buf2.Contains(leafKey, pos(10)) {
		t.Fatal("loaded should contain")
	}
}

func TestOCC_MixedSchemas(t *testing.T) {
	h := newHarness()
	entityPos := pos(1)
	h.addRootEntity(t, entityPos, "did:example:entity")
	scopePos := pos(2)
	h.addScopeEntity(t, scopePos, "did:example:judge", map[string]struct{}{"did:example:judge": {}})
	e1 := buildTestEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:judge", TargetRoot: ptrTo(entityPos), AuthorityPath: scopeAuth(), ScopePointer: ptrTo(scopePos)}, nil)
	e1Pos := pos(3)
	h.process(t, e1, e1Pos)
	e2 := buildTestEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:judge", TargetRoot: ptrTo(entityPos), AuthorityPath: scopeAuth(), ScopePointer: ptrTo(scopePos), PriorAuthority: ptrTo(e1Pos)}, nil)
	if r := h.process(t, e2, pos(4)); r.PathCCounts != 1 {
		t.Fatal("strict OCC with correct prior should succeed")
	}
}
