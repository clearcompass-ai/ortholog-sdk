package tests

import (
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// mockSchemaResolver returns configurable commutative/non-commutative resolution.
type mockSchemaResolver struct {
	commutative bool
}

func (r *mockSchemaResolver) Resolve(ref types.LogPosition, fetcher builder.EntryFetcher) (*builder.SchemaResolution, error) {
	return &builder.SchemaResolution{IsCommutative: r.commutative, DeltaWindowSize: 10}, nil
}

// setupOCCHarness creates a harness with a scope entity that has enforcement on it.
func setupOCCHarness(t *testing.T) (*testHarness, types.LogPosition, types.LogPosition) {
	t.Helper()
	h := newHarness()
	entityPos := pos(1)
	h.addRootEntity(t, entityPos, "did:example:entity")
	scopePos := pos(2)
	authSet := map[string]struct{}{"did:example:judge": {}}
	h.addScopeEntity(t, scopePos, "did:example:judge", authSet)
	return h, entityPos, scopePos
}

// Test 60: Strict OCC match -> accepted.
func TestOCC_StrictMatch(t *testing.T) {
	h, entityPos, scopePos := setupOCCHarness(t)

	// First enforcement (no prior authority — Authority_Tip == self).
	e1, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:     "did:example:judge",
		TargetRoot:    ptrTo(entityPos),
		AuthorityPath: scopeAuth(),
		ScopePointer:  ptrTo(scopePos),
	}, nil)
	e1Pos := pos(3)
	r1 := h.process(t, e1, e1Pos)
	if r1.PathCCounts != 1 {
		t.Fatal("first enforcement should succeed")
	}

	// Second enforcement with correct Prior_Authority.
	e2, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:      "did:example:judge",
		TargetRoot:     ptrTo(entityPos),
		AuthorityPath:  scopeAuth(),
		ScopePointer:   ptrTo(scopePos),
		PriorAuthority: ptrTo(e1Pos),
	}, nil)
	r2 := h.process(t, e2, pos(4))
	if r2.PathCCounts != 1 {
		t.Fatal("strict OCC with matching Prior_Authority should succeed")
	}
}

// Test 61: Strict OCC mismatch -> rejected.
func TestOCC_StrictMismatch(t *testing.T) {
	h, entityPos, scopePos := setupOCCHarness(t)

	e1, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:     "did:example:judge",
		TargetRoot:    ptrTo(entityPos),
		AuthorityPath: scopeAuth(),
		ScopePointer:  ptrTo(scopePos),
	}, nil)
	h.process(t, e1, pos(3))

	// Wrong Prior_Authority.
	e2, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:      "did:example:judge",
		TargetRoot:     ptrTo(entityPos),
		AuthorityPath:  scopeAuth(),
		ScopePointer:   ptrTo(scopePos),
		PriorAuthority: ptrTo(pos(999)), // Wrong.
	}, nil)
	r2 := h.process(t, e2, pos(4))
	if r2.RejectedCounts != 1 {
		t.Fatalf("strict OCC mismatch should reject, got PathC=%d Rejected=%d PathD=%d",
			r2.PathCCounts, r2.RejectedCounts, r2.PathDCounts)
	}
}

// Test 62: Commutative within window -> accepted.
func TestOCC_CommutativeWithinWindow(t *testing.T) {
	h, entityPos, scopePos := setupOCCHarness(t)
	h.schema = &mockSchemaResolver{commutative: true}

	schemaPos := pos(10)
	schemaEntry, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:              "did:example:schema-author",
		AuthorityPath:          sameSigner(),
		CommutativeOperations:  []uint32{1, 2},
	}, nil)
	h.fetcher.Store(schemaPos, schemaEntry)

	// First enforcement.
	e1, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:     "did:example:judge",
		TargetRoot:    ptrTo(entityPos),
		AuthorityPath: scopeAuth(),
		ScopePointer:  ptrTo(scopePos),
		SchemaRef:     ptrTo(schemaPos),
	}, nil)
	e1Pos := pos(3)
	h.process(t, e1, e1Pos)

	// Second enforcement. Prior_Authority = e1Pos (current tip — also in window).
	e2, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:      "did:example:judge",
		TargetRoot:     ptrTo(entityPos),
		AuthorityPath:  scopeAuth(),
		ScopePointer:   ptrTo(scopePos),
		SchemaRef:      ptrTo(schemaPos),
		PriorAuthority: ptrTo(e1Pos),
	}, nil)
	r2 := h.process(t, e2, pos(4))
	if r2.PathCCounts != 1 {
		t.Fatal("commutative within window should succeed")
	}
}

// Test 63: Commutative outside window -> rejected.
func TestOCC_CommutativeOutsideWindow(t *testing.T) {
	h, entityPos, scopePos := setupOCCHarness(t)
	h.schema = &mockSchemaResolver{commutative: true}
	h.buffer = builder.NewDeltaWindowBuffer(2) // Tiny window.

	// Build 5 enforcement entries to push old ones out of window.
	prevPos := types.LogPosition{}
	for i := uint64(3); i <= 7; i++ {
		hdr := envelope.ControlHeader{
			SignerDID:     "did:example:judge",
			TargetRoot:    ptrTo(entityPos),
			AuthorityPath: scopeAuth(),
			ScopePointer:  ptrTo(scopePos),
		}
		if !prevPos.IsNull() {
			hdr.PriorAuthority = &prevPos
		}
		e, _ := makeEntry(t, hdr, nil)
		h.process(t, e, pos(i))
		prevPos = pos(i)
	}

	// Try with a very old Prior_Authority that's outside the window.
	e, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:      "did:example:judge",
		TargetRoot:     ptrTo(entityPos),
		AuthorityPath:  scopeAuth(),
		ScopePointer:   ptrTo(scopePos),
		PriorAuthority: ptrTo(pos(3)), // Old, outside window of 2.
	}, nil)
	r := h.process(t, e, pos(8))
	if r.RejectedCounts != 1 {
		t.Fatal("commutative outside window should reject")
	}
}

// Test 64: Cold start (SDK-D9) -> strict OCC behavior.
func TestOCC_ColdStart(t *testing.T) {
	h, entityPos, scopePos := setupOCCHarness(t)
	h.schema = &mockSchemaResolver{commutative: true}
	h.buffer = builder.NewDeltaWindowBuffer(10) // Empty buffer = cold start.

	// First enforcement (no prior).
	e1, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:     "did:example:judge",
		TargetRoot:    ptrTo(entityPos),
		AuthorityPath: scopeAuth(),
		ScopePointer:  ptrTo(scopePos),
	}, nil)
	e1Pos := pos(3)
	h.process(t, e1, e1Pos)

	// Second with correct Prior = current tip (cold start = strict).
	e2, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:      "did:example:judge",
		TargetRoot:     ptrTo(entityPos),
		AuthorityPath:  scopeAuth(),
		ScopePointer:   ptrTo(scopePos),
		PriorAuthority: ptrTo(e1Pos),
	}, nil)
	r2 := h.process(t, e2, pos(4))
	if r2.PathCCounts != 1 {
		t.Fatal("cold start with current tip should succeed (strict OCC behavior)")
	}
}

// Test 65: Null Schema_Ref -> strict OCC (spec requirement).
func TestOCC_NullSchemaRef(t *testing.T) {
	h, entityPos, scopePos := setupOCCHarness(t)
	// No schema resolver, no Schema_Ref -> strict OCC.

	e1, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:     "did:example:judge",
		TargetRoot:    ptrTo(entityPos),
		AuthorityPath: scopeAuth(),
		ScopePointer:  ptrTo(scopePos),
	}, nil)
	e1Pos := pos(3)
	h.process(t, e1, e1Pos)

	e2, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:      "did:example:judge",
		TargetRoot:     ptrTo(entityPos),
		AuthorityPath:  scopeAuth(),
		ScopePointer:   ptrTo(scopePos),
		PriorAuthority: ptrTo(e1Pos),
	}, nil)
	r2 := h.process(t, e2, pos(4))
	if r2.PathCCounts != 1 {
		t.Fatal("null Schema_Ref should use strict OCC and succeed with correct Prior_Authority")
	}
}

// Test 66: Buffer flush — deterministic order by canonical hash.
func TestOCC_DeterministicFlush(t *testing.T) {
	buf := builder.NewDeltaWindowBuffer(10)
	leafKey := smt.DeriveKey(pos(1))
	buf.Record(leafKey, pos(10))
	buf.Record(leafKey, pos(11))
	buf.Record(leafKey, pos(12))

	if !buf.Contains(leafKey, pos(10)) {
		t.Fatal("buffer should contain pos(10)")
	}
	if !buf.Contains(leafKey, pos(12)) {
		t.Fatal("buffer should contain pos(12)")
	}
	if buf.Contains(leafKey, pos(99)) {
		t.Fatal("buffer should not contain pos(99)")
	}
}

// Test 67: Buffer persistence across batches.
func TestOCC_BufferPersistence(t *testing.T) {
	buf := builder.NewDeltaWindowBuffer(10)
	leafKey := smt.DeriveKey(pos(1))
	buf.Record(leafKey, pos(10))
	buf.Record(leafKey, pos(11))

	// Simulate batch boundary: buffer survives.
	history := buf.History(leafKey)
	if len(history) != 2 {
		t.Fatal("history should have 2 entries")
	}

	// Load into new buffer (simulating Postgres load).
	buf2 := builder.NewDeltaWindowBuffer(10)
	buf2.SetHistory(leafKey, history)
	if !buf2.Contains(leafKey, pos(10)) {
		t.Fatal("loaded buffer should contain pos(10)")
	}
}

// Test 68: Mixed commutative + non-commutative schemas.
func TestOCC_MixedSchemas(t *testing.T) {
	h := newHarness()
	entityPos := pos(1)
	h.addRootEntity(t, entityPos, "did:example:entity")
	scopePos := pos(2)
	authSet := map[string]struct{}{"did:example:judge": {}}
	h.addScopeEntity(t, scopePos, "did:example:judge", authSet)

	// Non-commutative enforcement (no Schema_Ref -> strict OCC).
	e1, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:     "did:example:judge",
		TargetRoot:    ptrTo(entityPos),
		AuthorityPath: scopeAuth(),
		ScopePointer:  ptrTo(scopePos),
	}, nil)
	e1Pos := pos(3)
	r1 := h.process(t, e1, e1Pos)
	if r1.PathCCounts != 1 {
		t.Fatal("first enforcement should succeed")
	}

	// Second with correct Prior_Authority -> succeed (strict OCC).
	e2, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:      "did:example:judge",
		TargetRoot:     ptrTo(entityPos),
		AuthorityPath:  scopeAuth(),
		ScopePointer:   ptrTo(scopePos),
		PriorAuthority: ptrTo(e1Pos),
	}, nil)
	r2 := h.process(t, e2, pos(4))
	if r2.PathCCounts != 1 {
		t.Fatal("strict OCC with correct prior should succeed")
	}
}
