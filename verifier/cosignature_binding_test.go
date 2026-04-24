// Package verifier — cosignature_binding_test.go holds the binding
// test for muEnableCosignatureBinding. See
// verifier/cosignature.mutation-audit.yaml for the registry.
package verifier

import (
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// TestIsCosignatureOf_PositionMismatch_Binding constructs a
// cosignature-shaped entry that references position A and asserts
// IsCosignatureOf returns false when the caller requests position B.
// With the gate on, the position-match clause rejects. With the
// gate off, the function short-circuits to true and this assertion
// fails — exactly the ORTHO-BUG-009 regression signal.
func TestIsCosignatureOf_PositionMismatch_Binding(t *testing.T) {
	positionA := types.LogPosition{LogDID: "did:web:example.com:log", Sequence: 1}
	positionB := types.LogPosition{LogDID: "did:web:example.com:log", Sequence: 99}

	// Construct a cosignature-shaped entry bound to positionA only.
	entry := &envelope.Entry{
		Header: envelope.ControlHeader{
			SignerDID:     "did:web:example.com:cosigner",
			CosignatureOf: &positionA,
		},
	}

	// Callers asking about positionA see true (the happy path).
	if !IsCosignatureOf(entry, positionA) {
		t.Fatal("IsCosignatureOf rejected a cosignature that DOES match positionA")
	}
	// Callers asking about positionB must see false — the gate is
	// what enforces the binding. With the gate off, this returns
	// true and the test fails.
	if IsCosignatureOf(entry, positionB) {
		t.Fatal("IsCosignatureOf accepted a cosignature for the WRONG position (muEnableCosignatureBinding not load-bearing?)")
	}
}

// TestIsCosignatureOf_NilInputs_Binding pins the two pre-gate
// rejection clauses that guard nil dereferences. These are not
// gated — they are structural invariants of the function — but
// the test keeps the cosignature-binding registry self-contained
// with coverage of every rejection path.
func TestIsCosignatureOf_NilInputs_Binding(t *testing.T) {
	position := types.LogPosition{LogDID: "did:web:example.com:log", Sequence: 1}
	if IsCosignatureOf(nil, position) {
		t.Fatal("IsCosignatureOf accepted nil entry")
	}
	entry := &envelope.Entry{
		Header: envelope.ControlHeader{SignerDID: "did:web:example.com:cosigner"},
	}
	if IsCosignatureOf(entry, position) {
		t.Fatal("IsCosignatureOf accepted entry with nil CosignatureOf")
	}
}
