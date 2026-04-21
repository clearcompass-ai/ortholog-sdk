/*
FILE PATH:

	verifier/cosignature_test.go

DESCRIPTION:

	Unit tests for IsCosignatureOf. Each failure mode of the three-step
	validation has its own test so that a regression in any single check
	produces a precise, actionable failure message rather than a generic
	"helper broken" diagnostic.

	Test matrix:

	  TestIsCosignatureOf_NilEntry                 — guard: nil entry
	  TestIsCosignatureOf_NilCosignatureOf         — guard: nil pointer field
	  TestIsCosignatureOf_WrongPosition            — guard: mismatched pos
	  TestIsCosignatureOf_HappyPath                — positive: all three hold
	  TestIsCosignatureOf_DifferentLogDID          — guard: same seq, different log
	  TestIsCosignatureOf_DifferentSequence        — guard: same log, different seq

	The last two test TestIsCosignatureOf_WrongPosition at finer
	granularity: LogPosition equality must check BOTH LogDID and Sequence.
	A cosignature for seq 42 in log A must not be accepted as cosignature
	for seq 42 in log B, and vice versa.

MUTATION PROBE DISCIPLINE
─────────────────────────
Each negative test must fail if the corresponding check in
IsCosignatureOf is removed:

  - Remove nil-entry guard → TestIsCosignatureOf_NilEntry must panic
  - Remove nil-field guard → TestIsCosignatureOf_NilCosignatureOf must panic
  - Remove position equality → TestIsCosignatureOf_WrongPosition must
    return true (wrong result); TestIsCosignatureOf_DifferentLogDID
    and TestIsCosignatureOf_DifferentSequence both must fail likewise.

Mutation evidence should be captured in the commit message once per
bug fix that depends on this helper.
*/
package verifier

import (
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ═══════════════════════════════════════════════════════════════════
// Fixture helpers
// ═══════════════════════════════════════════════════════════════════

// testPos produces a deterministic LogPosition for tests.
func testPos(logDID string, seq uint64) types.LogPosition {
	return types.LogPosition{LogDID: logDID, Sequence: seq}
}

// cosigEntry builds a minimal *envelope.Entry with Header.CosignatureOf
// set to the provided position pointer. Passing nil produces an entry
// with CosignatureOf == nil (the "not a cosignature" shape).
func cosigEntry(cosigOf *types.LogPosition) *envelope.Entry {
	return &envelope.Entry{
		Header: envelope.ControlHeader{
			CosignatureOf: cosigOf,
		},
	}
}

// ═══════════════════════════════════════════════════════════════════
// Negative path: nil guards
// ═══════════════════════════════════════════════════════════════════

// TestIsCosignatureOf_NilEntry confirms the nil-entry guard. A caller
// passing a nil entry pointer must receive false, not a panic. This
// is important because deserialization failures are common and callers
// should be able to chain without an explicit nil check at every site.
func TestIsCosignatureOf_NilEntry(t *testing.T) {
	if IsCosignatureOf(nil, testPos("did:web:any", 1)) {
		t.Fatal("IsCosignatureOf(nil, pos) returned true; must return false")
	}
}

// TestIsCosignatureOf_NilCosignatureOf confirms the nil-field guard.
// An entry that is not a cosignature (e.g., an ordinary record entry)
// has Header.CosignatureOf == nil by construction. IsCosignatureOf
// must return false without dereferencing the nil pointer.
func TestIsCosignatureOf_NilCosignatureOf(t *testing.T) {
	entry := cosigEntry(nil)
	if IsCosignatureOf(entry, testPos("did:web:any", 1)) {
		t.Fatal("IsCosignatureOf on entry with nil CosignatureOf returned true")
	}
}

// ═══════════════════════════════════════════════════════════════════
// Negative path: position mismatch (the security-critical case)
// ═══════════════════════════════════════════════════════════════════

// TestIsCosignatureOf_WrongPosition is the headline test. A cosignature
// that exists (CosignatureOf != nil) but references a different
// position than expected must be rejected. This is the check whose
// absence is the root cause of BUG-009, BUG-015, and BUG-016.
//
// If this test fails or is removed, every cosignature-gated operation
// in the SDK becomes spoofable by replaying unrelated cosignatures.
func TestIsCosignatureOf_WrongPosition(t *testing.T) {
	actualCosig := testPos("did:web:source", 100)
	expectedPos := testPos("did:web:source", 200)

	entry := cosigEntry(&actualCosig)
	if IsCosignatureOf(entry, expectedPos) {
		t.Fatal("CRITICAL: IsCosignatureOf accepted a cosignature for " +
			"position 100 as cosignature for position 200. The " +
			"position-equality check is broken; this exact pattern is " +
			"the root cause of BUG-009/015/016.")
	}
}

// TestIsCosignatureOf_DifferentLogDID guards the LogDID component of
// position equality. A cosignature for sequence 42 in log A must not
// be accepted as a cosignature for sequence 42 in log B. Without this
// check, cross-log cosignature replay becomes possible.
func TestIsCosignatureOf_DifferentLogDID(t *testing.T) {
	actualCosig := testPos("did:web:log-A", 42)
	expectedPos := testPos("did:web:log-B", 42)

	entry := cosigEntry(&actualCosig)
	if IsCosignatureOf(entry, expectedPos) {
		t.Fatal("IsCosignatureOf accepted same-sequence cosignature " +
			"from different log. Cross-log replay attack is possible.")
	}
}

// TestIsCosignatureOf_DifferentSequence guards the Sequence component
// of position equality. Symmetric to DifferentLogDID.
func TestIsCosignatureOf_DifferentSequence(t *testing.T) {
	actualCosig := testPos("did:web:log-A", 42)
	expectedPos := testPos("did:web:log-A", 43)

	entry := cosigEntry(&actualCosig)
	if IsCosignatureOf(entry, expectedPos) {
		t.Fatal("IsCosignatureOf accepted different-sequence cosignature " +
			"from same log. Position equality must be exact.")
	}
}

// ═══════════════════════════════════════════════════════════════════
// Positive path: all three conditions hold
// ═══════════════════════════════════════════════════════════════════

// TestIsCosignatureOf_HappyPath confirms the positive case: a non-nil
// entry with a non-nil CosignatureOf pointing at the expected position.
// This test must return true; a false result here indicates the
// helper has become overly restrictive and will cause false-negative
// rejections in production.
func TestIsCosignatureOf_HappyPath(t *testing.T) {
	pos := testPos("did:web:source", 42)
	entry := cosigEntry(&pos)

	if !IsCosignatureOf(entry, pos) {
		t.Fatal("IsCosignatureOf rejected a valid cosignature pointing " +
			"at the expected position. The helper is over-restrictive.")
	}
}

// TestIsCosignatureOf_HappyPath_DistinctPointerSameValue confirms
// position equality is value-based, not pointer-based. A cosignature
// references a position by value; the expected position is passed by
// value. Even though the two LogPosition values sit at different
// memory addresses, equality must succeed.
func TestIsCosignatureOf_HappyPath_DistinctPointerSameValue(t *testing.T) {
	// Two distinct LogPosition values with identical contents.
	cosigPos := testPos("did:web:source", 42)
	expectedPos := testPos("did:web:source", 42)

	entry := cosigEntry(&cosigPos)

	if !IsCosignatureOf(entry, expectedPos) {
		t.Fatal("IsCosignatureOf uses pointer equality, not value " +
			"equality. LogPosition.Equal must be called, not == .")
	}
}
