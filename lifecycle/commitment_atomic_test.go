package lifecycle

import (
	"errors"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/artifact"
)

// TestAtomicEmissionInvariant_FireOnSharesWithoutCommitment is the
// binding test for muEnableCommitmentEmissionAtomic. Constructs a
// pathological (materialCount > 0, commitmentEntry == nil) tuple
// that the production happy path never produces, and asserts
// AssertAtomicEmission returns ErrAtomicEmissionInvariantViolated.
//
// When the audit runner flips muEnableCommitmentEmissionAtomic to
// false, AssertAtomicEmission short-circuits to nil and this test
// fails — which is exactly the signal the mutation audit needs to
// confirm the switch is load-bearing.
func TestAtomicEmissionInvariant_FireOnSharesWithoutCommitment(t *testing.T) {
	err := AssertAtomicEmission(3, nil)
	if !errors.Is(err, ErrAtomicEmissionInvariantViolated) {
		t.Fatalf("AssertAtomicEmission(3, nil): want ErrAtomicEmissionInvariantViolated, got %v", err)
	}

	// The happy-path cases must succeed.
	if err := AssertAtomicEmission(0, nil); err != nil {
		t.Fatalf("AssertAtomicEmission(0, nil): want nil, got %v", err)
	}
	dummy := &envelope.Entry{}
	if err := AssertAtomicEmission(3, dummy); err != nil {
		t.Fatalf("AssertAtomicEmission(3, non-nil): want nil, got %v", err)
	}
}

// TestAtomicEmissionInvariant_PRESide exercises the CFrag-slice
// wrapper so both entry points to the invariant have a direct test.
func TestAtomicEmissionInvariant_PRESide(t *testing.T) {
	cf := &artifact.CFrag{}
	// non-empty CFrags + nil entry → assertion fires.
	if err := AssertPREAtomicEmission([]*artifact.CFrag{cf}, nil); !errors.Is(err, ErrAtomicEmissionInvariantViolated) {
		t.Fatalf("PRE nil entry: want violated, got %v", err)
	}
	// empty CFrags + nil entry → trivially satisfied.
	if err := AssertPREAtomicEmission(nil, nil); err != nil {
		t.Fatalf("PRE empty: want nil, got %v", err)
	}
	// non-empty CFrags + non-nil entry → satisfied.
	if err := AssertPREAtomicEmission([]*artifact.CFrag{cf}, &envelope.Entry{}); err != nil {
		t.Fatalf("PRE both populated: want nil, got %v", err)
	}
}
