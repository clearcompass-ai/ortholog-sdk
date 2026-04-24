// Package witness — equivocation_binding_test.go holds the binding
// test for muEnableEquivocationDetection. See
// witness/equivocation.mutation-audit.yaml for the registry.
package witness

import (
	"errors"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// TestEquivocationDetection_Binding constructs two heads at the
// same tree size with different root hashes — the precondition
// for a potential equivocation. Both heads carry undersized
// witness sets, so the downstream verification path inside
// DetectEquivocation will fail at VerifyTreeHead. The exact
// failure mode differs by gate state:
//
//   Gate ON  → DetectEquivocation reaches VerifyTreeHead, which
//              returns an error wrapped as
//              "witness/equivocation: head A verification: ..."
//              — non-nil error.
//   Gate OFF → the same-size, different-roots branch is bypassed
//              and DetectEquivocation returns (nil, nil) —
//              silently treating the equivocation candidate as
//              "not equivocation".
//
// The binding test asserts the gate-on behaviour: a non-nil error
// must surface from this input. With the gate off, the function
// returns (nil, nil) and the test fails — the signal that the
// equivocation-detection path is load-bearing.
func TestEquivocationDetection_Binding(t *testing.T) {
	headA := types.CosignedTreeHead{
		TreeHead: types.TreeHead{
			RootHash: [32]byte{0xAA},
			TreeSize: 100,
		},
		Signatures: []types.WitnessSignature{
			{PubKeyID: [32]byte{0x01}, SchemeTag: 0x01, SigBytes: make([]byte, 64)},
		},
	}
	headB := types.CosignedTreeHead{
		TreeHead: types.TreeHead{
			RootHash: [32]byte{0xBB}, // different root, same size
			TreeSize: 100,
		},
		Signatures: []types.WitnessSignature{
			{PubKeyID: [32]byte{0x01}, SchemeTag: 0x01, SigBytes: make([]byte, 64)},
		},
	}
	keys := []types.WitnessPublicKey{
		{ID: [32]byte{0x01}, PublicKey: make([]byte, 33)},
	}

	proof, err := DetectEquivocation(headA, headB, keys, 3, nil)
	if proof != nil {
		t.Fatalf("unexpected proof: %+v", proof)
	}
	// With the gate on, the same-size/different-roots branch
	// triggers VerifyTreeHead, which rejects the undersized witness
	// set with a non-nil error. With the gate off, the branch is
	// bypassed and we get (nil, nil) — i.e., err == nil.
	if err == nil {
		t.Fatal("DetectEquivocation returned (nil, nil) for same-size/different-roots input — gate off?")
	}
	// The error must NOT be ErrDifferentSizes (that's the early
	// branch above the gate, irrelevant to this binding).
	if errors.Is(err, ErrDifferentSizes) {
		t.Fatalf("unexpected ErrDifferentSizes: %v", err)
	}
}

// TestEquivocationDetection_DifferentSizes_PreGate confirms that
// the ErrDifferentSizes early branch fires regardless of the gate
// state (it sits above muEnableEquivocationDetection in the
// function flow). Documents the boundary between the gated branch
// and the structural pre-checks.
func TestEquivocationDetection_DifferentSizes_PreGate(t *testing.T) {
	headA := types.CosignedTreeHead{TreeHead: types.TreeHead{TreeSize: 100}}
	headB := types.CosignedTreeHead{TreeHead: types.TreeHead{TreeSize: 200}}
	_, err := DetectEquivocation(headA, headB, nil, 0, nil)
	if !errors.Is(err, ErrDifferentSizes) {
		t.Fatalf("want ErrDifferentSizes, got %v", err)
	}
}
