// Package witness — verify_binding_test.go holds the binding test
// for muEnableWitnessQuorumCount. See
// witness/verify.mutation-audit.yaml for the registry.
package witness

import (
	"strings"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// TestWitnessQuorumCount_Binding pins that VerifyTreeHead rejects
// an undersized witness key set with the gate's specific
// "witness set size %d < quorum %d" error message. With the gate
// on, the early-check fires before any cryptographic verification.
// With the gate off, the function falls through to the Phase-1
// primitive (signatures.VerifyWitnessCosignatures), which produces
// a different error or, depending on signature shape, may not
// catch the case at all.
//
// The specific-message assertion is what makes the gate
// load-bearing: if the gate is removed and the primitive happens
// to return a similar message, the test still fails because the
// exact substring this gate produces ("witness/verify: witness set
// size %d < quorum %d") does not appear in the primitive's output.
func TestWitnessQuorumCount_Binding(t *testing.T) {
	// Witness set of size 1, quorum K=3 → undersized.
	keys := []types.WitnessPublicKey{
		{ID: [32]byte{0x01}, PublicKey: make([]byte, 33)},
	}
	head := types.CosignedTreeHead{
		TreeHead: types.TreeHead{
			RootHash: [32]byte{0xAA},
			TreeSize: 1,
		},
		Signatures: []types.WitnessSignature{
			{PubKeyID: [32]byte{0x01}, SchemeTag: 0x01, SigBytes: make([]byte, 64)},
		},
	}

	_, err := VerifyTreeHead(head, keys, 3, nil)
	if err == nil {
		t.Fatal("VerifyTreeHead accepted undersized witness set (muEnableWitnessQuorumCount not load-bearing?)")
	}
	if !strings.Contains(err.Error(), "witness set size 1 < quorum 3") {
		t.Fatalf("want gate-specific message, got %q", err.Error())
	}
}
