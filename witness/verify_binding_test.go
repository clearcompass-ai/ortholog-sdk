// Package witness — verify_binding_test.go holds the binding tests
// for the three witness/verify.go mutation-audit gates:
//
//   muEnableWitnessQuorumCount   → TestWitnessQuorumCount_Binding (Group 6.1)
//   muEnableUniqueSigners        → TestWitnessUniqueSigners_Binding (Group 8.3)
//   muEnableWitnessKeyMembership → TestWitnessKeyMembership_Binding (Group 8.3)
//
// See witness/verify.mutation-audit.yaml for the registry.
package witness

import (
	"errors"
	"strings"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
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

// ─────────────────────────────────────────────────────────────────────
// muEnableUniqueSigners (Group 8.3)
// ─────────────────────────────────────────────────────────────────────

// TestWitnessUniqueSigners_Binding pins the post-verify uniqueness
// check by feeding countValidUnique a synthetic Phase-1 result with
// the same PubKeyID appearing in three "Valid: true" rows. With the
// gate on, the function counts the signer once. With the gate off,
// it counts every row separately.
//
// The unit test on countValidUnique avoids the work of constructing a
// full signed CosignedTreeHead with three identical signatures (which
// would also need three valid ECDSA signatures over the same payload);
// the gate's load-bearing behavior lives entirely in countValidUnique
// and asserting against it directly is precise and fast.
func TestWitnessUniqueSigners_Binding(t *testing.T) {
	id := [32]byte{0x42}
	r := &signatures.WitnessVerifyResult{
		Total:      3,
		ValidCount: 3,
		Results: []signatures.WitnessSignerResult{
			{PubKeyID: id, Valid: true},
			{PubKeyID: id, Valid: true},
			{PubKeyID: id, Valid: true},
		},
	}
	keys := []types.WitnessPublicKey{{ID: id}}

	got := countValidUnique(r, keys)
	if got != 1 {
		t.Fatalf("countValidUnique with three rows for one PubKeyID returned %d, want 1 (muEnableUniqueSigners not load-bearing?)", got)
	}
}

// TestWitnessUniqueSigners_QuorumRejection drives the gate through
// VerifyTreeHead's public surface and asserts ErrInsufficientWitnesses
// surfaces when the unique count drops below K. With the gate off,
// the duplicate signer counts toward quorum and VerifyTreeHead
// returns success — the load-bearing assertion fails.
//
// Hand-constructed BLS signatures would normally require Phase-1
// primitives that we don't want to depend on for a witness-layer
// binding test. We use the ECDSA path with a synthetic signature
// that Phase 1 will reject (length != 64 → invalid). All three
// rows therefore land at Valid=false and quorum rejection comes
// from Phase 1 first, which masks our gate. To observe the gate
// directly we use the unit-level countValidUnique test above; this
// public-surface test stays as a smoke check that the gate is
// wired into the call path.
func TestWitnessUniqueSigners_WiredIntoCallPath(t *testing.T) {
	id := [32]byte{0x42}
	keys := []types.WitnessPublicKey{{ID: id, PublicKey: make([]byte, 33)}}
	head := types.CosignedTreeHead{
		TreeHead: types.TreeHead{RootHash: [32]byte{0xAA}, TreeSize: 1},
		Signatures: []types.WitnessSignature{
			{PubKeyID: id, SchemeTag: 0x01, SigBytes: make([]byte, 64)},
			{PubKeyID: id, SchemeTag: 0x01, SigBytes: make([]byte, 64)},
		},
	}
	// Phase 1 will reject these signatures (zero bytes are not
	// valid ECDSA), so the call returns an insufficient-witnesses
	// error — but the error path it goes through includes the
	// gate's countValidUnique post-process. The assertion here is
	// just that the call surfaces ErrInsufficientWitnesses; the
	// gate-specific load-bearing assertion is in the unit test
	// above.
	_, err := VerifyTreeHead(head, keys, 1, nil)
	if err == nil {
		t.Fatal("VerifyTreeHead accepted invalid signatures")
	}
	if !errors.Is(err, ErrInsufficientWitnesses) {
		t.Fatalf("want ErrInsufficientWitnesses, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// muEnableWitnessKeyMembership (Group 8.3)
// ─────────────────────────────────────────────────────────────────────

// TestWitnessKeyMembership_Binding pins the post-verify membership
// check via countValidUnique. A successful row whose PubKeyID is NOT
// in the witness key set is dropped from the count when the gate is
// on. With the gate off, the row counts and the post-process matches
// pre-Group-8.3 semantics (the Phase-1 primitive's own membership
// check is the only line of defense — defense-in-depth at the
// witness layer is exactly what this gate provides).
func TestWitnessKeyMembership_Binding(t *testing.T) {
	known := [32]byte{0x01}
	stranger := [32]byte{0x02}
	r := &signatures.WitnessVerifyResult{
		Total:      2,
		ValidCount: 2,
		Results: []signatures.WitnessSignerResult{
			{PubKeyID: known, Valid: true},
			{PubKeyID: stranger, Valid: true},
		},
	}
	keys := []types.WitnessPublicKey{{ID: known}}

	got := countValidUnique(r, keys)
	if got != 1 {
		t.Fatalf("countValidUnique with one in-set + one out-of-set returned %d, want 1 (muEnableWitnessKeyMembership not load-bearing?)", got)
	}
}
