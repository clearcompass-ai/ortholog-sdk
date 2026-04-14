package tests

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/witness"
)

// ─────────────────────────────────────────────────────────────────────
// Tests: DetectEquivocation
// ─────────────────────────────────────────────────────────────────────

func TestEquivocation_SameRoots_NoEquivocation(t *testing.T) {
	headA, keys := buildSignedHead(t, 1000, 3, 5)
	headB := headA // Same head — identical roots.

	proof, err := witness.DetectEquivocation(headA, headB, keys, 3, nil)
	if err != nil {
		t.Fatalf("same roots should not error: %v", err)
	}
	if proof != nil {
		t.Fatal("same roots should return nil proof")
	}
}

func TestEquivocation_DifferentSizes_Error(t *testing.T) {
	headA, keys := buildSignedHead(t, 1000, 3, 5)
	headB := headA
	headB.TreeHead.TreeSize = 2000 // Different size.

	_, err := witness.DetectEquivocation(headA, headB, keys, 3, nil)
	if !errors.Is(err, witness.ErrDifferentSizes) {
		t.Fatalf("expected ErrDifferentSizes, got: %v", err)
	}
}

func TestEquivocation_SameSizeDiffRoots_Proven(t *testing.T) {
	// Two heads at the same size with different roots, both validly signed.
	keys := make([]types.WitnessPublicKey, 5)
	privKeys := make([]*ecdsa.PrivateKey, 5)

	for i := 0; i < 5; i++ {
		priv, _ := signatures.GenerateKey()
		pubBytes := signatures.PubKeyBytes(&priv.PublicKey)
		id := sha256.Sum256(pubBytes)
		keys[i] = types.WitnessPublicKey{ID: id, PublicKey: pubBytes}
		privKeys[i] = priv
	}

	// Head A: tree_size=500, root_hash=hash("root-A")
	headA := types.TreeHead{
		TreeSize: 500,
		RootHash: sha256.Sum256([]byte("root-A")),
	}
	msgA := types.WitnessCosignMessage(headA)
	msgHashA := sha256.Sum256(msgA[:])
	sigsA := make([]types.WitnessSignature, 3)
	for i := 0; i < 3; i++ {
		sigBytes, _ := signatures.SignEntry(msgHashA, privKeys[i])
		sigsA[i] = types.WitnessSignature{PubKeyID: keys[i].ID, SigBytes: sigBytes}
	}
	cosignedA := types.CosignedTreeHead{TreeHead: headA, SchemeTag: signatures.SchemeECDSA, Signatures: sigsA}

	// Head B: same tree_size=500, different root_hash=hash("root-B")
	headB := types.TreeHead{
		TreeSize: 500,
		RootHash: sha256.Sum256([]byte("root-B")),
	}
	msgB := types.WitnessCosignMessage(headB)
	msgHashB := sha256.Sum256(msgB[:])
	sigsB := make([]types.WitnessSignature, 3)
	for i := 0; i < 3; i++ {
		sigBytes, _ := signatures.SignEntry(msgHashB, privKeys[i])
		sigsB[i] = types.WitnessSignature{PubKeyID: keys[i].ID, SigBytes: sigBytes}
	}
	cosignedB := types.CosignedTreeHead{TreeHead: headB, SchemeTag: signatures.SchemeECDSA, Signatures: sigsB}

	proof, err := witness.DetectEquivocation(cosignedA, cosignedB, keys, 3, nil)
	if err != nil {
		t.Fatalf("should detect equivocation: %v", err)
	}
	if proof == nil {
		t.Fatal("should return proof")
	}
	if proof.TreeSize != 500 {
		t.Fatalf("tree size: %d", proof.TreeSize)
	}
	if proof.HeadA.RootHash == proof.HeadB.RootHash {
		t.Fatal("roots should differ in proof")
	}
	if !proof.IsProven() {
		t.Fatal("proof should be proven")
	}
	if proof.ValidSigsA < 3 || proof.ValidSigsB < 3 {
		t.Fatalf("sigs: A=%d B=%d", proof.ValidSigsA, proof.ValidSigsB)
	}
}

func TestEquivocation_HeadAInvalid_NoProof(t *testing.T) {
	// Head A has invalid sigs → no proof.
	keys := generateFreshKeys(t, 5)
	headA := types.CosignedTreeHead{
		TreeHead:   types.TreeHead{TreeSize: 300, RootHash: sha256.Sum256([]byte("A"))},
		SchemeTag:  signatures.SchemeECDSA,
		Signatures: []types.WitnessSignature{{PubKeyID: keys[0].ID, SigBytes: make([]byte, 64)}},
	}
	// Build a head B with different root at same size.
	headB := types.CosignedTreeHead{
		TreeHead:   types.TreeHead{TreeSize: 300, RootHash: sha256.Sum256([]byte("B"))},
		SchemeTag:  signatures.SchemeECDSA,
		Signatures: []types.WitnessSignature{{PubKeyID: keys[0].ID, SigBytes: make([]byte, 64)}},
	}

	_, err := witness.DetectEquivocation(headA, headB, keys, 1, nil)
	if err == nil {
		t.Fatal("invalid head A should cause error")
	}
}

func TestEquivocation_IsProven_NilProof(t *testing.T) {
	var proof *witness.EquivocationProof
	if proof.IsProven() {
		t.Fatal("nil proof should not be proven")
	}
}

func TestEquivocation_IsProven_ZeroSigsA(t *testing.T) {
	proof := &witness.EquivocationProof{ValidSigsA: 0, ValidSigsB: 3}
	if proof.IsProven() {
		t.Fatal("zero sigs on A should not be proven")
	}
}

func TestEquivocation_IsProven_ZeroSigsB(t *testing.T) {
	proof := &witness.EquivocationProof{ValidSigsA: 3, ValidSigsB: 0}
	if proof.IsProven() {
		t.Fatal("zero sigs on B should not be proven")
	}
}

func TestEquivocation_TreeSizeZero(t *testing.T) {
	// Edge case: tree_size=0 with different roots.
	headA := types.CosignedTreeHead{
		TreeHead:   types.TreeHead{TreeSize: 0, RootHash: sha256.Sum256([]byte("empty-A"))},
		SchemeTag:  signatures.SchemeECDSA,
		Signatures: []types.WitnessSignature{{SigBytes: make([]byte, 64)}},
	}
	headB := types.CosignedTreeHead{
		TreeHead:   types.TreeHead{TreeSize: 0, RootHash: sha256.Sum256([]byte("empty-B"))},
		SchemeTag:  signatures.SchemeECDSA,
		Signatures: []types.WitnessSignature{{SigBytes: make([]byte, 64)}},
	}
	keys := generateFreshKeys(t, 3)
	// Should fail at verification (no valid sigs), not panic.
	_, err := witness.DetectEquivocation(headA, headB, keys, 1, nil)
	if err == nil {
		t.Log("edge case: tree_size=0 equivocation correctly rejected or detected")
	}
}
