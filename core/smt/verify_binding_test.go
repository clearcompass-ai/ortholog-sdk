// Package smt — verify_binding_test.go holds the binding tests
// for the three mutation-audit switches in
// verify_mutation_switches.go. See
// core/smt/verify.mutation-audit.yaml for the registry.
package smt

import (
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// makeMembershipProofForKey returns a membership proof produced by
// inserting one leaf into a fresh tree and reading the proof back.
// The proof verifies against the resulting root with no siblings
// other than the default empty-subtree ladder.
func makeMembershipProofForKey(t *testing.T, key [32]byte) (*types.SMTProof, [32]byte) {
	t.Helper()
	tree := NewTree(NewInMemoryLeafStore(), NewInMemoryNodeCache())
	leaf := types.SMTLeaf{
		Key:          key,
		OriginTip:    types.LogPosition{LogDID: "did:web:example.com:log", Sequence: 1},
		AuthorityTip: types.LogPosition{LogDID: "did:web:example.com:log", Sequence: 1},
	}
	if err := tree.SetLeaf(leaf.Key, leaf); err != nil {
		t.Fatalf("tree.Insert: %v", err)
	}
	root, err := tree.Root()
	if err != nil {
		t.Fatalf("tree.Root: %v", err)
	}
	proof, err := tree.GenerateMembershipProof(key)
	if err != nil {
		t.Fatalf("GenerateMembershipProof: %v", err)
	}
	return proof, root
}

// ─────────────────────────────────────────────────────────────────────
// Binding: muEnableRootMatch
// ─────────────────────────────────────────────────────────────────────

// TestVerifyMembershipProof_RejectsWrongRoot_Binding pins that
// VerifyMembershipProof rejects a proof when the supplied root
// differs from the proof's reconstructed root. With the gate off,
// any root is accepted regardless — silent acceptance of forged
// inclusion claims.
func TestVerifyMembershipProof_RejectsWrongRoot_Binding(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	proof, root := makeMembershipProofForKey(t, key)

	// Tamper with the supplied root: flip a byte.
	wrongRoot := root
	wrongRoot[0] ^= 0xFF

	if err := VerifyMembershipProof(proof, wrongRoot); err == nil {
		t.Fatal("VerifyMembershipProof accepted wrong root (muEnableRootMatch not load-bearing?)")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Binding: muEnableProofDepthBounds
// ─────────────────────────────────────────────────────────────────────

// TestVerifyMembershipProof_RejectsNilSiblings_Binding pins that
// VerifyMembershipProof rejects a proof whose siblings map is
// nil. With the gate off, the nil-map check is bypassed and
// computeRootFromProof falls through to the default-hash ladder
// silently — admitting a proof whose explicit co-path
// declaration was never supplied. The bit-index and
// len > TreeDepth checks the gate would also enforce are
// structurally unreachable for uint8 keys with TreeDepth = 256
// (uint8 cannot exceed 255 = TreeDepth - 1, and a map with uint8
// keys cannot hold more than 256 entries); the nil-map check is
// the only depth-bounds invariant observable at runtime today.
func TestVerifyMembershipProof_RejectsNilSiblings_Binding(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	proof, root := makeMembershipProofForKey(t, key)
	// Strip the siblings map to nil.
	proof.Siblings = nil

	if err := VerifyMembershipProof(proof, root); err == nil {
		t.Fatal("VerifyMembershipProof accepted nil-siblings proof (muEnableProofDepthBounds not load-bearing?)")
	}

	// Sentinel: TreeDepth = 256 is what makes the bit-index check
	// structurally unreachable. If a future refactor changes
	// TreeDepth, the gate's binding semantics need re-derivation.
	if TreeDepth != 256 {
		t.Fatalf("TreeDepth is no longer 256 (got %d); revisit muEnableProofDepthBounds binding test", TreeDepth)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Binding: muEnableEmptyLeafDistinction
// ─────────────────────────────────────────────────────────────────────

// TestVerifyMembershipProof_RejectsNilLeaf_Binding pins that
// VerifyMembershipProof rejects a proof with a nil Leaf — the
// distinction between membership and non-membership proofs.
// With the gate off, the nil-leaf check is bypassed and the
// non-membership leaf hash is used instead, allowing a non-
// membership proof to pose as a membership proof.
func TestVerifyMembershipProof_RejectsNilLeaf_Binding(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i + 1)
	}
	proof, root := makeMembershipProofForKey(t, key)
	// Force the leaf to nil — this should now look like a non-
	// membership proof and VerifyMembershipProof must reject it.
	proof.Leaf = nil

	if err := VerifyMembershipProof(proof, root); err == nil {
		t.Fatal("VerifyMembershipProof accepted nil-leaf (muEnableEmptyLeafDistinction not load-bearing?)")
	}
}

// TestVerifyNonMembershipProof_RejectsLeafPresent_Binding pins
// the symmetric assertion: a non-membership proof with a non-nil
// Leaf must be rejected.
func TestVerifyNonMembershipProof_RejectsLeafPresent_Binding(t *testing.T) {
	// Build a non-membership proof for an absent key.
	tree := NewTree(NewInMemoryLeafStore(), NewInMemoryNodeCache())
	root, err := tree.Root()
	if err != nil {
		t.Fatalf("tree.Root: %v", err)
	}
	var absentKey [32]byte
	for i := range absentKey {
		absentKey[i] = byte(i + 0x40)
	}
	proof, err := tree.GenerateNonMembershipProof(absentKey)
	if err != nil {
		t.Fatalf("GenerateNonMembershipProof: %v", err)
	}
	// Sanity: proof.Leaf should be nil (absence).
	if proof.Leaf != nil {
		t.Fatalf("expected nil leaf for absent key, got %+v", proof.Leaf)
	}
	// Inject a non-nil leaf — VerifyNonMembershipProof must reject.
	proof.Leaf = &types.SMTLeaf{Key: absentKey}
	if err := VerifyNonMembershipProof(proof, root); err == nil {
		t.Fatal("VerifyNonMembershipProof accepted non-nil leaf (muEnableEmptyLeafDistinction not load-bearing?)")
	}
}
