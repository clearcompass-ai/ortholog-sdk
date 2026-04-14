package tests

import (
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ── Proof construction (6 tests) ───────────────────────────────────────

// Test 28: Key derivation — SHA-256(log_position) matches expected.
func TestProof_KeyDerivation(t *testing.T) {
	p := types.LogPosition{LogDID: "did:example:log", Sequence: 42}
	key1 := smt.DeriveKey(p)
	key2 := smt.DeriveKey(p)
	if key1 != key2 {
		t.Fatal("same position should produce same key")
	}
	// Different position -> different key.
	p2 := types.LogPosition{LogDID: "did:example:log", Sequence: 43}
	key3 := smt.DeriveKey(p2)
	if key1 == key3 {
		t.Fatal("different positions should produce different keys")
	}
}

// Test 29: Single membership proof -> verify -> pass.
func TestProof_MembershipVerify(t *testing.T) {
	tree := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeCache())
	p := pos(1)
	key := smt.DeriveKey(p)
	leaf := types.SMTLeaf{Key: key, OriginTip: p, AuthorityTip: p}
	tree.SetLeaf(key, leaf)
	root, _ := tree.Root()

	proof, err := tree.GenerateMembershipProof(key)
	if err != nil || proof == nil {
		t.Fatalf("GenerateMembershipProof: %v", err)
	}
	if err := smt.VerifyMembershipProof(proof, root); err != nil {
		t.Fatalf("VerifyMembershipProof: %v", err)
	}
}

// Test 30: Corrupt sibling -> verification fails.
func TestProof_CorruptSiblingFails(t *testing.T) {
	tree := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeCache())
	// Two leaves create non-default siblings along the diverging path.
	p1 := pos(1)
	k1 := smt.DeriveKey(p1)
	tree.SetLeaf(k1, types.SMTLeaf{Key: k1, OriginTip: p1, AuthorityTip: p1})
	p2 := pos(2)
	k2 := smt.DeriveKey(p2)
	tree.SetLeaf(k2, types.SMTLeaf{Key: k2, OriginTip: p2, AuthorityTip: p2})
	root, _ := tree.Root()

	proof, _ := tree.GenerateMembershipProof(k1)
	if len(proof.Siblings) == 0 {
		t.Fatal("expected non-default siblings with two leaves")
	}
	// Corrupt a sibling.
	for k := range proof.Siblings {
		proof.Siblings[k] = [32]byte{0xFF}
		break
	}
	if err := smt.VerifyMembershipProof(proof, root); err == nil {
		t.Fatal("corrupted proof should fail verification")
	}
}

// Test 31: Empty tree root = default hash.
func TestProof_EmptyTreeRoot(t *testing.T) {
	tree := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeCache())
	root, err := tree.Root()
	if err != nil {
		t.Fatal(err)
	}
	expected := smt.DefaultHash(smt.TreeDepth)
	if root != expected {
		t.Fatal("empty tree root should be default hash")
	}
}

// Test 32: Non-membership proof -> verify -> pass; then insert -> old proof fails.
func TestProof_NonMembershipAndStaleness(t *testing.T) {
	tree := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeCache())
	// Add one leaf so tree is non-empty.
	p1 := pos(1)
	k1 := smt.DeriveKey(p1)
	tree.SetLeaf(k1, types.SMTLeaf{Key: k1, OriginTip: p1, AuthorityTip: p1})

	// Non-membership proof for a different key.
	p2 := pos(999)
	k2 := smt.DeriveKey(p2)
	rootBefore, _ := tree.Root()
	proof, err := tree.GenerateNonMembershipProof(k2)
	if err != nil || proof == nil {
		t.Fatalf("GenerateNonMembershipProof: %v", err)
	}
	if err := smt.VerifyNonMembershipProof(proof, rootBefore); err != nil {
		t.Fatalf("non-membership should verify: %v", err)
	}

	// Insert the key — root changes.
	tree.SetLeaf(k2, types.SMTLeaf{Key: k2, OriginTip: p2, AuthorityTip: p2})
	rootAfter, _ := tree.Root()
	if rootBefore == rootAfter {
		t.Fatal("root should change after insertion")
	}
	// Old non-membership proof should fail against new root.
	if err := smt.VerifyNonMembershipProof(proof, rootAfter); err == nil {
		t.Fatal("stale non-membership proof should fail against new root")
	}
}

// Test 33: Merkle inclusion proof via stub.
func TestProof_MerkleInclusion(t *testing.T) {
	mt := smt.NewStubMerkleTree()
	h1 := [32]byte{1}
	h2 := [32]byte{2}
	h3 := [32]byte{3}
	mt.AppendLeaf(h1)
	mt.AppendLeaf(h2)
	mt.AppendLeaf(h3)

	head, _ := mt.Head()
	proof, err := mt.InclusionProof(1, head.TreeSize) // Second leaf.
	if err != nil {
		t.Fatal(err)
	}
	if err := smt.VerifyMerkleInclusion(proof, head.RootHash); err != nil {
		t.Fatalf("Merkle inclusion should verify: %v", err)
	}
}

// ── Proof sizes (3 tests) ──────────────────────────────────────────────

// Test 34: Batch 5 clustered keys — shared paths reduce size.
func TestProofSize_Batch5Clustered(t *testing.T) {
	tree := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeCache())
	keys := make([][32]byte, 5)
	for i := 0; i < 5; i++ {
		p := pos(uint64(i + 1))
		k := smt.DeriveKey(p)
		keys[i] = k
		tree.SetLeaf(k, types.SMTLeaf{Key: k, OriginTip: p, AuthorityTip: p})
	}
	proof, err := tree.GenerateBatchProof(keys)
	if err != nil || proof == nil {
		t.Fatalf("GenerateBatchProof: %v", err)
	}
	if len(proof.Entries) != 5 {
		t.Fatalf("entries: got %d, want 5", len(proof.Entries))
	}
}

// Test 35: Update leaf -> old proof fails (staleness detection).
func TestProofSize_StaleAfterUpdate(t *testing.T) {
	tree := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeCache())
	p := pos(1)
	k := smt.DeriveKey(p)
	tree.SetLeaf(k, types.SMTLeaf{Key: k, OriginTip: p, AuthorityTip: p})
	rootBefore, _ := tree.Root()

	proof, _ := tree.GenerateMembershipProof(k)
	if err := smt.VerifyMembershipProof(proof, rootBefore); err != nil {
		t.Fatal(err)
	}

	// Update the leaf.
	p2 := pos(2)
	tree.SetLeaf(k, types.SMTLeaf{Key: k, OriginTip: p2, AuthorityTip: p})
	rootAfter, _ := tree.Root()
	if rootBefore == rootAfter {
		t.Fatal("root should change")
	}
	if err := smt.VerifyMembershipProof(proof, rootAfter); err == nil {
		t.Fatal("stale proof should fail against new root")
	}
}

// Test 36: 100 leaves — key derivation produces unique keys.
func TestProofSize_100Leaves(t *testing.T) {
	seen := make(map[[32]byte]bool, 100)
	for i := 0; i < 100; i++ {
		p := types.LogPosition{LogDID: "did:example:log", Sequence: uint64(i)}
		k := smt.DeriveKey(p)
		if seen[k] {
			t.Fatalf("duplicate key at sequence %d", i)
		}
		seen[k] = true
	}
}

// ── Derivation commitments (3 tests) ───────────────────────────────────

// Test 37: Commitment matches batch mutations.
func TestDerivationCommitment_MatchesMutations(t *testing.T) {
	tree := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeCache())
	tree.StartTracking()

	p := pos(1)
	k := smt.DeriveKey(p)
	tree.SetLeaf(k, types.SMTLeaf{Key: k, OriginTip: p, AuthorityTip: p})

	mutations := tree.StopTracking()
	if len(mutations) != 1 {
		t.Fatalf("mutations: got %d, want 1", len(mutations))
	}
	if mutations[0].LeafKey != k {
		t.Fatal("mutation key mismatch")
	}
}

// Test 38: Replay commitment produces same post-root.
func TestDerivationCommitment_ReplayConsistent(t *testing.T) {
	tree := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeCache())
	rootBefore, _ := tree.Root()
	tree.StartTracking()

	p1 := pos(1)
	k1 := smt.DeriveKey(p1)
	tree.SetLeaf(k1, types.SMTLeaf{Key: k1, OriginTip: p1, AuthorityTip: p1})
	p2 := pos(2)
	k2 := smt.DeriveKey(p2)
	tree.SetLeaf(k2, types.SMTLeaf{Key: k2, OriginTip: p2, AuthorityTip: p2})

	mutations := tree.StopTracking()
	rootAfter, _ := tree.Root()

	commitment := smt.GenerateCommitment(p1, p2, rootBefore, rootAfter, mutations)
	if commitment.PriorSMTRoot != rootBefore {
		t.Fatal("prior root mismatch")
	}
	if commitment.PostSMTRoot != rootAfter {
		t.Fatal("post root mismatch")
	}
	if commitment.MutationCount != 2 {
		t.Fatalf("mutation count: got %d, want 2", commitment.MutationCount)
	}
}

// Test 39: Empty batch -> no mutations.
func TestDerivationCommitment_EmptyBatch(t *testing.T) {
	tree := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeCache())
	tree.StartTracking()
	mutations := tree.StopTracking()
	if len(mutations) != 0 {
		t.Fatalf("expected 0 mutations, got %d", len(mutations))
	}
}
