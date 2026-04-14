package tests

import (
	"encoding/binary"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

func TestProof_KeyDerivation(t *testing.T) {
	p := types.LogPosition{LogDID: "did:example:log", Sequence: 42}
	k1 := smt.DeriveKey(p)
	k2 := smt.DeriveKey(p)
	if k1 != k2 {
		t.Fatal("same position should produce same key")
	}
	p2 := types.LogPosition{LogDID: "did:example:log", Sequence: 43}
	if k1 == smt.DeriveKey(p2) {
		t.Fatal("different positions should produce different keys")
	}
}

func TestProof_MembershipVerify(t *testing.T) {
	tree := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeCache())
	p := pos(1)
	key := smt.DeriveKey(p)
	tree.SetLeaf(key, types.SMTLeaf{Key: key, OriginTip: p, AuthorityTip: p})
	root, _ := tree.Root()
	proof, err := tree.GenerateMembershipProof(key)
	if err != nil || proof == nil {
		t.Fatalf("GenerateMembershipProof: %v", err)
	}
	if err := smt.VerifyMembershipProof(proof, root); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestProof_CorruptSiblingFails(t *testing.T) {
	tree := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeCache())
	p1 := pos(1)
	k1 := smt.DeriveKey(p1)
	tree.SetLeaf(k1, types.SMTLeaf{Key: k1, OriginTip: p1, AuthorityTip: p1})
	p2 := pos(2)
	k2 := smt.DeriveKey(p2)
	tree.SetLeaf(k2, types.SMTLeaf{Key: k2, OriginTip: p2, AuthorityTip: p2})
	root, _ := tree.Root()
	proof, _ := tree.GenerateMembershipProof(k1)
	if len(proof.Siblings) == 0 {
		t.Fatal("expected non-default siblings")
	}
	for k := range proof.Siblings {
		proof.Siblings[k] = [32]byte{0xFF}
		break
	}
	if err := smt.VerifyMembershipProof(proof, root); err == nil {
		t.Fatal("corrupt should fail")
	}
}

func TestProof_EmptyTreeRoot(t *testing.T) {
	tree := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeCache())
	root, _ := tree.Root()
	if root != smt.DefaultHash(smt.TreeDepth) {
		t.Fatal("empty tree root should be default hash")
	}
}

func TestProof_NonMembershipAndStaleness(t *testing.T) {
	tree := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeCache())
	p1 := pos(1)
	k1 := smt.DeriveKey(p1)
	tree.SetLeaf(k1, types.SMTLeaf{Key: k1, OriginTip: p1, AuthorityTip: p1})
	p2 := pos(999)
	k2 := smt.DeriveKey(p2)
	rootBefore, _ := tree.Root()
	proof, err := tree.GenerateNonMembershipProof(k2)
	if err != nil || proof == nil {
		t.Fatal("GenerateNonMembershipProof failed")
	}
	if err := smt.VerifyNonMembershipProof(proof, rootBefore); err != nil {
		t.Fatalf("should verify: %v", err)
	}
	tree.SetLeaf(k2, types.SMTLeaf{Key: k2, OriginTip: p2, AuthorityTip: p2})
	rootAfter, _ := tree.Root()
	if rootBefore == rootAfter {
		t.Fatal("root should change")
	}
	if err := smt.VerifyNonMembershipProof(proof, rootAfter); err == nil {
		t.Fatal("stale proof should fail")
	}
}

func TestProof_MerkleInclusion(t *testing.T) {
	mt := smt.NewStubMerkleTree()
	// AppendLeaf takes raw bytes — StubMerkleTree hashes internally.
	mt.AppendLeaf([]byte{1})
	mt.AppendLeaf([]byte{2})
	mt.AppendLeaf([]byte{3})
	head, _ := mt.Head()
	proof, err := mt.InclusionProof(1, head.TreeSize)
	if err != nil {
		t.Fatal(err)
	}
	if err := smt.VerifyMerkleInclusion(proof, head.RootHash); err != nil {
		t.Fatalf("should verify: %v", err)
	}
}

// ── GAP 10: Batch proof size assertions ────────────────────────────────

func estimateBatchProofSize(proof *types.BatchProof) int {
	// Each SMT node: 2 (depth) + 8 (position) + 32 (hash) = 42 bytes
	// Each entry: ~42 bytes (LogPosition + hash)
	// Overhead: tree head, smt root
	size := 0
	size += len(proof.SMTNodes) * 42 // non-default siblings
	size += len(proof.Entries) * 42  // entry references
	size += 32 + 8                   // tree head root + size
	size += 32                       // SMT root
	return size
}

func estimateSingleProofSize(proof *types.SMTProof) int {
	return len(proof.Siblings)*32 + 32 + 16 // siblings + key + leaf
}

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
		t.Fatal("GenerateBatchProof failed")
	}
	if len(proof.Entries) != 5 {
		t.Fatalf("entries: got %d, want 5", len(proof.Entries))
	}
	batchSize := estimateBatchProofSize(proof)
	if batchSize > 5120 { // 5 KB
		t.Fatalf("batch 5 clustered size %d bytes exceeds 5KB target", batchSize)
	}
	t.Logf("Batch 5 clustered: %d bytes (%d SMT nodes)", batchSize, len(proof.SMTNodes))
}

func TestProofSize_Batch5VsIndividual(t *testing.T) {
	tree := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeCache())
	keys := make([][32]byte, 5)
	for i := 0; i < 5; i++ {
		p := pos(uint64(i*1000 + 1))
		k := smt.DeriveKey(p)
		keys[i] = k
		tree.SetLeaf(k, types.SMTLeaf{Key: k, OriginTip: p, AuthorityTip: p})
	}
	// Batch proof
	batchProof, _ := tree.GenerateBatchProof(keys)
	batchSize := estimateBatchProofSize(batchProof)
	// Individual proofs total
	individualTotal := 0
	for _, k := range keys {
		p, _ := tree.GenerateMembershipProof(k)
		if p != nil {
			individualTotal += estimateSingleProofSize(p)
		}
	}
	// Batch should not exceed 5x individual
	if batchSize > individualTotal*5 {
		t.Fatalf("batch size %d > 5x individual %d", batchSize, individualTotal)
	}
	t.Logf("Batch5 dispersed: batch=%d individual_total=%d ratio=%.2f", batchSize, individualTotal, float64(batchSize)/float64(individualTotal+1))
}

func TestProofSize_Batch20(t *testing.T) {
	tree := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeCache())
	keys := make([][32]byte, 20)
	for i := 0; i < 20; i++ {
		p := pos(uint64(i + 1))
		k := smt.DeriveKey(p)
		keys[i] = k
		tree.SetLeaf(k, types.SMTLeaf{Key: k, OriginTip: p, AuthorityTip: p})
	}
	proof, _ := tree.GenerateBatchProof(keys)
	batchSize := estimateBatchProofSize(proof)
	// Spec target: ~9KB. Allow 20% margin.
	if batchSize > 10800 { // 9KB * 1.2
		t.Fatalf("batch 20 size %d bytes exceeds ~9KB target", batchSize)
	}
	t.Logf("Batch 20: %d bytes (%d SMT nodes)", batchSize, len(proof.SMTNodes))
}

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
	tree.SetLeaf(k, types.SMTLeaf{Key: k, OriginTip: pos(2), AuthorityTip: p})
	rootAfter, _ := tree.Root()
	if rootBefore == rootAfter {
		t.Fatal("root should change")
	}
	if err := smt.VerifyMembershipProof(proof, rootAfter); err == nil {
		t.Fatal("stale proof should fail")
	}
}

func TestProofSize_100LeavesUniqueKeys(t *testing.T) {
	seen := make(map[[32]byte]bool, 100)
	for i := 0; i < 100; i++ {
		k := smt.DeriveKey(types.LogPosition{LogDID: "did:example:log", Sequence: uint64(i)})
		if seen[k] {
			t.Fatalf("duplicate key at %d", i)
		}
		seen[k] = true
	}
}

// ── Derivation commitments ─────────────────────────────────────────────

func TestDerivationCommitment_MatchesMutations(t *testing.T) {
	tree := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeCache())
	tree.StartTracking()
	p := pos(1)
	k := smt.DeriveKey(p)
	tree.SetLeaf(k, types.SMTLeaf{Key: k, OriginTip: p, AuthorityTip: p})
	mutations := tree.StopTracking()
	if len(mutations) != 1 {
		t.Fatalf("mutations: got %d", len(mutations))
	}
	if mutations[0].LeafKey != k {
		t.Fatal("mutation key mismatch")
	}
}

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
		t.Fatalf("mutation count: got %d", commitment.MutationCount)
	}
}

func TestDerivationCommitment_EmptyBatch(t *testing.T) {
	tree := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeCache())
	tree.StartTracking()
	mutations := tree.StopTracking()
	if len(mutations) != 0 {
		t.Fatalf("expected 0, got %d", len(mutations))
	}
}

// suppress unused import warning
var _ = binary.BigEndian
