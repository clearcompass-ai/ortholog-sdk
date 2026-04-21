// core/smt/merkle_wrap_test.go (new)

package smt_test

import (
	"crypto/sha256"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
)

// Reference RFC 6962 implementations, written from the spec text
// independently of the SDK's primitives. If the SDK's primitives
// drift, these references stay pinned, and the stub tree fails these
// tests loudly.
func refLeaf(data []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(data)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func refInterior(l, r [32]byte) [32]byte {
	var buf [65]byte
	buf[0] = 0x01
	copy(buf[1:33], l[:])
	copy(buf[33:65], r[:])
	return sha256.Sum256(buf[:])
}

// TestStubMerkleTree_RFC6962_TwoLeaves locks the canonical two-leaf
// tree case. Root = SHA-256(0x01 || leaf0 || leaf1), where each leaf
// is SHA-256(0x00 || data).
func TestStubMerkleTree_RFC6962_TwoLeaves(t *testing.T) {
	tree := smt.NewStubMerkleTree()
	pos0, _ := tree.AppendLeaf([]byte("hello"))
	pos1, _ := tree.AppendLeaf([]byte("world"))

	if pos0 != 0 || pos1 != 1 {
		t.Fatalf("positions = (%d, %d), want (0, 1)", pos0, pos1)
	}

	wantLeaf0 := refLeaf([]byte("hello"))
	wantLeaf1 := refLeaf([]byte("world"))
	wantRoot := refInterior(wantLeaf0, wantLeaf1)

	head, err := tree.Head()
	if err != nil {
		t.Fatal(err)
	}
	if head.RootHash != wantRoot {
		t.Errorf("root mismatch\n  got  %x\n  want %x", head.RootHash, wantRoot)
	}
	if head.TreeSize != 2 {
		t.Errorf("tree size = %d, want 2", head.TreeSize)
	}

	proof0, err := tree.InclusionProof(0, 2)
	if err != nil {
		t.Fatal(err)
	}
	if proof0.LeafHash != wantLeaf0 {
		t.Errorf("leaf 0 hash mismatch\n  got  %x\n  want %x", proof0.LeafHash, wantLeaf0)
	}
	if len(proof0.Siblings) != 1 || proof0.Siblings[0] != wantLeaf1 {
		t.Errorf("proof 0 siblings: got %x, want [%x]", proof0.Siblings, wantLeaf1)
	}
}

// TestStubMerkleTree_RFC6962_OddLeaf verifies the orphan-promotion
// rule at a 3-leaf tree. Tree structure:
//
//	    root
//	   /    \
//	  h01    L2    (L2 promoted unchanged)
//	 /   \
//	L0   L1
func TestStubMerkleTree_RFC6962_OddLeaf(t *testing.T) {
	tree := smt.NewStubMerkleTree()
	tree.AppendLeaf([]byte("a"))
	tree.AppendLeaf([]byte("b"))
	tree.AppendLeaf([]byte("c"))

	leafA := refLeaf([]byte("a"))
	leafB := refLeaf([]byte("b"))
	leafC := refLeaf([]byte("c"))
	hAB := refInterior(leafA, leafB)
	wantRoot := refInterior(hAB, leafC)

	head, _ := tree.Head()
	if head.RootHash != wantRoot {
		t.Errorf("3-leaf root mismatch\n  got  %x\n  want %x", head.RootHash, wantRoot)
	}
}

// TestStubMerkleTree_MatchesEnvelopePrimitive ensures AppendLeaf
// produces the exact same hash as envelope.EntryLeafHashBytes for
// the same input. If these two ever diverge, cross-log verification
// breaks silently in production.
func TestStubMerkleTree_MatchesEnvelopePrimitive(t *testing.T) {
	data := []byte("entry canonical bytes")

	tree := smt.NewStubMerkleTree()
	tree.AppendLeaf(data)
	proof, err := tree.InclusionProof(0, 1)
	if err != nil {
		t.Fatal(err)
	}

	want := envelope.EntryLeafHashBytes(data)
	if proof.LeafHash != want {
		t.Errorf("leaf hash divergence\n  stub     %x\n  envelope %x", proof.LeafHash, want)
	}
}
