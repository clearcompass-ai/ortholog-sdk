package smt

import (
	"crypto/sha256"
	"errors"
	"sync"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// MerkleTree abstracts the append-only Merkle tree (Tessera).
// Stubbed behind interface in Phase 1. Concrete adapter built in Phase 2.
type MerkleTree interface {
	// AppendLeaf adds an entry hash to the tree and returns its position.
	AppendLeaf(hash [32]byte) (position uint64, err error)

	// InclusionProof generates a Merkle inclusion proof for a position
	// against a given tree size.
	InclusionProof(position uint64, treeSize uint64) (*types.MerkleProof, error)

	// Head returns the current tree head (root hash + size).
	Head() (types.TreeHead, error)
}

// ── Stub implementation for SDK testing ────────────────────────────────

// StubMerkleTree is an in-memory Merkle tree for SDK testing.
// Not production-grade — does not implement proper tree structure.
// Production adapter (Tessera) built in Phase 2 from pilot Exp 2.
type StubMerkleTree struct {
	mu     sync.Mutex
	leaves [][32]byte
}

// NewStubMerkleTree creates a stub Merkle tree for testing.
func NewStubMerkleTree() *StubMerkleTree {
	return &StubMerkleTree{}
}

func (m *StubMerkleTree) AppendLeaf(hash [32]byte) (uint64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	pos := uint64(len(m.leaves))
	m.leaves = append(m.leaves, hash)
	return pos, nil
}

func (m *StubMerkleTree) InclusionProof(position uint64, treeSize uint64) (*types.MerkleProof, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if position >= uint64(len(m.leaves)) {
		return nil, errors.New("position out of range")
	}
	if treeSize > uint64(len(m.leaves)) {
		return nil, errors.New("tree size exceeds current size")
	}

	// Stub: return a proof with the leaf hash and a computed path.
	// Real implementation uses Tessera's tile-based proof generation.
	siblings := m.computePath(position, treeSize)
	return &types.MerkleProof{
		LeafPosition: position,
		LeafHash:     m.leaves[position],
		Siblings:     siblings,
		TreeSize:     treeSize,
	}, nil
}

func (m *StubMerkleTree) Head() (types.TreeHead, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(m.leaves) == 0 {
		return types.TreeHead{}, nil
	}

	root := m.computeRoot(0, uint64(len(m.leaves)))
	return types.TreeHead{
		RootHash: root,
		TreeSize: uint64(len(m.leaves)),
	}, nil
}

// computePath computes sibling hashes along the path for a simple binary tree.
func (m *StubMerkleTree) computePath(position uint64, treeSize uint64) [][32]byte {
	if treeSize <= 1 {
		return nil
	}

	var siblings [][32]byte
	level := m.leaves[:treeSize]
	hashes := make([][32]byte, len(level))
	copy(hashes, level)

	for len(hashes) > 1 {
		sibIdx := position ^ 1
		if sibIdx < uint64(len(hashes)) {
			siblings = append(siblings, hashes[sibIdx])
		}
		// Move up one level.
		newHashes := make([][32]byte, (len(hashes)+1)/2)
		for i := 0; i < len(hashes); i += 2 {
			if i+1 < len(hashes) {
				var combined [64]byte
				copy(combined[0:32], hashes[i][:])
				copy(combined[32:64], hashes[i+1][:])
				newHashes[i/2] = sha256.Sum256(combined[:])
			} else {
				newHashes[i/2] = hashes[i]
			}
		}
		hashes = newHashes
		position /= 2
	}

	return siblings
}

// computeRoot computes the Merkle root for a range of leaves.
func (m *StubMerkleTree) computeRoot(start, end uint64) [32]byte {
	if end-start == 0 {
		return [32]byte{}
	}
	if end-start == 1 {
		return m.leaves[start]
	}

	hashes := make([][32]byte, end-start)
	copy(hashes, m.leaves[start:end])

	for len(hashes) > 1 {
		newHashes := make([][32]byte, (len(hashes)+1)/2)
		for i := 0; i < len(hashes); i += 2 {
			if i+1 < len(hashes) {
				var combined [64]byte
				copy(combined[0:32], hashes[i][:])
				copy(combined[32:64], hashes[i+1][:])
				newHashes[i/2] = sha256.Sum256(combined[:])
			} else {
				newHashes[i/2] = hashes[i]
			}
		}
		hashes = newHashes
	}
	return hashes[0]
}
