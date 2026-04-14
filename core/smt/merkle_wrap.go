package smt

import (
	"crypto/sha256"
	"errors"
	"sync"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// MerkleTree is the append-only Merkle tree interface.
// AppendLeaf takes raw entry data (full wire bytes in production).
// The implementation computes the leaf hash internally.
// Callers never hash — mirrors Tessera's contract where the server
// computes RFC6962.HashLeaf(data).
type MerkleTree interface {
	AppendLeaf(data []byte) (uint64, error)
	InclusionProof(position, treeSize uint64) (*types.MerkleProof, error)
	Head() (types.TreeHead, error)
}

type StubMerkleTree struct {
	mu     sync.Mutex
	leaves [][32]byte
}

func NewStubMerkleTree() *StubMerkleTree { return &StubMerkleTree{} }

// AppendLeaf hashes the data and appends the resulting leaf hash.
// In production, Tessera computes RFC6962.HashLeaf(data).
// For testing, SHA-256 is equivalent — both are deterministic.
func (m *StubMerkleTree) AppendLeaf(data []byte) (uint64, error) {
	hash := sha256.Sum256(data)
	m.mu.Lock()
	defer m.mu.Unlock()
	pos := uint64(len(m.leaves))
	m.leaves = append(m.leaves, hash)
	return pos, nil
}

func (m *StubMerkleTree) InclusionProof(position, treeSize uint64) (*types.MerkleProof, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if position >= uint64(len(m.leaves)) {
		return nil, errors.New("position out of range")
	}
	if treeSize > uint64(len(m.leaves)) {
		return nil, errors.New("tree size exceeds current size")
	}
	siblings := m.computePath(position, treeSize)
	return &types.MerkleProof{LeafPosition: position, LeafHash: m.leaves[position], Siblings: siblings, TreeSize: treeSize}, nil
}

func (m *StubMerkleTree) Head() (types.TreeHead, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.leaves) == 0 {
		return types.TreeHead{}, nil
	}
	root := m.computeRoot(0, uint64(len(m.leaves)))
	return types.TreeHead{RootHash: root, TreeSize: uint64(len(m.leaves))}, nil
}

func (m *StubMerkleTree) computePath(position, treeSize uint64) [][32]byte {
	if treeSize <= 1 {
		return nil
	}
	var siblings [][32]byte
	hashes := make([][32]byte, treeSize)
	copy(hashes, m.leaves[:treeSize])
	for len(hashes) > 1 {
		sibIdx := position ^ 1
		if sibIdx < uint64(len(hashes)) {
			siblings = append(siblings, hashes[sibIdx])
		}
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
