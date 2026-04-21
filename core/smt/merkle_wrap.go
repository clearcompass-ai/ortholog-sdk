/*
FILE PATH:

	core/smt/merkle_wrap.go

DESCRIPTION:

	In-memory RFC 6962 Merkle tree used by SDK tests and any consumer
	that needs a non-persistent, byte-for-byte Tessera-equivalent
	transparency log.

	This implementation is NOT a production log. Its purpose is to
	produce hashes and proofs that match what a real Tessera log would
	produce for the same input data, so tests that pass against the
	stub produce the same byte outputs in production.

KEY ARCHITECTURAL DECISIONS:
  - RFC 6962 §2.1 compliance is LOAD-BEARING:
    Leaf hash:     SHA-256(0x00 || data)     [RFC6962LeafPrefix]
    Interior hash: SHA-256(0x01 || l || r)   [RFC6962NodePrefix]
    These domain separators are what make a Merkle tree
    second-preimage-resistant. A tree without them is a different
    hash structure — not interoperable with Tessera or any other
    RFC 6962 verifier.
  - Delegates leaf and interior hashing to envelope.EntryLeafHashBytes
    and envelope.MerkleInteriorHash. Every SDK path that constructs
    RFC 6962 hashes goes through those two primitives. If they ever
    change (they should not), this stub follows automatically.
  - Incomplete-pair ("orphan") promotion: when an odd leaf has no
    sibling at a given level, it is promoted unchanged to the next
    level. This matches RFC 6962 §2.1 ("if there is an odd number of
    elements, the last one is promoted to the next level").
  - AppendLeaf returns the leaf position (0-indexed). Callers use this
    position in subsequent InclusionProof calls.
  - Sync is coarse-grained (single mutex). The stub is not performance-
    critical; correctness over throughput.

OVERVIEW:

	Usage:
	    tree := smt.NewStubMerkleTree()
	    pos, _ := tree.AppendLeaf(canonicalBytes)
	    head, _ := tree.Head()
	    proof, _ := tree.InclusionProof(pos, head.TreeSize)
	    // proof.LeafHash == envelope.EntryLeafHashBytes(canonicalBytes)
	    // proof verifies against head.RootHash via RFC 6962 path.

KEY DEPENDENCIES:
  - core/envelope/tessera_compat.go: EntryLeafHashBytes,
    MerkleInteriorHash (single source of truth for RFC 6962 primitives)
  - types.MerkleProof, types.TreeHead
*/
package smt

import (
	"errors"
	"sync"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// MerkleTree is the append-only Merkle tree interface.
//
// AppendLeaf takes raw entry data (full wire bytes in production).
// The implementation MUST compute the RFC 6962 leaf hash internally;
// callers never pre-hash. This mirrors Tessera's contract, where the
// server computes rfc6962.DefaultHasher.HashLeaf(data).
type MerkleTree interface {
	AppendLeaf(data []byte) (uint64, error)
	InclusionProof(position, treeSize uint64) (*types.MerkleProof, error)
	Head() (types.TreeHead, error)
}

// StubMerkleTree is an in-memory RFC 6962-compliant Merkle tree.
//
// Byte-for-byte equivalent to a real Tessera log for the same input
// data. Tests that pass against this stub will pass against production
// Tessera; tests that fail against production Tessera will fail here
// too. That equivalence is the stub's entire purpose.
type StubMerkleTree struct {
	mu     sync.Mutex
	leaves [][32]byte // RFC 6962 leaf hashes (already 0x00-prefixed).
}

// NewStubMerkleTree returns an empty tree.
func NewStubMerkleTree() *StubMerkleTree { return &StubMerkleTree{} }

// AppendLeaf computes the RFC 6962 leaf hash of data and appends it.
// Returns the 0-indexed position of the new leaf.
//
// Leaf hash: SHA-256(0x00 || data).
func (m *StubMerkleTree) AppendLeaf(data []byte) (uint64, error) {
	leafHash := envelope.EntryLeafHashBytes(data)
	m.mu.Lock()
	defer m.mu.Unlock()
	pos := uint64(len(m.leaves))
	m.leaves = append(m.leaves, leafHash)
	return pos, nil
}

// InclusionProof returns a Merkle inclusion proof for the leaf at
// `position` within a tree of size `treeSize`.
//
// The returned proof's LeafHash is the RFC 6962 leaf hash produced by
// AppendLeaf — identical to envelope.EntryLeafHashBytes of the bytes
// that were appended. Cross-log verifiers check that this field matches
// an independently-computed entry hash.
func (m *StubMerkleTree) InclusionProof(position, treeSize uint64) (*types.MerkleProof, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if position >= uint64(len(m.leaves)) {
		return nil, errors.New("smt: position out of range")
	}
	if treeSize > uint64(len(m.leaves)) {
		return nil, errors.New("smt: tree size exceeds current size")
	}
	if position >= treeSize {
		return nil, errors.New("smt: position exceeds tree size")
	}
	siblings := m.computePath(position, treeSize)
	return &types.MerkleProof{
		LeafPosition: position,
		LeafHash:     m.leaves[position],
		Siblings:     siblings,
		TreeSize:     treeSize,
	}, nil
}

// Head returns the current tree head (root hash and size).
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

// computePath returns the sibling path from the leaf at `position` up
// to the root, using RFC 6962 interior node hashing.
//
// Caller must hold m.mu.
func (m *StubMerkleTree) computePath(position, treeSize uint64) [][32]byte {
	if treeSize <= 1 {
		return nil
	}
	var siblings [][32]byte

	// Snapshot the leaves for this tree size and walk up.
	hashes := make([][32]byte, treeSize)
	copy(hashes, m.leaves[:treeSize])

	for len(hashes) > 1 {
		sibIdx := position ^ 1
		if sibIdx < uint64(len(hashes)) {
			siblings = append(siblings, hashes[sibIdx])
		}
		hashes = hashLevel(hashes)
		position /= 2
	}
	return siblings
}

// computeRoot returns the RFC 6962 Merkle root over m.leaves[start:end].
//
// Caller must hold m.mu.
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
		hashes = hashLevel(hashes)
	}
	return hashes[0]
}

// hashLevel reduces one level of the tree using RFC 6962 interior
// hashing for paired nodes. An odd final node is promoted unchanged
// to the next level (RFC 6962 §2.1 orphan-promotion rule).
func hashLevel(hashes [][32]byte) [][32]byte {
	next := make([][32]byte, (len(hashes)+1)/2)
	for i := 0; i < len(hashes); i += 2 {
		if i+1 < len(hashes) {
			next[i/2] = envelope.MerkleInteriorHash(hashes[i], hashes[i+1])
		} else {
			// Orphan: promote unchanged.
			next[i/2] = hashes[i]
		}
	}
	return next
}
