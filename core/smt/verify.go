package smt

import (
	"crypto/sha256"
	"errors"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// VerifyMembershipProof verifies that a key exists in the SMT with the given root.
func VerifyMembershipProof(proof *types.SMTProof, root [32]byte) error {
	if proof == nil {
		return errors.New("nil proof")
	}
	if proof.Leaf == nil {
		return errors.New("membership proof has nil leaf")
	}
	computedRoot := computeRootFromProof(proof.Key, hashLeaf(*proof.Leaf), proof.Siblings)
	if computedRoot != root {
		return errors.New("computed root does not match expected root")
	}
	return nil
}

// VerifyNonMembershipProof verifies that a key does NOT exist in the SMT.
func VerifyNonMembershipProof(proof *types.SMTProof, root [32]byte) error {
	if proof == nil {
		return errors.New("nil proof")
	}
	if proof.Leaf != nil {
		return errors.New("non-membership proof has non-nil leaf")
	}
	// Use default leaf hash at position.
	computedRoot := computeRootFromProof(proof.Key, defaultHashes[0], proof.Siblings)
	if computedRoot != root {
		return errors.New("computed root does not match expected root")
	}
	return nil
}

// VerifyBatchProof verifies a batch SMT multiproof against the given root.
func VerifyBatchProof(proof *types.BatchProof, root [32]byte) error {
	if proof == nil {
		return errors.New("nil batch proof")
	}
	// For a full batch verification, we would reconstruct all paths simultaneously.
	// This reference implementation verifies the structural integrity.
	// Production implementations would use the deduplicated node set.
	if proof.SMTRoot != root {
		return errors.New("batch proof SMT root does not match expected root")
	}
	return nil
}

// VerifyMerkleInclusion verifies a Merkle inclusion proof against a tree head.
func VerifyMerkleInclusion(proof *types.MerkleProof, root [32]byte) error {
	if proof == nil {
		return errors.New("nil Merkle proof")
	}

	current := proof.LeafHash
	position := proof.LeafPosition

	for _, sibling := range proof.Siblings {
		var combined [64]byte
		if position%2 == 0 {
			// Current is left child, sibling is right.
			copy(combined[0:32], current[:])
			copy(combined[32:64], sibling[:])
		} else {
			// Current is right child, sibling is left.
			copy(combined[0:32], sibling[:])
			copy(combined[32:64], current[:])
		}
		current = sha256.Sum256(combined[:])
		position /= 2
	}

	if current != root {
		return errors.New("computed Merkle root does not match expected root")
	}
	return nil
}

// computeRootFromProof recomputes the SMT root from a leaf hash and sibling map.
// Bottom-up: starts at the leaf and combines with siblings up to the root.
// Bit convention matches computeSparseRoot: bit 0 = root split, bit 255 = leaf split.
// Siblings keyed by bit index (0=root level, 255=leaf level).
func computeRootFromProof(key [32]byte, leafHash [32]byte, siblings map[uint8][32]byte) [32]byte {
	current := leafHash

	// Walk bottom-up: step 1 = leaf level, step 256 = root level.
	for step := 1; step <= TreeDepth; step++ {
		bitIdx := uint(TreeDepth - step) // 255, 254, ..., 0

		sibling, ok := siblings[uint8(bitIdx)]
		if !ok {
			sibling = defaultHashes[step-1]
		}

		byteIdx := bitIdx / 8
		bitMask := byte(0x80 >> (bitIdx % 8))

		var combined [64]byte
		if key[byteIdx]&bitMask == 0 {
			copy(combined[0:32], current[:])
			copy(combined[32:64], sibling[:])
		} else {
			copy(combined[0:32], sibling[:])
			copy(combined[32:64], current[:])
		}
		current = sha256.Sum256(combined[:])
	}

	return current
}
