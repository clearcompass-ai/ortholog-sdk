package smt

import (
	"crypto/sha256"
	"errors"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

func VerifyMembershipProof(proof *types.SMTProof, root [32]byte) error {
	if proof == nil {
		return errors.New("nil proof")
	}
	if proof.Leaf == nil {
		return errors.New("membership proof has nil leaf")
	}
	computed := computeRootFromProof(proof.Key, hashLeaf(*proof.Leaf), proof.Siblings)
	if computed != root {
		return errors.New("computed root does not match expected root")
	}
	return nil
}

func VerifyNonMembershipProof(proof *types.SMTProof, root [32]byte) error {
	if proof == nil {
		return errors.New("nil proof")
	}
	if proof.Leaf != nil {
		return errors.New("non-membership proof has non-nil leaf")
	}
	computed := computeRootFromProof(proof.Key, defaultHashes[0], proof.Siblings)
	if computed != root {
		return errors.New("computed root does not match expected root")
	}
	return nil
}

func VerifyBatchProof(proof *types.BatchProof, root [32]byte) error {
	if proof == nil {
		return errors.New("nil batch proof")
	}
	if proof.SMTRoot != root {
		return errors.New("batch proof SMT root does not match expected root")
	}
	return nil
}

// VerifyMerkleInclusion verifies an RFC 6962 inclusion proof against
// an expected root. Walks the co-path bottom-up using the RFC 6962
// interior hash (SHA-256(0x01 || left || right)) — NOT plain SHA-256.
// The distinction is load-bearing: stub and production logs hash
// interior nodes with the 0x01 domain separator, so a plain-SHA-256
// walk diverges from the stored root by one byte at every level.
//
// Delegates to envelope.MerkleInteriorHash to keep the RFC 6962
// primitive single-sourced in core/envelope/tessera_compat.go. The
// stub tree in merkle_wrap.go uses the same primitive for root
// computation, guaranteeing verifier/prover agreement by construction.
func VerifyMerkleInclusion(proof *types.MerkleProof, root [32]byte) error {
	if proof == nil {
		return errors.New("nil Merkle proof")
	}
	current := proof.LeafHash
	position := proof.LeafPosition
	for _, sibling := range proof.Siblings {
		if position%2 == 0 {
			current = envelope.MerkleInteriorHash(current, sibling)
		} else {
			current = envelope.MerkleInteriorHash(sibling, current)
		}
		position /= 2
	}
	if current != root {
		return errors.New("computed Merkle root does not match expected root")
	}
	return nil
}

func computeRootFromProof(key [32]byte, leafHash [32]byte, siblings map[uint8][32]byte) [32]byte {
	current := leafHash
	for step := 1; step <= TreeDepth; step++ {
		bitIdx := uint(TreeDepth - step)
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
