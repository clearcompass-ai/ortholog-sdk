package smt

import (
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// GenerateMembershipProof generates a proof that key exists in the SMT.
// Returns non-default sibling hashes along the 256-bit path.
// At 10K leaves: avg 13 non-default hashes, ~517 bytes.
func (t *Tree) GenerateMembershipProof(key [32]byte) (*types.SMTProof, error) {
	leaf, err := t.leaves.Get(key)
	if err != nil {
		return nil, err
	}
	if leaf == nil {
		return nil, nil // Key doesn't exist; caller should use non-membership proof.
	}

	siblings, err := t.collectSiblings(key)
	if err != nil {
		return nil, err
	}

	return &types.SMTProof{
		Key:      key,
		Leaf:     leaf,
		Siblings: siblings,
	}, nil
}

// GenerateNonMembershipProof generates a proof that key does NOT exist in the SMT.
// Same structure as membership proof but Leaf is nil (default value at position).
func (t *Tree) GenerateNonMembershipProof(key [32]byte) (*types.SMTProof, error) {
	leaf, err := t.leaves.Get(key)
	if err != nil {
		return nil, err
	}
	if leaf != nil {
		return nil, nil // Key exists; caller should use membership proof.
	}

	siblings, err := t.collectSiblings(key)
	if err != nil {
		return nil, err
	}

	return &types.SMTProof{
		Key:      key,
		Leaf:     nil,
		Siblings: siblings,
	}, nil
}

// collectSiblings collects non-default sibling hashes along the path from leaf to root.
func (t *Tree) collectSiblings(key [32]byte) (map[uint8][32]byte, error) {
	siblings := make(map[uint8][32]byte)

	store, ok := t.leaves.(*InMemoryLeafStore)
	if !ok {
		return siblings, nil
	}

	// Build leaf hash map.
	leafHashes := make(map[[32]byte][32]byte)
	store.mu.RLock()
	for k, leaf := range store.store {
		leafHashes[k] = hashLeaf(leaf)
	}
	store.mu.RUnlock()

	// Walk from leaf to root, collecting the sibling hash at each level.
	t.collectSiblingsRecursive(key, leafHashes, TreeDepth, 0, siblings)

	return siblings, nil
}

// collectSiblingsRecursive recursively computes sibling hashes along the path.
func (t *Tree) collectSiblingsRecursive(
	targetKey [32]byte,
	leafHashes map[[32]byte][32]byte,
	depth int,
	bitOffset uint,
	siblings map[uint8][32]byte,
) [32]byte {
	if depth == 0 {
		h, ok := leafHashes[targetKey]
		if ok {
			return h
		}
		return defaultHashes[0]
	}

	if len(leafHashes) == 0 {
		return defaultHashes[depth]
	}

	// Partition into left/right.
	byteIdx := bitOffset / 8
	bitMask := byte(0x80 >> (bitOffset % 8))
	targetGoesLeft := targetKey[byteIdx]&bitMask == 0

	left := make(map[[32]byte][32]byte)
	right := make(map[[32]byte][32]byte)
	for key, hash := range leafHashes {
		if key[byteIdx]&bitMask == 0 {
			left[key] = hash
		} else {
			right[key] = hash
		}
	}

	var myHash, siblingHash [32]byte
	if targetGoesLeft {
		myHash = t.collectSiblingsRecursive(targetKey, left, depth-1, bitOffset+1, siblings)
		siblingHash = computeSparseRoot(right, depth-1)
	} else {
		siblingHash = computeSparseRoot(left, depth-1)
		myHash = t.collectSiblingsRecursive(targetKey, right, depth-1, bitOffset+1, siblings)
	}
	_ = myHash

	// Only store non-default siblings.
	if siblingHash != defaultHashes[depth-1] {
		siblings[uint8(TreeDepth-depth)] = siblingHash
	}

	return myHash
}
