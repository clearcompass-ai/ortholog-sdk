package smt

import "github.com/clearcompass-ai/ortholog-sdk/types"

func (t *Tree) GenerateMembershipProof(key [32]byte) (*types.SMTProof, error) {
	leaf, err := t.leaves.Get(key)
	if err != nil { return nil, err }
	if leaf == nil { return nil, nil }
	siblings, err := t.collectSiblings(key)
	if err != nil { return nil, err }
	return &types.SMTProof{Key: key, Leaf: leaf, Siblings: siblings}, nil
}

func (t *Tree) GenerateNonMembershipProof(key [32]byte) (*types.SMTProof, error) {
	leaf, err := t.leaves.Get(key)
	if err != nil { return nil, err }
	if leaf != nil { return nil, nil }
	siblings, err := t.collectSiblings(key)
	if err != nil { return nil, err }
	return &types.SMTProof{Key: key, Leaf: nil, Siblings: siblings}, nil
}

func (t *Tree) collectSiblings(key [32]byte) (map[uint8][32]byte, error) {
	siblings := make(map[uint8][32]byte)
	store, ok := t.leaves.(*InMemoryLeafStore)
	if !ok { return siblings, nil }
	leafHashes := make(map[[32]byte][32]byte)
	store.mu.RLock()
	for k, leaf := range store.store { leafHashes[k] = hashLeaf(leaf) }
	store.mu.RUnlock()
	t.collectSiblingsRecursive(key, leafHashes, TreeDepth, 0, siblings)
	return siblings, nil
}

func (t *Tree) collectSiblingsRecursive(targetKey [32]byte, leafHashes map[[32]byte][32]byte, depth int, bitOffset uint, siblings map[uint8][32]byte) [32]byte {
	if depth == 0 {
		h, ok := leafHashes[targetKey]
		if ok { return h }
		return defaultHashes[0]
	}
	if len(leafHashes) == 0 { return defaultHashes[depth] }
	byteIdx := bitOffset / 8
	bitMask := byte(0x80 >> (bitOffset % 8))
	targetGoesLeft := targetKey[byteIdx]&bitMask == 0
	left := make(map[[32]byte][32]byte)
	right := make(map[[32]byte][32]byte)
	for key, hash := range leafHashes {
		if key[byteIdx]&bitMask == 0 { left[key] = hash } else { right[key] = hash }
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
	if siblingHash != defaultHashes[depth-1] { siblings[uint8(TreeDepth-depth)] = siblingHash }
	return myHash
}
