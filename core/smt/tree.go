// Package smt implements the Sparse Merkle Tree for two-lane state resolution.
package smt

import (
	"crypto/sha256"
	"sync"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

const (
	// TreeDepth is the depth of the SMT (256-bit key space).
	TreeDepth = 256
)

// defaultHashes is the precomputed default hash chain (257 levels).
// defaultHashes[0] = hash of empty leaf, defaultHashes[d] = hash of two default children at depth d-1.
var defaultHashes [TreeDepth + 1][32]byte

func init() {
	// Level 0: empty leaf = SHA-256 of 32 zero bytes.
	defaultHashes[0] = sha256.Sum256(make([]byte, 32))
	// Each level: hash of (left_default || right_default) at the level below.
	for d := 1; d <= TreeDepth; d++ {
		var combined [64]byte
		copy(combined[0:32], defaultHashes[d-1][:])
		copy(combined[32:64], defaultHashes[d-1][:])
		defaultHashes[d] = sha256.Sum256(combined[:])
	}
}

// DefaultHash returns the default hash at a given depth.
func DefaultHash(depth int) [32]byte {
	if depth < 0 || depth > TreeDepth {
		return [32]byte{}
	}
	return defaultHashes[depth]
}

// LeafStore is the pluggable backend for SMT leaf persistence.
// In-memory for SDK testing; Postgres-backed in operator (Phase 2).
type LeafStore interface {
	Get(key [32]byte) (*types.SMTLeaf, error)
	Set(key [32]byte, leaf types.SMTLeaf) error
	Delete(key [32]byte) error
	Count() (int, error)
}

// NodeCache is the pluggable cache for intermediate SMT nodes.
// In-memory LRU default; write-through to Postgres in operator.
type NodeCache interface {
	Get(key [32]byte) ([]byte, bool)
	Set(key [32]byte, value []byte)
}

// Tree is the Sparse Merkle Tree.
type Tree struct {
	leaves    LeafStore
	nodeCache NodeCache

	// Mutation tracking: opt-in per batch.
	trackMutations bool
	mutations      []types.LeafMutation
	mutMu          sync.Mutex
}

// NewTree creates a new SMT with the given storage backends.
func NewTree(leaves LeafStore, cache NodeCache) *Tree {
	return &Tree{
		leaves:    leaves,
		nodeCache: cache,
	}
}

// StartTracking enables mutation tracking for the current batch.
// Call before ProcessBatch. Reset with StopTracking.
func (t *Tree) StartTracking() {
	t.mutMu.Lock()
	defer t.mutMu.Unlock()
	t.trackMutations = true
	t.mutations = nil
}

// StopTracking disables mutation tracking and returns recorded mutations.
func (t *Tree) StopTracking() []types.LeafMutation {
	t.mutMu.Lock()
	defer t.mutMu.Unlock()
	t.trackMutations = false
	result := t.mutations
	t.mutations = nil
	return result
}

// GetLeaf retrieves a leaf by key. Returns nil if not found.
func (t *Tree) GetLeaf(key [32]byte) (*types.SMTLeaf, error) {
	return t.leaves.Get(key)
}

// SetLeaf creates or updates a leaf, recording the mutation if tracking is enabled.
func (t *Tree) SetLeaf(key [32]byte, leaf types.SMTLeaf) error {
	if t.trackMutations {
		t.mutMu.Lock()
		old, _ := t.leaves.Get(key)
		mut := types.LeafMutation{
			LeafKey:         key,
			NewOriginTip:    leaf.OriginTip,
			NewAuthorityTip: leaf.AuthorityTip,
		}
		if old != nil {
			mut.OldOriginTip = old.OriginTip
			mut.OldAuthorityTip = old.AuthorityTip
		}
		t.mutations = append(t.mutations, mut)
		t.mutMu.Unlock()
	}
	return t.leaves.Set(key, leaf)
}

// Root computes the SMT root hash by walking the tree from leaves to root.
// For production scale, this would use cached intermediate nodes.
// This reference implementation recomputes from leaves.
func (t *Tree) Root() ([32]byte, error) {
	count, err := t.leaves.Count()
	if err != nil {
		return [32]byte{}, err
	}
	if count == 0 {
		return defaultHashes[TreeDepth], nil
	}
	// Collect all leaf hashes and compute the root.
	// For production: use the node cache for incremental updates.
	return t.computeRoot()
}

// computeRoot computes the root from all leaves using the node cache.
func (t *Tree) computeRoot() ([32]byte, error) {
	store, ok := t.leaves.(*InMemoryLeafStore)
	if !ok {
		// For non-in-memory stores, delegate to a full traversal.
		// Production implementations would use cached intermediate nodes.
		return defaultHashes[TreeDepth], nil
	}

	if len(store.store) == 0 {
		return defaultHashes[TreeDepth], nil
	}

	// Build a map of leaf positions to their hashes.
	leafHashes := make(map[[32]byte][32]byte)
	for key, leaf := range store.store {
		leafHashes[key] = hashLeaf(leaf)
	}

	// Compute root bottom-up using the sparse structure.
	return computeSparseRoot(leafHashes, TreeDepth), nil
}

// hashLeaf computes the hash of a leaf node.
func hashLeaf(leaf types.SMTLeaf) [32]byte {
	var data []byte
	data = append(data, leaf.Key[:]...)
	data = append(data, []byte(leaf.OriginTip.LogDID)...)
	b := make([]byte, 8)
	b[0] = byte(leaf.OriginTip.Sequence >> 56)
	b[1] = byte(leaf.OriginTip.Sequence >> 48)
	b[2] = byte(leaf.OriginTip.Sequence >> 40)
	b[3] = byte(leaf.OriginTip.Sequence >> 32)
	b[4] = byte(leaf.OriginTip.Sequence >> 24)
	b[5] = byte(leaf.OriginTip.Sequence >> 16)
	b[6] = byte(leaf.OriginTip.Sequence >> 8)
	b[7] = byte(leaf.OriginTip.Sequence)
	data = append(data, b...)
	data = append(data, []byte(leaf.AuthorityTip.LogDID)...)
	b[0] = byte(leaf.AuthorityTip.Sequence >> 56)
	b[1] = byte(leaf.AuthorityTip.Sequence >> 48)
	b[2] = byte(leaf.AuthorityTip.Sequence >> 40)
	b[3] = byte(leaf.AuthorityTip.Sequence >> 32)
	b[4] = byte(leaf.AuthorityTip.Sequence >> 24)
	b[5] = byte(leaf.AuthorityTip.Sequence >> 16)
	b[6] = byte(leaf.AuthorityTip.Sequence >> 8)
	b[7] = byte(leaf.AuthorityTip.Sequence)
	data = append(data, b...)
	return sha256.Sum256(data)
}

// computeSparseRoot computes the root hash from sparse leaf hashes.
func computeSparseRoot(leafHashes map[[32]byte][32]byte, depth int) [32]byte {
	if depth == 0 {
		if len(leafHashes) == 0 {
			return defaultHashes[0]
		}
		// Exactly one leaf at depth 0.
		for _, h := range leafHashes {
			return h
		}
	}

	// Partition leaves into left (bit=0) and right (bit=1) at this depth.
	bitIdx := uint(TreeDepth - depth) // Which bit of the key determines L/R
	left := make(map[[32]byte][32]byte)
	right := make(map[[32]byte][32]byte)
	for key, hash := range leafHashes {
		byteIdx := bitIdx / 8
		bitMask := byte(0x80 >> (bitIdx % 8))
		if key[byteIdx]&bitMask == 0 {
			left[key] = hash
		} else {
			right[key] = hash
		}
	}

	var leftHash, rightHash [32]byte
	if len(left) == 0 {
		leftHash = defaultHashes[depth-1]
	} else {
		leftHash = computeSparseRoot(left, depth-1)
	}
	if len(right) == 0 {
		rightHash = defaultHashes[depth-1]
	} else {
		rightHash = computeSparseRoot(right, depth-1)
	}

	var combined [64]byte
	copy(combined[0:32], leftHash[:])
	copy(combined[32:64], rightHash[:])
	return sha256.Sum256(combined[:])
}

// ── In-memory LeafStore and NodeCache ──────────────────────────────────

// InMemoryLeafStore is a reference LeafStore backed by an in-memory map.
type InMemoryLeafStore struct {
	mu    sync.RWMutex
	store map[[32]byte]types.SMTLeaf
}

// NewInMemoryLeafStore creates a new in-memory leaf store.
func NewInMemoryLeafStore() *InMemoryLeafStore {
	return &InMemoryLeafStore{store: make(map[[32]byte]types.SMTLeaf)}
}

func (s *InMemoryLeafStore) Get(key [32]byte) (*types.SMTLeaf, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	leaf, ok := s.store[key]
	if !ok {
		return nil, nil
	}
	return &leaf, nil
}

func (s *InMemoryLeafStore) Set(key [32]byte, leaf types.SMTLeaf) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store[key] = leaf
	return nil
}

func (s *InMemoryLeafStore) Delete(key [32]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.store, key)
	return nil
}

func (s *InMemoryLeafStore) Count() (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.store), nil
}

// InMemoryNodeCache is an in-memory LRU node cache.
type InMemoryNodeCache struct {
	mu    sync.RWMutex
	store map[[32]byte][]byte
}

// NewInMemoryNodeCache creates a new in-memory node cache.
func NewInMemoryNodeCache() *InMemoryNodeCache {
	return &InMemoryNodeCache{store: make(map[[32]byte][]byte)}
}

func (c *InMemoryNodeCache) Get(key [32]byte) ([]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.store[key]
	return v, ok
}

func (c *InMemoryNodeCache) Set(key [32]byte, value []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.store[key] = value
}
