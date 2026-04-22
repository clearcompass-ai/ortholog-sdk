package smt

import (
	"crypto/sha256"
	"sync"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

const TreeDepth = 256

var defaultHashes [TreeDepth + 1][32]byte

func init() {
	defaultHashes[0] = sha256.Sum256(make([]byte, 32))
	for d := 1; d <= TreeDepth; d++ {
		var combined [64]byte
		copy(combined[0:32], defaultHashes[d-1][:])
		copy(combined[32:64], defaultHashes[d-1][:])
		defaultHashes[d] = sha256.Sum256(combined[:])
	}
}

func DefaultHash(depth int) [32]byte {
	if depth < 0 || depth > TreeDepth {
		return [32]byte{}
	}
	return defaultHashes[depth]
}

// LeafReader is the read-only subset of LeafStore.
// Verifiers take this — they never mutate SMT state.
// LeafStore satisfies LeafReader implicitly (Go structural typing).
// InMemoryLeafStore and PostgresLeafStore both satisfy it without changes.
type LeafReader interface {
	Get(key [32]byte) (*types.SMTLeaf, error)
}

// LeafStore is the full read/write interface to SMT leaf storage.
//
// # CONTRACT — ATOMICITY OF SetBatch
//
// Implementations MUST guarantee all-or-nothing semantics for SetBatch:
// if the call returns nil, every leaf in the slice was written. If the
// call returns an error, no leaf was written. There is no partial-success
// state. Implementations that cannot guarantee this (e.g., stores backed
// by best-effort file writes without fsync, or network stores without
// transactional semantics) MUST NOT satisfy this interface.
//
// For persistent implementations, SetBatch typically maps to a single
// multi-row INSERT (Postgres), a batched Write (RocksDB), or an
// equivalent atomic primitive.
type LeafStore interface {
	Get(key [32]byte) (*types.SMTLeaf, error)
	Set(key [32]byte, leaf types.SMTLeaf) error
	SetBatch(leaves []types.SMTLeaf) error
	Delete(key [32]byte) error
	Count() (int, error)
}

type NodeCache interface {
	Get(key [32]byte) ([]byte, bool)
	Set(key [32]byte, value []byte)
}

type Tree struct {
	leaves         LeafStore
	nodeCache      NodeCache
	trackMutations bool
	mutations      []types.LeafMutation
	mutMu          sync.Mutex
}

func NewTree(leaves LeafStore, cache NodeCache) *Tree {
	return &Tree{leaves: leaves, nodeCache: cache}
}

func (t *Tree) StartTracking() {
	t.mutMu.Lock()
	defer t.mutMu.Unlock()
	t.trackMutations = true
	t.mutations = nil
}

func (t *Tree) StopTracking() []types.LeafMutation {
	t.mutMu.Lock()
	defer t.mutMu.Unlock()
	t.trackMutations = false
	result := t.mutations
	t.mutations = nil
	return result
}

func (t *Tree) GetLeaf(key [32]byte) (*types.SMTLeaf, error) { return t.leaves.Get(key) }

// Get implements LeafReader. Aliases GetLeaf so *Tree satisfies the
// read-only LeafReader interface used by core/scope and other readers
// that need only leaf lookup. The two methods are identical; callers
// inside the builder tend to spell it GetLeaf, callers passing *Tree
// as a LeafReader satisfy the interface via this method.
func (t *Tree) Get(key [32]byte) (*types.SMTLeaf, error) { return t.leaves.Get(key) }

// SetLeaf writes a single leaf and, if tracking is active, records a
// mutation describing the before/after state.
//
// For writes that form an atomic group (e.g., the main leaf and its
// intermediate leaf produced by one entry), callers should prefer
// SetLeaves, which commits the group through the backing store's
// atomic SetBatch primitive and records all mutations together.
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

// SetLeaves atomically commits a set of leaves through the backing
// store's SetBatch primitive. If tracking is active, mutation records
// for all leaves are appended together; if the commit fails, no
// mutations are recorded.
//
// Ordering: mutation records are appended in the same order as the
// input slice. Callers that care about downstream ordering (e.g., the
// delta-window buffer) should construct the slice accordingly.
//
// An empty slice is a no-op.
func (t *Tree) SetLeaves(leaves []types.SMTLeaf) error {
	if len(leaves) == 0 {
		return nil
	}

	// Snapshot old values before the commit, under the mutation lock.
	// If tracking is off, we skip the reads entirely — mutation records
	// aren't needed and the reads would be wasted work.
	var oldValues []types.SMTLeaf
	var oldPresent []bool
	if t.trackMutations {
		oldValues = make([]types.SMTLeaf, len(leaves))
		oldPresent = make([]bool, len(leaves))
		t.mutMu.Lock()
		for i, l := range leaves {
			old, _ := t.leaves.Get(l.Key)
			if old != nil {
				oldValues[i] = *old
				oldPresent[i] = true
			}
		}
		t.mutMu.Unlock()
	}

	// Commit atomically. On failure, no mutations are recorded.
	if err := t.leaves.SetBatch(leaves); err != nil {
		return err
	}

	// Record mutations only after successful commit.
	if t.trackMutations {
		t.mutMu.Lock()
		for i, l := range leaves {
			mut := types.LeafMutation{
				LeafKey:         l.Key,
				NewOriginTip:    l.OriginTip,
				NewAuthorityTip: l.AuthorityTip,
			}
			if oldPresent[i] {
				mut.OldOriginTip = oldValues[i].OriginTip
				mut.OldAuthorityTip = oldValues[i].AuthorityTip
			}
			t.mutations = append(t.mutations, mut)
		}
		t.mutMu.Unlock()
	}
	return nil
}

func (t *Tree) Root() ([32]byte, error) {
	count, err := t.leaves.Count()
	if err != nil {
		return [32]byte{}, err
	}
	if count == 0 {
		return defaultHashes[TreeDepth], nil
	}
	return t.computeRoot()
}

func (t *Tree) computeRoot() ([32]byte, error) {
	leafHashes, ok := collectLeafHashes(t.leaves)
	if !ok {
		return defaultHashes[TreeDepth], nil
	}
	if len(leafHashes) == 0 {
		return defaultHashes[TreeDepth], nil
	}
	return computeSparseRootCached(leafHashes, TreeDepth, [32]byte{}, t.nodeCache), nil
}

// collectLeafHashes returns the effective leaf hashes for a LeafStore that
// the SMT can iterate. It recognizes *InMemoryLeafStore directly and
// *OverlayLeafStore over an enumerable backing. For any other store type
// the second return value is false and the caller should fall back to the
// empty-tree hash (matching pre-existing behavior).
func collectLeafHashes(store LeafStore) (map[[32]byte][32]byte, bool) {
	switch s := store.(type) {
	case *InMemoryLeafStore:
		s.mu.RLock()
		out := make(map[[32]byte][32]byte, len(s.store))
		for key, leaf := range s.store {
			out[key] = hashLeaf(leaf)
		}
		s.mu.RUnlock()
		return out, true
	case *OverlayLeafStore:
		base, ok := collectLeafHashes(s.backing)
		if !ok {
			return nil, false
		}
		s.mu.RLock()
		for key, leaf := range s.buffer {
			base[key] = hashLeaf(leaf)
		}
		for key := range s.deleted {
			delete(base, key)
		}
		s.mu.RUnlock()
		return base, true
	default:
		return nil, false
	}
}

func hashLeaf(leaf types.SMTLeaf) [32]byte {
	var data []byte
	data = append(data, leaf.Key[:]...)
	data = append(data, []byte(leaf.OriginTip.LogDID)...)
	b := make([]byte, 8)
	for i := 0; i < 8; i++ {
		b[i] = byte(leaf.OriginTip.Sequence >> (56 - uint(i)*8))
	}
	data = append(data, b...)
	data = append(data, []byte(leaf.AuthorityTip.LogDID)...)
	for i := 0; i < 8; i++ {
		b[i] = byte(leaf.AuthorityTip.Sequence >> (56 - uint(i)*8))
	}
	data = append(data, b...)
	return sha256.Sum256(data)
}

func computeSparseRoot(leafHashes map[[32]byte][32]byte, depth int) [32]byte {
	if depth == 0 {
		if len(leafHashes) == 0 {
			return defaultHashes[0]
		}
		for _, h := range leafHashes {
			return h
		}
	}
	bitIdx := uint(TreeDepth - depth)
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

// nodeCacheKey returns a stable cache key identifying the interior SMT
// node at (depth, prefix). Only the top (TreeDepth - depth) bits of
// prefix are significant; lower bits MUST be zero. The depth is encoded
// in the leading byte to disambiguate nodes that share a prefix at
// different levels.
//
// Encoding: sha256(depth_be16 || prefix_32B). The hash gives a uniform
// 32-byte cache key suited to NodeCache's interface, and the depth-prefix
// composition is collision-free because depth is encoded explicitly.
func nodeCacheKey(depth int, prefix [32]byte) [32]byte {
	var raw [34]byte
	raw[0] = byte(depth >> 8)
	raw[1] = byte(depth)
	copy(raw[2:], prefix[:])
	return sha256.Sum256(raw[:])
}

// computeSparseRootCached is computeSparseRoot that additionally records
// each interior node hash into cache, keyed by (depth, prefix). Subsequent
// ComputeDirtyRoot calls consult this cache to avoid descending into clean
// subtrees, achieving O(M log N) rather than O(N) per batch.
func computeSparseRootCached(leafHashes map[[32]byte][32]byte, depth int, prefix [32]byte, cache NodeCache) [32]byte {
	if depth == 0 {
		if len(leafHashes) == 0 {
			return defaultHashes[0]
		}
		for _, h := range leafHashes {
			cache.Set(nodeCacheKey(0, prefix), h[:])
			return h
		}
	}
	bitIdx := uint(TreeDepth - depth)
	byteIdx := bitIdx / 8
	bitMask := byte(0x80 >> (bitIdx % 8))

	left := make(map[[32]byte][32]byte)
	right := make(map[[32]byte][32]byte)
	for key, hash := range leafHashes {
		if key[byteIdx]&bitMask == 0 {
			left[key] = hash
		} else {
			right[key] = hash
		}
	}

	leftPrefix := prefix
	rightPrefix := prefix
	rightPrefix[byteIdx] |= bitMask

	var leftHash, rightHash [32]byte
	if len(left) == 0 {
		leftHash = defaultHashes[depth-1]
	} else {
		leftHash = computeSparseRootCached(left, depth-1, leftPrefix, cache)
	}
	if len(right) == 0 {
		rightHash = defaultHashes[depth-1]
	} else {
		rightHash = computeSparseRootCached(right, depth-1, rightPrefix, cache)
	}
	var combined [64]byte
	copy(combined[0:32], leftHash[:])
	copy(combined[32:64], rightHash[:])
	h := sha256.Sum256(combined[:])
	cache.Set(nodeCacheKey(depth, prefix), h[:])
	return h
}

// ComputeDirtyRoot recomputes the SMT root after applying writes against
// a known prior root, walking only the modified branches.
//
// CALLER CONTRACT: the tree's NodeCache must be warm with respect to
// priorRoot. The required warmth is achieved by calling tree.Root() once
// against the prior leaf state (the existing computeRoot populates the
// cache as it descends). Subsequent ComputeDirtyRoot calls reuse those
// cached hashes for any subtree containing no dirty leaves.
//
// Cold-cache behavior: if a clean sibling's hash is absent from the cache,
// the function falls back to the empty-subtree default hash for that depth.
// This produces a correct root only if the clean subtree is genuinely
// empty in the prior tree. Callers that cannot guarantee a warm cache
// should use tree.Root() for full recomputation instead.
//
// Cost: O(M log N) where M is len(writes) and N is the leaf count, given
// a warm cache.
func (t *Tree) ComputeDirtyRoot(priorRoot [32]byte, writes map[[32]byte]types.SMTLeaf) ([32]byte, error) {
	if len(writes) == 0 {
		return priorRoot, nil
	}
	dirty := make(map[[32]byte][32]byte, len(writes))
	for key, leaf := range writes {
		dirty[key] = hashLeaf(leaf)
	}
	return computeDirtyRootRec(dirty, TreeDepth, [32]byte{}, t.nodeCache), nil
}

func computeDirtyRootRec(dirty map[[32]byte][32]byte, depth int, prefix [32]byte, cache NodeCache) [32]byte {
	if depth == 0 {
		// Leaf level: return the dirty leaf hash if present, else fall back
		// to the cached prior leaf hash, else empty-leaf default.
		if len(dirty) == 1 {
			for _, h := range dirty {
				cache.Set(nodeCacheKey(0, prefix), h[:])
				return h
			}
		}
		if cached, ok := cache.Get(nodeCacheKey(0, prefix)); ok && len(cached) == 32 {
			var out [32]byte
			copy(out[:], cached)
			return out
		}
		return defaultHashes[0]
	}

	if len(dirty) == 0 {
		// Clean subtree — use cached interior hash, or default if cold.
		if cached, ok := cache.Get(nodeCacheKey(depth, prefix)); ok && len(cached) == 32 {
			var out [32]byte
			copy(out[:], cached)
			return out
		}
		return defaultHashes[depth]
	}

	bitIdx := uint(TreeDepth - depth)
	byteIdx := bitIdx / 8
	bitMask := byte(0x80 >> (bitIdx % 8))

	left := make(map[[32]byte][32]byte)
	right := make(map[[32]byte][32]byte)
	for key, hash := range dirty {
		if key[byteIdx]&bitMask == 0 {
			left[key] = hash
		} else {
			right[key] = hash
		}
	}

	leftPrefix := prefix
	rightPrefix := prefix
	rightPrefix[byteIdx] |= bitMask

	leftHash := computeDirtyRootRec(left, depth-1, leftPrefix, cache)
	rightHash := computeDirtyRootRec(right, depth-1, rightPrefix, cache)

	var combined [64]byte
	copy(combined[0:32], leftHash[:])
	copy(combined[32:64], rightHash[:])
	h := sha256.Sum256(combined[:])
	cache.Set(nodeCacheKey(depth, prefix), h[:])
	return h
}

type InMemoryLeafStore struct {
	mu    sync.RWMutex
	store map[[32]byte]types.SMTLeaf
}

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

// SetBatch writes all leaves atomically under a single lock acquisition.
// Either every leaf in the slice is stored or — in the extraordinarily
// unlikely event of a runtime panic between map writes — the caller's
// observable state is whatever the map holds when the lock is released.
//
// In practice, map writes do not fail at runtime, so this implementation
// satisfies the strict atomicity contract: callers observe either the
// pre-call state or the fully post-call state, never an intermediate.
func (s *InMemoryLeafStore) SetBatch(leaves []types.SMTLeaf) error {
	if len(leaves) == 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, l := range leaves {
		s.store[l.Key] = l
	}
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

type InMemoryNodeCache struct {
	mu    sync.RWMutex
	store map[[32]byte][]byte
}

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
