/*
Package smt — overlay.go implements a write-buffering LeafStore decorator.

OverlayLeafStore wraps a backing LeafStore (typically a persistent one like
PostgresLeafStore) and buffers all writes in memory. Reads fall through to
the backing store only when the overlay has no pending mutation for the key.
The backing store is never modified by any operation on the overlay.

# MOTIVATION

The SDK's ProcessBatch function calls tree.SetLeaf repeatedly as it processes
entries. For an in-memory backing store this is fine — a failed ProcessBatch
call leaves behind in-memory state that the caller can discard by discarding
the tree. But for a persistent backing store (e.g., Postgres), each SetLeaf
call issues a live INSERT that commits independently of ProcessBatch's
completion. If ProcessBatch processes 900 entries and fails on entry 901,
the first 900 leaf mutations are permanently written while the corresponding
delta-buffer and builder-queue updates (which the operator performs
atomically after ProcessBatch returns) are never applied. The SMT state
diverges from the metadata state. Unrecoverable without manual intervention.

# USAGE CONTRACT

The caller invariant is: wrap the backing store, pass the overlay-backed
Tree to ProcessBatch, then — after ProcessBatch succeeds — iterate
result.Mutations and apply each one to the real backing store inside a
single transaction. If ProcessBatch fails, discard the overlay. No
cleanup required; no state is leaked.

# CONCURRENCY

OverlayLeafStore is safe for concurrent use. The buffer and tombstone set
are protected by a sync.RWMutex. The backing store's own concurrency
semantics are unchanged — reads that fall through serialize on whatever
lock the backing store uses.

However, ProcessBatch itself is single-threaded: it iterates entries in
order and makes exactly one SetLeaf call at a time. The mutex exists for
correctness in composition (e.g., a concurrent reader observing a
consistent view), not for internal parallelism.

SEMANTICS — SEMANTIC DIFFERENCES FROM backing

	Get:    returns buffered leaf if present; tombstone if deleted; falls
	        through to backing otherwise. Returned leaf is a deep copy —
	        caller mutation is safe.
	Set:    buffered only. Clears any tombstone for the key.
	SetBatch: same as Set, applied atomically (single mutex hold). Clears
	        tombstones for every key in the batch.
	Delete: adds a tombstone and removes any buffered write for the key.
	        Does NOT call through to backing.
	Count:  reflects the overlay's logical state — backing count plus
	        buffered additions minus tombstoned entries that exist in
	        backing. Non-trivial; O(|buffer| + |tombstones|) backing reads.

Count is the only non-constant-time operation. Callers should not invoke
it on a hot path. The primary use case — ProcessBatch — only calls Count
transitively via Root, which is invoked once per batch at the end.
*/
package smt

import (
	"sync"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// OverlayLeafStore buffers writes to a backing LeafStore in memory.
//
// The overlay never modifies the backing store. Committing overlay state
// to the backing store is the caller's responsibility and happens outside
// the LeafStore interface (via the mutations list returned by
// ProcessBatch).
type OverlayLeafStore struct {
	mu      sync.RWMutex
	backing LeafStore
	buffer  map[[32]byte]types.SMTLeaf
	deleted map[[32]byte]struct{}
}

// NewOverlayLeafStore wraps a backing LeafStore in a write-buffering overlay.
//
// The backing store is not modified by any operation on the returned overlay.
// The overlay holds a reference to backing; callers must not mutate backing
// directly while the overlay is in use, or reads through the overlay may
// observe inconsistent state.
func NewOverlayLeafStore(backing LeafStore) *OverlayLeafStore {
	if backing == nil {
		// Programming error. Panic is appropriate because every call site
		// knows at compile time whether backing is present.
		panic("smt: NewOverlayLeafStore called with nil backing store")
	}
	return &OverlayLeafStore{
		backing: backing,
		buffer:  make(map[[32]byte]types.SMTLeaf),
		deleted: make(map[[32]byte]struct{}),
	}
}

// Get returns the current logical value of the leaf at key, checking the
// overlay first. A buffered write wins over the backing store. A tombstone
// wins over both. The returned pointer is a deep copy — callers may mutate
// it without affecting overlay state.
func (o *OverlayLeafStore) Get(key [32]byte) (*types.SMTLeaf, error) {
	o.mu.RLock()
	if _, tomb := o.deleted[key]; tomb {
		o.mu.RUnlock()
		return nil, nil
	}
	if leaf, ok := o.buffer[key]; ok {
		// Deep copy — leaf is a value type, so = already copies; explicit
		// for documentation.
		cp := leaf
		o.mu.RUnlock()
		return &cp, nil
	}
	o.mu.RUnlock()

	// Fall through to backing. The backing store's returned pointer is
	// handed back directly; its ownership semantics are its own concern.
	return o.backing.Get(key)
}

// Set stores a leaf in the overlay buffer. If the key was tombstoned by a
// prior Delete, the tombstone is cleared — Set "un-deletes" the key.
func (o *OverlayLeafStore) Set(key [32]byte, leaf types.SMTLeaf) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.buffer[key] = leaf
	delete(o.deleted, key)
	return nil
}

// SetBatch applies multiple leaf writes to the overlay atomically (under a
// single mutex acquisition). Tombstones for any of the keys are cleared.
//
// This satisfies the atomicity contract on LeafStore.SetBatch: either all
// leaves are buffered or none are (in practice, either the mutex is held
// for the entire write or it isn't — there is no intermediate observable
// state).
//
// An empty slice is a no-op, including with respect to locking.
func (o *OverlayLeafStore) SetBatch(leaves []types.SMTLeaf) error {
	if len(leaves) == 0 {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, l := range leaves {
		o.buffer[l.Key] = l
		delete(o.deleted, l.Key)
	}
	return nil
}

// Delete marks a key as tombstoned in the overlay. Any buffered write for
// the key is removed. The backing store is not modified.
//
// After Delete, Get returns (nil, nil) for the key, and Count reflects the
// deletion — even if the backing store still has the entry.
func (o *OverlayLeafStore) Delete(key [32]byte) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	delete(o.buffer, key)
	o.deleted[key] = struct{}{}
	return nil
}

// Count returns the logical count of leaves visible through the overlay:
// backing count, plus buffered keys not already in backing, minus
// tombstoned keys that do exist in backing.
//
// This requires O(|buffer| + |tombstones|) Get calls on the backing store
// and is therefore not a cheap operation. Typical usage calls Count at
// most once per batch (from tree.Root), which is acceptable.
//
// An error from the backing store on any probe aborts the count.
func (o *OverlayLeafStore) Count() (int, error) {
	baseline, err := o.backing.Count()
	if err != nil {
		return 0, err
	}

	o.mu.RLock()
	bufferKeys := make([][32]byte, 0, len(o.buffer))
	for k := range o.buffer {
		bufferKeys = append(bufferKeys, k)
	}
	deletedKeys := make([][32]byte, 0, len(o.deleted))
	for k := range o.deleted {
		deletedKeys = append(deletedKeys, k)
	}
	o.mu.RUnlock()

	additions := 0
	for _, k := range bufferKeys {
		existing, err := o.backing.Get(k)
		if err != nil {
			return 0, err
		}
		if existing == nil {
			additions++
		}
	}

	deletions := 0
	for _, k := range deletedKeys {
		existing, err := o.backing.Get(k)
		if err != nil {
			return 0, err
		}
		if existing != nil {
			deletions++
		}
	}

	return baseline + additions - deletions, nil
}

// Mutations returns the pending writes and deletes in the overlay, in
// maps keyed by leaf key. Callers use this to apply the overlay's state
// to the backing store inside a transaction.
//
// Returned maps are copies — caller may mutate them without affecting
// overlay state. Invoked typically once, after ProcessBatch returns,
// inside the operator's transactional commit block.
func (o *OverlayLeafStore) Mutations() (writes map[[32]byte]types.SMTLeaf, deletes map[[32]byte]struct{}) {
	o.mu.RLock()
	defer o.mu.RUnlock()
	writes = make(map[[32]byte]types.SMTLeaf, len(o.buffer))
	for k, v := range o.buffer {
		writes[k] = v
	}
	deletes = make(map[[32]byte]struct{}, len(o.deleted))
	for k := range o.deleted {
		deletes[k] = struct{}{}
	}
	return writes, deletes
}

// Reset empties the overlay, reverting it to a just-constructed state.
// The backing store is not modified. Useful for reusing an overlay across
// multiple ProcessBatch calls without allocating a new one each time.
func (o *OverlayLeafStore) Reset() {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.buffer = make(map[[32]byte]types.SMTLeaf)
	o.deleted = make(map[[32]byte]struct{})
}
