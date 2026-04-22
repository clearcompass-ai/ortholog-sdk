package smt

import (
	"crypto/rand"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// makeLeaf is a tiny constructor used by the dirty-root tests.
func makeLeaf(key [32]byte, originSeq, authSeq uint64) types.SMTLeaf {
	return types.SMTLeaf{
		Key:          key,
		OriginTip:    types.LogPosition{LogDID: "did:test:log", Sequence: originSeq},
		AuthorityTip: types.LogPosition{LogDID: "did:test:log", Sequence: authSeq},
	}
}

func keyN(n byte) [32]byte {
	var k [32]byte
	k[0] = n
	return k
}

func randomKey(t *testing.T) [32]byte {
	t.Helper()
	var k [32]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return k
}

// ─────────────────────────────────────────────────────────────────────
// ComputeDirtyRoot semantics
// ─────────────────────────────────────────────────────────────────────

func TestComputeDirtyRoot_EmptyWritesReturnsPriorRoot(t *testing.T) {
	tree := NewTree(NewInMemoryLeafStore(), NewInMemoryNodeCache())
	prior := [32]byte{0xAB, 0xCD}

	got, err := tree.ComputeDirtyRoot(prior, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if got != prior {
		t.Fatalf("expected priorRoot to be returned unchanged when writes is nil")
	}
}

// TestComputeDirtyRoot_MatchesFullRecompute_Genesis: starting from an empty
// tree, applying writes via ComputeDirtyRoot must yield the same root as
// recomputing from scratch with the writes as the only leaves.
func TestComputeDirtyRoot_MatchesFullRecompute_Genesis(t *testing.T) {
	cache := NewInMemoryNodeCache()
	tree := NewTree(NewInMemoryLeafStore(), cache)

	// Prior root is the empty-tree root (computed with no leaves);
	// the cache stays cold for genesis, but every clean sibling is
	// genuinely empty so the default-hash fallback is correct.
	priorRoot, err := tree.Root()
	if err != nil {
		t.Fatalf("prior Root: %v", err)
	}

	writes := map[[32]byte]types.SMTLeaf{
		keyN(0x01): makeLeaf(keyN(0x01), 1, 1),
		keyN(0x80): makeLeaf(keyN(0x80), 2, 2),
	}

	got, err := tree.ComputeDirtyRoot(priorRoot, writes)
	if err != nil {
		t.Fatalf("ComputeDirtyRoot: %v", err)
	}

	// Reference: full recompute over the same leaf set.
	refStore := NewInMemoryLeafStore()
	for _, leaf := range writes {
		_ = refStore.Set(leaf.Key, leaf)
	}
	refTree := NewTree(refStore, NewInMemoryNodeCache())
	want, err := refTree.Root()
	if err != nil {
		t.Fatalf("ref Root: %v", err)
	}

	if got != want {
		t.Fatalf("dirty root != full recompute\n  got:  %x\n  want: %x", got, want)
	}
}

// TestComputeDirtyRoot_MatchesFullRecompute_PartialRange is the BUG-017
// scenario at the SMT level: a non-empty prior tree, plus a batch of
// mutations. Dirty-root with a warm cache must match a full recompute
// over the merged leaf set.
func TestComputeDirtyRoot_MatchesFullRecompute_PartialRange(t *testing.T) {
	prior := NewInMemoryLeafStore()
	for _, k := range []byte{0x01, 0x02, 0x10, 0x20, 0x80, 0xC0} {
		_ = prior.Set(keyN(k), makeLeaf(keyN(k), uint64(k), uint64(k)))
	}

	cache := NewInMemoryNodeCache()
	tree := NewTree(prior, cache)

	priorRoot, err := tree.Root() // warms the cache
	if err != nil {
		t.Fatalf("prior Root: %v", err)
	}

	// Mutations: update one existing leaf, add one new leaf.
	writes := map[[32]byte]types.SMTLeaf{
		keyN(0x10): makeLeaf(keyN(0x10), 999, 999), // updated
		keyN(0x40): makeLeaf(keyN(0x40), 40, 40),   // new
	}

	gotRoot, err := tree.ComputeDirtyRoot(priorRoot, writes)
	if err != nil {
		t.Fatalf("ComputeDirtyRoot: %v", err)
	}

	// Reference: full recompute over (prior leaves with updates applied)
	refStore := NewInMemoryLeafStore()
	for _, k := range []byte{0x01, 0x02, 0x10, 0x20, 0x80, 0xC0} {
		_ = refStore.Set(keyN(k), makeLeaf(keyN(k), uint64(k), uint64(k)))
	}
	for k, leaf := range writes {
		_ = refStore.Set(k, leaf)
	}
	refTree := NewTree(refStore, NewInMemoryNodeCache())
	wantRoot, err := refTree.Root()
	if err != nil {
		t.Fatalf("ref Root: %v", err)
	}

	if gotRoot != wantRoot {
		t.Fatalf("dirty root mismatch\n  got:  %x\n  want: %x", gotRoot, wantRoot)
	}
}

// TestComputeDirtyRoot_OverlayLeafStore validates the verifier scenario:
// priorState wrapped in OverlayLeafStore, replay buffered writes via the
// overlay, then ComputeDirtyRoot using the overlay's pending mutations.
func TestComputeDirtyRoot_OverlayLeafStore(t *testing.T) {
	priorBacking := NewInMemoryLeafStore()
	for _, k := range []byte{0x05, 0x55, 0xAA} {
		_ = priorBacking.Set(keyN(k), makeLeaf(keyN(k), uint64(k), uint64(k)))
	}

	overlay := NewOverlayLeafStore(priorBacking)
	cache := NewInMemoryNodeCache()
	tree := NewTree(overlay, cache)

	priorRoot, err := tree.Root() // warms cache through overlay -> backing
	if err != nil {
		t.Fatalf("prior Root: %v", err)
	}

	// Simulate a replay writing to the overlay (the buffer).
	_ = overlay.Set(keyN(0x55), makeLeaf(keyN(0x55), 5500, 5500)) // update
	_ = overlay.Set(keyN(0xF0), makeLeaf(keyN(0xF0), 240, 240))   // insert

	writes, _ := overlay.Mutations()
	gotRoot, err := tree.ComputeDirtyRoot(priorRoot, writes)
	if err != nil {
		t.Fatalf("ComputeDirtyRoot: %v", err)
	}

	// Reference: full recompute over the overlay's effective state.
	refTree := NewTree(overlay, NewInMemoryNodeCache())
	wantRoot, err := refTree.Root()
	if err != nil {
		t.Fatalf("ref Root: %v", err)
	}

	if gotRoot != wantRoot {
		t.Fatalf("overlay dirty root mismatch\n  got:  %x\n  want: %x", gotRoot, wantRoot)
	}
}

// TestComputeDirtyRoot_ColdCacheMatchesEmptyPrior is a sanity probe:
// against an empty prior tree (cold cache, but truly empty), ComputeDirtyRoot
// matches a full recompute. This guards against the cache-miss fallback
// being wrong in the genuinely-empty case.
func TestComputeDirtyRoot_ColdCacheMatchesEmptyPrior(t *testing.T) {
	cache := NewInMemoryNodeCache()
	tree := NewTree(NewInMemoryLeafStore(), cache)

	emptyRoot := DefaultHash(TreeDepth)

	writes := map[[32]byte]types.SMTLeaf{
		keyN(0x42): makeLeaf(keyN(0x42), 42, 42),
	}

	got, err := tree.ComputeDirtyRoot(emptyRoot, writes)
	if err != nil {
		t.Fatalf("ComputeDirtyRoot: %v", err)
	}

	refStore := NewInMemoryLeafStore()
	_ = refStore.Set(keyN(0x42), makeLeaf(keyN(0x42), 42, 42))
	want, err := NewTree(refStore, NewInMemoryNodeCache()).Root()
	if err != nil {
		t.Fatalf("ref: %v", err)
	}

	if got != want {
		t.Fatalf("cold-empty dirty root mismatch\n  got:  %x\n  want: %x", got, want)
	}
}

// TestComputeDirtyRoot_WarmCacheAvoidsLeafReads verifies the steady-state
// performance contract: once Root() has warmed the cache, ComputeDirtyRoot
// completes without consulting the LeafStore at all (clean siblings come
// from the cache, dirty leaves come from the writes argument).
func TestComputeDirtyRoot_WarmCacheAvoidsLeafReads(t *testing.T) {
	priorBacking := NewInMemoryLeafStore()
	for i := byte(0); i < 16; i++ {
		_ = priorBacking.Set(keyN(i), makeLeaf(keyN(i), uint64(i), uint64(i)))
	}

	counting := &countingLeafStore{inner: priorBacking}
	cache := NewInMemoryNodeCache()
	tree := NewTree(counting, cache)

	// Warm the cache.
	priorRoot, err := tree.Root()
	if err != nil {
		t.Fatalf("Root: %v", err)
	}
	counting.gets = 0 // reset after warm-up

	// Run ComputeDirtyRoot — must not call Get on the underlying store.
	writes := map[[32]byte]types.SMTLeaf{
		keyN(0x00): makeLeaf(keyN(0x00), 9999, 9999),
	}
	if _, err := tree.ComputeDirtyRoot(priorRoot, writes); err != nil {
		t.Fatalf("ComputeDirtyRoot: %v", err)
	}
	if counting.gets != 0 {
		t.Fatalf("ComputeDirtyRoot accessed LeafStore %d times — should use cache only", counting.gets)
	}
}

// countingLeafStore wraps a LeafStore to count Get calls.
type countingLeafStore struct {
	inner LeafStore
	gets  int
}

func (c *countingLeafStore) Get(key [32]byte) (*types.SMTLeaf, error) {
	c.gets++
	return c.inner.Get(key)
}
func (c *countingLeafStore) Set(key [32]byte, leaf types.SMTLeaf) error {
	return c.inner.Set(key, leaf)
}
func (c *countingLeafStore) SetBatch(leaves []types.SMTLeaf) error {
	return c.inner.SetBatch(leaves)
}
func (c *countingLeafStore) Delete(key [32]byte) error  { return c.inner.Delete(key) }
func (c *countingLeafStore) Count() (int, error)        { return c.inner.Count() }

// TestComputeDirtyRoot_PropertyTest_RandomBatches: for randomized leaf
// sets and mutation batches, ComputeDirtyRoot with a warm cache must
// equal a full recompute over the post-mutation leaf set.
func TestComputeDirtyRoot_PropertyTest_RandomBatches(t *testing.T) {
	const trials = 20
	const priorLeaves = 32
	const mutations = 8

	for trial := 0; trial < trials; trial++ {
		prior := NewInMemoryLeafStore()
		keys := make([][32]byte, 0, priorLeaves)
		for i := 0; i < priorLeaves; i++ {
			k := randomKey(t)
			keys = append(keys, k)
			_ = prior.Set(k, makeLeaf(k, uint64(i+1), uint64(i+1)))
		}

		cache := NewInMemoryNodeCache()
		tree := NewTree(prior, cache)
		priorRoot, err := tree.Root()
		if err != nil {
			t.Fatalf("trial %d: prior Root: %v", trial, err)
		}

		// Build a random mutation batch: half updates, half inserts.
		writes := make(map[[32]byte]types.SMTLeaf, mutations)
		for i := 0; i < mutations/2; i++ {
			k := keys[i] // update existing
			writes[k] = makeLeaf(k, uint64(10000+i), uint64(20000+i))
		}
		for i := 0; i < mutations/2; i++ {
			k := randomKey(t) // insert new
			writes[k] = makeLeaf(k, uint64(30000+i), uint64(40000+i))
		}

		gotRoot, err := tree.ComputeDirtyRoot(priorRoot, writes)
		if err != nil {
			t.Fatalf("trial %d: ComputeDirtyRoot: %v", trial, err)
		}

		// Build reference: prior leaves + writes, full recompute.
		ref := NewInMemoryLeafStore()
		for k, leaf := range prior.store {
			_ = ref.Set(k, leaf)
		}
		for k, leaf := range writes {
			_ = ref.Set(k, leaf)
		}
		wantRoot, err := NewTree(ref, NewInMemoryNodeCache()).Root()
		if err != nil {
			t.Fatalf("trial %d: ref Root: %v", trial, err)
		}

		if gotRoot != wantRoot {
			t.Fatalf("trial %d: dirty != recompute\n  got:  %x\n  want: %x", trial, gotRoot, wantRoot)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────
// nodeCacheKey is collision-resistant across (depth, prefix) tuples.
// ─────────────────────────────────────────────────────────────────────

func TestNodeCacheKey_DepthDisambiguation(t *testing.T) {
	prefix := [32]byte{}
	if nodeCacheKey(0, prefix) == nodeCacheKey(256, prefix) {
		t.Fatal("nodeCacheKey collides across depths for the zero prefix")
	}
	if nodeCacheKey(128, prefix) == nodeCacheKey(0, prefix) {
		t.Fatal("nodeCacheKey collides across depths")
	}
}

func TestNodeCacheKey_PrefixDisambiguation(t *testing.T) {
	a := [32]byte{0x80}
	b := [32]byte{0x40}
	if nodeCacheKey(255, a) == nodeCacheKey(255, b) {
		t.Fatal("nodeCacheKey collides across distinct prefixes at same depth")
	}
}

// ─────────────────────────────────────────────────────────────────────
// computeRoot now generalizes to OverlayLeafStore over InMemoryLeafStore.
// ─────────────────────────────────────────────────────────────────────

func TestComputeRoot_OverlayMatchesFlattened(t *testing.T) {
	backing := NewInMemoryLeafStore()
	for _, k := range []byte{0x11, 0x22, 0x33} {
		_ = backing.Set(keyN(k), makeLeaf(keyN(k), uint64(k), uint64(k)))
	}

	overlay := NewOverlayLeafStore(backing)
	_ = overlay.Set(keyN(0x22), makeLeaf(keyN(0x22), 2222, 2222))           // override
	_ = overlay.Set(keyN(0x44), makeLeaf(keyN(0x44), uint64(0x44), uint64(0x44))) // insert

	gotRoot, err := NewTree(overlay, NewInMemoryNodeCache()).Root()
	if err != nil {
		t.Fatalf("overlay Root: %v", err)
	}

	flat := NewInMemoryLeafStore()
	for _, k := range []byte{0x11, 0x33, 0x44} {
		_ = flat.Set(keyN(k), makeLeaf(keyN(k), uint64(k), uint64(k)))
	}
	_ = flat.Set(keyN(0x22), makeLeaf(keyN(0x22), 2222, 2222))

	wantRoot, err := NewTree(flat, NewInMemoryNodeCache()).Root()
	if err != nil {
		t.Fatalf("flat Root: %v", err)
	}

	if gotRoot != wantRoot {
		t.Fatalf("overlay root != flattened root\n  got:  %x\n  want: %x", gotRoot, wantRoot)
	}
}
