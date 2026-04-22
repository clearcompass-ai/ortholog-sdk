package builder

import (
	"errors"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// failingLeafStore wraps an InMemoryLeafStore and forces SetBatch to fail.
// It is used to exercise the all-or-nothing commit contract of
// applyLeafUpdates: when the backing store rejects the batch, no leaf
// may be durably written and the Δ-window buffer must be untouched
// (ORTHO-BUG-002).
type failingLeafStore struct {
	inner   *smt.InMemoryLeafStore
	batchEr error
}

func (s *failingLeafStore) Get(key [32]byte) (*types.SMTLeaf, error) {
	return s.inner.Get(key)
}
func (s *failingLeafStore) Set(key [32]byte, leaf types.SMTLeaf) error {
	return s.inner.Set(key, leaf)
}
func (s *failingLeafStore) SetBatch(leaves []types.SMTLeaf) error {
	return s.batchEr
}
func (s *failingLeafStore) Delete(key [32]byte) error { return s.inner.Delete(key) }
func (s *failingLeafStore) Count() (int, error)       { return s.inner.Count() }

func makeLeafKey(b byte) [32]byte {
	var k [32]byte
	k[0] = b
	return k
}

// TestApplyLeafUpdates_AtomicityOnStoreFailure verifies ORTHO-BUG-002:
// a failing atomic batch commit leaves the SMT and Δ-window buffer
// unchanged. The previous non-atomic implementation wrote up to the
// failing index before rolling back, corrupting the tree.
func TestApplyLeafUpdates_AtomicityOnStoreFailure(t *testing.T) {
	wantErr := errors.New("injected store failure")
	store := &failingLeafStore{inner: smt.NewInMemoryLeafStore(), batchEr: wantErr}
	tree := smt.NewTree(store, smt.NewInMemoryNodeCache())
	buffer := NewDeltaWindowBuffer(10)

	k1, k2 := makeLeafKey(0x01), makeLeafKey(0x02)
	tip1 := types.LogPosition{LogDID: "did:ortholog:a", Sequence: 5}
	tip2 := types.LogPosition{LogDID: "did:ortholog:a", Sequence: 7}

	updates := []leafUpdate{
		{key: k1, leaf: types.SMTLeaf{Key: k1, OriginTip: tip1, AuthorityTip: tip1}, bufferPos: tip1, recordsBuffer: true},
		{key: k2, leaf: types.SMTLeaf{Key: k2, OriginTip: tip2, AuthorityTip: tip2}, bufferPos: tip2, recordsBuffer: true},
	}

	err := applyLeafUpdates(tree, buffer, updates)
	if err == nil {
		t.Fatal("applyLeafUpdates: expected error on failing SetBatch, got nil")
	}
	if !errors.Is(err, wantErr) {
		t.Fatalf("applyLeafUpdates: want error wrapping %v, got %v", wantErr, err)
	}

	if got, err := store.inner.Count(); err != nil || got != 0 {
		t.Fatalf("backing store mutated on failed batch: count=%d err=%v", got, err)
	}
	if buffer.Len() != 0 {
		t.Fatalf("Δ-window buffer recorded entries on failed batch: len=%d", buffer.Len())
	}
}

// TestApplyLeafUpdates_SuccessCommitsAllAndRecordsBuffer asserts the happy
// path: every leaf is persisted and Δ-window records are appended only
// after the commit completes.
func TestApplyLeafUpdates_SuccessCommitsAllAndRecordsBuffer(t *testing.T) {
	store := smt.NewInMemoryLeafStore()
	tree := smt.NewTree(store, smt.NewInMemoryNodeCache())
	buffer := NewDeltaWindowBuffer(10)

	k1, k2, k3 := makeLeafKey(0x01), makeLeafKey(0x02), makeLeafKey(0x03)
	tipA := types.LogPosition{LogDID: "did:ortholog:a", Sequence: 1}
	tipB := types.LogPosition{LogDID: "did:ortholog:a", Sequence: 2}
	tipC := types.LogPosition{LogDID: "did:ortholog:a", Sequence: 3}

	updates := []leafUpdate{
		{key: k1, leaf: types.SMTLeaf{Key: k1, OriginTip: tipA, AuthorityTip: tipA}, bufferPos: tipA, recordsBuffer: true},
		{key: k2, leaf: types.SMTLeaf{Key: k2, OriginTip: tipB, AuthorityTip: tipB}},                                          // no buffer
		{key: k3, leaf: types.SMTLeaf{Key: k3, OriginTip: tipC, AuthorityTip: tipC}, bufferPos: tipC, recordsBuffer: true},
	}

	if err := applyLeafUpdates(tree, buffer, updates); err != nil {
		t.Fatalf("applyLeafUpdates: %v", err)
	}
	for _, k := range [][32]byte{k1, k2, k3} {
		l, err := store.Get(k)
		if err != nil || l == nil {
			t.Fatalf("leaf %x not persisted: err=%v leaf=%v", k[:4], err, l)
		}
	}
	if got := buffer.Len(); got != 2 {
		t.Fatalf("buffer records: want 2 (k1, k3), got %d", got)
	}
	if !buffer.Contains(k1, tipA) {
		t.Fatalf("buffer missing record for k1/tipA")
	}
	if !buffer.Contains(k3, tipC) {
		t.Fatalf("buffer missing record for k3/tipC")
	}
	if buffer.Contains(k2, tipB) {
		t.Fatalf("buffer incorrectly recorded k2 (recordsBuffer=false)")
	}
}

// TestApplyLeafUpdates_EmptyIsNoop documents that the empty-batch case
// is a safe no-op — not an error and not a spurious SetBatch call.
func TestApplyLeafUpdates_EmptyIsNoop(t *testing.T) {
	// Failing store; if applyLeafUpdates invoked SetBatch on an empty
	// slice, the failure would surface. The function must short-circuit.
	store := &failingLeafStore{inner: smt.NewInMemoryLeafStore(), batchEr: errors.New("must-not-be-called")}
	tree := smt.NewTree(store, smt.NewInMemoryNodeCache())
	buffer := NewDeltaWindowBuffer(10)

	if err := applyLeafUpdates(tree, buffer, nil); err != nil {
		t.Fatalf("empty batch: want nil, got %v", err)
	}
	if err := applyLeafUpdates(tree, buffer, []leafUpdate{}); err != nil {
		t.Fatalf("empty batch: want nil, got %v", err)
	}
}
