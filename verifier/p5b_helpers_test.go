// Shared helpers for the migrated phase5_part_b tests
// (contest_override_test.go, key_rotation_test.go, fraud_proofs_bug017_test.go).
//
// These helpers were originally defined in tests/helpers_test.go,
// tests/phase5_part_a_test.go, and tests/phase5_part_b_test.go. They are
// recreated here so the migrated tests can live alongside the code they
// exercise. The original tests/* helpers continue to serve other tests
// in the tests/ package.

package verifier

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

const (
	p5bTestDestinationDID = "did:web:test.exchange.example"
	p5bTestLogDID         = "did:ortholog:testlog1"
)

func p5bPos(seq uint64) types.LogPosition {
	return types.LogPosition{LogDID: p5bTestLogDID, Sequence: seq}
}

func p5bPtr[T any](v T) *T { return &v }

func p5bSameSigner() *envelope.AuthorityPath { v := envelope.AuthoritySameSigner; return &v }
func p5bScopeAuth() *envelope.AuthorityPath  { v := envelope.AuthorityScopeAuthority; return &v }

// p5bBuildEntry constructs a fully-valid v6 entry for test purposes,
// attaching a deterministic 64-byte zero-ECDSA signature so the entry
// satisfies the v6 invariant (every entry must carry at least one
// signature whose SignerDID matches the header's). Tests that exercise
// real signature cryptography should overwrite entry.Signatures after
// construction.
func p5bBuildEntry(t *testing.T, h envelope.ControlHeader, payload []byte) *envelope.Entry {
	t.Helper()
	entry, err := envelope.NewUnsignedEntry(h, payload)
	if err != nil {
		t.Fatalf("p5bBuildEntry: NewUnsignedEntry: %v", err)
	}
	entry.Signatures = []envelope.Signature{{
		SignerDID: h.SignerDID,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     make([]byte, 64),
	}}
	if err := entry.Validate(); err != nil {
		t.Fatalf("p5bBuildEntry: Validate failed: %v", err)
	}
	return entry
}

func p5bMustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

// p5bMockFetcher is an in-memory EntryFetcher used by all migrated tests.
type p5bMockFetcher struct {
	entries map[types.LogPosition]*types.EntryWithMetadata
}

func newP5BMockFetcher() *p5bMockFetcher {
	return &p5bMockFetcher{entries: make(map[types.LogPosition]*types.EntryWithMetadata)}
}

func (f *p5bMockFetcher) Fetch(pos types.LogPosition) (*types.EntryWithMetadata, error) {
	meta, ok := f.entries[pos]
	if !ok {
		return nil, nil
	}
	return meta, nil
}

func (f *p5bMockFetcher) Store(p types.LogPosition, entry *envelope.Entry) {
	if err := entry.Validate(); err != nil {
		panic(fmt.Sprintf(
			"p5bMockFetcher.Store: invalid entry at position %s: %v\n"+
				"Route construction through p5bBuildEntry instead of "+
				"envelope.NewUnsignedEntry.", p, err))
	}
	f.entries[p] = &types.EntryWithMetadata{
		CanonicalBytes: envelope.Serialize(entry),
		LogTime:        time.Now(),
		Position:       p,
	}
}

// p5bHarness wraps tree + fetcher + leafstore and provides the
// addEntity/storeEntry/setLeaf/advanceAuthorityTip operations used by
// the contest and rotation tests.
type p5bHarness struct {
	tree    *smt.Tree
	leaves  *smt.InMemoryLeafStore
	fetcher *p5bMockFetcher
}

func newP5BHarness() *p5bHarness {
	leaves := smt.NewInMemoryLeafStore()
	return &p5bHarness{
		tree:    smt.NewTree(leaves, smt.NewInMemoryNodeCache()),
		leaves:  leaves,
		fetcher: newP5BMockFetcher(),
	}
}

func (h *p5bHarness) addEntity(t *testing.T, p types.LogPosition, signerDID string) {
	t.Helper()
	entry := p5bBuildEntry(t, envelope.ControlHeader{
		Destination:   p5bTestDestinationDID,
		SignerDID:     signerDID,
		AuthorityPath: p5bSameSigner(),
	}, nil)
	h.fetcher.Store(p, entry)
	key := smt.DeriveKey(p)
	leaf := types.SMTLeaf{Key: key, OriginTip: p, AuthorityTip: p}
	if err := h.tree.SetLeaf(key, leaf); err != nil {
		t.Fatal(err)
	}
}

func (h *p5bHarness) addEntityWithPayload(t *testing.T, p types.LogPosition, signerDID string, payload []byte) {
	t.Helper()
	entry := p5bBuildEntry(t, envelope.ControlHeader{
		Destination:   p5bTestDestinationDID,
		SignerDID:     signerDID,
		AuthorityPath: p5bSameSigner(),
	}, payload)
	h.fetcher.Store(p, entry)
	key := smt.DeriveKey(p)
	leaf := types.SMTLeaf{Key: key, OriginTip: p, AuthorityTip: p}
	if err := h.tree.SetLeaf(key, leaf); err != nil {
		t.Fatal(err)
	}
}

func (h *p5bHarness) storeEntry(t *testing.T, p types.LogPosition, entry *envelope.Entry) {
	t.Helper()
	h.fetcher.Store(p, entry)
}

func (h *p5bHarness) setLeaf(t *testing.T, key [32]byte, leaf types.SMTLeaf) {
	t.Helper()
	if err := h.tree.SetLeaf(key, leaf); err != nil {
		t.Fatal(err)
	}
}

func (h *p5bHarness) advanceAuthorityTip(t *testing.T, entityPos, newTip types.LogPosition) {
	t.Helper()
	key := smt.DeriveKey(entityPos)
	leaf, _ := h.leaves.Get(key)
	if leaf == nil {
		t.Fatalf("leaf not found for %s", entityPos)
	}
	updated := *leaf
	updated.AuthorityTip = newTip
	h.setLeaf(t, key, updated)
}

// _ keeps imports honest if a helper goes unused for a moment during edits.
var _ = builder.NewDeltaWindowBuffer
