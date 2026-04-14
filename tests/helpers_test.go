package tests

import (
	"testing"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

const testLogDID = "did:ortholog:testlog1"

func pos(seq uint64) types.LogPosition {
	return types.LogPosition{LogDID: testLogDID, Sequence: seq}
}

func foreignPos(seq uint64) types.LogPosition {
	return types.LogPosition{LogDID: "did:ortholog:foreign", Sequence: seq}
}

func ptrTo[T any](v T) *T { return &v }

func sameSigner() *envelope.AuthorityPath { v := envelope.AuthoritySameSigner; return &v }
func delegation() *envelope.AuthorityPath { v := envelope.AuthorityDelegation; return &v }
func scopeAuth() *envelope.AuthorityPath  { v := envelope.AuthorityScopeAuthority; return &v }

func makeEntry(t *testing.T, h envelope.ControlHeader, payload []byte) (*envelope.Entry, []byte) {
	t.Helper()
	entry, err := envelope.NewEntry(h, payload)
	if err != nil {
		t.Fatalf("NewEntry: %v", err)
	}
	return entry, envelope.Serialize(entry)
}

type MockFetcher struct {
	entries map[types.LogPosition]*types.EntryWithMetadata
}

func NewMockFetcher() *MockFetcher {
	return &MockFetcher{entries: make(map[types.LogPosition]*types.EntryWithMetadata)}
}

func (f *MockFetcher) Fetch(pos types.LogPosition) (*types.EntryWithMetadata, error) {
	meta, ok := f.entries[pos]
	if !ok { return nil, nil }
	return meta, nil
}

func (f *MockFetcher) Store(p types.LogPosition, entry *envelope.Entry) {
	f.entries[p] = &types.EntryWithMetadata{
		CanonicalBytes: envelope.Serialize(entry),
		LogTime:        time.Now(),
		Position:       p,
	}
}

type testHarness struct {
	tree    *smt.Tree
	fetcher *MockFetcher
	schema  builder.SchemaResolver
	buffer  *builder.DeltaWindowBuffer
}

func newHarness() *testHarness {
	return &testHarness{
		tree:    smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeCache()),
		fetcher: NewMockFetcher(),
		buffer:  builder.NewDeltaWindowBuffer(10),
	}
}

func (h *testHarness) addRootEntity(t *testing.T, p types.LogPosition, signerDID string) *envelope.Entry {
	t.Helper()
	entry, _ := makeEntry(t, envelope.ControlHeader{SignerDID: signerDID, AuthorityPath: sameSigner()}, nil)
	h.fetcher.Store(p, entry)
	key := smt.DeriveKey(p)
	leaf := types.SMTLeaf{Key: key, OriginTip: p, AuthorityTip: p}
	if err := h.tree.SetLeaf(key, leaf); err != nil { t.Fatal(err) }
	return entry
}

func (h *testHarness) addDelegation(t *testing.T, delegPos types.LogPosition, signerDID, delegateDID string) *envelope.Entry {
	t.Helper()
	entry, _ := makeEntry(t, envelope.ControlHeader{SignerDID: signerDID, AuthorityPath: sameSigner(), DelegateDID: &delegateDID}, nil)
	h.fetcher.Store(delegPos, entry)
	key := smt.DeriveKey(delegPos)
	_ = h.tree.SetLeaf(key, types.SMTLeaf{Key: key, OriginTip: delegPos, AuthorityTip: delegPos})
	return entry
}

func (h *testHarness) addScopeEntity(t *testing.T, p types.LogPosition, signerDID string, authoritySet map[string]struct{}) *envelope.Entry {
	t.Helper()
	entry, _ := makeEntry(t, envelope.ControlHeader{SignerDID: signerDID, AuthorityPath: sameSigner(), AuthoritySet: authoritySet}, nil)
	h.fetcher.Store(p, entry)
	key := smt.DeriveKey(p)
	_ = h.tree.SetLeaf(key, types.SMTLeaf{Key: key, OriginTip: p, AuthorityTip: p})
	return entry
}

func (h *testHarness) process(t *testing.T, entry *envelope.Entry, p types.LogPosition) *builder.BatchResult {
	t.Helper()
	h.fetcher.Store(p, entry)
	result, err := builder.ProcessBatch(h.tree, []*envelope.Entry{entry}, []types.LogPosition{p}, h.fetcher, h.schema, testLogDID, h.buffer)
	if err != nil { t.Fatalf("ProcessBatch: %v", err) }
	return result
}

func (h *testHarness) leafOriginTip(t *testing.T, p types.LogPosition) types.LogPosition {
	t.Helper()
	leaf, err := h.tree.GetLeaf(smt.DeriveKey(p))
	if err != nil || leaf == nil { t.Fatalf("leaf not found for %s", p) }
	return leaf.OriginTip
}

func (h *testHarness) leafAuthorityTip(t *testing.T, p types.LogPosition) types.LogPosition {
	t.Helper()
	leaf, err := h.tree.GetLeaf(smt.DeriveKey(p))
	if err != nil || leaf == nil { t.Fatalf("leaf not found for %s", p) }
	return leaf.AuthorityTip
}

func intToStr(n int) string {
	if n == 0 { return "0" }
	neg := n < 0; if neg { n = -n }
	digits := make([]byte, 0, 8)
	for n > 0 { digits = append([]byte{byte('0' + n%10)}, digits...); n /= 10 }
	if neg { digits = append([]byte{'-'}, digits...) }
	return string(digits)
}

func zeroPad3(n int) string {
	return string([]byte{byte('0' + n/100%10), byte('0' + n/10%10), byte('0' + n%10)})
}

func didForIndex(i int) string { return "did:example:user" + intToStr(i/10) }
