package scope

import (
	"errors"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// Test fixtures — package-local, no cross-package coupling.
// ─────────────────────────────────────────────────────────────────────

const testLogDID = "did:ortholog:scopetest"
const foreignLogDID = "did:ortholog:scopetest-foreign"
const testDestination = "did:web:scope.test.example"

func pos(seq uint64) types.LogPosition {
	return types.LogPosition{LogDID: testLogDID, Sequence: seq}
}

func foreignPos(seq uint64) types.LogPosition {
	return types.LogPosition{LogDID: foreignLogDID, Sequence: seq}
}

// countingFetcher is a map-backed types.EntryFetcher that also records
// how many Fetch calls the walker made. Tests that assert "no fetcher
// call was made" (cross-log fail-fast) use the counter.
type countingFetcher struct {
	entries map[types.LogPosition]*types.EntryWithMetadata
	calls   int
}

func newCountingFetcher() *countingFetcher {
	return &countingFetcher{entries: make(map[types.LogPosition]*types.EntryWithMetadata)}
}

func (f *countingFetcher) Fetch(p types.LogPosition) (*types.EntryWithMetadata, error) {
	f.calls++
	if m, ok := f.entries[p]; ok {
		return m, nil
	}
	return nil, nil
}

// storeScopeEntry builds a valid v6 scope (creation or amendment)
// entry, Serializes it, and registers it with the fetcher + seeds
// its SMT leaf's OriginTip. The caller specifies the position, the
// AuthoritySet, and optionally a PriorAuthority pointer.
func storeScopeEntry(
	t *testing.T,
	f *countingFetcher,
	store *smt.InMemoryLeafStore,
	at types.LogPosition,
	authoritySet map[string]struct{},
	prior *types.LogPosition,
	scopeLeafPos types.LogPosition,
) {
	t.Helper()
	h := envelope.ControlHeader{
		Destination:    testDestination,
		SignerDID:      "did:example:governor",
		AuthorityPath:  scopeAuthPtr(),
		AuthoritySet:   authoritySet,
		PriorAuthority: prior,
	}
	// If this is an amendment (has PriorAuthority), it must also point
	// at the scope via ScopePointer + TargetRoot. The primitive does
	// not read those, but envelope.Validate does.
	if prior != nil {
		sp := scopeLeafPos
		h.ScopePointer = &sp
		tr := scopeLeafPos
		h.TargetRoot = &tr
	}
	entry, err := envelope.NewUnsignedEntry(h, nil)
	if err != nil {
		t.Fatalf("NewUnsignedEntry at %s: %v", at, err)
	}
	entry.Signatures = []envelope.Signature{{
		SignerDID: entry.Header.SignerDID,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     make([]byte, 64),
	}}
	if err := entry.Validate(); err != nil {
		t.Fatalf("Validate at %s: %v", at, err)
	}
	f.entries[at] = &types.EntryWithMetadata{
		CanonicalBytes: envelope.Serialize(entry),
		Position:       at,
	}
	// Seed the scope's leaf OriginTip at the latest governing position.
	scopeKey := smt.DeriveKey(scopeLeafPos)
	if err := store.Set(scopeKey, types.SMTLeaf{
		Key:       scopeKey,
		OriginTip: at,
	}); err != nil {
		t.Fatalf("seed leaf at %s: %v", at, err)
	}
}

func scopeAuthPtr() *envelope.AuthorityPath {
	v := envelope.AuthorityScopeAuthority
	return &v
}

func authSet(dids ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(dids))
	for _, d := range dids {
		m[d] = struct{}{}
	}
	return m
}

// ─────────────────────────────────────────────────────────────────────
// Scenario 1 — scope with no amendments
// ─────────────────────────────────────────────────────────────────────

// TestAuthorizedSetAtPosition_NoAmendments: scope created, no
// amendments. Any query position at-or-after creation returns the
// creation's set.
func TestAuthorizedSetAtPosition_NoAmendments(t *testing.T) {
	fetcher := newCountingFetcher()
	store := smt.NewInMemoryLeafStore()
	scope := pos(10)

	// Single creation entry with judge, clerk in the set.
	storeScopeEntry(t, fetcher, store, scope, authSet("did:j:judge", "did:j:clerk"), nil, scope)

	// Query at creation.
	got, err := AuthorizedSetAtPosition(scope, pos(10), fetcher, store)
	if err != nil {
		t.Fatalf("query at creation: %v", err)
	}
	if len(got) != 2 || got["did:j:judge"] == (struct{}{}) == false {
		t.Fatalf("query at creation: want judge+clerk, got %v", got)
	}

	// Query at a much later position — still the creation's set.
	got, err = AuthorizedSetAtPosition(scope, pos(9000), fetcher, store)
	if err != nil {
		t.Fatalf("query at later pos: %v", err)
	}
	if _, ok := got["did:j:clerk"]; !ok {
		t.Fatalf("query at later pos: want clerk in set, got %v", got)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Scenario 2 — scope with one amendment
// ─────────────────────────────────────────────────────────────────────

// TestAuthorizedSetAtPosition_OneAmendment: creation at pos 10 with
// judge+clerk; amendment at pos 50 replaces clerk with bailiff.
// A query at pos 30 (before amendment) returns judge+clerk;
// at pos 60 (after amendment) returns judge+bailiff.
func TestAuthorizedSetAtPosition_OneAmendment(t *testing.T) {
	fetcher := newCountingFetcher()
	store := smt.NewInMemoryLeafStore()
	scope := pos(10)
	amend := pos(50)

	storeScopeEntry(t, fetcher, store, scope, authSet("did:j:judge", "did:j:clerk"), nil, scope)
	// Amendment advances OriginTip — re-seed the leaf to point at it.
	storeScopeEntry(t, fetcher, store, amend, authSet("did:j:judge", "did:j:bailiff"), &scope, scope)

	pre, err := AuthorizedSetAtPosition(scope, pos(30), fetcher, store)
	if err != nil {
		t.Fatalf("pre-amendment: %v", err)
	}
	if _, ok := pre["did:j:clerk"]; !ok {
		t.Fatalf("pre-amendment: want clerk, got %v", pre)
	}
	if _, ok := pre["did:j:bailiff"]; ok {
		t.Fatalf("pre-amendment: bailiff leaked into pre-amendment set %v", pre)
	}

	post, err := AuthorizedSetAtPosition(scope, pos(60), fetcher, store)
	if err != nil {
		t.Fatalf("post-amendment: %v", err)
	}
	if _, ok := post["did:j:bailiff"]; !ok {
		t.Fatalf("post-amendment: want bailiff, got %v", post)
	}
	if _, ok := post["did:j:clerk"]; ok {
		t.Fatalf("post-amendment: clerk persisted into post-amendment set %v", post)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Scenario 3 — scope with multiple amendments
// ─────────────────────────────────────────────────────────────────────

// TestAuthorizedSetAtPosition_MultipleAmendments asserts the walker
// terminates at the correct historical entry when queried at various
// positions across a 3-amendment chain.
func TestAuthorizedSetAtPosition_MultipleAmendments(t *testing.T) {
	fetcher := newCountingFetcher()
	store := smt.NewInMemoryLeafStore()
	scope := pos(10)
	a1 := pos(50)
	a2 := pos(100)
	a3 := pos(200)

	storeScopeEntry(t, fetcher, store, scope, authSet("A"), nil, scope)
	storeScopeEntry(t, fetcher, store, a1, authSet("A", "B"), &scope, scope)
	storeScopeEntry(t, fetcher, store, a2, authSet("B", "C"), &a1, scope)
	storeScopeEntry(t, fetcher, store, a3, authSet("C", "D"), &a2, scope)

	cases := []struct {
		name string
		at   types.LogPosition
		want []string
	}{
		{"before-a1", pos(30), []string{"A"}},
		{"at-a1", pos(50), []string{"A", "B"}},
		{"between-a1-a2", pos(80), []string{"A", "B"}},
		{"at-a2", pos(100), []string{"B", "C"}},
		{"between-a2-a3", pos(150), []string{"B", "C"}},
		{"at-a3", pos(200), []string{"C", "D"}},
		{"after-a3", pos(500), []string{"C", "D"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := AuthorizedSetAtPosition(scope, tc.at, fetcher, store)
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("%s: want %v, got %v", tc.name, tc.want, got)
			}
			for _, d := range tc.want {
				if _, ok := got[d]; !ok {
					t.Fatalf("%s: want %q in set, got %v", tc.name, d, got)
				}
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────
// Scenario 4 — cycle detection
// ─────────────────────────────────────────────────────────────────────

// TestAuthorizedSetAtPosition_CycleDetected: a Prior_Authority
// loop — A0 ← A1 ← A2 ← A1 (A2's Prior points back to A1) — must
// terminate with ErrScopeCycle, not run MaxHistoryDepth iterations.
func TestAuthorizedSetAtPosition_CycleDetected(t *testing.T) {
	fetcher := newCountingFetcher()
	store := smt.NewInMemoryLeafStore()
	scope := pos(10)
	a1 := pos(50)
	a2 := pos(100)

	storeScopeEntry(t, fetcher, store, scope, authSet("A"), nil, scope)
	storeScopeEntry(t, fetcher, store, a1, authSet("B"), &scope, scope)
	// Forge a cycle: a2's PriorAuthority points back to a1. Use the
	// raw-construction path because envelope validation has no reason
	// to forbid this shape.
	storeScopeEntry(t, fetcher, store, a2, authSet("C"), &a1, scope)
	// Re-seed the leaf at a2 (storeScopeEntry did that), then
	// rewrite a1's stored entry so its PriorAuthority points at a2 —
	// closing the loop.
	h := envelope.ControlHeader{
		Destination:    testDestination,
		SignerDID:      "did:example:governor",
		AuthorityPath:  scopeAuthPtr(),
		AuthoritySet:   authSet("B"),
		PriorAuthority: &a2, // cycle: a1 → a2 → a1
		ScopePointer:   &scope,
		TargetRoot:     &scope,
	}
	e, err := envelope.NewUnsignedEntry(h, nil)
	if err != nil {
		t.Fatalf("forge cycle entry: %v", err)
	}
	e.Signatures = []envelope.Signature{{SignerDID: h.SignerDID, AlgoID: envelope.SigAlgoECDSA, Bytes: make([]byte, 64)}}
	if err := e.Validate(); err != nil {
		t.Fatalf("forge cycle validate: %v", err)
	}
	fetcher.entries[a1] = &types.EntryWithMetadata{CanonicalBytes: envelope.Serialize(e), Position: a1}

	// Query at a position the walk would keep chasing backward.
	_, err = AuthorizedSetAtPosition(scope, pos(5), fetcher, store)
	if err == nil {
		t.Fatal("cycle: expected error, got nil")
	}
	if !errors.Is(err, ErrScopeCycle) {
		t.Fatalf("cycle: want ErrScopeCycle, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Scenario 5 — position precedes scope creation
// ─────────────────────────────────────────────────────────────────────

// TestAuthorizedSetAtPosition_PositionBeforeCreation: query at a
// position earlier than the scope's own creation must return
// ErrScopePositionUnknown — the set for a point that predates the
// scope is not defined, and the primitive must refuse to invent one.
func TestAuthorizedSetAtPosition_PositionBeforeCreation(t *testing.T) {
	fetcher := newCountingFetcher()
	store := smt.NewInMemoryLeafStore()
	scope := pos(100)

	storeScopeEntry(t, fetcher, store, scope, authSet("A"), nil, scope)

	_, err := AuthorizedSetAtPosition(scope, pos(50), fetcher, store)
	if err == nil {
		t.Fatal("pos before creation: expected error, got nil")
	}
	if !errors.Is(err, ErrScopePositionUnknown) {
		t.Fatalf("pos before creation: want ErrScopePositionUnknown, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Scenario 6 — cross-log query position, fail-fast
// ─────────────────────────────────────────────────────────────────────

// TestAuthorizedSetAtPosition_CrossLogQueryFailsFast: a query whose
// position is on a foreign log must fail immediately — before any
// fetcher call — with ErrCrossLogScopeHistory. Verified by the
// fetcher's call counter remaining zero.
func TestAuthorizedSetAtPosition_CrossLogQueryFailsFast(t *testing.T) {
	fetcher := newCountingFetcher()
	store := smt.NewInMemoryLeafStore()
	scope := pos(10)
	storeScopeEntry(t, fetcher, store, scope, authSet("A"), nil, scope)
	// Reset the fetcher counter to exclude the setup call (the
	// setup stores the entry but doesn't Fetch it).
	fetcher.calls = 0

	_, err := AuthorizedSetAtPosition(scope, foreignPos(50), fetcher, store)
	if err == nil {
		t.Fatal("cross-log query: expected error, got nil")
	}
	if !errors.Is(err, ErrCrossLogScopeHistory) {
		t.Fatalf("cross-log query: want ErrCrossLogScopeHistory, got %v", err)
	}
	if fetcher.calls != 0 {
		t.Fatalf("cross-log query: fetcher called %d times, want 0 (fail-fast before any fetch)", fetcher.calls)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Scenario 7 — cross-log Prior_Authority mid-walk
// ─────────────────────────────────────────────────────────────────────

// TestAuthorizedSetAtPosition_CrossLogPriorAuthority: an amendment
// whose Prior_Authority points to a foreign log must halt the walk
// with ErrCrossLogScopeHistory at the follow step. The error path
// is the "walk state preserved for diagnostics" case — the error
// message must include both log DIDs for operator triage.
func TestAuthorizedSetAtPosition_CrossLogPriorAuthority(t *testing.T) {
	fetcher := newCountingFetcher()
	store := smt.NewInMemoryLeafStore()
	scope := pos(10)

	// Normal creation.
	storeScopeEntry(t, fetcher, store, scope, authSet("A"), nil, scope)

	// Amendment at pos(50) whose Prior_Authority crosses to a
	// foreign log. Must not be legitimate; scope history is a
	// single-log invariant under Decision 47.
	foreign := foreignPos(7)
	h := envelope.ControlHeader{
		Destination:    testDestination,
		SignerDID:      "did:example:governor",
		AuthorityPath:  scopeAuthPtr(),
		AuthoritySet:   authSet("B"),
		PriorAuthority: &foreign,
		ScopePointer:   &scope,
		TargetRoot:     &scope,
	}
	e, err := envelope.NewUnsignedEntry(h, nil)
	if err != nil {
		t.Fatalf("build amendment: %v", err)
	}
	e.Signatures = []envelope.Signature{{SignerDID: h.SignerDID, AlgoID: envelope.SigAlgoECDSA, Bytes: make([]byte, 64)}}
	if err := e.Validate(); err != nil {
		t.Fatalf("validate amendment: %v", err)
	}
	amend := pos(50)
	fetcher.entries[amend] = &types.EntryWithMetadata{CanonicalBytes: envelope.Serialize(e), Position: amend}
	// Seed the leaf to make the latest governance position amend.
	scopeKey := smt.DeriveKey(scope)
	if err := store.Set(scopeKey, types.SMTLeaf{Key: scopeKey, OriginTip: amend}); err != nil {
		t.Fatalf("reseed leaf: %v", err)
	}

	// Query at a position that would require following the
	// cross-log Prior_Authority (i.e., before amend).
	_, err = AuthorizedSetAtPosition(scope, pos(20), fetcher, store)
	if err == nil {
		t.Fatal("cross-log Prior_Authority: expected error, got nil")
	}
	if !errors.Is(err, ErrCrossLogScopeHistory) {
		t.Fatalf("cross-log Prior_Authority: want ErrCrossLogScopeHistory, got %v", err)
	}
}
