package builder

import (
	"errors"
	"testing"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// fastRetryCfg keeps test wallclock delay minimal.
func fastRetryCfg(maxAttempts int) RetryConfig {
	return RetryConfig{
		MaxAttempts: maxAttempts,
		BaseDelay:   1 * time.Microsecond,
		MaxDelay:    1 * time.Microsecond,
	}
}

// retryTestLogDID is a distinct DID so this file's tests don't collide
// with other builder_test.go fixtures.
const retryTestLogDID = "did:ortholog:retrytest"
const retryTestDestination = "did:web:retry.test.example"

func retryPos(seq uint64) types.LogPosition {
	return types.LogPosition{LogDID: retryTestLogDID, Sequence: seq}
}

// retryFetcher is a local fetcher used by retry tests; mirrors the
// occFetcher pattern in classifier_occ_test.go but kept separate to
// avoid cross-file helper coupling.
type retryFetcher map[types.LogPosition]*types.EntryWithMetadata

func (f retryFetcher) Fetch(p types.LogPosition) (*types.EntryWithMetadata, error) {
	if m, ok := f[p]; ok {
		return m, nil
	}
	return nil, nil
}

func (f retryFetcher) store(t *testing.T, p types.LogPosition, e *envelope.Entry) {
	t.Helper()
	e.Signatures = []envelope.Signature{{
		SignerDID: e.Header.SignerDID,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     make([]byte, 64),
	}}
	if err := e.Validate(); err != nil {
		t.Fatalf("retryFetcher.store: invalid entry: %v", err)
	}
	f[p] = &types.EntryWithMetadata{
		CanonicalBytes: envelope.Serialize(e),
		Position:       p,
	}
}

func retryMustEntry(t *testing.T, h envelope.ControlHeader) *envelope.Entry {
	t.Helper()
	e, err := envelope.NewUnsignedEntry(h, nil)
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	return e
}

// buildRootNewLeafEntry builds a new-leaf entry (Path classification
// routes it through the new-leaf branch in processEntry).
func buildRootNewLeafEntry(t *testing.T, signer string) *envelope.Entry {
	t.Helper()
	return retryMustEntry(t, envelope.ControlHeader{
		Destination:   retryTestDestination,
		SignerDID:     signer,
		AuthorityPath: occSameSigner(),
	})
}

// ─────────────────────────────────────────────────────────────────────
// ORTHO-BUG-003 — surgical retry behaviour
// ─────────────────────────────────────────────────────────────────────

// TestProcessWithRetry_HappyPath_NoRetries confirms a clean batch
// returns on the first attempt with zero rejections.
func TestProcessWithRetry_HappyPath_NoRetries(t *testing.T) {
	tree := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeCache())
	fetcher := retryFetcher{}

	e := buildRootNewLeafEntry(t, "did:example:a")
	r, err := ProcessWithRetry(ProcessWithRetryParams{
		Tree:        tree,
		Entries:     []*envelope.Entry{e},
		Positions:   []types.LogPosition{retryPos(1)},
		Fetcher:     fetcher,
		LocalLogDID: retryTestLogDID,
		DeltaBuffer: NewDeltaWindowBuffer(10),
		Config:      fastRetryCfg(3),
	})
	if err != nil {
		t.Fatalf("ProcessWithRetry: %v", err)
	}
	if r.Attempts != 1 {
		t.Fatalf("expected 1 attempt, got %d", r.Attempts)
	}
	if len(r.RejectedPositions) != 0 {
		t.Fatalf("expected 0 rejections, got %v", r.RejectedPositions)
	}
	if r.NewLeafCounts != 1 {
		t.Fatalf("expected NewLeafCounts=1, got %d", r.NewLeafCounts)
	}
}

// TestProcessWithRetry_RejectedIndicesRetryOnly verifies the core
// ORTHO-BUG-003 fix: when an entry is rejected on attempt 1, attempt 2
// re-submits ONLY that entry, so entries accepted on attempt 1 are not
// re-applied (which would cause ErrTipRegression and spurious PathD
// accounting).
//
// We use a Path C enforcement entry with a stale Prior_Authority —
// the live builder rejects via verifyPriorAuthority (algorithm.go:304)
// with PathResultRejected, and no resolver is supplied so strict OCC
// applies.
func TestProcessWithRetry_RejectedIndicesRetryOnly(t *testing.T) {
	tree := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeCache())
	fetcher := retryFetcher{}

	// Seed target entity and scope leaf so the Path C entry resolves
	// all fetches and leaf lookups.
	entityPos := retryPos(100)
	entity := retryMustEntry(t, envelope.ControlHeader{
		Destination:   retryTestDestination,
		SignerDID:     "did:example:entity",
		AuthorityPath: occSameSigner(),
	})
	fetcher.store(t, entityPos, entity)

	scopePos := retryPos(101)
	scope := retryMustEntry(t, envelope.ControlHeader{
		Destination:   retryTestDestination,
		SignerDID:     "did:example:judge",
		AuthorityPath: occSameSigner(),
		AuthoritySet:  map[string]struct{}{"did:example:judge": {}},
	})
	fetcher.store(t, scopePos, scope)

	entityKey := smt.DeriveKey(entityPos)
	scopeKey := smt.DeriveKey(scopePos)
	currentAuthorityTip := retryPos(50)
	if err := tree.SetLeaves([]types.SMTLeaf{
		{Key: entityKey, OriginTip: entityPos, AuthorityTip: currentAuthorityTip},
		{Key: scopeKey, OriginTip: scopePos, AuthorityTip: scopePos},
	}); err != nil {
		t.Fatalf("seed leaves: %v", err)
	}

	// Two valid new-leaf entries sandwiching an always-rejected Path C
	// enforcement (stale Prior_Authority, strict OCC ⇒ rejected).
	okA := buildRootNewLeafEntry(t, "did:example:a")
	okB := buildRootNewLeafEntry(t, "did:example:b")
	stalePriorAuth := retryPos(40) // not == currentAuthorityTip (50)
	alwaysRejected := retryMustEntry(t, envelope.ControlHeader{
		Destination:    retryTestDestination,
		SignerDID:      "did:example:judge",
		TargetRoot:     ptrTo(entityPos),
		AuthorityPath:  occScopeAuth(),
		ScopePointer:   ptrTo(scopePos),
		PriorAuthority: ptrTo(stalePriorAuth),
	})

	entries := []*envelope.Entry{okA, alwaysRejected, okB}
	positions := []types.LogPosition{retryPos(1), retryPos(2), retryPos(3)}

	r, err := ProcessWithRetry(ProcessWithRetryParams{
		Tree:        tree,
		Entries:     entries,
		Positions:   positions,
		Fetcher:     fetcher,
		LocalLogDID: retryTestLogDID,
		DeltaBuffer: NewDeltaWindowBuffer(10),
		Config:      fastRetryCfg(3),
	})
	if err != nil {
		t.Fatalf("ProcessWithRetry: %v", err)
	}

	// The rejected entry is at original index 1 and stays rejected
	// across all attempts. Final report must point at the ORIGINAL
	// batch index, not the retry sub-batch index.
	if len(r.RejectedPositions) != 1 || r.RejectedPositions[0] != 1 {
		t.Fatalf("want RejectedPositions=[1] (original index), got %v", r.RejectedPositions)
	}

	// Each valid new-leaf entry must contribute EXACTLY ONCE across
	// all attempts. Before the ORTHO-BUG-003 fix, the full batch was
	// resubmitted each attempt: okA and okB would be re-executed,
	// hitting ErrTipRegression and inflating PathDCounts by 2 per
	// extra attempt.
	if r.NewLeafCounts != 2 {
		t.Fatalf("expected NewLeafCounts=2 (each ok entry applied once), got %d", r.NewLeafCounts)
	}
	if r.PathDCounts != 0 {
		t.Fatalf("expected PathDCounts=0 (no false tip-regressions), got %d", r.PathDCounts)
	}

	// Attempts: exhausted against the un-heal-able rejection.
	if r.Attempts != 3 {
		t.Fatalf("expected 3 attempts (max), got %d", r.Attempts)
	}
}

// TestProcessWithRetry_AllAccepted_SingleAttempt confirms a batch with
// zero rejections returns after one attempt and applies every entry.
func TestProcessWithRetry_AllAccepted_SingleAttempt(t *testing.T) {
	tree := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeCache())
	fetcher := retryFetcher{}

	entries := []*envelope.Entry{
		buildRootNewLeafEntry(t, "did:example:a"),
		buildRootNewLeafEntry(t, "did:example:b"),
		buildRootNewLeafEntry(t, "did:example:c"),
	}
	positions := []types.LogPosition{retryPos(1), retryPos(2), retryPos(3)}

	r, err := ProcessWithRetry(ProcessWithRetryParams{
		Tree:        tree,
		Entries:     entries,
		Positions:   positions,
		Fetcher:     fetcher,
		LocalLogDID: retryTestLogDID,
		DeltaBuffer: NewDeltaWindowBuffer(10),
		Config:      fastRetryCfg(5),
	})
	if err != nil {
		t.Fatalf("ProcessWithRetry: %v", err)
	}
	if r.Attempts != 1 {
		t.Fatalf("expected 1 attempt, got %d", r.Attempts)
	}
	if r.NewLeafCounts != 3 {
		t.Fatalf("expected NewLeafCounts=3, got %d", r.NewLeafCounts)
	}
	if len(r.RejectedPositions) != 0 {
		t.Fatalf("expected 0 rejections, got %v", r.RejectedPositions)
	}
}

// TestProcessBatch_RejectedPositionsReported asserts ProcessBatch
// surfaces per-index rejection data (the contract ProcessWithRetry
// depends on). Uses the same Path C OCC-mismatch vector as the retry
// test since it produces a deterministic PathResultRejected that the
// envelope layer does not block at construction time.
func TestProcessBatch_RejectedPositionsReported(t *testing.T) {
	tree := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeCache())
	fetcher := retryFetcher{}

	entityPos := retryPos(100)
	entity := retryMustEntry(t, envelope.ControlHeader{
		Destination:   retryTestDestination,
		SignerDID:     "did:example:entity",
		AuthorityPath: occSameSigner(),
	})
	fetcher.store(t, entityPos, entity)

	scopePos := retryPos(101)
	scope := retryMustEntry(t, envelope.ControlHeader{
		Destination:   retryTestDestination,
		SignerDID:     "did:example:judge",
		AuthorityPath: occSameSigner(),
		AuthoritySet:  map[string]struct{}{"did:example:judge": {}},
	})
	fetcher.store(t, scopePos, scope)

	entityKey := smt.DeriveKey(entityPos)
	scopeKey := smt.DeriveKey(scopePos)
	if err := tree.SetLeaves([]types.SMTLeaf{
		{Key: entityKey, OriginTip: entityPos, AuthorityTip: retryPos(50)},
		{Key: scopeKey, OriginTip: scopePos, AuthorityTip: scopePos},
	}); err != nil {
		t.Fatalf("seed leaves: %v", err)
	}

	rejected := retryMustEntry(t, envelope.ControlHeader{
		Destination:    retryTestDestination,
		SignerDID:      "did:example:judge",
		TargetRoot:     ptrTo(entityPos),
		AuthorityPath:  occScopeAuth(),
		ScopePointer:   ptrTo(scopePos),
		PriorAuthority: ptrTo(retryPos(40)),
	})
	ok := buildRootNewLeafEntry(t, "did:example:a")

	entries := []*envelope.Entry{ok, rejected, ok}
	positions := []types.LogPosition{retryPos(1), retryPos(2), retryPos(3)}

	result, err := ProcessBatch(tree, entries, positions, fetcher, nil, retryTestLogDID, NewDeltaWindowBuffer(10))
	if err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}
	if len(result.RejectedPositions) != 1 || result.RejectedPositions[0] != 1 {
		t.Fatalf("want RejectedPositions=[1], got %v", result.RejectedPositions)
	}
}

// ─────────────────────────────────────────────────────────────────────
// H5 — PathFailureReasons surfaces per-entry structural errors
// ─────────────────────────────────────────────────────────────────────

// TestProcessBatch_PathFailureReasonsRecordsTipRegression exercises
// the H5 fix: a Path A amendment whose position would cause a tip
// regression is classified as PathD, and the concrete ErrTipRegression
// is surfaced in BatchResult.PathFailureReasons at the failing index.
// The two flanking valid entries must have nil slots.
func TestProcessBatch_PathFailureReasonsRecordsTipRegression(t *testing.T) {
	tree := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeCache())
	fetcher := retryFetcher{}

	// Seed a target entity with a high-sequence OriginTip so a later
	// Path A amendment at a lower sequence triggers assertMonotonic.
	entityPos := retryPos(500)
	entity := retryMustEntry(t, envelope.ControlHeader{
		Destination:   retryTestDestination,
		SignerDID:     "did:example:alice",
		AuthorityPath: occSameSigner(),
	})
	fetcher.store(t, entityPos, entity)
	ekey := smt.DeriveKey(entityPos)
	if err := tree.SetLeaves([]types.SMTLeaf{{Key: ekey, OriginTip: entityPos, AuthorityTip: entityPos}}); err != nil {
		t.Fatalf("seed leaf: %v", err)
	}

	// A valid new-leaf entry that will succeed — its PathFailureReasons
	// slot must remain nil.
	okA := buildRootNewLeafEntry(t, "did:example:b")

	// A Path A amendment at pos(10) targeting entityPos (pos 500).
	// assertMonotonic will fire ErrTipRegression (10 <= 500, same log).
	regressing := retryMustEntry(t, envelope.ControlHeader{
		Destination:   retryTestDestination,
		SignerDID:     "did:example:alice",
		TargetRoot:    ptrTo(entityPos),
		AuthorityPath: occSameSigner(),
	})

	okB := buildRootNewLeafEntry(t, "did:example:c")

	entries := []*envelope.Entry{okA, regressing, okB}
	positions := []types.LogPosition{retryPos(1), retryPos(10), retryPos(11)}

	result, err := ProcessBatch(tree, entries, positions, fetcher, nil, retryTestLogDID, NewDeltaWindowBuffer(10))
	if err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}

	if got := len(result.PathFailureReasons); got != len(entries) {
		t.Fatalf("PathFailureReasons length: want %d, got %d", len(entries), got)
	}
	if result.PathFailureReasons[0] != nil {
		t.Fatalf("index 0 (valid entry): want nil reason, got %v", result.PathFailureReasons[0])
	}
	if result.PathFailureReasons[1] == nil {
		t.Fatal("index 1 (regressing entry): want non-nil reason, got nil")
	}
	if !errors.Is(result.PathFailureReasons[1], ErrTipRegression) {
		t.Fatalf("index 1: want ErrTipRegression, got %v", result.PathFailureReasons[1])
	}
	if result.PathFailureReasons[2] != nil {
		t.Fatalf("index 2 (valid entry): want nil reason, got %v", result.PathFailureReasons[2])
	}
	if result.PathDCounts != 1 {
		t.Fatalf("PathDCounts: want 1, got %d", result.PathDCounts)
	}
}

// TestProcessBatch_PathFailureReasonsNilForLegitimatePathD asserts
// the other side of the H5 contract: an entry legitimately routed to
// PathD without an error (e.g., foreign-log target, evidence-cap
// snapshot shape) leaves its PathFailureReasons slot nil. This is
// what lets operators distinguish "genuine PathD" from "structural
// failure the builder absorbed."
func TestProcessBatch_PathFailureReasonsNilForLegitimatePathD(t *testing.T) {
	tree := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeCache())
	fetcher := retryFetcher{}

	// A Path A entry whose TargetRoot references a foreign log ⇒
	// processEntry returns PathResultPathD with nil error (Decision 47
	// locality enforcement).
	foreign := retryMustEntry(t, envelope.ControlHeader{
		Destination:   retryTestDestination,
		SignerDID:     "did:example:bob",
		TargetRoot:    &types.LogPosition{LogDID: "did:ortholog:foreign", Sequence: 1},
		AuthorityPath: occSameSigner(),
	})

	entries := []*envelope.Entry{foreign}
	positions := []types.LogPosition{retryPos(1)}

	result, err := ProcessBatch(tree, entries, positions, fetcher, nil, retryTestLogDID, NewDeltaWindowBuffer(10))
	if err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}
	if result.PathDCounts != 1 {
		t.Fatalf("PathDCounts: want 1, got %d", result.PathDCounts)
	}
	if result.PathFailureReasons[0] != nil {
		t.Fatalf("legitimate PathD: want nil reason, got %v", result.PathFailureReasons[0])
	}
}
