package tests

import (
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ── Derivation commitment builder tests (3 tests) ─────────────────────

// Test 69: Commitment matches batch mutations.
func TestBuilderCommitment_MatchesMutations(t *testing.T) {
	h := newHarness()
	rootBefore, _ := h.tree.Root()

	entry, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:     "did:example:alice",
		AuthorityPath: sameSigner(),
	}, nil)
	entryPos := pos(1)
	result := h.process(t, entry, entryPos)

	commitment := builder.GenerateBatchCommitment(entryPos, entryPos, rootBefore, result)
	if commitment.MutationCount != uint32(len(result.Mutations)) {
		t.Fatalf("mutation count: got %d, want %d", commitment.MutationCount, len(result.Mutations))
	}
	if commitment.PostSMTRoot != result.NewRoot {
		t.Fatal("commitment post root should match batch result root")
	}
}

// Test 70: Replay commitment produces same post-root.
func TestBuilderCommitment_ReplayConsistent(t *testing.T) {
	h := newHarness()
	rootBefore, _ := h.tree.Root()

	entries := make([]*envelope.Entry, 5)
	positions := make([]types.LogPosition, 5)
	for i := 0; i < 5; i++ {
		e, _ := makeEntry(t, envelope.ControlHeader{
			SignerDID:     "did:example:alice",
			AuthorityPath: sameSigner(),
		}, nil)
		entries[i] = e
		positions[i] = pos(uint64(i + 1))
		h.fetcher.Store(positions[i], e)
	}

	result, err := builder.ProcessBatch(h.tree, entries, positions, h.fetcher, nil, testLogDID, h.buffer)
	if err != nil {
		t.Fatal(err)
	}

	// Replay on a fresh tree should produce the same root.
	h2 := newHarness()
	for i, e := range entries {
		h2.fetcher.Store(positions[i], e)
	}
	result2, err := builder.ProcessBatch(h2.tree, entries, positions, h2.fetcher, nil, testLogDID, h2.buffer)
	if err != nil {
		t.Fatal(err)
	}

	if result.NewRoot != result2.NewRoot {
		t.Fatal("replayed batch should produce identical root")
	}

	commitment := builder.GenerateBatchCommitment(positions[0], positions[4], rootBefore, result)
	if commitment.PriorSMTRoot != rootBefore {
		t.Fatal("commitment prior root mismatch")
	}
}

// Test 71: Empty batch -> no commitment mutations.
func TestBuilderCommitment_EmptyBatch(t *testing.T) {
	h := newHarness()
	rootBefore, _ := h.tree.Root()
	result, err := builder.ProcessBatch(h.tree, nil, nil, h.fetcher, nil, testLogDID, h.buffer)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Mutations) != 0 {
		t.Fatal("empty batch should have no mutations")
	}
	if result.NewRoot != rootBefore {
		t.Fatal("empty batch should not change root")
	}
}

// ── THE GATE TEST ──────────────────────────────────────────────────────

// Test 72: TWO INDEPENDENT BUILDERS, SAME 1000-ENTRY LOG, IDENTICAL ROOTS.
// If this fails, nothing above Phase 1 works.
func TestBuilderDeterminism_1000Entries(t *testing.T) {
	const N = 1000

	// Generate a deterministic sequence of entries.
	entries := make([]*envelope.Entry, N)
	positions := make([]types.LogPosition, N)

	for i := 0; i < N; i++ {
		seq := uint64(i + 1)
		p := pos(seq)
		positions[i] = p

		switch {
		case i%10 == 0:
			// Root entity creation.
			entries[i], _ = makeEntry(t, envelope.ControlHeader{
				SignerDID:     didForIndex(i),
				AuthorityPath: sameSigner(),
				EventTime:     int64(i) * 1000000,
			}, []byte{byte(i)})

		case i%10 == 1 && i > 10:
			// Path A amendment targeting previous root entity.
			rootSeq := uint64(i - i%10 + 1) // Most recent root entity.
			signer := didForIndex(i - i%10)
			entries[i], _ = makeEntry(t, envelope.ControlHeader{
				SignerDID:     signer,
				TargetRoot:    ptrTo(pos(rootSeq)),
				AuthorityPath: sameSigner(),
				EventTime:     int64(i) * 1000000,
			}, []byte{byte(i)})

		default:
			// Commentary entries (no SMT impact).
			entries[i], _ = makeEntry(t, envelope.ControlHeader{
				SignerDID: didForIndex(i),
				EventTime: int64(i) * 1000000,
			}, []byte{byte(i)})
		}
	}

	// Builder 1.
	tree1 := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeCache())
	fetcher1 := NewMockFetcher()
	for i, e := range entries {
		fetcher1.Store(positions[i], e)
	}
	buf1 := builder.NewDeltaWindowBuffer(10)
	result1, err := builder.ProcessBatch(tree1, entries, positions, fetcher1, nil, testLogDID, buf1)
	if err != nil {
		t.Fatalf("Builder 1: %v", err)
	}

	// Builder 2 (completely independent).
	tree2 := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeCache())
	fetcher2 := NewMockFetcher()
	for i, e := range entries {
		fetcher2.Store(positions[i], e)
	}
	buf2 := builder.NewDeltaWindowBuffer(10)
	result2, err := builder.ProcessBatch(tree2, entries, positions, fetcher2, nil, testLogDID, buf2)
	if err != nil {
		t.Fatalf("Builder 2: %v", err)
	}

	// THE GATE: identical roots.
	if result1.NewRoot != result2.NewRoot {
		t.Fatalf("DETERMINISM FAILURE: Builder 1 root %x != Builder 2 root %x",
			result1.NewRoot[:8], result2.NewRoot[:8])
	}

	// Verify path counts match.
	if result1.PathACounts != result2.PathACounts {
		t.Fatalf("PathA counts: %d vs %d", result1.PathACounts, result2.PathACounts)
	}
	if result1.CommentaryCounts != result2.CommentaryCounts {
		t.Fatalf("Commentary counts: %d vs %d", result1.CommentaryCounts, result2.CommentaryCounts)
	}
	if result1.NewLeafCounts != result2.NewLeafCounts {
		t.Fatalf("NewLeaf counts: %d vs %d", result1.NewLeafCounts, result2.NewLeafCounts)
	}

	// Sanity: should have some root entities, some amendments, and many commentaries.
	if result1.NewLeafCounts == 0 {
		t.Fatal("expected some new leaves")
	}
	if result1.CommentaryCounts == 0 {
		t.Fatal("expected some commentary entries")
	}

	t.Logf("DETERMINISM PASS: root=%x | leaves=%d pathA=%d commentary=%d",
		result1.NewRoot[:8], result1.NewLeafCounts, result1.PathACounts, result1.CommentaryCounts)
}


