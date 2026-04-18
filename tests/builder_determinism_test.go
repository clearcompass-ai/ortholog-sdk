package tests

import (
	"testing"
	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

func TestBuilderCommitment_MatchesMutations(t *testing.T) {
	h := newHarness(); rootBefore, _ := h.tree.Root()
	entry, _ := makeEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:alice", AuthorityPath: sameSigner()}, nil)
	entryPos := pos(1); result := h.process(t, entry, entryPos)
	commitment := builder.GenerateBatchCommitment(entryPos, entryPos, rootBefore, result)
	if commitment.MutationCount != uint32(len(result.Mutations)) { t.Fatal("mutation count mismatch") }
	if commitment.PostSMTRoot != result.NewRoot { t.Fatal("post root mismatch") }
}

func TestBuilderCommitment_ReplayConsistent(t *testing.T) {
	h := newHarness(); rootBefore, _ := h.tree.Root()
	entries := make([]*envelope.Entry, 5); positions := make([]types.LogPosition, 5)
	for i := 0; i < 5; i++ {
		e, _ := makeEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:alice", AuthorityPath: sameSigner()}, nil)
		entries[i] = e; positions[i] = pos(uint64(i+1)); h.fetcher.Store(positions[i], e)
	}
	result, _ := builder.ProcessBatch(h.tree, entries, positions, h.fetcher, nil, testLogDID, h.buffer)
	h2 := newHarness()
	for i, e := range entries { h2.fetcher.Store(positions[i], e) }
	result2, _ := builder.ProcessBatch(h2.tree, entries, positions, h2.fetcher, nil, testLogDID, h2.buffer)
	if result.NewRoot != result2.NewRoot { t.Fatal("replayed batch should produce identical root") }
	commitment := builder.GenerateBatchCommitment(positions[0], positions[4], rootBefore, result)
	if commitment.PriorSMTRoot != rootBefore { t.Fatal("commitment prior root mismatch") }
}

func TestBuilderCommitment_EmptyBatch(t *testing.T) {
	h := newHarness(); rootBefore, _ := h.tree.Root()
	result, _ := builder.ProcessBatch(h.tree, nil, nil, h.fetcher, nil, testLogDID, h.buffer)
	if len(result.Mutations) != 0 { t.Fatal("empty batch should have no mutations") }
	if result.NewRoot != rootBefore { t.Fatal("empty batch should not change root") }
}

func TestBuilderDeterminism_1000Entries(t *testing.T) {
	const N = 1000
	entries := make([]*envelope.Entry, N); positions := make([]types.LogPosition, N)
	for i := 0; i < N; i++ {
		seq := uint64(i + 1); positions[i] = pos(seq)
		switch {
		case i%10 == 0:
			entries[i], _ = makeEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: didForIndex(i), AuthorityPath: sameSigner(), EventTime: int64(i) * 1000000}, []byte{byte(i)})
		case i%10 == 1 && i > 10:
			rootSeq := uint64(i - i%10 + 1); signer := didForIndex(i - i%10)
			entries[i], _ = makeEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: signer, TargetRoot: ptrTo(pos(rootSeq)), AuthorityPath: sameSigner(), EventTime: int64(i) * 1000000}, []byte{byte(i)})
		default:
			entries[i], _ = makeEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: didForIndex(i), EventTime: int64(i) * 1000000}, []byte{byte(i)})
		}
	}
	tree1 := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeCache())
	f1 := NewMockFetcher(); for i, e := range entries { f1.Store(positions[i], e) }
	r1, _ := builder.ProcessBatch(tree1, entries, positions, f1, nil, testLogDID, builder.NewDeltaWindowBuffer(10))
	tree2 := smt.NewTree(smt.NewInMemoryLeafStore(), smt.NewInMemoryNodeCache())
	f2 := NewMockFetcher(); for i, e := range entries { f2.Store(positions[i], e) }
	r2, _ := builder.ProcessBatch(tree2, entries, positions, f2, nil, testLogDID, builder.NewDeltaWindowBuffer(10))
	if r1.NewRoot != r2.NewRoot { t.Fatalf("DETERMINISM FAILURE: %x != %x", r1.NewRoot[:8], r2.NewRoot[:8]) }
	if r1.PathACounts != r2.PathACounts { t.Fatal("PathA counts differ") }
	if r1.CommentaryCounts != r2.CommentaryCounts { t.Fatal("Commentary counts differ") }
	if r1.NewLeafCounts == 0 { t.Fatal("expected some leaves") }
	if r1.CommentaryCounts == 0 { t.Fatal("expected some commentary") }
	t.Logf("DETERMINISM PASS: root=%x leaves=%d pathA=%d commentary=%d", r1.NewRoot[:8], r1.NewLeafCounts, r1.PathACounts, r1.CommentaryCounts)
}
