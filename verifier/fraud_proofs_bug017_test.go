/*
FILE PATH: verifier/fraud_proofs_bug017_test.go

DESCRIPTION:

	Co-located tests for VerifyDerivationCommitment after the BUG-017 fix.

	BUG-017 was a partial-range rejection: the verifier seeded its tree
	only from commitment.Mutations, so any commitment whose log range
	started after genesis had a seeded root that didn't match
	commitment.PriorSMTRoot — honest operators were flagged as fraudulent.

	The fix takes a caller-supplied priorState (smt.LeafStore) representing
	the tree at PriorSMTRoot, wraps it in an OverlayLeafStore so replay
	writes don't mutate caller state, and uses tree.ComputeDirtyRoot for
	an O(M log N) post-root check against a warm node cache.

	Test cases:

	  TestFraud_BUG017_PartialRangeAcceptsValidCommitment
	    Headline regression: build a commitment against a non-empty prior
	    tree (a partial-range slice), and verify it as Valid. The pre-fix
	    code returns Valid:false here.

	  TestFraud_ValidCommitment
	    Genesis-range parity with the original test.

	  TestFraud_SingleCorruptMutation / MultipleCorruptMutations
	    Migrated from phase5_part_b_test.go. A corrupt mutation surfaces
	    a per-leaf FraudProof.

	  TestFraud_EmptyCommitment_Valid
	    Empty commitments short-circuit to Valid.

	  TestFraud_WrongPriorStateMismatch
	    Replaces the old TestFraud_WrongPreRoot. Caller passes a priorState
	    that does not match commitment.PriorSMTRoot; the post-root check
	    catches the divergence.

	  TestFraud_CorrectMutationsWrongPostRoot
	    Migrated. Tampering with PostSMTRoot is detected via the dirty-root
	    comparison.

	  TestFraud_CommitmentClaimsExtraMutation
	    Migrated. A phantom mutation in the commitment surfaces as a
	    FraudProof referencing the phantom leaf.

	  TestFraud_PriorStateNotMutatedOnFraudulentCommitment
	    Invariant: the caller's priorState is unchanged after verification,
	    even when the commitment is fraudulent. OverlayLeafStore is the
	    mechanism.
*/
package verifier

import (
	"fmt"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// buildGenesisCommitmentFixture is the BUG-017 test analogue of the
// original tests/phase5_part_b_test.go buildCommitmentFixture. It builds
// n entries against an empty prior tree and returns the commitment, the
// EntryFetcher used by the build, and the prior leaf store (empty).
func buildGenesisCommitmentFixture(t *testing.T, n int) (
	commitment types.SMTDerivationCommitment,
	fetcher *p5bMockFetcher,
	priorState smt.LeafStore,
) {
	t.Helper()
	prior := smt.NewInMemoryLeafStore()
	tree := smt.NewTree(prior, smt.NewInMemoryNodeCache())
	mock := newP5BMockFetcher()
	buf := builder.NewDeltaWindowBuffer(10)

	entries := make([]*envelope.Entry, n)
	positions := make([]types.LogPosition, n)
	for i := 0; i < n; i++ {
		e := p5bBuildEntry(t, envelope.ControlHeader{
			Destination:   p5bTestDestinationDID,
			SignerDID:     fmt.Sprintf("did:example:fp-signer%d", i),
			AuthorityPath: p5bSameSigner(),
		}, []byte(fmt.Sprintf("fp-payload-%d", i)))
		entries[i] = e
		positions[i] = p5bPos(uint64(i + 1))
		mock.Store(positions[i], e)
	}

	rootBefore, _ := tree.Root()
	result, err := builder.ProcessBatch(tree, entries, positions, mock, nil, p5bTestLogDID, buf)
	if err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}

	// For the genesis fixture, the prior store is empty when handed back
	// to the verifier. The build above mutated the local 'prior' store as
	// a side-effect of ProcessBatch, so we hand back a fresh empty store
	// representing the state BEFORE the batch.
	freshPrior := smt.NewInMemoryLeafStore()
	commitment = builder.GenerateBatchCommitment(positions[0], positions[len(positions)-1], rootBefore, result)
	return commitment, mock, freshPrior
}

// buildPartialRangeCommitmentFixture is the BUG-017 regression fixture.
// It pre-populates a prior tree with `priorN` historical leaves
// (representing log entries before the audited batch), then runs a
// `batchN`-entry batch against the resulting tree. The returned
// priorState reflects the tree's state BEFORE the batch — exactly what a
// monitor performing a partial-range audit would have on hand.
func buildPartialRangeCommitmentFixture(t *testing.T, priorN, batchN int) (
	commitment types.SMTDerivationCommitment,
	fetcher *p5bMockFetcher,
	priorState smt.LeafStore,
) {
	t.Helper()
	prior := smt.NewInMemoryLeafStore()
	mock := newP5BMockFetcher()

	// Seed historical leaves and entries (sequences 1..priorN).
	for i := 0; i < priorN; i++ {
		pos := p5bPos(uint64(i + 1))
		entry := p5bBuildEntry(t, envelope.ControlHeader{
			Destination:   p5bTestDestinationDID,
			SignerDID:     fmt.Sprintf("did:example:hist-signer%d", i),
			AuthorityPath: p5bSameSigner(),
		}, []byte(fmt.Sprintf("hist-%d", i)))
		mock.Store(pos, entry)
		key := smt.DeriveKey(pos)
		_ = prior.Set(key, types.SMTLeaf{Key: key, OriginTip: pos, AuthorityTip: pos})
	}

	// Snapshot the prior store so we can hand the verifier a clean copy.
	priorSnapshot := smt.NewInMemoryLeafStore()
	for i := 0; i < priorN; i++ {
		pos := p5bPos(uint64(i + 1))
		key := smt.DeriveKey(pos)
		l, _ := prior.Get(key)
		_ = priorSnapshot.Set(key, *l)
	}

	tree := smt.NewTree(prior, smt.NewInMemoryNodeCache())
	rootBefore, err := tree.Root()
	if err != nil {
		t.Fatalf("rootBefore: %v", err)
	}

	// The batch under audit (sequences priorN+1 .. priorN+batchN).
	entries := make([]*envelope.Entry, batchN)
	positions := make([]types.LogPosition, batchN)
	for i := 0; i < batchN; i++ {
		seq := uint64(priorN + i + 1)
		pos := p5bPos(seq)
		entry := p5bBuildEntry(t, envelope.ControlHeader{
			Destination:   p5bTestDestinationDID,
			SignerDID:     fmt.Sprintf("did:example:batch-signer%d", i),
			AuthorityPath: p5bSameSigner(),
		}, []byte(fmt.Sprintf("batch-%d", i)))
		mock.Store(pos, entry)
		entries[i] = entry
		positions[i] = pos
	}

	buf := builder.NewDeltaWindowBuffer(10)
	result, err := builder.ProcessBatch(tree, entries, positions, mock, nil, p5bTestLogDID, buf)
	if err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}

	commitment = builder.GenerateBatchCommitment(positions[0], positions[len(positions)-1], rootBefore, result)
	return commitment, mock, priorSnapshot
}

// ─────────────────────────────────────────────────────────────────────
// BUG-017 headline regression
// ─────────────────────────────────────────────────────────────────────

// TestFraud_BUG017_PartialRangeAcceptsValidCommitment is the test that
// would have caught BUG-017. The pre-fix verifier seeded only from
// commitment.Mutations and rejected the partial-range commitment as
// Valid:false. The post-fix verifier consumes the caller's priorState
// and accepts.
func TestFraud_BUG017_PartialRangeAcceptsValidCommitment(t *testing.T) {
	commitment, fetcher, priorState := buildPartialRangeCommitmentFixture(t, 5, 3)

	result, err := VerifyDerivationCommitment(commitment, priorState, fetcher, nil, p5bTestLogDID)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !result.Valid {
		t.Fatalf(
			"BUG-017 REGRESSION: partial-range commitment rejected.\n"+
				"  proofs: %d\n"+
				"  Pre-fix code seeds from mutations only and fails for any "+
				"non-genesis range. Post-fix must accept this as valid.",
			len(result.Proofs))
	}
	if len(result.Proofs) != 0 {
		t.Fatalf("valid commitment should have no proofs, got %d", len(result.Proofs))
	}
}

// ─────────────────────────────────────────────────────────────────────
// Migrated TestFraud_* cases (genesis range)
// ─────────────────────────────────────────────────────────────────────

func TestFraud_ValidCommitment(t *testing.T) {
	commitment, fetcher, priorState := buildGenesisCommitmentFixture(t, 5)

	result, err := VerifyDerivationCommitment(commitment, priorState, fetcher, nil, p5bTestLogDID)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !result.Valid {
		t.Fatalf("valid commitment should pass, got %d proofs", len(result.Proofs))
	}
	if len(result.Proofs) != 0 {
		t.Fatal("valid commitment should have no proofs")
	}
}

func TestFraud_SingleCorruptMutation(t *testing.T) {
	commitment, fetcher, priorState := buildGenesisCommitmentFixture(t, 3)

	if len(commitment.Mutations) > 0 {
		commitment.Mutations[0].NewOriginTip = p5bPos(9999)
	}

	result, err := VerifyDerivationCommitment(commitment, priorState, fetcher, nil, p5bTestLogDID)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if result.Valid {
		t.Fatal("corrupt mutation should be detected")
	}
	if len(result.Proofs) < 1 {
		t.Fatal("should have at least 1 fraud proof")
	}
	found := false
	for _, p := range result.Proofs {
		if p.ClaimedNewOriginTip.Equal(p5bPos(9999)) {
			found = true
		}
	}
	if !found {
		t.Fatal("fraud proof should reference the corrupt claimed tip")
	}
}

func TestFraud_MultipleCorruptMutations(t *testing.T) {
	commitment, fetcher, priorState := buildGenesisCommitmentFixture(t, 5)

	for i := range commitment.Mutations {
		if i < 2 {
			commitment.Mutations[i].NewOriginTip = p5bPos(uint64(8000 + i))
		}
	}

	result, err := VerifyDerivationCommitment(commitment, priorState, fetcher, nil, p5bTestLogDID)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if result.Valid {
		t.Fatal("multiple corrupt mutations should be detected")
	}
	if len(result.Proofs) < 2 {
		t.Fatalf("expected at least 2 fraud proofs, got %d", len(result.Proofs))
	}
}

func TestFraud_EmptyCommitment_Valid(t *testing.T) {
	commitment := types.SMTDerivationCommitment{
		MutationCount: 0,
		Mutations:     nil,
	}
	fetcher := newP5BMockFetcher()
	priorState := smt.NewInMemoryLeafStore()

	result, err := VerifyDerivationCommitment(commitment, priorState, fetcher, nil, p5bTestLogDID)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !result.Valid {
		t.Fatal("empty commitment should be valid")
	}
}

// TestFraud_WrongPriorStateMismatch: if the caller hands the verifier a
// priorState that does NOT match commitment.PriorSMTRoot (here: a
// non-empty store paired with a genesis-range commitment), the
// dirty-root post-check catches the divergence.
func TestFraud_WrongPriorStateMismatch(t *testing.T) {
	commitment, fetcher, _ := buildGenesisCommitmentFixture(t, 3)

	// Inject a leaf into priorState that the genesis commitment doesn't
	// know about. The verifier's computed post-root will include this
	// extra leaf and diverge from commitment.PostSMTRoot.
	wrongPrior := smt.NewInMemoryLeafStore()
	rogueKey := smt.DeriveKey(p5bPos(123456))
	_ = wrongPrior.Set(rogueKey, types.SMTLeaf{
		Key:          rogueKey,
		OriginTip:    p5bPos(123456),
		AuthorityTip: p5bPos(123456),
	})

	result, err := VerifyDerivationCommitment(commitment, wrongPrior, fetcher, nil, p5bTestLogDID)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if result.Valid {
		t.Fatal("priorState that does not match PriorSMTRoot should produce a post-root divergence")
	}
}

func TestFraud_CorrectMutationsWrongPostRoot(t *testing.T) {
	commitment, fetcher, priorState := buildGenesisCommitmentFixture(t, 3)

	commitment.PostSMTRoot = [32]byte{0xAA}

	result, err := VerifyDerivationCommitment(commitment, priorState, fetcher, nil, p5bTestLogDID)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if result.Valid {
		t.Fatal("wrong PostSMTRoot should be detected")
	}
}

func TestFraud_CommitmentClaimsExtraMutation(t *testing.T) {
	commitment, fetcher, priorState := buildGenesisCommitmentFixture(t, 3)

	phantom := types.LeafMutation{
		LeafKey:         smt.DeriveKey(p5bPos(777)),
		OldOriginTip:    types.LogPosition{},
		NewOriginTip:    p5bPos(778),
		OldAuthorityTip: types.LogPosition{},
		NewAuthorityTip: p5bPos(778),
	}
	commitment.Mutations = append(commitment.Mutations, phantom)
	commitment.MutationCount++

	result, err := VerifyDerivationCommitment(commitment, priorState, fetcher, nil, p5bTestLogDID)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if result.Valid {
		t.Fatal("phantom mutation should be detected as fraud")
	}
	found := false
	for _, p := range result.Proofs {
		if p.LeafKey == smt.DeriveKey(p5bPos(777)) {
			found = true
		}
	}
	if !found {
		t.Fatal("fraud proof should reference the phantom leaf key")
	}
}

// TestFraud_PriorStateNotMutatedOnFraudulentCommitment is an invariant
// check: the verifier MUST NOT modify the caller's priorState even when
// the commitment is fraudulent. The OverlayLeafStore is the mechanism
// that guarantees this.
func TestFraud_PriorStateNotMutatedOnFraudulentCommitment(t *testing.T) {
	commitment, fetcher, priorState := buildPartialRangeCommitmentFixture(t, 5, 3)

	// Corrupt a mutation so verification fails.
	if len(commitment.Mutations) > 0 {
		commitment.Mutations[0].NewOriginTip = p5bPos(99999)
	}

	// Snapshot priorState before the call.
	preCount, _ := priorState.Count()
	preLeaves := snapshotInMemoryStore(t, priorState.(*smt.InMemoryLeafStore))

	result, err := VerifyDerivationCommitment(commitment, priorState, fetcher, nil, p5bTestLogDID)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if result.Valid {
		t.Fatal("corrupt commitment should fail")
	}

	postCount, _ := priorState.Count()
	if postCount != preCount {
		t.Fatalf("priorState count changed: pre=%d post=%d", preCount, postCount)
	}
	postLeaves := snapshotInMemoryStore(t, priorState.(*smt.InMemoryLeafStore))
	if !leafSnapshotsEqual(preLeaves, postLeaves) {
		t.Fatal("priorState leaf set was mutated by a fraudulent verification")
	}
}

func snapshotInMemoryStore(t *testing.T, store *smt.InMemoryLeafStore) map[[32]byte]types.SMTLeaf {
	t.Helper()
	out := make(map[[32]byte]types.SMTLeaf)
	count, _ := store.Count()
	if count == 0 {
		return out
	}
	// Walk the keys we know about by re-reading them. We don't have a
	// public iterator on the LeafStore interface, but for the tests'
	// fixture sizes we can re-scan via the canonical sequence space.
	for seq := uint64(1); seq <= 1000; seq++ {
		key := smt.DeriveKey(p5bPos(seq))
		if leaf, _ := store.Get(key); leaf != nil {
			out[key] = *leaf
		}
	}
	return out
}

func leafSnapshotsEqual(a, b map[[32]byte]types.SMTLeaf) bool {
	if len(a) != len(b) {
		return false
	}
	for k, va := range a {
		vb, ok := b[k]
		if !ok {
			return false
		}
		if !va.OriginTip.Equal(vb.OriginTip) || !va.AuthorityTip.Equal(vb.AuthorityTip) {
			return false
		}
	}
	return true
}
