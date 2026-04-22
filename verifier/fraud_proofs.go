/*
Package verifier — fraud_proofs.go replays entries from a derivation
commitment against a caller-supplied prior SMT snapshot and detects
divergences in either the per-leaf mutations or the post-replay root.

ARCHITECTURE — BUG-017
──────────────────────
Earlier revisions of this file seeded the verifier's tree only from the
mutations carried by the commitment. That is correct exclusively for a
genesis commitment (sequence 0+); for any commitment whose log range
starts after genesis, the prior tree contains leaves outside the batch
and the seeded-tree root necessarily diverges from the commitment's
PriorSMTRoot, falsely flagging honest operators as fraudulent.

The fix is structural: the caller supplies the prior tree state as an
smt.LeafStore. The verifier wraps it in an OverlayLeafStore so that
replay writes are buffered ephemerally and never pollute the caller's
persistent state, then compares per-leaf mutations and computes the
post-root incrementally via tree.ComputeDirtyRoot — O(M log N) once
the cache is warm, no full-tree iteration per batch.

CALLER CONTRACT
───────────────
priorState MUST correspond to commitment.PriorSMTRoot. The verifier
does not separately validate this. If the caller supplies a store that
does not match PriorSMTRoot, the post-root comparison will surface the
discrepancy as a FraudProofResult{Valid: false} just like genuine
fraud — there is no separate error path, by design.

Depends only on Phase 1 ProcessBatch — no Phase 5 dependencies.

Consumed by:
  - Monitoring services detecting malicious SMT operators
  - Bridge contracts verifying state transitions
*/
package verifier

import (
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────

// FraudProof is O(1) evidence of an incorrect leaf mutation.
type FraudProof struct {
	// LeafKey identifies the leaf with the divergence.
	LeafKey [32]byte

	// ClaimedNewOriginTip is what the commitment says the new OriginTip is.
	ClaimedNewOriginTip types.LogPosition
	// ActualNewOriginTip is what the replay actually produced.
	ActualNewOriginTip types.LogPosition

	// ClaimedNewAuthTip is what the commitment says the new AuthorityTip is.
	ClaimedNewAuthTip types.LogPosition
	// ActualNewAuthTip is what the replay actually produced.
	ActualNewAuthTip types.LogPosition
}

// FraudProofResult holds the outcome of commitment verification.
type FraudProofResult struct {
	// Valid is true if the commitment matches the replay exactly.
	Valid bool

	// Proofs contains one FraudProof per divergent leaf mutation.
	// Empty if Valid is true.
	Proofs []FraudProof
}

// ─────────────────────────────────────────────────────────────────────
// VerifyDerivationCommitment
// ─────────────────────────────────────────────────────────────────────

// VerifyDerivationCommitment replays entries from a derivation commitment
// against a caller-supplied prior SMT snapshot and reports per-leaf fraud
// proofs and/or a root-level mismatch.
//
// priorState is the leaf store representing the SMT at commitment.PriorSMTRoot.
// The verifier wraps it in an OverlayLeafStore so replay writes are
// buffered ephemerally — priorState is never mutated, regardless of
// outcome. Callers are responsible for ensuring priorState matches
// PriorSMTRoot; mismatches surface as a post-root divergence (Valid: false
// with no per-leaf proofs).
//
// Algorithm:
//  1. Wrap priorState in OverlayLeafStore + a fresh OverlayNodeCache
//  2. Compute the prior root via tree.Root() — warms the node cache for
//     the subsequent dirty-root computation
//  3. Fetch entries in [LogRangeStart, LogRangeEnd] via the EntryFetcher
//  4. Replay entries via builder.ProcessBatch (writes buffer in overlay)
//  5. Per-leaf comparison: replayed mutations vs commitment.Mutations
//  6. Compute post-root via tree.ComputeDirtyRoot using the warm cache
//     and compare to commitment.PostSMTRoot
//  7. Any divergence → FraudProofResult{Valid: false}
//
// Cost: O(M log N) per batch once the cache is warm, where M is the
// mutation count and N is the leaf count.
func VerifyDerivationCommitment(
	commitment types.SMTDerivationCommitment,
	priorState smt.LeafStore,
	fetcher types.EntryFetcher,
	schemaRes builder.SchemaResolver,
	logDID string,
) (*FraudProofResult, error) {
	// Handle empty commitment.
	if commitment.MutationCount == 0 && len(commitment.Mutations) == 0 {
		return &FraudProofResult{Valid: true}, nil
	}
	if priorState == nil {
		return nil, fmt.Errorf("verifier/fraud: priorState is required (use smt.NewInMemoryLeafStore for an empty prior)")
	}

	// 1. Wrap caller's prior state. Writes go to the overlay only.
	leafOverlay := smt.NewOverlayLeafStore(priorState)
	cacheOverlay := smt.NewOverlayNodeCache(smt.NewInMemoryNodeCache())
	tree := smt.NewTree(leafOverlay, cacheOverlay)

	// 2. Compute prior root over the supplied state. Side effect: warms
	// the node cache so the post-replay ComputeDirtyRoot can run in
	// O(M log N) without descending into clean subtrees.
	if _, err := tree.Root(); err != nil {
		return nil, fmt.Errorf("verifier/fraud: warm prior root: %w", err)
	}

	// 3. Fetch entries in range.
	startSeq := commitment.LogRangeStart.Sequence
	endSeq := commitment.LogRangeEnd.Sequence
	if endSeq < startSeq {
		return nil, fmt.Errorf("verifier/fraud: invalid range: start=%d > end=%d", startSeq, endSeq)
	}

	var entries []*envelope.Entry
	var positions []types.LogPosition
	for seq := startSeq; seq <= endSeq; seq++ {
		pos := types.LogPosition{LogDID: logDID, Sequence: seq}
		meta, err := fetcher.Fetch(pos)
		if err != nil || meta == nil {
			continue // Entry not found — operator may have omitted it.
		}
		entry, err := envelope.Deserialize(meta.CanonicalBytes)
		if err != nil {
			continue
		}
		entries = append(entries, entry)
		positions = append(positions, pos)
	}

	// 4. Replay via ProcessBatch. Writes accumulate in leafOverlay's buffer.
	buf := builder.NewDeltaWindowBuffer(10)
	result, err := builder.ProcessBatch(tree, entries, positions, fetcher, schemaRes, logDID, buf)
	if err != nil {
		return nil, fmt.Errorf("verifier/fraud: ProcessBatch: %w", err)
	}

	// 5. Compare mutations.
	var proofs []FraudProof

	committed := make(map[[32]byte]types.LeafMutation, len(commitment.Mutations))
	for _, m := range commitment.Mutations {
		committed[m.LeafKey] = m
	}

	replayed := make(map[[32]byte]types.LeafMutation, len(result.Mutations))
	for _, m := range result.Mutations {
		replayed[m.LeafKey] = m
	}

	// Each committed mutation must match the replay.
	for key, cm := range committed {
		rm, found := replayed[key]
		if !found {
			proofs = append(proofs, FraudProof{
				LeafKey:             key,
				ClaimedNewOriginTip: cm.NewOriginTip,
				ActualNewOriginTip:  cm.OldOriginTip,
				ClaimedNewAuthTip:   cm.NewAuthorityTip,
				ActualNewAuthTip:    cm.OldAuthorityTip,
			})
			continue
		}
		if !cm.NewOriginTip.Equal(rm.NewOriginTip) || !cm.NewAuthorityTip.Equal(rm.NewAuthorityTip) {
			proofs = append(proofs, FraudProof{
				LeafKey:             key,
				ClaimedNewOriginTip: cm.NewOriginTip,
				ActualNewOriginTip:  rm.NewOriginTip,
				ClaimedNewAuthTip:   cm.NewAuthorityTip,
				ActualNewAuthTip:    rm.NewAuthorityTip,
			})
		}
	}

	// Replayed mutations not mentioned by the commitment are also fraud.
	for key, rm := range replayed {
		if _, found := committed[key]; !found {
			proofs = append(proofs, FraudProof{
				LeafKey:             key,
				ClaimedNewOriginTip: types.LogPosition{},
				ActualNewOriginTip:  rm.NewOriginTip,
				ClaimedNewAuthTip:   types.LogPosition{},
				ActualNewAuthTip:    rm.NewAuthorityTip,
			})
		}
	}

	// 6. Post-root check via the dirty path. Uses the warm cache from
	// step 2 plus the overlay's buffered writes. O(M log N).
	writes, _ := leafOverlay.Mutations()
	postRoot, err := tree.ComputeDirtyRoot(commitment.PriorSMTRoot, writes)
	if err != nil {
		return nil, fmt.Errorf("verifier/fraud: ComputeDirtyRoot: %w", err)
	}
	if postRoot != commitment.PostSMTRoot {
		// Per-leaf checks may also have produced proofs; surface both.
		return &FraudProofResult{Valid: false, Proofs: proofs}, nil
	}

	if len(proofs) > 0 {
		return &FraudProofResult{Valid: false, Proofs: proofs}, nil
	}

	return &FraudProofResult{Valid: true}, nil
}
