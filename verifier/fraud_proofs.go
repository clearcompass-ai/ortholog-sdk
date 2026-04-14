/*
Package verifier — fraud_proofs.go replays entries from a derivation
commitment against a prior SMT snapshot and detects divergences.

Takes a DerivationCommitment (range of entries + claimed pre/post SMT
roots + claimed leaf mutations), constructs a fresh smt.Tree initialized
with the prior leaf states, replays entries via builder.ProcessBatch,
and compares each resulting LeafMutation against the commitment's
claimed mutations.

Any divergence produces an O(1) fraud proof per incorrect mutation —
just the leaf key, the expected mutation, and the actual mutation.

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
// and compares the result against the claimed mutations and post-root.
//
// Algorithm:
//  1. Build fresh smt.Tree with InMemoryLeafStore + InMemoryNodeCache
//  2. Seed prior state: for each mutation, set leaf to old tips
//  3. Fetch entries in [LogRangeStart.Sequence, LogRangeEnd.Sequence]
//  4. Deserialize entries, call builder.ProcessBatch
//  5. Compare result mutations against commitment mutations
//  6. Check PostSMTRoot match
//  7. Any divergence → FraudProof
func VerifyDerivationCommitment(
	commitment types.SMTDerivationCommitment,
	fetcher EntryFetcher,
	schemaRes builder.SchemaResolver,
	logDID string,
) (*FraudProofResult, error) {
	// Handle empty commitment.
	if commitment.MutationCount == 0 && len(commitment.Mutations) == 0 {
		return &FraudProofResult{Valid: true}, nil
	}

	// 1. Build fresh tree.
	leafStore := smt.NewInMemoryLeafStore()
	nodeCache := smt.NewInMemoryNodeCache()
	tree := smt.NewTree(leafStore, nodeCache)

	// 2. Seed prior state from commitment mutations.
	for _, mut := range commitment.Mutations {
		// Skip new leaves (no prior state).
		if mut.OldOriginTip.IsNull() && mut.OldAuthorityTip.IsNull() {
			continue
		}
		oldLeaf := types.SMTLeaf{
			Key:          mut.LeafKey,
			OriginTip:    mut.OldOriginTip,
			AuthorityTip: mut.OldAuthorityTip,
		}
		if err := leafStore.Set(mut.LeafKey, oldLeaf); err != nil {
			return nil, fmt.Errorf("verifier/fraud: seed leaf %x: %w", mut.LeafKey[:8], err)
		}
	}

	// 2b. Verify PriorSMTRoot matches the seeded tree state.
	// If the commitment claims a different prior root than what the seeded
	// tree produces, the commitment is fraudulent.
	seededRoot, _ := tree.Root()
	if seededRoot != commitment.PriorSMTRoot {
		return &FraudProofResult{Valid: false}, nil
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

	// 4. Replay via ProcessBatch.
	buf := builder.NewDeltaWindowBuffer(10)
	result, err := builder.ProcessBatch(tree, entries, positions, fetcher, schemaRes, logDID, buf)
	if err != nil {
		return nil, fmt.Errorf("verifier/fraud: ProcessBatch: %w", err)
	}

	// 5. Compare mutations.
	var proofs []FraudProof

	// Index committed mutations by leaf key.
	committed := make(map[[32]byte]types.LeafMutation, len(commitment.Mutations))
	for _, m := range commitment.Mutations {
		committed[m.LeafKey] = m
	}

	// Index replayed mutations by leaf key.
	replayed := make(map[[32]byte]types.LeafMutation, len(result.Mutations))
	for _, m := range result.Mutations {
		replayed[m.LeafKey] = m
	}

	// Check each committed mutation against replay.
	for key, cm := range committed {
		rm, found := replayed[key]
		if !found {
			// Commitment claims mutation for a key replay didn't touch.
			proofs = append(proofs, FraudProof{
				LeafKey:             key,
				ClaimedNewOriginTip: cm.NewOriginTip,
				ActualNewOriginTip:  cm.OldOriginTip, // Unchanged.
				ClaimedNewAuthTip:   cm.NewAuthorityTip,
				ActualNewAuthTip:    cm.OldAuthorityTip, // Unchanged.
			})
			continue
		}

		// Compare new tips.
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

	// Check for mutations replay produced that commitment doesn't mention.
	for key, rm := range replayed {
		if _, found := committed[key]; !found {
			proofs = append(proofs, FraudProof{
				LeafKey:             key,
				ClaimedNewOriginTip: types.LogPosition{}, // Not claimed.
				ActualNewOriginTip:  rm.NewOriginTip,
				ClaimedNewAuthTip:   types.LogPosition{}, // Not claimed.
				ActualNewAuthTip:    rm.NewAuthorityTip,
			})
		}
	}

	// 6. Check PostSMTRoot.
	if len(proofs) == 0 && result.NewRoot != commitment.PostSMTRoot {
		// Individual mutations match but root diverges.
		// This is still fraud — return invalid with no per-leaf proofs.
		return &FraudProofResult{Valid: false}, nil
	}

	if len(proofs) > 0 {
		return &FraudProofResult{Valid: false, Proofs: proofs}, nil
	}

	return &FraudProofResult{Valid: true}, nil
}
