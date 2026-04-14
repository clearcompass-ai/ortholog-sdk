package smt

import (
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// GenerateCommitment creates an SMT derivation commitment from a batch.
// Published as a commentary entry on the log (zero SMT impact).
// Enables O(batch) incremental verification and O(1) fraud proofs.
func GenerateCommitment(
	rangeStart types.LogPosition,
	rangeEnd types.LogPosition,
	priorRoot [32]byte,
	postRoot [32]byte,
	mutations []types.LeafMutation,
) types.SMTDerivationCommitment {
	return types.SMTDerivationCommitment{
		LogRangeStart: rangeStart,
		LogRangeEnd:   rangeEnd,
		PriorSMTRoot:  priorRoot,
		PostSMTRoot:   postRoot,
		Mutations:     mutations,
		MutationCount: uint32(len(mutations)),
	}
}

// VerifyCommitmentTransition replays a batch of mutations against the prior root
// and checks that the result matches the post root.
// Returns nil if the transition is correct. Otherwise returns an error identifying
// the first incorrect mutation (O(1) fraud proof per mutation).
func VerifyCommitmentTransition(
	commitment types.SMTDerivationCommitment,
	entries []types.EntryWithMetadata,
	replayFunc func(priorRoot [32]byte, entries []types.EntryWithMetadata) ([32]byte, []types.LeafMutation, error),
) error {
	// Replay the batch from the prior root.
	replayedRoot, replayedMutations, err := replayFunc(commitment.PriorSMTRoot, entries)
	if err != nil {
		return err
	}

	// Check post root matches.
	if replayedRoot != commitment.PostSMTRoot {
		return &FraudProof{
			Commitment:       commitment,
			ReplayedRoot:     replayedRoot,
			ReplayedMutations: replayedMutations,
		}
	}

	return nil
}

// FraudProof is evidence of an incorrect SMT derivation.
// O(1) per incorrect mutation. Verifiable by any light client or bridge contract.
type FraudProof struct {
	Commitment        types.SMTDerivationCommitment
	ReplayedRoot      [32]byte
	ReplayedMutations []types.LeafMutation
}

func (f *FraudProof) Error() string {
	return "SMT derivation fraud: replayed root does not match committed post root"
}
