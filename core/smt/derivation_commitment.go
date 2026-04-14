package smt

import "github.com/clearcompass-ai/ortholog-sdk/types"

func GenerateCommitment(rangeStart, rangeEnd types.LogPosition, priorRoot, postRoot [32]byte, mutations []types.LeafMutation) types.SMTDerivationCommitment {
	return types.SMTDerivationCommitment{
		LogRangeStart: rangeStart, LogRangeEnd: rangeEnd,
		PriorSMTRoot: priorRoot, PostSMTRoot: postRoot,
		Mutations: mutations, MutationCount: uint32(len(mutations)),
	}
}

func VerifyCommitmentTransition(commitment types.SMTDerivationCommitment, entries []types.EntryWithMetadata,
	replayFunc func([32]byte, []types.EntryWithMetadata) ([32]byte, []types.LeafMutation, error)) error {
	replayedRoot, replayedMutations, err := replayFunc(commitment.PriorSMTRoot, entries)
	if err != nil { return err }
	if replayedRoot != commitment.PostSMTRoot {
		return &FraudProof{Commitment: commitment, ReplayedRoot: replayedRoot, ReplayedMutations: replayedMutations}
	}
	return nil
}

type FraudProof struct {
	Commitment        types.SMTDerivationCommitment
	ReplayedRoot      [32]byte
	ReplayedMutations []types.LeafMutation
}

func (f *FraudProof) Error() string { return "SMT derivation fraud: replayed root does not match committed post root" }
