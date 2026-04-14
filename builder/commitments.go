package builder

import (
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// GenerateBatchCommitment creates an SMT derivation commitment from a batch result.
// Published by the operator as a commentary entry (Target_Root null, Authority_Path null).
// The commitment enables O(batch) incremental verification and O(1) fraud proofs.
func GenerateBatchCommitment(
	rangeStart types.LogPosition,
	rangeEnd types.LogPosition,
	priorRoot [32]byte,
	result *BatchResult,
) types.SMTDerivationCommitment {
	return smt.GenerateCommitment(rangeStart, rangeEnd, priorRoot, result.NewRoot, result.Mutations)
}
