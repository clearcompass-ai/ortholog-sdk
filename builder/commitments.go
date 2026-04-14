package builder

import (
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

func GenerateBatchCommitment(rangeStart, rangeEnd types.LogPosition, priorRoot [32]byte, result *BatchResult) types.SMTDerivationCommitment {
	return smt.GenerateCommitment(rangeStart, rangeEnd, priorRoot, result.NewRoot, result.Mutations)
}
