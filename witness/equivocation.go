/*
witness/equivocation.go — Equivocation detection.

Two cosigned tree heads at the same tree_size with different root_hash
AND both carrying valid K-of-N signatures = cryptographic proof of
operator misbehavior (log fork). This proof is unforgeable.

Three outcomes:
  - Same roots → nil, nil (no equivocation)
  - Different sizes → nil, ErrDifferentSizes (not equivocation, just different states)
  - Same size, different roots, both valid → EquivocationProof

EquivocationProof consumed by:
  - Phase 6 scope.go objective trigger classifier
  - Phase 2 operator equivocation_monitor.go
  - Domain monitoring services
*/
package witness

import (
	"errors"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────

// ErrDifferentSizes is returned when two heads have different tree sizes.
// This is not equivocation — it's two snapshots at different points in time.
var ErrDifferentSizes = errors.New("witness/equivocation: different tree sizes")

// ─────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────

// EquivocationProof is cryptographic evidence that an operator published
// two different roots for the same tree size, both validly cosigned.
// This is unforgeable: producing it requires K-of-N witness keys.
type EquivocationProof struct {
	TreeSize  uint64
	HeadA     types.CosignedTreeHead
	HeadB     types.CosignedTreeHead
	ValidSigsA int
	ValidSigsB int
}

// ─────────────────────────────────────────────────────────────────────
// DetectEquivocation
// ─────────────────────────────────────────────────────────────────────

// DetectEquivocation checks whether two cosigned tree heads constitute
// a provable equivocation.
//
// Returns:
//   - (*EquivocationProof, nil): equivocation detected and proven
//   - (nil, nil): no equivocation (same roots)
//   - (nil, ErrDifferentSizes): not equivocation (different sizes)
//   - (nil, error): verification failure
//
// Both heads must have valid K-of-N signatures for the proof to hold.
// If either head fails verification, no proof is generated — a head
// with invalid signatures proves nothing about operator behavior.
func DetectEquivocation(
	headA, headB types.CosignedTreeHead,
	witnessKeys []types.WitnessPublicKey,
	quorumK int,
	blsVerifier signatures.BLSVerifier,
) (*EquivocationProof, error) {
	// Different sizes → not equivocation.
	if headA.TreeSize != headB.TreeSize {
		return nil, ErrDifferentSizes
	}

	// Same roots → no equivocation.
	if headA.RootHash == headB.RootHash {
		return nil, nil
	}

	// Same size, different roots → potential equivocation.
	// Verify both heads have valid quorum signatures.
	resultA, errA := VerifyTreeHead(headA, witnessKeys, quorumK, blsVerifier)
	if errA != nil {
		return nil, fmt.Errorf("witness/equivocation: head A verification: %w", errA)
	}

	resultB, errB := VerifyTreeHead(headB, witnessKeys, quorumK, blsVerifier)
	if errB != nil {
		return nil, fmt.Errorf("witness/equivocation: head B verification: %w", errB)
	}

	// Both valid → proven equivocation.
	return &EquivocationProof{
		TreeSize:   headA.TreeSize,
		HeadA:      headA,
		HeadB:      headB,
		ValidSigsA: resultA.ValidCount,
		ValidSigsB: resultB.ValidCount,
	}, nil
}

// IsProven returns true if this proof has valid signatures on both heads.
func (p *EquivocationProof) IsProven() bool {
	return p != nil && p.ValidSigsA > 0 && p.ValidSigsB > 0
}
