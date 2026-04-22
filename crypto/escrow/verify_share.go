// Package escrow — verify_share.go validates shares before they are used
// in reconstruction.
//
// Two public functions:
//
//	ValidateShareFormat validates a single share's structural properties:
//	  supported Version, non-degenerate Threshold, non-zero Index,
//	  non-zero SplitID, and (for V1) that V2-only fields are empty.
//	  This is a per-share check.
//
//	VerifyShareSet validates a collection of shares for mutual consistency
//	  and reconstruction eligibility: all shares agree on Version,
//	  Threshold, and SplitID; Indices are unique; the set size meets
//	  the declared Threshold (closes BUG-010 at the boundary).
//
// Naming: the previous function was called VerifyShare, which implied
// cryptographic verification that V1 does not provide. V1 is a structural
// check only — actual cryptographic share verification (each share is a
// valid share of a specific secret) requires Pedersen commitments and
// lands with V2. The rename reflects what the V1 function actually does.
package escrow

import "fmt"

// ValidateShareFormat checks the structural integrity of a single share.
//
// Returns nil if the share is well-formed. Returns a typed error (see
// share_format.go for sentinels) identifying the first failure.
//
// Checks:
//   - Version == VersionV1 (rejects V2 and unknown versions).
//   - Threshold >= 2 (rejects degenerate 1-of-N and zero).
//   - Index != 0 (index 0 is reserved; evaluating f(0) would reveal the secret).
//   - SplitID != [32]byte{} (every share must be bound to a split).
//   - BlindingFactor is zero (V1 must not populate V2-only fields).
//   - CommitmentHash is zero (V1 must not populate V2-only fields).
//
// Does not validate the share's cryptographic validity — that requires
// Pedersen VSS (V2).
func ValidateShareFormat(s Share) error {
	if s.Version != VersionV1 {
		return fmt.Errorf(
			"%w: got 0x%02x, expected 0x%02x (V1 GF(256))",
			ErrUnsupportedVersion, s.Version, VersionV1,
		)
	}
	if s.Threshold < 2 {
		return fmt.Errorf(
			"%w: share threshold is %d, minimum is 2",
			ErrInvalidThreshold, s.Threshold,
		)
	}
	if s.Index == 0 {
		return fmt.Errorf("%w: index 0 is reserved", ErrInvalidIndex)
	}
	if zeroArray32(s.SplitID) {
		return fmt.Errorf("%w", ErrSplitIDMissing)
	}
	if !zeroArray32(s.BlindingFactor) {
		return fmt.Errorf("%w: BlindingFactor must be zero in V1", ErrV1FieldNotEmpty)
	}
	if !zeroArray32(s.CommitmentHash) {
		return fmt.Errorf("%w: CommitmentHash must be zero in V1", ErrV1FieldNotEmpty)
	}
	return nil
}

// VerifyShareSet validates a set of shares for mutual consistency and
// reconstruction eligibility.
//
// Returns nil if the set is valid for reconstruction. Returns a typed
// error (see share_format.go for sentinels) identifying the first
// failure.
//
// Checks (in order):
//   - Set is non-empty.
//   - Every share passes ValidateShareFormat.
//   - All shares agree on Version.
//   - All shares agree on Threshold.
//   - All shares agree on SplitID (prevents cross-split mixing).
//   - All Indices are unique.
//   - len(shares) >= Threshold (closes BUG-010).
//
// A caller who wants to validate a share set that might not meet the
// threshold (e.g., during collection, before enough shares have arrived)
// should call ValidateShareFormat per share and track mutual consistency
// independently. VerifyShareSet is the pre-Reconstruct gate.
func VerifyShareSet(shares []Share) error {
	if len(shares) == 0 {
		return ErrEmptyShareSet
	}

	// Validate each share structurally first.
	for i, s := range shares {
		if err := ValidateShareFormat(s); err != nil {
			return fmt.Errorf("escrow/verify: share %d: %w", i, err)
		}
	}

	// All shares passed per-share validation; now check set consistency.
	// We use the first share as the reference.
	first := shares[0]

	seenIdx := make(map[byte]bool, len(shares))
	for i, s := range shares {
		if s.Version != first.Version {
			return fmt.Errorf(
				"%w: share 0 has version 0x%02x, share %d has 0x%02x",
				ErrVersionMismatch, first.Version, i, s.Version,
			)
		}
		if s.Threshold != first.Threshold {
			return fmt.Errorf(
				"%w: share 0 has threshold %d, share %d has %d",
				ErrThresholdMismatch, first.Threshold, i, s.Threshold,
			)
		}
		if s.SplitID != first.SplitID {
			return fmt.Errorf(
				"%w: share 0 has split id %x, share %d has %x",
				ErrSplitIDMismatch, first.SplitID[:8], i, s.SplitID[:8],
			)
		}
		if seenIdx[s.Index] {
			return fmt.Errorf(
				"%w: index %d appears more than once",
				ErrDuplicateIndex, s.Index,
			)
		}
		seenIdx[s.Index] = true
	}

	// Threshold check — the load-bearing BUG-010 closure. Must come after
	// the per-share and consistency checks so we know Threshold is valid
	// and consistent across the set.
	if len(shares) < int(first.Threshold) {
		return fmt.Errorf(
			"%w: have %d shares, need at least %d",
			ErrBelowThreshold, len(shares), first.Threshold,
		)
	}

	return nil
}
