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
// Dispatches on Version:
//
//   - VersionV1: V2-only fields (BlindingFactor, CommitmentHash) MUST
//     be zero. FieldTag MUST be 0 (legacy) or SchemeGF256Tag.
//   - VersionV2: V2-only fields MUST be non-zero. FieldTag MUST be
//     0 (legacy tolerance) or SchemePedersenTag.
//   - any other value: ErrUnsupportedVersion.
//
// Common gates apply to both versions: Threshold >= 2, Index != 0,
// SplitID != zero.
//
// Does NOT validate the share's cryptographic validity. For V1,
// no such check exists by design. For V2, call
// VerifyShareAgainstCommitments with the published commitment set.
func ValidateShareFormat(s Share) error {
	switch s.Version {
	case VersionV1:
		return validateShareFormatV1(s)
	case VersionV2:
		return validateShareFormatV2(s)
	default:
		return fmt.Errorf(
			"%w: got 0x%02x, expected 0x%02x (V1) or 0x%02x (V2)",
			ErrUnsupportedVersion, s.Version, VersionV1, VersionV2,
		)
	}
}

// validateShareFormatV1 implements the pre-Phase-B validation contract.
// Kept byte-identical to the v7.5 behaviour; any change here is a V1
// regression and is a merge-blocker.
//
// Each check is gated by a mutation-audit switch so the audit runner
// can flip it and confirm the listed binding test fires. See
// verify_share_mutation_switches.go.
func validateShareFormatV1(s Share) error {
	if s.Threshold < 2 {
		return fmt.Errorf(
			"%w: share threshold is %d, minimum is 2",
			ErrInvalidThreshold, s.Threshold,
		)
	}
	if muEnableShareIndexNonZero {
		if s.Index == 0 {
			return fmt.Errorf("%w: index 0 is reserved", ErrInvalidIndex)
		}
	}
	if muEnableSplitIDPresent {
		if zeroArray32(s.SplitID) {
			return fmt.Errorf("%w", ErrSplitIDMissing)
		}
	}
	if muEnableV1FieldEmptyCheck {
		if !zeroArray32(s.BlindingFactor) {
			return fmt.Errorf("%w: BlindingFactor must be zero in V1", ErrV1FieldNotEmpty)
		}
		if !zeroArray32(s.CommitmentHash) {
			return fmt.Errorf("%w: CommitmentHash must be zero in V1", ErrV1FieldNotEmpty)
		}
	}
	// FieldTag discriminates which scheme produced this share. Zero
	// is tolerated for legacy shares that predate the field; any
	// explicit non-zero value MUST equal SchemeGF256Tag (V1 GF(256)).
	// Unknown non-zero values indicate either a forgery or a share
	// from a future scheme being fed into V1 code — both rejected.
	if muEnableFieldTagDiscrimination {
		if s.FieldTag != 0 && s.FieldTag != SchemeGF256Tag {
			return fmt.Errorf("%w: 0x%02x", ErrUnknownFieldTag, s.FieldTag)
		}
	}
	return nil
}

// validateShareFormatV2 enforces the Phase B V2 structural contract.
// A V2 share carries a populated blinding factor and a commitment
// hash; both are required for Pedersen verification to succeed
// downstream. A zero value here indicates either a V1 share with a
// Version-byte forgery, or a genuinely corrupted V2 share — both
// cases are hard-rejected here before the cryptographic check runs.
func validateShareFormatV2(s Share) error {
	if s.Threshold < 2 {
		return fmt.Errorf(
			"%w: V2 share threshold is %d, minimum is 2",
			ErrInvalidThreshold, s.Threshold,
		)
	}
	if muEnableShareIndexNonZero {
		if s.Index == 0 {
			return fmt.Errorf("%w: index 0 is reserved", ErrInvalidIndex)
		}
	}
	if muEnableSplitIDPresent {
		if zeroArray32(s.SplitID) {
			return fmt.Errorf("%w", ErrSplitIDMissing)
		}
	}
	if muEnableV2FieldPopulatedCheck {
		if zeroArray32(s.BlindingFactor) {
			return fmt.Errorf(
				"%w: BlindingFactor is zero for V2 share index %d",
				ErrV2FieldEmpty, s.Index,
			)
		}
		if zeroArray32(s.CommitmentHash) {
			return fmt.Errorf(
				"%w: CommitmentHash is zero for V2 share index %d",
				ErrV2FieldEmpty, s.Index,
			)
		}
	}
	if muEnableFieldTagDiscrimination {
		if s.FieldTag != 0 && s.FieldTag != SchemePedersenTag {
			return fmt.Errorf(
				"%w: V2 share with non-Pedersen field tag 0x%02x",
				ErrUnknownFieldTag, s.FieldTag,
			)
		}
	}
	return nil
}

// VerifyShare is a structural alias for ValidateShareFormat retained
// for callers migrating from the pre-rename public name. See the
// package-level naming note in the file header.
func VerifyShare(s Share) error { return ValidateShareFormat(s) }

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
