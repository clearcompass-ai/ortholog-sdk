/*
Package escrow — verify_share.go validates individual Shamir shares before
reconstruction. Checks field tag (0x01 = GF(256)) and value length (32 bytes).

ReconstructGF256 already rejects mixed/unrecognized tags during reconstruction,
but VerifyShare allows callers to validate shares one at a time during collection
(e.g., recovery.CollectShares) without waiting for full reconstruction.

Phase 6 Part B naming clarification #2: the plan originally referenced
"escrow.VerifyShare" which was not a standalone function. This file adds it.
*/
package escrow

import "fmt"

// VerifyShare validates a single Shamir share's structural integrity.
//
// Checks:
//   - FieldTag == 0x01 (GF(256)). Unrecognized tags are rejected.
//   - Index != 0 (index 0 is reserved).
//   - Value length == 32 bytes (secp256k1 scalar width).
//
// This is the pre-reconstruction validation gate. CollectShares calls this
// on each share as it arrives from an escrow node. Invalid shares are
// rejected immediately rather than poisoning reconstruction.
func VerifyShare(s Share) error {
	if s.FieldTag != FieldTagGF256 {
		return fmt.Errorf("escrow/verify: unrecognized field tag 0x%02x (expected 0x%02x GF(256))", s.FieldTag, FieldTagGF256)
	}
	if s.Index == 0 {
		return fmt.Errorf("escrow/verify: share index 0 is reserved")
	}
	if len(s.Value) != 32 {
		return fmt.Errorf("escrow/verify: share value length %d (expected 32)", len(s.Value))
	}
	return nil
}

// VerifyShareSet validates a collection of shares for mutual consistency.
// All shares must have the same field tag and value length, with unique indices.
// Returns nil if valid, error identifying the first inconsistency.
func VerifyShareSet(shares []Share) error {
	if len(shares) == 0 {
		return fmt.Errorf("escrow/verify: empty share set")
	}
	seen := make(map[byte]bool, len(shares))
	for i, s := range shares {
		if err := VerifyShare(s); err != nil {
			return fmt.Errorf("escrow/verify: share %d: %w", i, err)
		}
		if seen[s.Index] {
			return fmt.Errorf("escrow/verify: duplicate share index %d", s.Index)
		}
		seen[s.Index] = true
	}
	return nil
}
