// Package schema — escrow_split_commitment_v1.go declares the
// escrow-split-commitment-v1 schema (ADR-005 §4). Parallel structure
// to pre_grant_commitment_v1.go: same JSON envelope, same
// admission-time discipline, swap of the wire serializer and
// commitment type.
//
// Validation contract (ADR-005 §4):
//   - schema_id field equals escrow-split-commitment-v1.
//   - commitment_bytes_hex decodes to a structurally valid wire
//     buffer via DeserializeEscrowSplitCommitment — threshold bounds,
//     set-length consistency, non-empty dealer DID, and every point
//     on-curve secp256k1 all fire at this boundary.
package schema

import (
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/escrow"
)

// ─────────────────────────────────────────────────────────────────────
// Escrow split commitment — validator + parser
// ─────────────────────────────────────────────────────────────────────

// ValidateEscrowSplitCommitmentEntry is the admission-time validator
// for escrow-split-commitment-v1 entries. Parallel to
// ValidatePREGrantCommitmentEntry; see that function's godoc for the
// boundary between admission and lifecycle verification.
func ValidateEscrowSplitCommitmentEntry(entry *envelope.Entry) error {
	if entry == nil {
		return fmt.Errorf("%w: nil entry", ErrCommitmentPayloadMalformed)
	}
	raw, err := decodeCommitmentPayload(entry.DomainPayload, EscrowSplitCommitmentSchemaID)
	if err != nil {
		return err
	}
	if _, err := escrow.DeserializeEscrowSplitCommitment(raw); err != nil {
		return fmt.Errorf("%w: deserialize: %v", ErrCommitmentPayloadMalformed, err)
	}
	return nil
}

// ParseEscrowSplitCommitmentEntry extracts the EscrowSplitCommitment
// from an escrow-split-commitment-v1 entry. Parallel to
// ParsePREGrantCommitmentEntry.
func ParseEscrowSplitCommitmentEntry(entry *envelope.Entry) (*escrow.EscrowSplitCommitment, error) {
	if entry == nil {
		return nil, fmt.Errorf("%w: nil entry", ErrCommitmentPayloadMalformed)
	}
	raw, err := decodeCommitmentPayload(entry.DomainPayload, EscrowSplitCommitmentSchemaID)
	if err != nil {
		return nil, err
	}
	c, err := escrow.DeserializeEscrowSplitCommitment(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: deserialize: %v", ErrCommitmentPayloadMalformed, err)
	}
	return c, nil
}
