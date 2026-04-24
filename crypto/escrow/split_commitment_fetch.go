// Package escrow — split_commitment_fetch.go ships the v7.75 escrow
// split commitment lookup primitive per ADR-005 §6.2. Parallel to
// crypto/artifact/pre_grant_commitment_fetch.go — same equivocation
// discipline, same on-log payload envelope, swap of the commitment
// type and the SplitID derivation.
//
// Asymmetry vs PRE. The escrow SplitID is NOT deterministic from
// public grant context: it is derived from (dealerDID, nonce) where
// nonce is a private input the dealer held at split time. Callers
// therefore supply the SplitID directly — typically from the
// StoredMappingV2.SplitID field, from a share envelope's SplitID, or
// from out-of-band metadata recorded at split time. There is no
// equivalent of ComputePREGrantSplitID derivation here.
package escrow

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// EscrowSplitCommitmentSchemaID is the v7.75 schema identifier for
// on-log escrow split commitments.
const EscrowSplitCommitmentSchemaID = "escrow-split-commitment-v1"

// ─────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────

// ErrEscrowCommitmentEquivocation is returned by
// FetchEscrowSplitCommitment when more than one commitment entry
// matches the requested SplitID. See
// EscrowCommitmentEquivocationError for the carried evidence.
var ErrEscrowCommitmentEquivocation = errors.New(
	"escrow: commitment equivocation detected (multiple entries for one SplitID)",
)

// EscrowCommitmentEquivocationError carries the equivocation evidence
// exactly as the PRE side does. Callers use errors.As to extract
// both entries for governance reporting.
type EscrowCommitmentEquivocationError struct {
	SchemaID string
	SplitID  [32]byte
	Entries  []*types.EntryWithMetadata
}

func (e *EscrowCommitmentEquivocationError) Error() string {
	return fmt.Sprintf(
		"escrow: %d commitment entries for schema %q SplitID %x — equivocation",
		len(e.Entries), e.SchemaID, e.SplitID[:8],
	)
}

// Unwrap makes errors.Is(e, ErrEscrowCommitmentEquivocation) succeed.
func (e *EscrowCommitmentEquivocationError) Unwrap() error {
	return ErrEscrowCommitmentEquivocation
}

// Is lets callers match via errors.Is without type-asserting.
func (e *EscrowCommitmentEquivocationError) Is(target error) bool {
	return target == ErrEscrowCommitmentEquivocation
}

// ─────────────────────────────────────────────────────────────────────
// FetchEscrowSplitCommitment
// ─────────────────────────────────────────────────────────────────────

// FetchEscrowSplitCommitment locates the on-log escrow split
// commitment for a given SplitID. Parallel to
// FetchPREGrantCommitment with the PRE-vs-escrow asymmetry captured
// in the signature: the caller supplies the SplitID directly (the
// escrow SplitID is not deterministic from public context).
//
// Returns:
//
//   - (commitment, nil) when exactly one entry matches.
//   - (nil, nil) when no entry matches.
//   - (nil, *EscrowCommitmentEquivocationError wrapping
//     ErrEscrowCommitmentEquivocation) on multiple matches.
//   - (nil, transport error) on fetcher failure.
//
// The returned commitment is structurally validated at deserialize
// but not yet verified against the dealer DID and nonce. Callers
// that need the binding check call VerifyEscrowSplitCommitment with
// the nonce from their local stored metadata.
func FetchEscrowSplitCommitment(
	fetcher types.CommitmentFetcher,
	splitID [32]byte,
) (*EscrowSplitCommitment, error) {
	if fetcher == nil {
		return nil, fmt.Errorf("escrow: FetchEscrowSplitCommitment: nil fetcher")
	}
	entries, err := fetcher.FindCommitmentEntries(EscrowSplitCommitmentSchemaID, splitID)
	if err != nil {
		return nil, fmt.Errorf("escrow: fetch commitment entries: %w", err)
	}
	if len(entries) == 0 {
		return nil, nil
	}
	if len(entries) > 1 {
		return nil, &EscrowCommitmentEquivocationError{
			SchemaID: EscrowSplitCommitmentSchemaID,
			SplitID:  splitID,
			Entries:  entries,
		}
	}

	commitment, err := decodeEscrowSplitCommitmentEntry(entries[0])
	if err != nil {
		return nil, err
	}
	// Defensive SplitID cross-check (same pattern as the PRE side).
	if commitment.SplitID != splitID {
		return nil, fmt.Errorf(
			"escrow: fetched commitment SplitID %x does not match requested %x",
			commitment.SplitID[:8], splitID[:8],
		)
	}
	return commitment, nil
}

// decodeEscrowSplitCommitmentEntry extracts the EscrowSplitCommitment
// from the JSON envelope carried in entry.CanonicalBytes. The
// envelope shape mirrors the PRE side:
//
//	{"schema_id": "escrow-split-commitment-v1",
//	 "commitment_bytes_hex": "<hex-encoded wire bytes>"}
func decodeEscrowSplitCommitmentEntry(meta *types.EntryWithMetadata) (*EscrowSplitCommitment, error) {
	if meta == nil {
		return nil, fmt.Errorf("escrow: nil commitment entry metadata")
	}
	entry, err := envelope.Deserialize(meta.CanonicalBytes)
	if err != nil {
		return nil, fmt.Errorf("escrow: deserialize entry: %w", err)
	}
	var env struct {
		SchemaID           string `json:"schema_id"`
		CommitmentBytesHex string `json:"commitment_bytes_hex"`
	}
	if err := json.Unmarshal(entry.DomainPayload, &env); err != nil {
		return nil, fmt.Errorf("escrow: unmarshal commitment payload: %w", err)
	}
	if env.SchemaID != EscrowSplitCommitmentSchemaID {
		return nil, fmt.Errorf(
			"escrow: commitment entry schema_id %q, want %q",
			env.SchemaID, EscrowSplitCommitmentSchemaID,
		)
	}
	raw, err := hex.DecodeString(env.CommitmentBytesHex)
	if err != nil {
		return nil, fmt.Errorf("escrow: hex decode commitment: %w", err)
	}
	return DeserializeEscrowSplitCommitment(raw)
}
