// Package builder — commitment_entry_builders.go ships the two
// commitment-entry builders for v7.75 Phase C per ADR-005 §4:
//
//   - BuildPREGrantCommitmentEntry produces a signed Path A commentary
//     entry whose DomainPayload carries the serialized PREGrantCommitment
//     under the pre-grant-commitment-v1 schema.
//   - BuildEscrowSplitCommitmentEntry is the parallel builder for the
//     escrow side, under the escrow-split-commitment-v1 schema.
//
// Both builders follow the destination-binding discipline: validateCommon
// enforces non-empty SignerDID and a well-formed Destination via
// envelope.ValidateDestination, and the Destination is copied into the
// ControlHeader where serialize.go binds it into the canonical hash.
//
// Schema ID encoding. Commentary entries do not carry a SchemaRef
// LogPosition (they are Path A commentary per ADR-005 §3). To make the
// commitment-entry schema visible at admission and search time without
// inventing a new control-header field, both builders wrap the
// serialized commitment bytes in a tiny JSON envelope that carries:
//
//	{"schema_id": "pre-grant-commitment-v1" | "escrow-split-commitment-v1",
//	 "commitment_bytes_hex": "..."}
//
// The schema package's Validate* functions hex-decode the inner bytes and
// hand them to DeserializePREGrantCommitment /
// DeserializeEscrowSplitCommitment. This keeps the wire form of the
// commitment itself byte-identical to what Group 3.2 and 3.3 shipped;
// only the on-log payload wrapper adds the schema-id tag for admission
// dispatch.
package builder

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/artifact"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/escrow"
)

// ─────────────────────────────────────────────────────────────────────
// Commitment-entry errors
// ─────────────────────────────────────────────────────────────────────

var (
	// ErrNilCommitment is returned when a Build*CommitmentEntry builder
	// receives a nil commitment pointer. Builders take pointers (not
	// values) so a mistaken-zero-value caller is caught at build time
	// rather than silently producing a malformed entry.
	ErrNilCommitment = errors.New("builder/entry: commitment must not be nil")
)

// ─────────────────────────────────────────────────────────────────────
// Schema identifiers
// ─────────────────────────────────────────────────────────────────────

// PREGrantCommitmentSchemaID re-exports the canonical constant from
// crypto/artifact so builder callers can reference it without
// importing artifact/ directly. The artifact package is the source
// of truth because it also owns the fetch and parse primitives that
// consume the same identifier.
const PREGrantCommitmentSchemaID = artifact.PREGrantCommitmentSchemaID

// EscrowSplitCommitmentSchemaID re-exports the canonical escrow
// schema ID from crypto/escrow.
const EscrowSplitCommitmentSchemaID = escrow.EscrowSplitCommitmentSchemaID

// ─────────────────────────────────────────────────────────────────────
// Wire envelope for commitment entries
// ─────────────────────────────────────────────────────────────────────

// commitmentEntryPayload is the on-log JSON envelope for both
// commitment schemas. The inner commitment bytes are hex-encoded so
// the envelope is valid JSON; the outer wrapper carries the schema ID
// for admission-time dispatch.
type commitmentEntryPayload struct {
	SchemaID           string `json:"schema_id"`
	CommitmentBytesHex string `json:"commitment_bytes_hex"`
}

// ─────────────────────────────────────────────────────────────────────
// PRE grant commitment builder
// ─────────────────────────────────────────────────────────────────────

// PREGrantCommitmentEntryParams configures a PRE grant commitment
// entry. The Destination must be the target exchange DID; SignerDID
// is the grantor whose signature binds the commitment to the grant
// context. Commitment carries the (SplitID, M, N, CommitmentSet)
// tuple produced by NewPREGrantCommitmentFromVSS.
type PREGrantCommitmentEntryParams struct {
	Destination string // DID of target exchange. Required.
	SignerDID   string // Grantor DID; signer whose key binds the commitment.
	Commitment  *artifact.PREGrantCommitment
	EventTime   int64
}

// BuildPREGrantCommitmentEntry produces a signed Path A commentary
// entry carrying the serialized PREGrantCommitment under schema
// pre-grant-commitment-v1. The returned entry has:
//
//   - SignerDID set, Destination set (validated via validateCommon).
//   - AuthorityPath and TargetRoot nil (Path A commentary).
//   - DomainPayload = JSON({schema_id, commitment_bytes_hex}).
//
// ADR-005 §4 anchors this builder as part of the SDK-complete
// commitment-entry surface; callers emit this entry atomically with
// the grant operation that produced the commitment.
func BuildPREGrantCommitmentEntry(p PREGrantCommitmentEntryParams) (*envelope.Entry, error) {
	if err := validateCommon(p.SignerDID, p.Destination); err != nil {
		return nil, err
	}
	if p.Commitment == nil {
		return nil, ErrNilCommitment
	}
	raw, err := artifact.SerializePREGrantCommitment(*p.Commitment)
	if err != nil {
		return nil, fmt.Errorf("builder/entry: serialize PRE commitment: %w", err)
	}
	payload, err := json.Marshal(commitmentEntryPayload{
		SchemaID:           PREGrantCommitmentSchemaID,
		CommitmentBytesHex: hex.EncodeToString(raw),
	})
	if err != nil {
		return nil, fmt.Errorf("builder/entry: marshal PRE commitment payload: %w", err)
	}
	return envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:   p.SignerDID,
		Destination: p.Destination,
		EventTime:   p.EventTime,
	}, payload)
}

// ─────────────────────────────────────────────────────────────────────
// Escrow split commitment builder
// ─────────────────────────────────────────────────────────────────────

// EscrowSplitCommitmentEntryParams configures an escrow split
// commitment entry. SignerDID is the dealer whose signature binds the
// commitment to the (dealerDID, nonce) derivation. Commitment carries
// the (SplitID, M, N, DealerDID, CommitmentSet) tuple produced by
// NewEscrowSplitCommitmentFromVSS.
type EscrowSplitCommitmentEntryParams struct {
	Destination string // DID of target exchange. Required.
	SignerDID   string // Dealer DID; signer whose key binds the commitment.
	Commitment  *escrow.EscrowSplitCommitment
	EventTime   int64
}

// BuildEscrowSplitCommitmentEntry is the parallel builder for the
// escrow side. It produces a signed Path A commentary entry carrying
// the serialized EscrowSplitCommitment under schema
// escrow-split-commitment-v1. The same payload envelope and
// destination-binding discipline as the PRE builder applies.
//
// ADR-005 §4 anchors this builder as part of the SDK-complete
// commitment-entry surface; callers emit this entry atomically with
// the split operation that produced the commitment.
func BuildEscrowSplitCommitmentEntry(p EscrowSplitCommitmentEntryParams) (*envelope.Entry, error) {
	if err := validateCommon(p.SignerDID, p.Destination); err != nil {
		return nil, err
	}
	if p.Commitment == nil {
		return nil, ErrNilCommitment
	}
	raw, err := escrow.SerializeEscrowSplitCommitment(*p.Commitment)
	if err != nil {
		return nil, fmt.Errorf("builder/entry: serialize escrow commitment: %w", err)
	}
	payload, err := json.Marshal(commitmentEntryPayload{
		SchemaID:           EscrowSplitCommitmentSchemaID,
		CommitmentBytesHex: hex.EncodeToString(raw),
	})
	if err != nil {
		return nil, fmt.Errorf("builder/entry: marshal escrow commitment payload: %w", err)
	}
	return envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:   p.SignerDID,
		Destination: p.Destination,
		EventTime:   p.EventTime,
	}, payload)
}
