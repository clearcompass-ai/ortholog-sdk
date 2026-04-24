// Package artifact — pre_grant_commitment_fetch.go ships the v7.75
// PRE grant commitment lookup primitive per ADR-005 §6.2. Consumers
// (VerifyAndDecryptArtifact, recipient-side receive loops, auditors)
// call FetchPREGrantCommitment to locate the on-log commitment for
// a grant before running the cryptographic verification.
//
// Equivocation detection. If the operator's query layer returns
// more than one commitment entry for the same SplitID, the dealer
// has signed two distinct commitments under the same grant context.
// Per ADR-005 §3 this is cryptographic evidence of dealer malice:
// FetchPREGrantCommitment returns ErrCommitmentEquivocation carrying
// both entries so the caller can record the equivocation for
// governance action and refuse to proceed with reconstruction or
// decryption.
package artifact

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// PREGrantCommitmentSchemaID is the v7.75 schema identifier for
// on-log PRE grant commitments. Kept in sync with the builder- and
// schema-package constants; a drift here would break
// commitment-entry dispatch.
const PREGrantCommitmentSchemaID = "pre-grant-commitment-v1"

// ─────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────

// ErrCommitmentEquivocation is returned by FetchPREGrantCommitment
// and FetchEscrowSplitCommitment when more than one commitment entry
// matches the requested SplitID. The equivocation evidence is
// carried on the error so callers can include both entries when
// reporting the event to the governance / witness layer.
//
// Callers typically match on the sentinel via errors.Is and then
// type-assert to *CommitmentEquivocationError to extract both
// entries:
//
//	if err := fetchErr; errors.Is(err, ErrCommitmentEquivocation) {
//	    var evidence *artifact.CommitmentEquivocationError
//	    if errors.As(err, &evidence) {
//	        reportEquivocation(evidence.SplitID, evidence.Entries)
//	    }
//	    return errWithdrawnGrant
//	}
var ErrCommitmentEquivocation = errors.New(
	"pre: commitment equivocation detected (multiple entries for one SplitID)",
)

// CommitmentEquivocationError carries the equivocation evidence.
// Entries holds every entry the fetcher returned for the requested
// SplitID — never fewer than two — so the caller can inspect each
// for its position, sequence, cosignatures, and other on-log
// metadata before deciding how to route the equivocation upstream.
type CommitmentEquivocationError struct {
	SchemaID string
	SplitID  [32]byte
	Entries  []*types.EntryWithMetadata
}

func (e *CommitmentEquivocationError) Error() string {
	return fmt.Sprintf(
		"pre: %d commitment entries for schema %q SplitID %x — equivocation",
		len(e.Entries), e.SchemaID, e.SplitID[:8],
	)
}

// Unwrap makes CommitmentEquivocationError route through errors.Is
// against ErrCommitmentEquivocation.
func (e *CommitmentEquivocationError) Unwrap() error { return ErrCommitmentEquivocation }

// Is lets callers match via errors.Is without type-asserting when
// they don't need the evidence.
func (e *CommitmentEquivocationError) Is(target error) bool {
	return target == ErrCommitmentEquivocation
}

// ─────────────────────────────────────────────────────────────────────
// FetchPREGrantCommitment
// ─────────────────────────────────────────────────────────────────────

// FetchPREGrantCommitment locates the on-log PRE grant commitment for
// a (grantorDID, recipientDID, artifactCID) triple. Derives the
// deterministic SplitID via ComputePREGrantSplitID, queries the
// supplied fetcher, deserializes the payload, and returns the
// commitment struct.
//
// Returns:
//
//   - (commitment, nil) when exactly one entry matches.
//   - (nil, nil) when no entry matches. A missing commitment is a
//     normal outcome during recovery or history replay; callers
//     that require a commitment at this point should surface the
//     nil case as a higher-level error appropriate to their
//     context.
//   - (nil, ErrCommitmentEquivocation wrapped in a
//     *CommitmentEquivocationError) when two or more entries match
//     the same SplitID. Callers MUST NOT proceed with decryption
//     using a commitment set from an equivocating dealer.
//   - (nil, transport error) on fetcher failure.
//
// The commitment struct returned is structurally validated at
// deserialize (threshold bounds, set-length, on-curve) but is NOT
// yet verified against the (grantor, recipient, artifact) context.
// Callers that need SplitID binding call
// VerifyPREGrantCommitment — or, more commonly, rely on the fact
// that this function already recomputed the SplitID from public
// context and looked up an entry whose payload-embedded SplitID
// must match.
func FetchPREGrantCommitment(
	fetcher types.CommitmentFetcher,
	grantorDID, recipientDID string,
	artifactCID storage.CID,
) (*PREGrantCommitment, error) {
	if fetcher == nil {
		return nil, fmt.Errorf("pre: FetchPREGrantCommitment: nil fetcher")
	}
	splitID := ComputePREGrantSplitID(grantorDID, recipientDID, artifactCID)

	entries, err := fetcher.FindCommitmentEntries(PREGrantCommitmentSchemaID, splitID)
	if err != nil {
		return nil, fmt.Errorf("pre: fetch commitment entries: %w", err)
	}
	if len(entries) == 0 {
		return nil, nil
	}
	if len(entries) > 1 {
		return nil, &CommitmentEquivocationError{
			SchemaID: PREGrantCommitmentSchemaID,
			SplitID:  splitID,
			Entries:  entries,
		}
	}

	commitment, err := decodePREGrantCommitmentEntry(entries[0])
	if err != nil {
		return nil, err
	}
	// Defensive: the fetcher indexed on SplitID, but confirm the
	// payload's own SplitID matches. A mismatch is either a fetcher
	// bug or an entry the operator indexed incorrectly; either way,
	// the caller should see it rather than silently trust the
	// fetcher's answer.
	if commitment.SplitID != splitID {
		return nil, fmt.Errorf(
			"pre: fetched commitment SplitID %x does not match expected %x",
			commitment.SplitID[:8], splitID[:8],
		)
	}
	return commitment, nil
}

// decodePREGrantCommitmentEntry extracts the PREGrantCommitment
// from the JSON envelope carried in entry.CanonicalBytes. The
// envelope shape is:
//
//	{"schema_id": "pre-grant-commitment-v1",
//	 "commitment_bytes_hex": "<hex-encoded wire bytes>"}
//
// Kept package-private because the envelope shape is an internal
// wire-boundary detail — callers that want the commitment struct
// back use FetchPREGrantCommitment or
// schema.ParsePREGrantCommitmentEntry (which lives at the admission
// layer and consumes *envelope.Entry directly).
func decodePREGrantCommitmentEntry(meta *types.EntryWithMetadata) (*PREGrantCommitment, error) {
	if meta == nil {
		return nil, fmt.Errorf("pre: nil commitment entry metadata")
	}
	entry, err := envelope.Deserialize(meta.CanonicalBytes)
	if err != nil {
		return nil, fmt.Errorf("pre: deserialize entry: %w", err)
	}
	var env struct {
		SchemaID           string `json:"schema_id"`
		CommitmentBytesHex string `json:"commitment_bytes_hex"`
	}
	if err := json.Unmarshal(entry.DomainPayload, &env); err != nil {
		return nil, fmt.Errorf("pre: unmarshal commitment payload: %w", err)
	}
	if env.SchemaID != PREGrantCommitmentSchemaID {
		return nil, fmt.Errorf(
			"pre: commitment entry schema_id %q, want %q",
			env.SchemaID, PREGrantCommitmentSchemaID,
		)
	}
	raw, err := hex.DecodeString(env.CommitmentBytesHex)
	if err != nil {
		return nil, fmt.Errorf("pre: hex decode commitment: %w", err)
	}
	return DeserializePREGrantCommitment(raw)
}
