// Package schema — pre_grant_commitment_v1.go declares the
// pre-grant-commitment-v1 schema (ADR-005 §4). The schema's payload
// is a JSON envelope carrying the serialized PREGrantCommitment plus
// a schema-id tag; this file holds the schema ID constant, the
// admission-time payload validator, and the payload-to-commitment
// decoder that lookup primitives consume.
//
// Validation contract (ADR-005 §4):
//   - schema_id field equals pre-grant-commitment-v1.
//   - commitment_bytes_hex decodes to a structurally valid wire
//     buffer via DeserializePREGrantCommitment — threshold bounds,
//     set-length consistency, and every point on-curve secp256k1 all
//     fire at this boundary.
//
// Out of scope at admission: envelope signatures, log membership,
// recipient authorization. Those are lifecycle-layer concerns that
// VerifyPREGrantCommitment and the caller-authorization pipeline
// address separately.
package schema

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/artifact"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/escrow"
)

// PREGrantCommitmentSchemaID re-exports the canonical constant from
// crypto/artifact. The artifact package is the source of truth for
// the string because it owns the corresponding fetch and parse
// primitives.
const PREGrantCommitmentSchemaID = artifact.PREGrantCommitmentSchemaID

// EscrowSplitCommitmentSchemaID re-exports the canonical constant
// from crypto/escrow for the same reason.
const EscrowSplitCommitmentSchemaID = escrow.EscrowSplitCommitmentSchemaID

// ─────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────

var (
	// ErrCommitmentPayloadMalformed is returned when an entry tagged
	// as a commitment-schema entry carries a payload that does not
	// parse as the expected JSON envelope or whose inner bytes do
	// not deserialize.
	ErrCommitmentPayloadMalformed = errors.New("schema: commitment entry payload malformed")

	// ErrCommitmentSchemaIDMismatch is returned when an entry's
	// payload schema_id does not match the expected constant. Guards
	// against routing mistakes at the admission dispatcher.
	ErrCommitmentSchemaIDMismatch = errors.New("schema: commitment entry schema_id mismatch")
)

// ─────────────────────────────────────────────────────────────────────
// Payload envelope
// ─────────────────────────────────────────────────────────────────────

// commitmentPayloadEnvelope is the wire shape both commitment
// schemas use for their on-log payload. Kept package-private;
// consumers interact through the Parse*CommitmentEntry helpers.
type commitmentPayloadEnvelope struct {
	SchemaID           string `json:"schema_id"`
	CommitmentBytesHex string `json:"commitment_bytes_hex"`
}

// decodeCommitmentPayload returns the raw commitment bytes after
// validating the schema_id tag matches the expected value.
func decodeCommitmentPayload(payload []byte, expectedSchemaID string) ([]byte, error) {
	var env commitmentPayloadEnvelope
	if err := json.Unmarshal(payload, &env); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCommitmentPayloadMalformed, err)
	}
	if env.SchemaID != expectedSchemaID {
		return nil, fmt.Errorf("%w: got %q, want %q",
			ErrCommitmentSchemaIDMismatch, env.SchemaID, expectedSchemaID)
	}
	raw, err := hex.DecodeString(env.CommitmentBytesHex)
	if err != nil {
		return nil, fmt.Errorf("%w: hex decode: %v", ErrCommitmentPayloadMalformed, err)
	}
	return raw, nil
}

// ─────────────────────────────────────────────────────────────────────
// PRE grant commitment — validator + parser
// ─────────────────────────────────────────────────────────────────────

// ValidatePREGrantCommitmentEntry is the admission-time validator for
// pre-grant-commitment-v1 entries. It verifies the payload envelope,
// hex-decodes the commitment bytes, and hands them to
// DeserializePREGrantCommitment — which validates threshold bounds,
// set-length consistency, and on-curve points.
//
// A nil return means the entry is structurally valid. Admission still
// needs to verify the envelope signature (handled by the signature
// layer) and, at lifecycle time, the SplitID binding to the grant
// context (VerifyPREGrantCommitment). This function does not verify
// those — it is the admission-layer boundary.
func ValidatePREGrantCommitmentEntry(entry *envelope.Entry) error {
	if entry == nil {
		return fmt.Errorf("%w: nil entry", ErrCommitmentPayloadMalformed)
	}
	raw, err := decodeCommitmentPayload(entry.DomainPayload, PREGrantCommitmentSchemaID)
	if err != nil {
		return err
	}
	if _, err := artifact.DeserializePREGrantCommitment(raw); err != nil {
		return fmt.Errorf("%w: deserialize: %v", ErrCommitmentPayloadMalformed, err)
	}
	return nil
}

// ParsePREGrantCommitmentEntry extracts the PREGrantCommitment from a
// pre-grant-commitment-v1 entry. Used by FetchPREGrantCommitment and
// any other consumer that needs the commitment struct back from the
// on-log payload. Returns the same error set as
// ValidatePREGrantCommitmentEntry plus the structural errors from
// DeserializePREGrantCommitment.
func ParsePREGrantCommitmentEntry(entry *envelope.Entry) (*artifact.PREGrantCommitment, error) {
	if entry == nil {
		return nil, fmt.Errorf("%w: nil entry", ErrCommitmentPayloadMalformed)
	}
	raw, err := decodeCommitmentPayload(entry.DomainPayload, PREGrantCommitmentSchemaID)
	if err != nil {
		return nil, err
	}
	c, err := artifact.DeserializePREGrantCommitment(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: deserialize: %v", ErrCommitmentPayloadMalformed, err)
	}
	return c, nil
}
