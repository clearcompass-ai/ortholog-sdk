package schema

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"testing"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/artifact"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/escrow"
)

// syntheticPoint returns compressed(k·G) on secp256k1.
func syntheticPoint(t *testing.T, k int64) [33]byte {
	t.Helper()
	c := secp256k1.S256()
	buf := make([]byte, 32)
	s := new(big.Int).SetInt64(k).Bytes()
	copy(buf[32-len(s):], s)
	x, y := c.ScalarBaseMult(buf)
	var out [33]byte
	if y.Bit(0) == 0 {
		out[0] = 0x02
	} else {
		out[0] = 0x03
	}
	xb := x.Bytes()
	copy(out[1+32-len(xb):], xb)
	return out
}

// commitmentEntry builds a valid on-log payload for one of the two
// commitment schemas. Centralizes the JSON wrapping the builder layer
// produces so every test works from the same scaffold.
func commitmentEntry(t *testing.T, schemaID string, bytes []byte) *envelope.Entry {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"schema_id":            schemaID,
		"commitment_bytes_hex": hex.EncodeToString(bytes),
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return &envelope.Entry{DomainPayload: payload}
}

// ─────────────────────────────────────────────────────────────────────
// ValidatePREGrantCommitmentEntry
// ─────────────────────────────────────────────────────────────────────

func TestValidatePREGrantCommitmentEntry_HappyPath(t *testing.T) {
	c := artifact.PREGrantCommitment{
		M:             2,
		N:             3,
		CommitmentSet: [][33]byte{syntheticPoint(t, 1), syntheticPoint(t, 2)},
	}
	raw, err := artifact.SerializePREGrantCommitment(c)
	if err != nil {
		t.Fatalf("SerializePREGrantCommitment: %v", err)
	}
	entry := commitmentEntry(t, PREGrantCommitmentSchemaID, raw)
	if err := ValidatePREGrantCommitmentEntry(entry); err != nil {
		t.Fatalf("Validate happy path: %v", err)
	}
}

func TestValidatePREGrantCommitmentEntry_NilEntry(t *testing.T) {
	if err := ValidatePREGrantCommitmentEntry(nil); !errors.Is(err, ErrCommitmentPayloadMalformed) {
		t.Fatalf("want ErrCommitmentPayloadMalformed, got %v", err)
	}
}

func TestValidatePREGrantCommitmentEntry_RejectsSchemaIDMismatch(t *testing.T) {
	c := artifact.PREGrantCommitment{
		M:             2,
		N:             3,
		CommitmentSet: [][33]byte{syntheticPoint(t, 1), syntheticPoint(t, 2)},
	}
	raw, _ := artifact.SerializePREGrantCommitment(c)
	// Build under the ESCROW schema id to exercise cross-routing rejection.
	entry := commitmentEntry(t, EscrowSplitCommitmentSchemaID, raw)
	if err := ValidatePREGrantCommitmentEntry(entry); !errors.Is(err, ErrCommitmentSchemaIDMismatch) {
		t.Fatalf("want ErrCommitmentSchemaIDMismatch, got %v", err)
	}
}

func TestValidatePREGrantCommitmentEntry_RejectsMalformedPayload(t *testing.T) {
	entry := &envelope.Entry{DomainPayload: []byte("not-json")}
	if err := ValidatePREGrantCommitmentEntry(entry); !errors.Is(err, ErrCommitmentPayloadMalformed) {
		t.Fatalf("want ErrCommitmentPayloadMalformed, got %v", err)
	}
}

func TestValidatePREGrantCommitmentEntry_RejectsMalformedCommitmentBytes(t *testing.T) {
	// Valid schema_id but hex decodes to garbage.
	entry := commitmentEntry(t, PREGrantCommitmentSchemaID, []byte{0xFF, 0x00})
	if err := ValidatePREGrantCommitmentEntry(entry); !errors.Is(err, ErrCommitmentPayloadMalformed) {
		t.Fatalf("want ErrCommitmentPayloadMalformed, got %v", err)
	}
}

func TestValidatePREGrantCommitmentEntry_RejectsBadHex(t *testing.T) {
	payload, _ := json.Marshal(map[string]any{
		"schema_id":            PREGrantCommitmentSchemaID,
		"commitment_bytes_hex": "not-hex",
	})
	entry := &envelope.Entry{DomainPayload: payload}
	if err := ValidatePREGrantCommitmentEntry(entry); !errors.Is(err, ErrCommitmentPayloadMalformed) {
		t.Fatalf("want ErrCommitmentPayloadMalformed, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// ParsePREGrantCommitmentEntry
// ─────────────────────────────────────────────────────────────────────

func TestParsePREGrantCommitmentEntry_RoundTrip(t *testing.T) {
	var splitID [32]byte
	for i := range splitID {
		splitID[i] = byte(i + 7)
	}
	c := artifact.PREGrantCommitment{
		SplitID:       splitID,
		M:             3,
		N:             5,
		CommitmentSet: [][33]byte{syntheticPoint(t, 1), syntheticPoint(t, 2), syntheticPoint(t, 3)},
	}
	raw, _ := artifact.SerializePREGrantCommitment(c)
	entry := commitmentEntry(t, PREGrantCommitmentSchemaID, raw)
	got, err := ParsePREGrantCommitmentEntry(entry)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.SplitID != c.SplitID || got.M != c.M || got.N != c.N {
		t.Fatalf("round-trip drift: %+v vs %+v", got, c)
	}
}

// ─────────────────────────────────────────────────────────────────────
// ValidateEscrowSplitCommitmentEntry + ParseEscrowSplitCommitmentEntry
// ─────────────────────────────────────────────────────────────────────

func TestValidateEscrowSplitCommitmentEntry_HappyPath(t *testing.T) {
	c := escrow.EscrowSplitCommitment{
		M:             2,
		N:             3,
		DealerDID:     "did:web:example.com:dealer",
		CommitmentSet: [][33]byte{syntheticPoint(t, 1), syntheticPoint(t, 2)},
	}
	raw, err := escrow.SerializeEscrowSplitCommitment(c)
	if err != nil {
		t.Fatalf("SerializeEscrowSplitCommitment: %v", err)
	}
	entry := commitmentEntry(t, EscrowSplitCommitmentSchemaID, raw)
	if err := ValidateEscrowSplitCommitmentEntry(entry); err != nil {
		t.Fatalf("Validate happy path: %v", err)
	}
}

func TestValidateEscrowSplitCommitmentEntry_RejectsSchemaIDMismatch(t *testing.T) {
	c := escrow.EscrowSplitCommitment{
		M:             2,
		N:             3,
		DealerDID:     "did:web:example.com:dealer",
		CommitmentSet: [][33]byte{syntheticPoint(t, 1), syntheticPoint(t, 2)},
	}
	raw, _ := escrow.SerializeEscrowSplitCommitment(c)
	entry := commitmentEntry(t, PREGrantCommitmentSchemaID, raw)
	if err := ValidateEscrowSplitCommitmentEntry(entry); !errors.Is(err, ErrCommitmentSchemaIDMismatch) {
		t.Fatalf("want ErrCommitmentSchemaIDMismatch, got %v", err)
	}
}

func TestValidateEscrowSplitCommitmentEntry_NilEntry(t *testing.T) {
	if err := ValidateEscrowSplitCommitmentEntry(nil); !errors.Is(err, ErrCommitmentPayloadMalformed) {
		t.Fatalf("want ErrCommitmentPayloadMalformed, got %v", err)
	}
}

func TestParseEscrowSplitCommitmentEntry_RoundTrip(t *testing.T) {
	var splitID [32]byte
	for i := range splitID {
		splitID[i] = byte(i + 3)
	}
	c := escrow.EscrowSplitCommitment{
		SplitID:       splitID,
		M:             3,
		N:             5,
		DealerDID:     "did:web:example.com:dealer",
		CommitmentSet: [][33]byte{syntheticPoint(t, 1), syntheticPoint(t, 2), syntheticPoint(t, 3)},
	}
	raw, _ := escrow.SerializeEscrowSplitCommitment(c)
	entry := commitmentEntry(t, EscrowSplitCommitmentSchemaID, raw)
	got, err := ParseEscrowSplitCommitmentEntry(entry)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.SplitID != c.SplitID || got.DealerDID != c.DealerDID {
		t.Fatalf("round-trip drift")
	}
}
