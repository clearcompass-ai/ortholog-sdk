package builder

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

// syntheticPoint returns compressed(k·G) on secp256k1 for small k.
// Deterministic; suitable for building commitment sets without VSS.
func syntheticPoint(t *testing.T, k int64) [33]byte {
	t.Helper()
	c := secp256k1.S256()
	buf := make([]byte, 32)
	s := new(big.Int).SetInt64(k).Bytes()
	copy(buf[32-len(s):], s)
	x, y := c.ScalarBaseMult(buf)
	if y.Bit(0) == 0 {
		var out [33]byte
		out[0] = 0x02
		xb := x.Bytes()
		copy(out[1+32-len(xb):], xb)
		return out
	}
	var out [33]byte
	out[0] = 0x03
	xb := x.Bytes()
	copy(out[1+32-len(xb):], xb)
	return out
}

func sampleDestination() string {
	return "did:web:example.com:destination"
}

// ─────────────────────────────────────────────────────────────────────
// BuildPREGrantCommitmentEntry
// ─────────────────────────────────────────────────────────────────────

func TestBuildPREGrantCommitmentEntry_HappyPath(t *testing.T) {
	var splitID [32]byte
	for i := range splitID {
		splitID[i] = byte(i + 1)
	}
	c := &artifact.PREGrantCommitment{
		SplitID:       splitID,
		M:             3,
		N:             5,
		CommitmentSet: [][33]byte{syntheticPoint(t, 1), syntheticPoint(t, 2), syntheticPoint(t, 3)},
	}
	entry, err := BuildPREGrantCommitmentEntry(PREGrantCommitmentEntryParams{
		Destination: sampleDestination(),
		SignerDID:   "did:web:example.com:grantor",
		Commitment:  c,
		EventTime:   1000,
	})
	if err != nil {
		t.Fatalf("BuildPREGrantCommitmentEntry: %v", err)
	}
	if entry == nil {
		t.Fatal("entry is nil")
	}
	if entry.Header.Destination != sampleDestination() {
		t.Fatalf("Destination mismatch: %q", entry.Header.Destination)
	}
	if entry.Header.SignerDID != "did:web:example.com:grantor" {
		t.Fatalf("SignerDID mismatch: %q", entry.Header.SignerDID)
	}
	if entry.Header.AuthorityPath != nil {
		t.Fatal("AuthorityPath must be nil for Path A commentary")
	}
	if entry.Header.TargetRoot != nil {
		t.Fatal("TargetRoot must be nil for Path A commentary")
	}

	var env struct {
		SchemaID           string `json:"schema_id"`
		CommitmentBytesHex string `json:"commitment_bytes_hex"`
	}
	if err := json.Unmarshal(entry.DomainPayload, &env); err != nil {
		t.Fatalf("payload is not JSON: %v", err)
	}
	if env.SchemaID != PREGrantCommitmentSchemaID {
		t.Fatalf("schema_id = %q, want %q", env.SchemaID, PREGrantCommitmentSchemaID)
	}
	raw, err := hex.DecodeString(env.CommitmentBytesHex)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	decoded, err := artifact.DeserializePREGrantCommitment(raw)
	if err != nil {
		t.Fatalf("deserialize round-trip: %v", err)
	}
	if decoded.SplitID != c.SplitID || decoded.M != c.M || decoded.N != c.N {
		t.Fatalf("round-trip drift: %+v vs %+v", decoded, c)
	}
}

func TestBuildPREGrantCommitmentEntry_NilCommitment(t *testing.T) {
	_, err := BuildPREGrantCommitmentEntry(PREGrantCommitmentEntryParams{
		Destination: sampleDestination(),
		SignerDID:   "did:web:example.com:grantor",
		Commitment:  nil,
	})
	if !errors.Is(err, ErrNilCommitment) {
		t.Fatalf("want ErrNilCommitment, got %v", err)
	}
}

func TestBuildPREGrantCommitmentEntry_RejectsEmptyDestination(t *testing.T) {
	c := &artifact.PREGrantCommitment{
		M:             2,
		N:             2,
		CommitmentSet: [][33]byte{syntheticPoint(t, 1), syntheticPoint(t, 2)},
	}
	_, err := BuildPREGrantCommitmentEntry(PREGrantCommitmentEntryParams{
		Destination: "",
		SignerDID:   "did:web:example.com:grantor",
		Commitment:  c,
	})
	if !errors.Is(err, envelope.ErrDestinationEmpty) {
		t.Fatalf("want ErrDestinationEmpty, got %v", err)
	}
}

func TestBuildPREGrantCommitmentEntry_RejectsEmptySigner(t *testing.T) {
	c := &artifact.PREGrantCommitment{
		M:             2,
		N:             2,
		CommitmentSet: [][33]byte{syntheticPoint(t, 1), syntheticPoint(t, 2)},
	}
	_, err := BuildPREGrantCommitmentEntry(PREGrantCommitmentEntryParams{
		Destination: sampleDestination(),
		SignerDID:   "",
		Commitment:  c,
	})
	if !errors.Is(err, ErrEmptySignerDID) {
		t.Fatalf("want ErrEmptySignerDID, got %v", err)
	}
}

func TestBuildPREGrantCommitmentEntry_RejectsMalformedCommitment(t *testing.T) {
	// M=0 breaks threshold bounds at serialize.
	c := &artifact.PREGrantCommitment{M: 0, N: 0}
	_, err := BuildPREGrantCommitmentEntry(PREGrantCommitmentEntryParams{
		Destination: sampleDestination(),
		SignerDID:   "did:web:example.com:grantor",
		Commitment:  c,
	})
	if err == nil {
		t.Fatal("want error on malformed commitment, got nil")
	}
}

// ─────────────────────────────────────────────────────────────────────
// BuildEscrowSplitCommitmentEntry
// ─────────────────────────────────────────────────────────────────────

func TestBuildEscrowSplitCommitmentEntry_HappyPath(t *testing.T) {
	var splitID [32]byte
	for i := range splitID {
		splitID[i] = byte(i + 10)
	}
	dealer := "did:web:example.com:dealer"
	c := &escrow.EscrowSplitCommitment{
		SplitID:       splitID,
		M:             3,
		N:             5,
		DealerDID:     dealer,
		CommitmentSet: [][33]byte{syntheticPoint(t, 1), syntheticPoint(t, 2), syntheticPoint(t, 3)},
	}
	entry, err := BuildEscrowSplitCommitmentEntry(EscrowSplitCommitmentEntryParams{
		Destination: sampleDestination(),
		SignerDID:   dealer,
		Commitment:  c,
		EventTime:   2000,
	})
	if err != nil {
		t.Fatalf("BuildEscrowSplitCommitmentEntry: %v", err)
	}
	if entry.Header.Destination != sampleDestination() {
		t.Fatalf("Destination mismatch: %q", entry.Header.Destination)
	}
	if entry.Header.SignerDID != dealer {
		t.Fatalf("SignerDID mismatch: %q", entry.Header.SignerDID)
	}
	if entry.Header.AuthorityPath != nil {
		t.Fatal("AuthorityPath must be nil")
	}
	if entry.Header.TargetRoot != nil {
		t.Fatal("TargetRoot must be nil")
	}

	var env struct {
		SchemaID           string `json:"schema_id"`
		CommitmentBytesHex string `json:"commitment_bytes_hex"`
	}
	if err := json.Unmarshal(entry.DomainPayload, &env); err != nil {
		t.Fatalf("payload is not JSON: %v", err)
	}
	if env.SchemaID != EscrowSplitCommitmentSchemaID {
		t.Fatalf("schema_id = %q, want %q", env.SchemaID, EscrowSplitCommitmentSchemaID)
	}
	raw, err := hex.DecodeString(env.CommitmentBytesHex)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	decoded, err := escrow.DeserializeEscrowSplitCommitment(raw)
	if err != nil {
		t.Fatalf("deserialize round-trip: %v", err)
	}
	if decoded.DealerDID != dealer || decoded.SplitID != c.SplitID {
		t.Fatalf("round-trip drift")
	}
}

func TestBuildEscrowSplitCommitmentEntry_NilCommitment(t *testing.T) {
	_, err := BuildEscrowSplitCommitmentEntry(EscrowSplitCommitmentEntryParams{
		Destination: sampleDestination(),
		SignerDID:   "did:web:example.com:dealer",
		Commitment:  nil,
	})
	if !errors.Is(err, ErrNilCommitment) {
		t.Fatalf("want ErrNilCommitment, got %v", err)
	}
}

func TestBuildEscrowSplitCommitmentEntry_RejectsEmptyDestination(t *testing.T) {
	c := &escrow.EscrowSplitCommitment{
		M:             2,
		N:             2,
		DealerDID:     "did:web:example.com:dealer",
		CommitmentSet: [][33]byte{syntheticPoint(t, 1), syntheticPoint(t, 2)},
	}
	_, err := BuildEscrowSplitCommitmentEntry(EscrowSplitCommitmentEntryParams{
		Destination: "",
		SignerDID:   "did:web:example.com:dealer",
		Commitment:  c,
	})
	if !errors.Is(err, envelope.ErrDestinationEmpty) {
		t.Fatalf("want ErrDestinationEmpty, got %v", err)
	}
}
