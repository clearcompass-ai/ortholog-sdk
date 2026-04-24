package escrow

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// Mock CommitmentFetcher
// ─────────────────────────────────────────────────────────────────────

type mockEscrowFetcher struct {
	entries map[string][]*types.EntryWithMetadata
	failOn  string
}

func newMockEscrowFetcher() *mockEscrowFetcher {
	return &mockEscrowFetcher{entries: make(map[string][]*types.EntryWithMetadata)}
}

func (f *mockEscrowFetcher) key(schemaID string, splitID [32]byte) string {
	return schemaID + "|" + hex.EncodeToString(splitID[:])
}

func (f *mockEscrowFetcher) Store(schemaID string, splitID [32]byte, meta *types.EntryWithMetadata) {
	k := f.key(schemaID, splitID)
	f.entries[k] = append(f.entries[k], meta)
}

func (f *mockEscrowFetcher) FindCommitmentEntries(schemaID string, splitID [32]byte) ([]*types.EntryWithMetadata, error) {
	if f.failOn != "" && f.failOn == schemaID {
		return nil, errors.New("mock: transport failure")
	}
	return append([]*types.EntryWithMetadata(nil), f.entries[f.key(schemaID, splitID)]...), nil
}

// escrowCommitmentMeta wraps an EscrowSplitCommitment in the on-log
// envelope shape and returns the EntryWithMetadata the fetcher would
// serve.
func escrowCommitmentMeta(t *testing.T, signer string, c EscrowSplitCommitment) *types.EntryWithMetadata {
	t.Helper()
	raw, err := SerializeEscrowSplitCommitment(c)
	if err != nil {
		t.Fatalf("SerializeEscrowSplitCommitment: %v", err)
	}
	payload, err := json.Marshal(map[string]any{
		"schema_id":            EscrowSplitCommitmentSchemaID,
		"commitment_bytes_hex": hex.EncodeToString(raw),
	})
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	entry, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:   signer,
		Destination: "did:web:example.com:exchange",
	}, payload)
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	entry.Signatures = []envelope.Signature{{
		SignerDID: signer,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     make([]byte, 64),
	}}
	if err := entry.Validate(); err != nil {
		t.Fatalf("entry.Validate: %v", err)
	}
	return &types.EntryWithMetadata{
		CanonicalBytes: envelope.Serialize(entry),
		Position:       types.LogPosition{LogDID: "did:web:example.com:log", Sequence: 1},
	}
}

// ─────────────────────────────────────────────────────────────────────
// FetchEscrowSplitCommitment
// ─────────────────────────────────────────────────────────────────────

func TestFetchEscrowSplitCommitment_HappyPath(t *testing.T) {
	dealer, _, splitID := canonicalEscrowFixture(t)
	c := buildSyntheticEscrowCommitment(t, 3, 5)
	fetcher := newMockEscrowFetcher()
	fetcher.Store(EscrowSplitCommitmentSchemaID, splitID, escrowCommitmentMeta(t, dealer, c))

	got, err := FetchEscrowSplitCommitment(fetcher, splitID)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got == nil {
		t.Fatal("got nil commitment")
	}
	if got.SplitID != splitID {
		t.Fatalf("SplitID drift")
	}
	if got.DealerDID != dealer {
		t.Fatalf("DealerDID = %q, want %q", got.DealerDID, dealer)
	}
}

func TestFetchEscrowSplitCommitment_NotFound_ReturnsNilNil(t *testing.T) {
	_, _, splitID := canonicalEscrowFixture(t)
	fetcher := newMockEscrowFetcher()
	got, err := FetchEscrowSplitCommitment(fetcher, splitID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatal("want nil on not-found")
	}
}

func TestFetchEscrowSplitCommitment_NilFetcher(t *testing.T) {
	_, _, splitID := canonicalEscrowFixture(t)
	_, err := FetchEscrowSplitCommitment(nil, splitID)
	if err == nil {
		t.Fatal("want error on nil fetcher")
	}
}

func TestFetchEscrowSplitCommitment_EquivocationDetected(t *testing.T) {
	dealer, _, splitID := canonicalEscrowFixture(t)
	c1 := buildSyntheticEscrowCommitment(t, 3, 5)
	c2 := buildSyntheticEscrowCommitment(t, 4, 5)

	fetcher := newMockEscrowFetcher()
	fetcher.Store(EscrowSplitCommitmentSchemaID, splitID, escrowCommitmentMeta(t, dealer, c1))
	fetcher.Store(EscrowSplitCommitmentSchemaID, splitID, escrowCommitmentMeta(t, dealer, c2))

	_, err := FetchEscrowSplitCommitment(fetcher, splitID)
	if !errors.Is(err, ErrEscrowCommitmentEquivocation) {
		t.Fatalf("want ErrEscrowCommitmentEquivocation, got %v", err)
	}
	var evidence *EscrowCommitmentEquivocationError
	if !errors.As(err, &evidence) {
		t.Fatal("errors.As did not recover evidence")
	}
	if len(evidence.Entries) != 2 {
		t.Fatalf("Entries len=%d, want 2", len(evidence.Entries))
	}
	if evidence.SchemaID != EscrowSplitCommitmentSchemaID {
		t.Fatalf("schema_id drift: %q", evidence.SchemaID)
	}
}

func TestFetchEscrowSplitCommitment_FetcherError(t *testing.T) {
	_, _, splitID := canonicalEscrowFixture(t)
	fetcher := newMockEscrowFetcher()
	fetcher.failOn = EscrowSplitCommitmentSchemaID
	_, err := FetchEscrowSplitCommitment(fetcher, splitID)
	if err == nil {
		t.Fatal("want transport error")
	}
}

func TestFetchEscrowSplitCommitment_RejectsIndexedSplitIDMismatch(t *testing.T) {
	dealer, _, splitID := canonicalEscrowFixture(t)
	c := buildSyntheticEscrowCommitment(t, 3, 5)
	// Tamper the SplitID on the payload; index under the legitimate SplitID.
	var bogus [32]byte
	for i := range bogus {
		bogus[i] = 0xAA
	}
	c.SplitID = bogus

	fetcher := newMockEscrowFetcher()
	fetcher.Store(EscrowSplitCommitmentSchemaID, splitID, escrowCommitmentMeta(t, dealer, c))

	_, err := FetchEscrowSplitCommitment(fetcher, splitID)
	if err == nil {
		t.Fatal("want SplitID mismatch error")
	}
}

func TestFetchEscrowSplitCommitment_MalformedPayload(t *testing.T) {
	_, _, splitID := canonicalEscrowFixture(t)
	entry, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:   "did:web:example.com:attacker",
		Destination: "did:web:example.com:exchange",
	}, []byte("not-json"))
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	entry.Signatures = []envelope.Signature{{
		SignerDID: "did:web:example.com:attacker",
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     make([]byte, 64),
	}}
	fetcher := newMockEscrowFetcher()
	fetcher.Store(EscrowSplitCommitmentSchemaID, splitID, &types.EntryWithMetadata{
		CanonicalBytes: envelope.Serialize(entry),
	})

	_, err = FetchEscrowSplitCommitment(fetcher, splitID)
	if err == nil {
		t.Fatal("want error on malformed payload")
	}
}

func TestEscrowSplitCommitmentSchemaID_Constant(t *testing.T) {
	if EscrowSplitCommitmentSchemaID != "escrow-split-commitment-v1" {
		t.Fatalf("schema id drift: %q", EscrowSplitCommitmentSchemaID)
	}
}
