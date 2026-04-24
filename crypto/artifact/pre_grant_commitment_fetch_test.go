package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// Mock CommitmentFetcher — keyed by (schemaID, splitID)
// ─────────────────────────────────────────────────────────────────────

type mockCommitmentFetcher struct {
	entries map[string][]*types.EntryWithMetadata
	failOn  string
}

func newMockCommitmentFetcher() *mockCommitmentFetcher {
	return &mockCommitmentFetcher{entries: make(map[string][]*types.EntryWithMetadata)}
}

func (f *mockCommitmentFetcher) key(schemaID string, splitID [32]byte) string {
	return schemaID + "|" + hex.EncodeToString(splitID[:])
}

func (f *mockCommitmentFetcher) Store(schemaID string, splitID [32]byte, meta *types.EntryWithMetadata) {
	k := f.key(schemaID, splitID)
	f.entries[k] = append(f.entries[k], meta)
}

func (f *mockCommitmentFetcher) FindCommitmentEntries(schemaID string, splitID [32]byte) ([]*types.EntryWithMetadata, error) {
	if f.failOn != "" && f.failOn == schemaID {
		return nil, errors.New("mock: transport failure")
	}
	return append([]*types.EntryWithMetadata(nil), f.entries[f.key(schemaID, splitID)]...), nil
}

// commitmentMetaFromStruct wraps a PREGrantCommitment in the on-log
// envelope shape (JSON {schema_id, commitment_bytes_hex}) and returns
// the EntryWithMetadata the fetcher would serve.
func commitmentMetaFromStruct(t *testing.T, signer string, c PREGrantCommitment) *types.EntryWithMetadata {
	t.Helper()
	raw, err := SerializePREGrantCommitment(c)
	if err != nil {
		t.Fatalf("SerializePREGrantCommitment: %v", err)
	}
	payload, err := json.Marshal(map[string]any{
		"schema_id":            PREGrantCommitmentSchemaID,
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
// FetchPREGrantCommitment
// ─────────────────────────────────────────────────────────────────────

func TestFetchPREGrantCommitment_HappyPath(t *testing.T) {
	grantor, recipient, cid, splitID := canonicalPREFixture(t)
	c := buildSyntheticCommitment(t, 3, 5)

	fetcher := newMockCommitmentFetcher()
	fetcher.Store(PREGrantCommitmentSchemaID, splitID, commitmentMetaFromStruct(t, grantor, c))

	got, err := FetchPREGrantCommitment(fetcher, grantor, recipient, cid)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got == nil {
		t.Fatal("got nil commitment")
	}
	if got.SplitID != splitID {
		t.Fatalf("SplitID drift: %x vs %x", got.SplitID[:8], splitID[:8])
	}
	if got.M != 3 || got.N != 5 {
		t.Fatalf("(M,N) = (%d,%d), want (3,5)", got.M, got.N)
	}
}

func TestFetchPREGrantCommitment_NotFound_ReturnsNilNil(t *testing.T) {
	grantor, recipient, cid, _ := canonicalPREFixture(t)
	fetcher := newMockCommitmentFetcher() // empty

	got, err := FetchPREGrantCommitment(fetcher, grantor, recipient, cid)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("want nil commitment on not-found, got %+v", got)
	}
}

func TestFetchPREGrantCommitment_NilFetcher(t *testing.T) {
	grantor, recipient, cid, _ := canonicalPREFixture(t)
	_, err := FetchPREGrantCommitment(nil, grantor, recipient, cid)
	if err == nil {
		t.Fatal("want error on nil fetcher")
	}
}

func TestFetchPREGrantCommitment_EquivocationDetected(t *testing.T) {
	grantor, recipient, cid, splitID := canonicalPREFixture(t)
	c1 := buildSyntheticCommitment(t, 3, 5)
	c2 := buildSyntheticCommitment(t, 4, 5) // distinct M — different wire bytes

	fetcher := newMockCommitmentFetcher()
	fetcher.Store(PREGrantCommitmentSchemaID, splitID, commitmentMetaFromStruct(t, grantor, c1))
	fetcher.Store(PREGrantCommitmentSchemaID, splitID, commitmentMetaFromStruct(t, grantor, c2))

	_, err := FetchPREGrantCommitment(fetcher, grantor, recipient, cid)
	if !errors.Is(err, ErrCommitmentEquivocation) {
		t.Fatalf("want ErrCommitmentEquivocation, got %v", err)
	}
	var evidence *CommitmentEquivocationError
	if !errors.As(err, &evidence) {
		t.Fatal("errors.As did not recover evidence")
	}
	if len(evidence.Entries) != 2 {
		t.Fatalf("evidence.Entries len=%d, want 2", len(evidence.Entries))
	}
	if evidence.SchemaID != PREGrantCommitmentSchemaID {
		t.Fatalf("evidence schema_id = %q", evidence.SchemaID)
	}
	if evidence.SplitID != splitID {
		t.Fatalf("evidence SplitID drift")
	}
}

func TestFetchPREGrantCommitment_FetcherError(t *testing.T) {
	grantor, recipient, cid, _ := canonicalPREFixture(t)
	fetcher := newMockCommitmentFetcher()
	fetcher.failOn = PREGrantCommitmentSchemaID
	_, err := FetchPREGrantCommitment(fetcher, grantor, recipient, cid)
	if err == nil {
		t.Fatal("want transport error")
	}
}

func TestFetchPREGrantCommitment_RejectsIndexedSplitIDMismatch(t *testing.T) {
	// The operator's index mis-routes: entry claims SplitID=X but
	// fetcher returns it under SplitID=Y. FetchPREGrantCommitment
	// must detect the drift rather than silently trust the fetcher.
	grantor, recipient, cid, splitID := canonicalPREFixture(t)

	// Build a commitment bound to a DIFFERENT SplitID.
	var badSplitID [32]byte
	for i := range badSplitID {
		badSplitID[i] = 0xCC
	}
	c := buildSyntheticCommitment(t, 3, 5)
	c.SplitID = badSplitID

	fetcher := newMockCommitmentFetcher()
	// Index it under the EXPECTED splitID, but payload claims badSplitID.
	fetcher.Store(PREGrantCommitmentSchemaID, splitID, commitmentMetaFromStruct(t, grantor, c))

	_, err := FetchPREGrantCommitment(fetcher, grantor, recipient, cid)
	if err == nil {
		t.Fatal("want SplitID mismatch error from defensive cross-check")
	}
}

func TestFetchPREGrantCommitment_MalformedPayload(t *testing.T) {
	_, _, cid, splitID := canonicalPREFixture(t)
	// Build an entry whose DomainPayload is not the commitment envelope.
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
	meta := &types.EntryWithMetadata{
		CanonicalBytes: envelope.Serialize(entry),
	}

	fetcher := newMockCommitmentFetcher()
	fetcher.Store(PREGrantCommitmentSchemaID, splitID, meta)

	_, err = FetchPREGrantCommitment(fetcher, "did:web:example.com:grantor", "did:web:example.com:recipient", cid)
	if err == nil {
		t.Fatal("want error on malformed payload")
	}
}

// ─────────────────────────────────────────────────────────────────────
// SchemaID constant
// ─────────────────────────────────────────────────────────────────────

func TestPREGrantCommitmentSchemaID_Constant(t *testing.T) {
	if PREGrantCommitmentSchemaID != "pre-grant-commitment-v1" {
		t.Fatalf("schema id drift: %q", PREGrantCommitmentSchemaID)
	}
	// Sanity that ComputePREGrantSplitID is a pure function of its
	// inputs (property the fetcher relies on).
	grantor, recipient, _, _ := canonicalPREFixture(t)
	dig := sha256.Sum256([]byte("artifact/1"))
	cid := storage.CID{Algorithm: storage.AlgoSHA256, Digest: dig[:]}
	a := ComputePREGrantSplitID(grantor, recipient, cid)
	b := ComputePREGrantSplitID(grantor, recipient, cid)
	if a != b {
		t.Fatal("ComputePREGrantSplitID not pure")
	}
}
