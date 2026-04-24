// Package integration — commitment_lifecycle_harness_test.go holds
// the shared commitmentLog mock operator query layer used by the
// PRE and escrow end-to-end tests (Subgroup 3.7).
//
// The mock indexes commitment entries by (schema_id, SplitID), the
// same shape a production operator's admission pipeline would keep
// internally. Mirrors what FetchPREGrantCommitment and
// FetchEscrowSplitCommitment consume in production — a
// types.CommitmentFetcher that returns every entry matching the
// requested (schema, SplitID) pair.
//
// Compile-time parity check near the bottom of this file asserts
// the mock satisfies types.CommitmentFetcher. If the interface
// changes, this file fails to compile — calling attention to the
// narrow-interface drift at build time rather than at test run time.
package integration

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// commitmentLog is the in-memory stand-in for an operator's
// commitment-entry query layer. Indexes on (schema_id, SplitID)
// exactly as FindCommitmentEntries' contract expects.
type commitmentLog struct {
	byKey map[string][]*types.EntryWithMetadata
}

func newCommitmentLog() *commitmentLog {
	return &commitmentLog{byKey: make(map[string][]*types.EntryWithMetadata)}
}

func (l *commitmentLog) key(schemaID string, splitID [32]byte) string {
	return schemaID + "|" + hex.EncodeToString(splitID[:])
}

// Publish extracts the (schema_id, SplitID) pair from a commitment
// entry and indexes it for FindCommitmentEntries. Mirrors what an
// operator's admission pipeline would do on receipt of a commitment
// entry after schema validation.
//
// The builders in builder/commitment_entry_builders.go return
// unsigned entries (NewUnsignedEntry); the integration harness
// attaches a deterministic 64-byte zero ECDSA signature to satisfy
// envelope.Validate before Serialize. This mirrors the pattern used
// by tests/helpers_test.go buildTestEntry.
func (l *commitmentLog) Publish(t *testing.T, entry *envelope.Entry) {
	t.Helper()
	if entry == nil {
		t.Fatal("Publish nil entry")
	}
	if len(entry.Signatures) == 0 {
		entry.Signatures = []envelope.Signature{{
			SignerDID: entry.Header.SignerDID,
			AlgoID:    envelope.SigAlgoECDSA,
			Bytes:     make([]byte, 64),
		}}
	}
	if err := entry.Validate(); err != nil {
		t.Fatalf("publish: Validate after signature attach: %v", err)
	}
	var env struct {
		SchemaID           string `json:"schema_id"`
		CommitmentBytesHex string `json:"commitment_bytes_hex"`
	}
	if err := json.Unmarshal(entry.DomainPayload, &env); err != nil {
		t.Fatalf("publish: unmarshal envelope: %v", err)
	}
	raw, err := hex.DecodeString(env.CommitmentBytesHex)
	if err != nil {
		t.Fatalf("publish: hex decode: %v", err)
	}
	// Both PRE and escrow wire forms begin with SplitID (32 bytes).
	if len(raw) < 32 {
		t.Fatalf("publish: commitment wire too short: %d", len(raw))
	}
	var splitID [32]byte
	copy(splitID[:], raw[:32])

	meta := &types.EntryWithMetadata{
		CanonicalBytes: envelope.Serialize(entry),
		Position: types.LogPosition{
			LogDID:   entry.Header.Destination,
			Sequence: uint64(len(l.byKey)) + 1,
		},
	}
	k := l.key(env.SchemaID, splitID)
	l.byKey[k] = append(l.byKey[k], meta)
}

// FindCommitmentEntries returns every entry indexed under
// (schemaID, splitID). Returns (nil, nil) on miss.
func (l *commitmentLog) FindCommitmentEntries(schemaID string, splitID [32]byte) ([]*types.EntryWithMetadata, error) {
	return append([]*types.EntryWithMetadata(nil), l.byKey[l.key(schemaID, splitID)]...), nil
}

// Compile-time check that commitmentLog satisfies the
// CommitmentFetcher contract.
var _ types.CommitmentFetcher = (*commitmentLog)(nil)
