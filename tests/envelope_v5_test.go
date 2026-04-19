/*
V5 wire format tests using the existing test helpers.

Validates:
  - Canonical hash determinism across repeated NewEntry calls
  - Admission proof length-prefixing isolates Authority_Skip (SDK-3 regression)
  - Version policy rejection for unknown versions
  - Structural rejections: oversized payload, empty DID, non-ASCII DID,
    evidence cap on non-snapshot entries, short preamble

Per Wave 1.5, domain identity does not travel in the Control Header.
Domain semantics are resolved via SchemaRef pinned lookup; there is no
DomainManifestVersion field on the header to test round-trip coverage of.
*/
package tests

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

func TestV5_CanonicalHashDeterministic(t *testing.T) {
	t.Parallel()
	// Two entries built from identical header + payload inputs must
	// produce identical canonical hashes. This is the foundational
	// determinism property — every other protocol invariant
	// (replayability, fraud proofs, SMT identity) depends on it.
	header := envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     "did:test:determinism",
		AuthorityPath: sameSigner(),
		EventTime:     1700000000,
	}
	e1, err := envelope.NewUnsignedEntry(header, []byte("{}"))
	if err != nil {
		t.Fatalf("NewEntry (first): %v", err)
	}
	e2, err := envelope.NewUnsignedEntry(header, []byte("{}"))
	if err != nil {
		t.Fatalf("NewEntry (second): %v", err)
	}
	if envelope.EntryIdentity(e1) != envelope.EntryIdentity(e2) {
		t.Error("canonical hash not deterministic across NewEntry calls")
	}
}

func TestV5_RoundTripPreservesAllFields(t *testing.T) {
	t.Parallel()
	// Spot-check that a header populated with a representative mix of
	// optional fields round-trips cleanly through Serialize / Deserialize.
	// This is the "field churn" canary — if Wave 1.5 accidentally dropped
	// a field from serializeHeaderBody or deserializeHeaderBody, this test
	// catches it.
	targetRoot := types.LogPosition{LogDID: "did:test:log", Sequence: 42}
	schemaRef := types.LogPosition{LogDID: "did:test:log", Sequence: 7}
	eventTime := int64(1700000000)

	entry, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     "did:test:roundtrip",
		TargetRoot:    &targetRoot,
		AuthorityPath: sameSigner(),
		SchemaRef:     &schemaRef,
		EventTime:     eventTime,
	}, []byte(`{"kind":"amendment","v":1}`))

	if err != nil {
		t.Fatalf("NewEntry: %v", err)
	}

	wire := envelope.Serialize(entry)
	round, err := envelope.Deserialize(wire)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}

	if round.Header.ProtocolVersion != envelope.CurrentProtocolVersion() {
		t.Errorf("ProtocolVersion: got %d, want %d",
			round.Header.ProtocolVersion, envelope.CurrentProtocolVersion())
	}
	if round.Header.SignerDID != "did:test:roundtrip" {
		t.Errorf("SignerDID: got %q", round.Header.SignerDID)
	}
	if round.Header.TargetRoot == nil || !round.Header.TargetRoot.Equal(targetRoot) {
		t.Errorf("TargetRoot: got %v, want %v", round.Header.TargetRoot, targetRoot)
	}
	if round.Header.SchemaRef == nil || !round.Header.SchemaRef.Equal(schemaRef) {
		t.Errorf("SchemaRef: got %v, want %v", round.Header.SchemaRef, schemaRef)
	}
	if round.Header.EventTime != eventTime {
		t.Errorf("EventTime: got %d, want %d", round.Header.EventTime, eventTime)
	}
	if !bytes.Equal(round.DomainPayload, entry.DomainPayload) {
		t.Errorf("DomainPayload: got %q, want %q",
			round.DomainPayload, entry.DomainPayload)
	}
}

func TestV5_AuthoritySkipIsolatedFromAdmissionProof(t *testing.T) {
	t.Parallel()
	// Admission proof's length-prefixed body must not corrupt Authority_Skip
	// parsing, regardless of admission proof contents. This is the SDK-3
	// regression test — a bug here means a malformed admission proof could
	// silently shift subsequent field offsets and corrupt verifier state.
	skip := types.LogPosition{LogDID: "did:anchor", Sequence: 100}
	commit := [32]byte{1, 2, 3, 4}
	var hash [32]byte
	for i := range hash {
		hash[i] = byte(i)
	}

	entry, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:   "did:test:isolation",
		EventTime:   1700000000,
		AdmissionProof: &envelope.AdmissionProofBody{
			Mode:            2,
			Difficulty:      20,
			HashFunc:        1,
			Epoch:           1234,
			SubmitterCommit: &commit,
			Nonce:           9876543210,
			Hash:            hash,
		},
		AuthoritySkip: &skip,
	}, []byte("{}"))

	if err != nil {
		t.Fatalf("NewEntry: %v", err)
	}

	round, err := envelope.Deserialize(envelope.Serialize(entry))
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if round.Header.AuthoritySkip == nil || !round.Header.AuthoritySkip.Equal(skip) {
		t.Errorf("AuthoritySkip: got %v, want %v", round.Header.AuthoritySkip, skip)
	}
	if round.Header.AdmissionProof == nil {
		t.Fatal("AdmissionProof: got nil")
	}
	if round.Header.AdmissionProof.Epoch != 1234 {
		t.Errorf("AdmissionProof.Epoch = %d, want 1234", round.Header.AdmissionProof.Epoch)
	}
}

func TestV5_RejectsUnknownVersion(t *testing.T) {
	t.Parallel()
	// Bytes 0–1 = version 99 (unknown). Bytes 2–5 = HBL=0. Bytes 6–9 = payload_len=0.
	// Valid wire framing, but the version policy rejects anything not in the
	// version table (currently only v5 is ACTIVE).
	buf := make([]byte, 0, 10)
	buf = binary.BigEndian.AppendUint16(buf, 99)
	buf = binary.BigEndian.AppendUint32(buf, 0)
	buf = binary.BigEndian.AppendUint32(buf, 0)
	_, err := envelope.Deserialize(buf)
	if !errors.Is(err, envelope.ErrUnknownVersion) {
		t.Errorf("Deserialize(v99) = %v, want ErrUnknownVersion", err)
	}
}

func TestV5_OversizedPayloadRejected(t *testing.T) {
	t.Parallel()
	// Payload alone exceeds MaxCanonicalBytes. NewEntry catches this during
	// its post-serialize size check before returning the entry to the caller.
	oversized := make([]byte, envelope.MaxCanonicalBytes+1)
	_, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:   "did:test",
		EventTime:   1700000000,
	}, oversized)

	if !errors.Is(err, envelope.ErrCanonicalTooLarge) {
		t.Errorf("oversized = %v, want ErrCanonicalTooLarge", err)
	}
}

func TestV5_EmptySignerDIDRejected(t *testing.T) {
	t.Parallel()
	// Every entry requires a Signer_DID. NewEntry refuses empty strings
	// to prevent unsigned or ambiguously-attributed entries entering the log.
	_, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:   "",
		EventTime:   1700000000,
	}, nil)

	if !errors.Is(err, envelope.ErrEmptySignerDID) {
		t.Errorf("empty DID = %v, want ErrEmptySignerDID", err)
	}
}

func TestV5_NonASCIISignerDIDRejected(t *testing.T) {
	t.Parallel()
	// Decision 15: SDK enforces ASCII-only DIDs in strict mode.
	// The 0x80 byte is the first invalid high-bit character.
	_, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:   "did:test:\x80",
		EventTime:   1700000000,
	}, nil)

	if !errors.Is(err, envelope.ErrNonASCIIDID) {
		t.Errorf("non-ASCII DID = %v, want ErrNonASCIIDID", err)
	}
}

func TestV5_TooManyEvidencePointers(t *testing.T) {
	t.Parallel()
	// Non-snapshot entries are capped at MaxEvidencePointers (32).
	// Only authority snapshots (Path C + TargetRoot + PriorAuthority)
	// are exempt — enforced via isAuthoritySnapshotShape in serialize.go.
	pointers := make([]types.LogPosition, envelope.MaxEvidencePointers+1)
	for i := range pointers {
		pointers[i] = types.LogPosition{LogDID: "did:web:evidence", Sequence: uint64(i + 1)}
	}
	_, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		Destination:      testDestinationDID,
		SignerDID:        "did:test:evcap",
		EventTime:        1700000000,
		EvidencePointers: pointers,
	}, nil)

	if !errors.Is(err, envelope.ErrTooManyEvidencePointers) {
		t.Errorf("too many evidence pointers = %v, want ErrTooManyEvidencePointers", err)
	}
}

func TestV5_ShortPreambleRejected(t *testing.T) {
	t.Parallel()
	// The preamble is fixed at 6 bytes (uint16 version + uint32 HBL).
	// Fewer bytes means the entry is structurally malformed — can't
	// even read the version field safely.
	_, err := envelope.Deserialize([]byte{0x00, 0x04, 0x00}) // 3 bytes < 6
	if !errors.Is(err, envelope.ErrMalformedPreamble) {
		t.Errorf("short preamble = %v, want ErrMalformedPreamble", err)
	}
}
