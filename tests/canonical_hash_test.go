package tests

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

func TestCanonicalHash_Determinism(t *testing.T) {
	entry, _ := makeEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:alice", EventTime: 1700000000000000}, []byte("payload"))
	h1 := envelope.EntryIdentity(entry)
	h2 := envelope.EntryIdentity(entry)
	if h1 != h2 {
		t.Fatal("same entry produced different hashes")
	}
}

func TestCanonicalHash_RoundTrip(t *testing.T) {
	entry, _ := makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:   "did:example:bob", TargetRoot: ptrTo(pos(42)), AuthorityPath: sameSigner(),
		EventTime: -1000000, AuthoritySet: map[string]struct{}{"did:example:a": {}, "did:example:b": {}},
		DelegateDID: ptrTo("did:example:delegate"), EvidencePointers: []types.LogPosition{pos(1), pos(2)},
	}, []byte("round-trip-test"))
	b1 := envelope.Serialize(entry)
	entry2, err := envelope.Deserialize(b1)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	b2 := envelope.Serialize(entry2)
	if !bytes.Equal(b1, b2) {
		t.Fatalf("round-trip failed: %d vs %d bytes", len(b1), len(b2))
	}
}

func TestCanonicalHash_ASCIINormalization(t *testing.T) {
	entry, _ := makeEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:ascii-only-123"}, nil)
	h := envelope.EntryIdentity(entry)
	if h == [32]byte{} {
		t.Fatal("hash should not be zero")
	}
}

func TestCanonicalHash_NonASCIIRejected(t *testing.T) {
	_, err := envelope.NewEntry(envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:\x80bad"}, nil)
	if err == nil {
		t.Fatal("expected error for non-ASCII byte in ASCII-only mode")
	}
}

func TestCanonicalHash_EmptyDIDRejected(t *testing.T) {
	_, err := envelope.NewEntry(envelope.ControlHeader{Destination: testDestinationDID, SignerDID: ""}, nil)
	if err == nil {
		t.Fatal("expected error for empty Signer_DID")
	}
}
func TestCanonicalHash_PreambleForwardCompat(t *testing.T) {
	// Forward compatibility invariant: a v5 parser encountering unknown
	// trailing bytes within the HBL region must tolerate them (simulating
	// a future v6 entry with additive fields), skip them, and continue
	// to parse the payload correctly.
	//
	// This test extends HBL by 8 bytes and injects 8 zero bytes between
	// the known header fields and the payload length prefix. A tolerant
	// parser must deserialize successfully and produce an entry with the
	// original payload intact.
	entry, _ := makeEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:fwdcompat"}, []byte("original-payload"))
	serialized := envelope.Serialize(entry)

	hbl := binary.BigEndian.Uint32(serialized[2:6])
	binary.BigEndian.PutUint32(serialized[2:6], hbl+8)
	payloadStart := 6 + hbl

	modified := make([]byte, 0, len(serialized)+8)
	modified = append(modified, serialized[:payloadStart]...)
	modified = append(modified, 0, 0, 0, 0, 0, 0, 0, 0) // simulated v6 trailing bytes
	modified = append(modified, serialized[payloadStart:]...)

	recovered, err := envelope.Deserialize(modified)
	if err != nil {
		t.Fatalf("tolerant HBL parsing should accept unknown trailing bytes: %v", err)
	}
	if recovered.Header.SignerDID != "did:example:fwdcompat" {
		t.Fatalf("SignerDID corrupted: got %q", recovered.Header.SignerDID)
	}
	if string(recovered.DomainPayload) != "original-payload" {
		t.Fatalf("payload corrupted: got %q, want %q",
			recovered.DomainPayload, "original-payload")
	}
}

func TestCanonicalHash_PreambleStructure(t *testing.T) {
	entry, _ := makeEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:preamble"}, []byte("test"))
	b := envelope.Serialize(entry)
	version := binary.BigEndian.Uint16(b[0:2])
	if version != 5 {
		t.Fatalf("version: got %d, want 3", version)
	}
	hbl := binary.BigEndian.Uint32(b[2:6])
	if hbl == 0 {
		t.Fatal("HBL should be > 0")
	}
	payloadStart := 6 + hbl
	payloadLen := binary.BigEndian.Uint32(b[payloadStart : payloadStart+4])
	if payloadLen != 4 {
		t.Fatalf("payload length: got %d, want 4", payloadLen)
	}
}

func TestCanonicalHash_PreambleConsistency(t *testing.T) {
	entry, _ := makeEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:corrupt"}, nil)
	b := envelope.Serialize(entry)
	hbl := binary.BigEndian.Uint32(b[2:6])
	binary.BigEndian.PutUint32(b[2:6], hbl+100)
	_, err := envelope.Deserialize(b)
	if err == nil {
		t.Fatal("expected error for corrupt HBL")
	}
}

func TestCanonicalHash_NegativeTimestamp(t *testing.T) {
	entry, _ := makeEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:preepoch", EventTime: -86400000000}, nil)
	b := envelope.Serialize(entry)
	entry2, err := envelope.Deserialize(b)
	if err != nil {
		t.Fatal(err)
	}
	if entry2.Header.EventTime != -86400000000 {
		t.Fatalf("timestamp: got %d", entry2.Header.EventTime)
	}
}

func TestCanonicalHash_MaxSequence(t *testing.T) {
	maxPos := types.LogPosition{LogDID: "did:example:log", Sequence: ^uint64(0)}
	entry, _ := makeEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:max", TargetRoot: &maxPos}, nil)
	b := envelope.Serialize(entry)
	entry2, err := envelope.Deserialize(b)
	if err != nil {
		t.Fatal(err)
	}
	if entry2.Header.TargetRoot.Sequence != ^uint64(0) {
		t.Fatal("max uint64 not preserved")
	}
}

func TestCanonicalHash_AuthoritySet100(t *testing.T) {
	set := make(map[string]struct{}, 100)
	for i := 0; i < 100; i++ {
		set["did:example:auth"+zeroPad3(i)] = struct{}{}
	}
	entry1, _ := makeEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:scope", AuthoritySet: set}, nil)
	b1 := envelope.Serialize(entry1)
	entry2, _ := makeEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:scope", AuthoritySet: set}, nil)
	b2 := envelope.Serialize(entry2)
	if !bytes.Equal(b1, b2) {
		t.Fatal("AuthoritySet serialization not deterministic")
	}
}

func TestCanonicalHash_AuthoritySetNilEquivalence(t *testing.T) {
	e1, _ := makeEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:nilset", AuthoritySet: nil}, nil)
	e2, _ := makeEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:nilset", AuthoritySet: map[string]struct{}{}}, nil)
	if envelope.EntryIdentity(e1) != envelope.EntryIdentity(e2) {
		t.Fatal("nil and empty should produce identical hashes")
	}
}

func TestCanonicalHash_NullLogPosition(t *testing.T) {
	// Property 1: Determinism — nil TargetRoot produces identical bytes
	//   across independent serializations. Tessera requires this.
	entry1, _ := makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:   "did:example:nullpos",
		TargetRoot:  nil,
	}, nil)
	entry2, _ := makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:   "did:example:nullpos",
		TargetRoot:  nil,
	}, nil)
	b1 := envelope.Serialize(entry1)
	b2 := envelope.Serialize(entry2)
	if !bytes.Equal(b1, b2) {
		t.Fatal("two entries with nil TargetRoot must serialize identically")
	}

	// Property 2: Distinguishability — nil vs any non-nil TargetRoot
	//   must produce a different canonical hash. Tessera requires this
	//   so different semantic entries land on different tile leaves.
	nonNil := types.LogPosition{LogDID: "did:example:log", Sequence: 1}
	entry3, _ := makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:   "did:example:nullpos",
		TargetRoot:  &nonNil,
	}, nil)
	b3 := envelope.Serialize(entry3)

	h1 := sha256.Sum256(b1)
	h3 := sha256.Sum256(b3)
	if h1 == h3 {
		t.Fatal("nil TargetRoot and non-nil TargetRoot must produce different canonical hashes")
	}

	// Property 3: Round-trip stability — deserialize recovers nil,
	//   re-serialize produces identical bytes. Tessera-critical:
	//   operators that re-parse entries (e.g., in store/entries.go)
	//   must not drift the hash.
	roundTripped, err := envelope.Deserialize(b1)
	if err != nil {
		t.Fatalf("deserialize failed: %v", err)
	}
	if roundTripped.Header.TargetRoot != nil {
		t.Fatal("nil TargetRoot must survive round-trip as nil")
	}
	b1Again := envelope.Serialize(roundTripped)
	if !bytes.Equal(b1, b1Again) {
		t.Fatal("round-trip must produce byte-identical serialization")
	}
}
func TestCanonicalHash_SignatureWireRoundTrip(t *testing.T) {
	entry, _ := makeEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:sigtest"}, []byte("signed"))
	canonical := envelope.Serialize(entry)
	fakeSig := make([]byte, 64)
	for i := range fakeSig {
		fakeSig[i] = byte(i)
	}
	wire := envelope.MustAppendSignature(canonical, envelope.SigAlgoECDSA, fakeSig)
	gotCanonical, gotAlgo, gotSig, err := envelope.StripSignature(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotCanonical, canonical) {
		t.Fatal("stripped canonical bytes don't match")
	}
	if gotAlgo != envelope.SigAlgoECDSA {
		t.Fatalf("algo mismatch")
	}
	if !bytes.Equal(gotSig, fakeSig) {
		t.Fatal("stripped sig doesn't match")
	}
}

func TestCanonicalHash_EntrySizeValidation(t *testing.T) {
	pointers := make([]types.LogPosition, envelope.MaxEvidencePointers+1)
	for i := range pointers {
		pointers[i] = pos(uint64(i + 1))
	}
	_, err := envelope.NewEntry(envelope.ControlHeader{
		Destination:      testDestinationDID,
		SignerDID:        "did:example:overcap",
		EvidencePointers: pointers,
	}, nil)
	if err == nil {
		t.Fatalf("expected error for %d Evidence_Pointers on non-snapshot", len(pointers))
	}
}

// ── GAP 5: Test 16 — Subject_Identifier serialization ─────────────────
func TestCanonicalHash_SubjectIdentifier(t *testing.T) {
	subjectBytes := []byte("subject-opaque-identifier-bytes!")

	// Entry WITH Subject_Identifier populated
	entryWith, _ := makeEntry(t, envelope.ControlHeader{
		Destination:       testDestinationDID,
		SignerDID:         "did:example:issuer",
		SubjectIdentifier: subjectBytes,
	}, []byte("credential"))

	// Entry WITHOUT Subject_Identifier (nil)
	entryWithout, _ := makeEntry(t, envelope.ControlHeader{
		Destination: testDestinationDID,
		SignerDID:   "did:example:issuer",
	}, []byte("credential"))

	// Hashes must differ
	hashWith := envelope.EntryIdentity(entryWith)
	hashWithout := envelope.EntryIdentity(entryWithout)
	if hashWith == hashWithout {
		t.Fatal("entry with Subject_Identifier must hash differently from entry without")
	}

	// Round-trip identity: Subject_Identifier bytes preserved exactly
	serialized := envelope.Serialize(entryWith)
	recovered, err := envelope.Deserialize(serialized)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if !bytes.Equal(recovered.Header.SubjectIdentifier, subjectBytes) {
		t.Fatalf("Subject_Identifier round-trip failed: got %x, want %x",
			recovered.Header.SubjectIdentifier, subjectBytes)
	}

	// Re-serialize produces identical bytes
	reserialized := envelope.Serialize(recovered)
	if !bytes.Equal(serialized, reserialized) {
		t.Fatal("Subject_Identifier re-serialization not identity")
	}
}
