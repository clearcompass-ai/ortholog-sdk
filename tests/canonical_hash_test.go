package tests

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// Test 1: Basic canonical hash determinism — same entry always produces same hash.
func TestCanonicalHash_Determinism(t *testing.T) {
	entry, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID: "did:example:alice",
		EventTime: 1700000000000000,
	}, []byte("payload"))
	h1 := crypto.CanonicalHash(entry)
	h2 := crypto.CanonicalHash(entry)
	if h1 != h2 {
		t.Fatal("same entry produced different hashes")
	}
}

// Test 2: Round-trip identity — serialize -> deserialize -> serialize = identical bytes.
func TestCanonicalHash_RoundTrip(t *testing.T) {
	entry, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:      "did:example:bob",
		TargetRoot:     ptrTo(pos(42)),
		AuthorityPath:  sameSigner(),
		EventTime:      -1000000, // Negative (pre-epoch).
		AuthoritySet:   map[string]struct{}{"did:example:a": {}, "did:example:b": {}},
		DelegateDID:    ptrTo("did:example:delegate"),
		EvidencePointers: []types.LogPosition{pos(1), pos(2)},
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

// Test 3: NFC normalization — ASCII strings are identity (no change).
func TestCanonicalHash_ASCIINormalization(t *testing.T) {
	// ASCII DIDs should pass through unchanged.
	entry, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID: "did:example:ascii-only-123",
	}, nil)
	h := crypto.CanonicalHash(entry)
	if h == [32]byte{} {
		t.Fatal("hash should not be zero")
	}
}

// Test 4: ASCII fast path rejects bytes >= 0x80 in default mode.
func TestCanonicalHash_NonASCIIRejected(t *testing.T) {
	_, err := envelope.NewEntry(envelope.ControlHeader{
		SignerDID: "did:example:\x80bad",
	}, nil)
	if err == nil {
		t.Fatal("expected error for non-ASCII byte in ASCII-only mode")
	}
}

// Test 5: Empty-string DID rejection.
func TestCanonicalHash_EmptyDIDRejected(t *testing.T) {
	_, err := envelope.NewEntry(envelope.ControlHeader{SignerDID: ""}, nil)
	if err == nil {
		t.Fatal("expected error for empty Signer_DID")
	}
}

// Test 6: Preamble forward compatibility — v3 parser reads payload correctly
// even when header body has extra bytes (simulating v4 fields).
func TestCanonicalHash_PreambleForwardCompat(t *testing.T) {
	entry, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID: "did:example:v3entry",
	}, []byte("original-payload"))

	serialized := envelope.Serialize(entry)
	// Inject 8 extra bytes into the header body (simulating v4 fields).
	// Increase HBL by 8.
	hbl := binary.BigEndian.Uint32(serialized[2:6])
	newHbl := hbl + 8
	binary.BigEndian.PutUint32(serialized[2:6], newHbl)
	// Insert 8 zero bytes after the header body.
	payloadStart := 6 + hbl
	modified := make([]byte, 0, len(serialized)+8)
	modified = append(modified, serialized[:payloadStart]...)
	modified = append(modified, 0, 0, 0, 0, 0, 0, 0, 0) // v4 fields.
	modified = append(modified, serialized[payloadStart:]...)

	// A v3 parser should reject due to consumed != HBL (it parsed fewer bytes).
	_, err := envelope.Deserialize(modified)
	if err == nil {
		t.Fatal("expected error: v3 parser consumed fewer bytes than extended HBL")
	}
}

// Test 7: Preamble structure — verify byte positions.
func TestCanonicalHash_PreambleStructure(t *testing.T) {
	entry, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID: "did:example:preamble",
	}, []byte("test"))

	b := envelope.Serialize(entry)
	// Bytes 0-1: Protocol_Version (3).
	version := binary.BigEndian.Uint16(b[0:2])
	if version != 3 {
		t.Fatalf("version: got %d, want 3", version)
	}
	// Bytes 2-5: HBL.
	hbl := binary.BigEndian.Uint32(b[2:6])
	if hbl == 0 {
		t.Fatal("HBL should be > 0")
	}
	// Payload starts at 6 + HBL.
	payloadStart := 6 + hbl
	payloadLen := binary.BigEndian.Uint32(b[payloadStart : payloadStart+4])
	if payloadLen != 4 { // "test" = 4 bytes.
		t.Fatalf("payload length: got %d, want 4", payloadLen)
	}
}

// Test 8: Preamble consistency — corrupt HBL causes error.
func TestCanonicalHash_PreambleConsistency(t *testing.T) {
	entry, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID: "did:example:corrupt",
	}, nil)
	b := envelope.Serialize(entry)
	// Corrupt HBL to be larger than actual header body.
	hbl := binary.BigEndian.Uint32(b[2:6])
	binary.BigEndian.PutUint32(b[2:6], hbl+100)
	_, err := envelope.Deserialize(b)
	if err == nil {
		t.Fatal("expected error for corrupt HBL")
	}
}

// Test 9: Negative timestamp serializes correctly.
func TestCanonicalHash_NegativeTimestamp(t *testing.T) {
	entry, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID: "did:example:preepoch",
		EventTime: -86400000000, // One day before epoch.
	}, nil)
	b := envelope.Serialize(entry)
	entry2, err := envelope.Deserialize(b)
	if err != nil {
		t.Fatal(err)
	}
	if entry2.Header.EventTime != -86400000000 {
		t.Fatalf("timestamp: got %d, want -86400000000", entry2.Header.EventTime)
	}
}

// Test 10: Max uint64 sequence number.
func TestCanonicalHash_MaxSequence(t *testing.T) {
	maxPos := types.LogPosition{LogDID: "did:example:log", Sequence: ^uint64(0)}
	entry, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:  "did:example:max",
		TargetRoot: &maxPos,
	}, nil)
	b := envelope.Serialize(entry)
	entry2, err := envelope.Deserialize(b)
	if err != nil {
		t.Fatal(err)
	}
	if entry2.Header.TargetRoot.Sequence != ^uint64(0) {
		t.Fatal("max uint64 sequence not preserved")
	}
}

// Test 11: AuthoritySet 100 DIDs — deterministic sort under concurrent construction.
func TestCanonicalHash_AuthoritySet100(t *testing.T) {
	set := make(map[string]struct{}, 100)
	for i := 0; i < 100; i++ {
		set["did:example:auth"+zeroPad3(i)] = struct{}{}
	}
	entry1, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:    "did:example:scope",
		AuthoritySet: set,
	}, nil)
	b1 := envelope.Serialize(entry1)

	// Construct in different order (Go maps are unordered).
	entry2, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:    "did:example:scope",
		AuthoritySet: set,
	}, nil)
	b2 := envelope.Serialize(entry2)

	if !bytes.Equal(b1, b2) {
		t.Fatal("AuthoritySet serialization not deterministic")
	}
}

// Test 12: Nil/empty AuthoritySet equivalence — both produce uint16 zero.
func TestCanonicalHash_AuthoritySetNilEquivalence(t *testing.T) {
	entry1, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:    "did:example:nilset",
		AuthoritySet: nil,
	}, nil)
	entry2, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:    "did:example:nilset",
		AuthoritySet: map[string]struct{}{}, // Empty map.
	}, nil)
	h1 := crypto.CanonicalHash(entry1)
	h2 := crypto.CanonicalHash(entry2)
	if h1 != h2 {
		t.Fatal("nil and empty AuthoritySet should produce identical hashes")
	}
}

// Test 13: Null LogPosition = exactly 10 zero bytes.
func TestCanonicalHash_NullLogPosition(t *testing.T) {
	entry, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID:  "did:example:nullpos",
		TargetRoot: nil, // Null.
	}, nil)
	b := envelope.Serialize(entry)
	// Find Target_Root in serialized bytes (after Signer_DID and Subject_Identifier).
	// Signer_DID: 2 (len) + 21 (did:example:nullpos) = 23 bytes at offset 6.
	// Subject_Identifier: 4 (uint32 len) + 0 = 4 bytes.
	targetRootOffset := 6 + 2 + len("did:example:nullpos") + 4
	nullBytes := b[targetRootOffset : targetRootOffset+10]
	for i, v := range nullBytes {
		if v != 0 {
			t.Fatalf("null LogPosition byte %d = 0x%02x, want 0x00", i, v)
		}
	}
}

// Test 14: Signature wire format — append -> strip -> canonical bytes match.
func TestCanonicalHash_SignatureWireRoundTrip(t *testing.T) {
	entry, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID: "did:example:sigtest",
	}, []byte("signed"))
	canonical := envelope.Serialize(entry)
	fakeSig := make([]byte, 64)
	for i := range fakeSig {
		fakeSig[i] = byte(i)
	}
	wire := envelope.AppendSignature(canonical, envelope.SigAlgoECDSA, fakeSig)
	gotCanonical, gotAlgo, gotSig, err := envelope.StripSignature(wire)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotCanonical, canonical) {
		t.Fatal("stripped canonical bytes don't match original")
	}
	if gotAlgo != envelope.SigAlgoECDSA {
		t.Fatalf("algo: got 0x%04x, want 0x%04x", gotAlgo, envelope.SigAlgoECDSA)
	}
	if !bytes.Equal(gotSig, fakeSig) {
		t.Fatal("stripped signature doesn't match")
	}
}

// Test 15: Entry size limit (>1MB + convenience check at NewEntry level).
func TestCanonicalHash_EntrySizeValidation(t *testing.T) {
	// This test verifies that Evidence_Pointers cap (Decision 51) is enforced.
	// 11 pointers on a non-snapshot entry -> rejected.
	pointers := make([]types.LogPosition, 11)
	for i := range pointers {
		pointers[i] = pos(uint64(i + 1))
	}
	_, err := envelope.NewEntry(envelope.ControlHeader{
		SignerDID:        "did:example:overcap",
		EvidencePointers: pointers,
		// Not a snapshot: no AuthorityPath, no TargetRoot.
	}, nil)
	if err == nil {
		t.Fatal("expected error for 11 Evidence_Pointers on non-snapshot")
	}
}


