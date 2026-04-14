package tests

import (
	"crypto/sha256"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/storage"
)

// TestCID_RoundTrip:
//
//	Compute(data, SHA256) → String() → ParseCID() → Bytes()
//	→ ParseCID(string of Bytes()) → same CID.
//	Verify(correct data) → true. Verify(wrong data) → false.
func TestCID_RoundTrip(t *testing.T) {
	data := []byte("content-addressed artifact payload")
	cid := storage.Compute(data)

	// String round-trip
	s := cid.String()
	parsed, err := storage.ParseCID(s)
	if err != nil {
		t.Fatalf("ParseCID(%q): %v", s, err)
	}
	if !cid.Equal(parsed) {
		t.Fatal("parsed CID should equal original")
	}

	// Bytes round-trip via String
	b := cid.Bytes()
	parsedB, err := storage.ParseCIDBytes(b)
	if err != nil {
		t.Fatalf("ParseCIDBytes: %v", err)
	}
	if !cid.Equal(parsedB) {
		t.Fatal("bytes-parsed CID should equal original")
	}

	// Verify correct data
	if !cid.Verify(data) {
		t.Fatal("CID should verify correct data")
	}

	// Verify tampered data rejected
	tampered := append([]byte{}, data...)
	tampered[0] ^= 0xFF
	if cid.Verify(tampered) {
		t.Fatal("CID should reject tampered data")
	}

	// ContentStore round-trip
	cs := storage.NewInMemoryContentStore()
	cs.Push(cid, data)
	fetched, err := cs.Fetch(cid)
	if err != nil {
		t.Fatalf("ContentStore Fetch: %v", err)
	}
	if string(fetched) != string(data) {
		t.Fatal("ContentStore round-trip mismatch")
	}
}

// TestCID_UnrecognizedAlgorithm:
//
//	ParseCID with unknown algorithm tag → error.
//	Compute with SHA256 vs SHA3_256 → different CIDs for same data.
func TestCID_UnrecognizedAlgorithm(t *testing.T) {
	// ParseCID with unknown algorithm name → error
	_, err := storage.ParseCID("bogus:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
	if err == nil {
		t.Fatal("ParseCID should reject unknown algorithm name")
	}

	// ParseCIDBytes with unknown algorithm tag → error
	unknownTag := make([]byte, 33) // tag 0xFF + 32 bytes
	unknownTag[0] = 0xFF
	_, err = storage.ParseCIDBytes(unknownTag)
	if err == nil {
		t.Fatal("ParseCIDBytes should reject unknown algorithm tag 0xFF")
	}

	// Register SHA3_256 (0x16) with a distinct hash function
	const algoSHA3_256 storage.HashAlgorithm = 0x16
	storage.RegisterAlgorithm(algoSHA3_256, "sha3-256", 32, func(data []byte) []byte {
		// Use SHA-256 with a domain prefix to simulate a different algorithm.
		// Real SHA3 would use x/crypto/sha3, but this suffices for testing
		// that different algorithm tags produce different CIDs.
		h := sha256.Sum256(append([]byte("sha3-256-sim:"), data...))
		return h[:]
	})

	data := []byte("same input, different algorithms")
	cidSHA256 := storage.Compute(data)
	cidSHA3 := storage.ComputeWith(data, algoSHA3_256)

	// Different algorithm tags → different CIDs
	if cidSHA256.Equal(cidSHA3) {
		t.Fatal("SHA256 and SHA3_256 should produce different CIDs for same data")
	}

	// Both verify their own data
	if !cidSHA256.Verify(data) {
		t.Fatal("SHA256 CID should verify")
	}
	if !cidSHA3.Verify(data) {
		t.Fatal("SHA3_256 CID should verify")
	}

	// SHA3 CID round-trips through String/Parse
	s := cidSHA3.String()
	parsedSHA3, err := storage.ParseCID(s)
	if err != nil {
		t.Fatalf("ParseCID SHA3: %v", err)
	}
	if !cidSHA3.Equal(parsedSHA3) {
		t.Fatal("SHA3 CID should round-trip through String/ParseCID")
	}
}

// TestCID_BytesRoundTrip:
//
//	CID.Bytes() → ParseCIDBytes(from bytes) → identical CID.
//	For deterministic serialization in Domain Payloads.
func TestCID_BytesRoundTrip(t *testing.T) {
	data := []byte("bytes round-trip for deterministic serialization")
	cid := storage.Compute(data)

	// Bytes → ParseCIDBytes → Equal
	b := cid.Bytes()
	parsed, err := storage.ParseCIDBytes(b)
	if err != nil {
		t.Fatalf("ParseCIDBytes: %v", err)
	}
	if !cid.Equal(parsed) {
		t.Fatal("bytes-parsed CID should equal original")
	}

	// Bytes length: 1 (tag) + 32 (SHA-256 digest) = 33
	if len(b) != 33 {
		t.Fatalf("SHA256 CID bytes should be 33, got %d", len(b))
	}

	// Tag byte is 0x12 (SHA-256 multihash code)
	if b[0] != 0x12 {
		t.Fatalf("first byte should be 0x12 (SHA-256), got 0x%02x", b[0])
	}

	// Identical data → identical bytes (determinism)
	cid2 := storage.Compute(data)
	b2 := cid2.Bytes()
	if len(b) != len(b2) {
		t.Fatal("same data should produce same-length CID bytes")
	}
	for i := range b {
		if b[i] != b2[i] {
			t.Fatalf("CID bytes differ at position %d", i)
		}
	}
}
