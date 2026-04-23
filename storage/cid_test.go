package storage

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

// TestCID_BytesIncludesAlgorithmTag pins the authoritative wire
// contract for CID: Bytes() is algorithm_byte || digest. The
// algorithm byte leading Bytes() is what makes cross-algorithm
// collision resistance structural — two CIDs carrying identical
// 32-byte digests under different registered algorithms produce
// distinct Bytes() outputs.
//
// This contract is relied upon by the v7.75 PRE Grant SplitID
// derivation (ADR-005 §2), which hashes artifactCID.Bytes() (not
// artifactCID.Digest). A future engineer shortcutting to .Digest
// alone would readmit a cross-algorithm collision class that the
// Bytes() mandate closes.
func TestCID_BytesIncludesAlgorithmTag(t *testing.T) {
	digest := sha256.Sum256([]byte("artifact-content"))
	cid := CID{Algorithm: AlgoSHA256, Digest: digest[:]}

	b := cid.Bytes()
	if len(b) != 1+len(digest) {
		t.Fatalf("Bytes() length = %d, want %d (1 algo + %d digest)", len(b), 1+len(digest), len(digest))
	}
	if b[0] != byte(AlgoSHA256) {
		t.Fatalf("Bytes()[0] = 0x%02x, want 0x%02x (AlgoSHA256)", b[0], byte(AlgoSHA256))
	}
	if !bytes.Equal(b[1:], digest[:]) {
		t.Fatalf("Bytes()[1:] does not match digest:\n  got:  %x\n  want: %x", b[1:], digest[:])
	}
}

// TestCID_CrossAlgorithmCollisionResistance pins the structural
// cross-algorithm property that the Bytes() mandate in ADR-005 §2
// relies on: two CIDs with the same 32-byte digest but different
// algorithm tags produce distinct Bytes() outputs.
//
// If this test ever regresses — for example because a future
// refactor starts dropping the algorithm byte from the authoritative
// wire form — the PRE Grant SplitID construction would produce
// colliding SplitIDs for cryptographically distinct artifacts, which
// in turn would cause commitment-entry lookup to return the wrong
// commitment for the wrong artifact. This is why the property is
// pinned in the storage package independently of the PRE construction.
func TestCID_CrossAlgorithmCollisionResistance(t *testing.T) {
	// Register a second hypothetical algorithm tag sharing the
	// SHA-256 digest size. The hash function is irrelevant to the
	// test; what matters is that RegisterAlgorithm succeeds and
	// that Bytes() reflects the registered algorithm tag.
	const hypotheticalAlgo HashAlgorithm = 0xF1
	RegisterAlgorithm(hypotheticalAlgo, "test-algo-f1", 32, func(data []byte) []byte {
		h := sha256.Sum256(data)
		return h[:]
	})

	digest := sha256.Sum256([]byte("collision-probe"))

	cid1 := CID{Algorithm: AlgoSHA256, Digest: digest[:]}
	cid2 := CID{Algorithm: hypotheticalAlgo, Digest: digest[:]}

	b1 := cid1.Bytes()
	b2 := cid2.Bytes()

	if bytes.Equal(b1, b2) {
		t.Fatalf("Bytes() collided across algorithm tags — cross-algorithm collision resistance is broken\n  cid1: %x\n  cid2: %x", b1, b2)
	}
	if b1[0] == b2[0] {
		t.Fatalf("leading algorithm byte equal across algorithms: 0x%02x — Bytes() is not including the tag", b1[0])
	}
	if !bytes.Equal(b1[1:], b2[1:]) {
		t.Fatalf("digest tail mismatch despite identical Digest field:\n  b1[1:]: %x\n  b2[1:]: %x", b1[1:], b2[1:])
	}
}

// TestCID_BytesRoundTripThroughParse pins that Bytes() and
// ParseCIDBytes are exact inverses. Any drift in the wire layout
// (for example, prepending a version byte before the algo tag, or
// length-prefixing the digest) would break downstream consumers
// that hash the Bytes() output into SplitIDs.
func TestCID_BytesRoundTripThroughParse(t *testing.T) {
	digest := sha256.Sum256([]byte("round-trip"))
	cid := CID{Algorithm: AlgoSHA256, Digest: digest[:]}

	b := cid.Bytes()
	parsed, err := ParseCIDBytes(b)
	if err != nil {
		t.Fatalf("ParseCIDBytes: %v", err)
	}
	if parsed.Algorithm != cid.Algorithm {
		t.Fatalf("algorithm mismatch: got 0x%02x, want 0x%02x", byte(parsed.Algorithm), byte(cid.Algorithm))
	}
	if !bytes.Equal(parsed.Digest, cid.Digest) {
		t.Fatalf("digest mismatch:\n  got:  %x\n  want: %x", parsed.Digest, cid.Digest)
	}
}

// TestCID_BytesIsVariableLengthReady guards the contract that the
// Bytes() output length depends on the algorithm's digest size. A
// future algorithm registered with a non-32-byte digest must produce
// a Bytes() of the corresponding length, not a truncated or padded
// fixed-size output. This is why any consumer hashing Bytes() must
// route through the universal length-prefix rule rather than assume
// a fixed offset for the digest tail.
func TestCID_BytesIsVariableLengthReady(t *testing.T) {
	const shortAlgo HashAlgorithm = 0xE2
	RegisterAlgorithm(shortAlgo, "test-algo-e2", 16, func(data []byte) []byte {
		h := sha256.Sum256(data)
		return h[:16]
	})
	cid := ComputeWith([]byte("short"), shortAlgo)
	b := cid.Bytes()
	if len(b) != 17 {
		t.Fatalf("Bytes() length for 16-byte-digest algo = %d, want 17", len(b))
	}
	if b[0] != byte(shortAlgo) {
		t.Fatalf("algo byte mismatch: 0x%02x, want 0x%02x", b[0], byte(shortAlgo))
	}
}
