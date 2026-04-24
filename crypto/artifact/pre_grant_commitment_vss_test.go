package artifact

import (
	"bytes"
	"crypto/elliptic"
	"errors"
	"math/big"
	"testing"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// ─────────────────────────────────────────────────────────────────────
// VSS interop — boundary between RAM (uncompressed) and wire (compressed)
// ─────────────────────────────────────────────────────────────────────

// testKFragRecipientPub returns a deterministic 65-byte uncompressed
// recipient public key for PRE_GenerateKFrags tests.
func testKFragRecipientPub(t *testing.T) []byte {
	t.Helper()
	c := secp256k1.S256()
	rxSk := new(big.Int).SetInt64(7)
	rxX, rxY := c.ScalarBaseMult(padBigInt(rxSk))
	pk := make([]byte, 65)
	pk[0] = 0x04
	rxXb := rxX.Bytes()
	rxYb := rxY.Bytes()
	copy(pk[1+32-len(rxXb):33], rxXb)
	copy(pk[33+32-len(rxYb):], rxYb)
	return pk
}

// ─────────────────────────────────────────────────────────────────────
// NewPREGrantCommitmentFromVSS — happy path
// ─────────────────────────────────────────────────────────────────────

// TestPREGrantCommitment_NewFromVSS_Roundtrip exercises the RAM→wire
// conversion against live VSS output. PRE_GenerateKFrags produces a
// vss.Commitments whose Points are 65-byte uncompressed; the
// constructor converts each to 33 bytes compressed. Every converted
// point must still be on-curve secp256k1.
func TestPREGrantCommitment_NewFromVSS_Roundtrip(t *testing.T) {
	skOwner := padBigInt(new(big.Int).SetInt64(3))
	pkRx := testKFragRecipientPub(t)

	_, commitments, err := PRE_GenerateKFrags(skOwner, pkRx, 3, 5)
	if err != nil {
		t.Fatalf("PRE_GenerateKFrags: %v", err)
	}
	if commitments.Threshold() != 3 {
		t.Fatalf("commitments.Threshold() = %d, want 3", commitments.Threshold())
	}

	_, _, _, splitID := canonicalPREFixture(t)
	pgc, err := NewPREGrantCommitmentFromVSS(splitID, 3, 5, commitments)
	if err != nil {
		t.Fatalf("NewPREGrantCommitmentFromVSS: %v", err)
	}
	if pgc.M != 3 || pgc.N != 5 {
		t.Fatalf("(M,N) = (%d,%d), want (3,5)", pgc.M, pgc.N)
	}
	if len(pgc.CommitmentSet) != 3 {
		t.Fatalf("len(CommitmentSet) = %d, want 3", len(pgc.CommitmentSet))
	}
	if pgc.SplitID != splitID {
		t.Fatalf("SplitID mismatch")
	}

	// Every compressed point decompresses and is on-curve.
	c := secp256k1.S256()
	for i, p := range pgc.CommitmentSet {
		x, y, err := decompressPoint(p[:])
		if err != nil {
			t.Fatalf("decompress point %d: %v", i, err)
		}
		if !c.IsOnCurve(x, y) {
			t.Fatalf("point %d not on curve", i)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────
// NewPREGrantCommitmentFromVSS — rejection paths
// ─────────────────────────────────────────────────────────────────────

// TestPREGrantCommitment_NewFromVSS_RejectsThresholdBounds asserts
// invalid (M, N) at the constructor boundary.
func TestPREGrantCommitment_NewFromVSS_RejectsThresholdBounds(t *testing.T) {
	skOwner := padBigInt(new(big.Int).SetInt64(3))
	_, commitments, err := PRE_GenerateKFrags(skOwner, testKFragRecipientPub(t), 2, 3)
	if err != nil {
		t.Fatalf("PRE_GenerateKFrags: %v", err)
	}
	_, _, _, splitID := canonicalPREFixture(t)

	cases := []struct {
		name string
		M, N int
	}{
		{"M_zero", 0, 3},
		{"M_one", 1, 3},
		{"M_above_N", 5, 3},
		{"N_above_255", 2, 256},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewPREGrantCommitmentFromVSS(splitID, tc.M, tc.N, commitments)
			if !errors.Is(err, ErrCommitmentThresholdBounds) {
				t.Fatalf("want ErrCommitmentThresholdBounds, got %v", err)
			}
		})
	}
}

// TestPREGrantCommitment_NewFromVSS_RejectsMMismatch asserts that
// if commitments.Threshold() != M the constructor rejects.
func TestPREGrantCommitment_NewFromVSS_RejectsMMismatch(t *testing.T) {
	skOwner := padBigInt(new(big.Int).SetInt64(3))
	_, commitments, err := PRE_GenerateKFrags(skOwner, testKFragRecipientPub(t), 2, 3)
	if err != nil {
		t.Fatalf("PRE_GenerateKFrags: %v", err)
	}
	_, _, _, splitID := canonicalPREFixture(t)
	// commitments.Threshold() == 2 but caller claims M == 3.
	_, err = NewPREGrantCommitmentFromVSS(splitID, 3, 5, commitments)
	if !errors.Is(err, ErrCommitmentSetLength) {
		t.Fatalf("want ErrCommitmentSetLength, got %v", err)
	}
}

// TestPREGrantCommitment_NewFromVSS_RejectsOffCurveInput asserts
// that a vss.Commitments containing an off-curve 65-byte point is
// rejected. Constructs the bad point directly: valid 0x04 prefix
// but x==P (outside the field) so elliptic.Unmarshal's on-curve
// check fails.
func TestPREGrantCommitment_NewFromVSS_RejectsOffCurveInput(t *testing.T) {
	skOwner := padBigInt(new(big.Int).SetInt64(3))
	_, commitments, err := PRE_GenerateKFrags(skOwner, testKFragRecipientPub(t), 2, 3)
	if err != nil {
		t.Fatalf("PRE_GenerateKFrags: %v", err)
	}
	// Tamper: replace the second point's x with P (field prime).
	curve := secp256k1.S256()
	p := curve.Params().P
	bad := make([]byte, 65)
	bad[0] = 0x04
	pb := p.Bytes()
	copy(bad[1+32-len(pb):33], pb)
	// y = 1 (arbitrary; the on-curve check will fail on x alone).
	bad[64] = 1
	commitments.Points[1] = bad

	_, _, _, splitID := canonicalPREFixture(t)
	_, err = NewPREGrantCommitmentFromVSS(splitID, 2, 3, commitments)
	if !errors.Is(err, ErrCommitmentPointOffCurve) {
		t.Fatalf("want ErrCommitmentPointOffCurve, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// ToVSSCommitments — compressed → uncompressed round-trip
// ─────────────────────────────────────────────────────────────────────

// TestPREGrantCommitment_ToVSS_Roundtrip asserts that
// NewPREGrantCommitmentFromVSS followed by ToVSSCommitments reproduces
// the original vss.Commitments bytes exactly.
func TestPREGrantCommitment_ToVSS_Roundtrip(t *testing.T) {
	skOwner := padBigInt(new(big.Int).SetInt64(5))
	_, origCommitments, err := PRE_GenerateKFrags(skOwner, testKFragRecipientPub(t), 3, 5)
	if err != nil {
		t.Fatalf("PRE_GenerateKFrags: %v", err)
	}
	_, _, _, splitID := canonicalPREFixture(t)

	pgc, err := NewPREGrantCommitmentFromVSS(splitID, 3, 5, origCommitments)
	if err != nil {
		t.Fatalf("NewPREGrantCommitmentFromVSS: %v", err)
	}
	back, err := pgc.ToVSSCommitments()
	if err != nil {
		t.Fatalf("ToVSSCommitments: %v", err)
	}
	if back.Threshold() != origCommitments.Threshold() {
		t.Fatalf("threshold drift: got %d want %d", back.Threshold(), origCommitments.Threshold())
	}
	for i := range origCommitments.Points {
		if !bytes.Equal(back.Points[i], origCommitments.Points[i]) {
			t.Fatalf("point %d bytes differ after RAM→wire→RAM round-trip\n  orig: %x\n  back: %x",
				i, origCommitments.Points[i], back.Points[i])
		}
	}
	// Hash must round-trip byte-identically — this is the invariant
	// the core/vss primitive relies on for CommitmentHash matching.
	if back.Hash() != origCommitments.Hash() {
		t.Fatalf("commitment hash drift across round-trip")
	}
}

// TestPREGrantCommitment_ToVSS_RejectsMismatchedM asserts that a
// commitment whose CommitmentSet length disagrees with M is rejected
// at conversion time.
func TestPREGrantCommitment_ToVSS_RejectsMismatchedM(t *testing.T) {
	c := buildSyntheticCommitment(t, 3, 5)
	c.M = 4 // disagree with len(CommitmentSet)
	if _, err := c.ToVSSCommitments(); !errors.Is(err, ErrCommitmentSetLength) {
		t.Fatalf("want ErrCommitmentSetLength, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Live end-to-end: generate → convert → serialize → deserialize → verify
// ─────────────────────────────────────────────────────────────────────

// TestPREGrantCommitment_EndToEndFromGenerateKFrags walks the full
// pipeline using live PRE_GenerateKFrags output. Produces a
// commitment entry bound to the canonical fixture SplitID; serializes
// to wire; deserializes; verifies against the canonical tuple. Proof
// that the RAM-to-wire boundary and the verifier agree on the same
// commitment set a grantor would actually publish.
func TestPREGrantCommitment_EndToEndFromGenerateKFrags(t *testing.T) {
	grantor, recipient, cid, splitID := canonicalPREFixture(t)

	skOwner := padBigInt(new(big.Int).SetInt64(11))
	_, commitments, err := PRE_GenerateKFrags(skOwner, testKFragRecipientPub(t), 3, 5)
	if err != nil {
		t.Fatalf("PRE_GenerateKFrags: %v", err)
	}
	pgc, err := NewPREGrantCommitmentFromVSS(splitID, 3, 5, commitments)
	if err != nil {
		t.Fatalf("NewPREGrantCommitmentFromVSS: %v", err)
	}

	wire, err := SerializePREGrantCommitment(*pgc)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	if len(wire) != PREGrantCommitmentWireLen(3) {
		t.Fatalf("wire length %d, want %d", len(wire), PREGrantCommitmentWireLen(3))
	}
	got, err := DeserializePREGrantCommitment(wire)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if err := VerifyPREGrantCommitment(got, grantor, recipient, cid); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// Ensure ToVSSCommitments from the deserialized entry produces
	// points that still marshal under elliptic.Marshal — i.e., the
	// boundary is symmetric.
	back, err := got.ToVSSCommitments()
	if err != nil {
		t.Fatalf("ToVSSCommitments: %v", err)
	}
	c := secp256k1.S256()
	for i, p := range back.Points {
		x, y := elliptic.Unmarshal(c, p)
		if x == nil || !c.IsOnCurve(x, y) {
			t.Fatalf("point %d failed on-curve after RAM→wire→RAM", i)
		}
	}
}
