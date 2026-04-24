package escrow

import (
	"bytes"
	"crypto/elliptic"
	"errors"
	"testing"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/clearcompass-ai/ortholog-sdk/core/vss"
)

// ─────────────────────────────────────────────────────────────────────
// VSS interop — boundary between RAM (uncompressed) and wire (compressed)
// ─────────────────────────────────────────────────────────────────────

// liveVSSCommitments runs vss.Split and returns a Commitments whose
// Threshold() matches M. The secret value is not used in any
// assertion; it is discarded.
func liveVSSCommitments(t *testing.T, M, N int) vss.Commitments {
	t.Helper()
	var secret [vss.SecretSize]byte
	for i := range secret {
		secret[i] = byte(i + 1)
	}
	_, commitments, err := vss.Split(secret, M, N)
	if err != nil {
		t.Fatalf("vss.Split(M=%d, N=%d): %v", M, N, err)
	}
	return commitments
}

// TestEscrowSplitCommitment_NewFromVSS_Roundtrip exercises the RAM→wire
// conversion against live vss.Split output. Every converted point must
// still be on-curve secp256k1 after compression.
func TestEscrowSplitCommitment_NewFromVSS_Roundtrip(t *testing.T) {
	commitments := liveVSSCommitments(t, 3, 5)
	if commitments.Threshold() != 3 {
		t.Fatalf("commitments.Threshold() = %d, want 3", commitments.Threshold())
	}

	dealer, _, splitID := canonicalEscrowFixture(t)
	esc, err := NewEscrowSplitCommitmentFromVSS(splitID, 3, 5, dealer, commitments)
	if err != nil {
		t.Fatalf("NewEscrowSplitCommitmentFromVSS: %v", err)
	}
	if esc.M != 3 || esc.N != 5 {
		t.Fatalf("(M,N) = (%d,%d), want (3,5)", esc.M, esc.N)
	}
	if esc.DealerDID != dealer {
		t.Fatalf("DealerDID mismatch: got %q, want %q", esc.DealerDID, dealer)
	}
	if len(esc.CommitmentSet) != 3 {
		t.Fatalf("len(CommitmentSet) = %d, want 3", len(esc.CommitmentSet))
	}
	if esc.SplitID != splitID {
		t.Fatalf("SplitID mismatch")
	}

	c := secp256k1.S256()
	for i, p := range esc.CommitmentSet {
		x, y, err := escrowDecompressPoint(p[:])
		if err != nil {
			t.Fatalf("decompress point %d: %v", i, err)
		}
		if !c.IsOnCurve(x, y) {
			t.Fatalf("point %d not on curve", i)
		}
	}
}

// TestEscrowSplitCommitment_NewFromVSS_RejectsThresholdBounds covers
// M<2, M>N, N>255, and empty DealerDID.
func TestEscrowSplitCommitment_NewFromVSS_RejectsThresholdBounds(t *testing.T) {
	commitments := liveVSSCommitments(t, 3, 5)
	dealer, _, splitID := canonicalEscrowFixture(t)

	cases := []struct {
		name string
		M, N int
		did  string
		want error
	}{
		{"M_below_2", 1, 5, dealer, ErrEscrowCommitmentThresholdBounds},
		{"M_above_N", 6, 5, dealer, ErrEscrowCommitmentThresholdBounds},
		{"N_above_255", 3, 256, dealer, ErrEscrowCommitmentThresholdBounds},
		{"empty_dealer", 3, 5, "", ErrEscrowCommitmentDealerDID},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewEscrowSplitCommitmentFromVSS(splitID, tc.M, tc.N, tc.did, commitments)
			if !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
}

// TestEscrowSplitCommitment_NewFromVSS_RejectsMMismatch asserts that
// supplying M that does not match commitments.Threshold() is rejected.
func TestEscrowSplitCommitment_NewFromVSS_RejectsMMismatch(t *testing.T) {
	commitments := liveVSSCommitments(t, 3, 5)
	dealer, _, splitID := canonicalEscrowFixture(t)
	// Commitments carry M=3, but we claim M=4.
	_, err := NewEscrowSplitCommitmentFromVSS(splitID, 4, 5, dealer, commitments)
	if !errors.Is(err, ErrEscrowCommitmentSetLength) {
		t.Fatalf("want ErrEscrowCommitmentSetLength, got %v", err)
	}
}

// TestEscrowSplitCommitment_NewFromVSS_RejectsOffCurveInput asserts
// that a commitments value carrying a non-on-curve point is rejected.
func TestEscrowSplitCommitment_NewFromVSS_RejectsOffCurveInput(t *testing.T) {
	commitments := liveVSSCommitments(t, 3, 5)
	dealer, _, splitID := canonicalEscrowFixture(t)
	// Corrupt the first point: replace with bytes that elliptic.Unmarshal
	// cannot decode to a valid on-curve pair.
	bad := make([]byte, 65)
	bad[0] = 0x04
	for i := 1; i < 65; i++ {
		bad[i] = 0xFF
	}
	commitments.Points[0] = bad
	_, err := NewEscrowSplitCommitmentFromVSS(splitID, 3, 5, dealer, commitments)
	if !errors.Is(err, ErrEscrowCommitmentPointOffCurve) {
		t.Fatalf("want ErrEscrowCommitmentPointOffCurve, got %v", err)
	}
}

// TestEscrowSplitCommitment_ToVSS_Roundtrip confirms that compressed
// wire points convert back to 65-byte uncompressed exactly. The
// round-trip preserves point identity.
func TestEscrowSplitCommitment_ToVSS_Roundtrip(t *testing.T) {
	commitments := liveVSSCommitments(t, 3, 5)
	dealer, _, splitID := canonicalEscrowFixture(t)
	esc, err := NewEscrowSplitCommitmentFromVSS(splitID, 3, 5, dealer, commitments)
	if err != nil {
		t.Fatalf("NewEscrowSplitCommitmentFromVSS: %v", err)
	}

	back, err := esc.ToVSSCommitments()
	if err != nil {
		t.Fatalf("ToVSSCommitments: %v", err)
	}
	if back.Threshold() != commitments.Threshold() {
		t.Fatalf("threshold mismatch: got %d, want %d", back.Threshold(), commitments.Threshold())
	}
	curve := secp256k1.S256()
	for i := range commitments.Points {
		x1, y1 := elliptic.Unmarshal(curve, commitments.Points[i])
		x2, y2 := elliptic.Unmarshal(curve, back.Points[i])
		if x1 == nil || x2 == nil {
			t.Fatalf("point %d failed to unmarshal", i)
		}
		if x1.Cmp(x2) != 0 || y1.Cmp(y2) != 0 {
			t.Fatalf("point %d coordinates drifted through round-trip", i)
		}
		if !bytes.Equal(commitments.Points[i], back.Points[i]) {
			t.Fatalf("point %d bytes drifted through round-trip", i)
		}
	}
}

// TestEscrowSplitCommitment_ToVSS_RejectsMismatchedM asserts the nil
// safety + set-length guard in ToVSSCommitments.
func TestEscrowSplitCommitment_ToVSS_RejectsMismatchedM(t *testing.T) {
	var c *EscrowSplitCommitment
	if _, err := c.ToVSSCommitments(); !errors.Is(err, ErrEscrowCommitmentSetLength) {
		t.Fatalf("nil: want ErrEscrowCommitmentSetLength, got %v", err)
	}
	esc := buildSyntheticEscrowCommitment(t, 3, 5)
	esc.CommitmentSet = esc.CommitmentSet[:2]
	if _, err := esc.ToVSSCommitments(); !errors.Is(err, ErrEscrowCommitmentSetLength) {
		t.Fatalf("truncated: want ErrEscrowCommitmentSetLength, got %v", err)
	}
}

// TestEscrowSplitCommitment_EndToEndFromSplitV2 drives the parity
// property end-to-end: a live SplitV2 produces commitments whose
// wire-form round-trip through (Serialize, Deserialize, ToVSS) is
// equivalent to the original commitment set.
func TestEscrowSplitCommitment_EndToEndFromSplitV2(t *testing.T) {
	secret := make([]byte, SecretSize)
	for i := range secret {
		secret[i] = byte(42 + i)
	}
	dealer := "did:web:example.com:dealer-e2e"
	var nonce [32]byte
	for i := range nonce {
		nonce[i] = byte(i + 7)
	}
	_, commitments, splitID, err := SplitV2(secret, 3, 5, dealer, nonce)
	if err != nil {
		t.Fatalf("SplitV2: %v", err)
	}
	esc, err := NewEscrowSplitCommitmentFromVSS(splitID, 3, 5, dealer, commitments)
	if err != nil {
		t.Fatalf("NewEscrowSplitCommitmentFromVSS: %v", err)
	}
	if err := VerifyEscrowSplitCommitment(esc, nonce); err != nil {
		t.Fatalf("Verify (live): %v", err)
	}

	wire, err := SerializeEscrowSplitCommitment(*esc)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	back, err := DeserializeEscrowSplitCommitment(wire)
	if err != nil {
		t.Fatalf("Deserialize: %v", err)
	}
	if err := VerifyEscrowSplitCommitment(back, nonce); err != nil {
		t.Fatalf("Verify (round-trip): %v", err)
	}
}
