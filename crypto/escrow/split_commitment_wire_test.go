package escrow

import (
	"errors"
	"math/big"
	"testing"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// ─────────────────────────────────────────────────────────────────────
// Deterministic test fixtures
// ─────────────────────────────────────────────────────────────────────

// syntheticEscrowCompressedPoint returns compressed(k·G) on secp256k1
// for a scalar k. Deterministic and cheap — used to build commitment-
// set fixtures without running the full VSS Split path.
func syntheticEscrowCompressedPoint(t *testing.T, k int64) [33]byte {
	t.Helper()
	c := secp256k1.S256()
	scalar := new(big.Int).SetInt64(k).Bytes()
	// Left-pad to 32 bytes (elliptic.Curve ScalarBaseMult accepts shorter).
	buf := make([]byte, 32)
	copy(buf[32-len(scalar):], scalar)
	x, y := c.ScalarBaseMult(buf)
	var out [33]byte
	copy(out[:], escrowCompressedPoint(x, y))
	return out
}

// canonicalEscrowFixture pins the (dealerDID, nonce) tuple used across
// the Group 3.3 commitment tests.
func canonicalEscrowFixture(t *testing.T) (string, [32]byte, [32]byte) {
	t.Helper()
	dealer := "did:web:example.com:dealer"
	var nonce [32]byte
	for i := range nonce {
		nonce[i] = byte(i + 1)
	}
	splitID := ComputeEscrowSplitID(dealer, nonce)
	return dealer, nonce, splitID
}

// buildSyntheticEscrowCommitment constructs an EscrowSplitCommitment
// whose CommitmentSet is M synthetic (i+1)·G compressed points. The
// SplitID and DealerDID come from canonicalEscrowFixture.
func buildSyntheticEscrowCommitment(t *testing.T, M, N int) EscrowSplitCommitment {
	t.Helper()
	dealer, _, splitID := canonicalEscrowFixture(t)
	set := make([][33]byte, M)
	for i := 0; i < M; i++ {
		set[i] = syntheticEscrowCompressedPoint(t, int64(i+1))
	}
	return EscrowSplitCommitment{
		SplitID:       splitID,
		M:             byte(M),
		N:             byte(N),
		DealerDID:     dealer,
		CommitmentSet: set,
	}
}

// ─────────────────────────────────────────────────────────────────────
// Round-trip serialization
// ─────────────────────────────────────────────────────────────────────

func TestEscrowSplitCommitment_RoundTrip(t *testing.T) {
	cases := [][2]int{
		{2, 2},
		{2, 3},
		{3, 5},
		{5, 7},
		{10, 20},
		{2, 255},
		{128, 200},
	}
	for _, mn := range cases {
		M, N := mn[0], mn[1]
		orig := buildSyntheticEscrowCommitment(t, M, N)
		wire, err := SerializeEscrowSplitCommitment(orig)
		if err != nil {
			t.Fatalf("Serialize M=%d N=%d: %v", M, N, err)
		}
		want := EscrowSplitCommitmentWireLen(M, orig.DealerDID)
		if len(wire) != want {
			t.Fatalf("M=%d: wire length = %d, want %d", M, len(wire), want)
		}
		got, err := DeserializeEscrowSplitCommitment(wire)
		if err != nil {
			t.Fatalf("Deserialize M=%d N=%d: %v", M, N, err)
		}
		if got.SplitID != orig.SplitID {
			t.Fatalf("M=%d: SplitID mismatch", M)
		}
		if got.M != orig.M || got.N != orig.N {
			t.Fatalf("M=%d: (M,N) mismatch: got (%d,%d), want (%d,%d)",
				M, got.M, got.N, orig.M, orig.N)
		}
		if got.DealerDID != orig.DealerDID {
			t.Fatalf("M=%d: DealerDID mismatch: %q vs %q", M, got.DealerDID, orig.DealerDID)
		}
		if len(got.CommitmentSet) != len(orig.CommitmentSet) {
			t.Fatalf("M=%d: CommitmentSet length mismatch", M)
		}
		for i := range orig.CommitmentSet {
			if got.CommitmentSet[i] != orig.CommitmentSet[i] {
				t.Fatalf("M=%d: CommitmentSet[%d] mismatch", M, i)
			}
		}
	}
}

// ─────────────────────────────────────────────────────────────────────
// Size bound at M=255
// ─────────────────────────────────────────────────────────────────────

// TestEscrowSplitCommitment_SizeCap_M255 confirms the wire length at
// M=255 equals 34 + 2 + len(dealerDID) + 33*255.
func TestEscrowSplitCommitment_SizeCap_M255(t *testing.T) {
	c := buildSyntheticEscrowCommitment(t, 255, 255)
	wire, err := SerializeEscrowSplitCommitment(c)
	if err != nil {
		t.Fatalf("Serialize M=255: %v", err)
	}
	want := 34 + 2 + len(c.DealerDID) + 33*255
	if len(wire) != want {
		t.Fatalf("M=255 wire length = %d, want %d", len(wire), want)
	}
	if _, err := DeserializeEscrowSplitCommitment(wire); err != nil {
		t.Fatalf("Deserialize M=255: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Serialize-side rejection paths
// ─────────────────────────────────────────────────────────────────────

func TestEscrowSplitCommitment_SerializeRejectsThresholdBounds(t *testing.T) {
	cases := []struct {
		name string
		M, N int
	}{
		{"M_zero", 0, 5},
		{"M_one", 1, 5},
		{"M_above_N", 6, 5},
		{"N_zero_with_nonzero_M", 3, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dealer, _, splitID := canonicalEscrowFixture(t)
			c := EscrowSplitCommitment{
				SplitID:   splitID,
				M:         byte(tc.M),
				N:         byte(tc.N),
				DealerDID: dealer,
			}
			if tc.M >= 2 && tc.M <= 255 {
				c.CommitmentSet = make([][33]byte, tc.M)
				for i := range c.CommitmentSet {
					c.CommitmentSet[i] = syntheticEscrowCompressedPoint(t, int64(i+1))
				}
			}
			_, err := SerializeEscrowSplitCommitment(c)
			if !errors.Is(err, ErrEscrowCommitmentThresholdBounds) {
				t.Fatalf("want ErrEscrowCommitmentThresholdBounds, got %v", err)
			}
		})
	}
}

func TestEscrowSplitCommitment_SerializeRejectsEmptyDealerDID(t *testing.T) {
	c := buildSyntheticEscrowCommitment(t, 3, 5)
	c.DealerDID = ""
	_, err := SerializeEscrowSplitCommitment(c)
	if !errors.Is(err, ErrEscrowCommitmentDealerDID) {
		t.Fatalf("want ErrEscrowCommitmentDealerDID, got %v", err)
	}
}

func TestEscrowSplitCommitment_SerializeRejectsSetLengthMismatch(t *testing.T) {
	c := buildSyntheticEscrowCommitment(t, 3, 5)
	c.CommitmentSet = c.CommitmentSet[:2]
	_, err := SerializeEscrowSplitCommitment(c)
	if !errors.Is(err, ErrEscrowCommitmentSetLength) {
		t.Fatalf("short set: want ErrEscrowCommitmentSetLength, got %v", err)
	}
	c2 := buildSyntheticEscrowCommitment(t, 3, 5)
	c2.CommitmentSet = append(c2.CommitmentSet, syntheticEscrowCompressedPoint(t, 4))
	_, err = SerializeEscrowSplitCommitment(c2)
	if !errors.Is(err, ErrEscrowCommitmentSetLength) {
		t.Fatalf("long set: want ErrEscrowCommitmentSetLength, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Deserialize-side rejection paths
// ─────────────────────────────────────────────────────────────────────

func TestEscrowSplitCommitment_DeserializeRejectsShortBuffer(t *testing.T) {
	for _, n := range []int{0, 1, 31, 34, 35} {
		buf := make([]byte, n)
		_, err := DeserializeEscrowSplitCommitment(buf)
		if !errors.Is(err, ErrEscrowCommitmentWireLength) &&
			!errors.Is(err, ErrEscrowCommitmentThresholdBounds) &&
			!errors.Is(err, ErrEscrowCommitmentDealerDID) {
			t.Fatalf("len=%d: want structural error, got %v", n, err)
		}
	}
}

func TestEscrowSplitCommitment_DeserializeRejectsWrongLength(t *testing.T) {
	c := buildSyntheticEscrowCommitment(t, 3, 5)
	wire, err := SerializeEscrowSplitCommitment(c)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	short := wire[:len(wire)-1]
	if _, err := DeserializeEscrowSplitCommitment(short); !errors.Is(err, ErrEscrowCommitmentWireLength) {
		t.Fatalf("short: want ErrEscrowCommitmentWireLength, got %v", err)
	}
	long := append(append([]byte{}, wire...), 0x00)
	if _, err := DeserializeEscrowSplitCommitment(long); !errors.Is(err, ErrEscrowCommitmentWireLength) {
		t.Fatalf("long: want ErrEscrowCommitmentWireLength, got %v", err)
	}
}

func TestEscrowSplitCommitment_DeserializeRejectsBadThreshold(t *testing.T) {
	buf := make([]byte, 36)
	buf[32] = 0 // M=0
	buf[33] = 5 // N=5
	buf[34] = 0x00
	buf[35] = 0x01
	if _, err := DeserializeEscrowSplitCommitment(buf); !errors.Is(err, ErrEscrowCommitmentThresholdBounds) {
		t.Fatalf("M=0: want ErrEscrowCommitmentThresholdBounds, got %v", err)
	}
	buf[32] = 6 // M>N
	if _, err := DeserializeEscrowSplitCommitment(buf); !errors.Is(err, ErrEscrowCommitmentThresholdBounds) {
		t.Fatalf("M>N: want ErrEscrowCommitmentThresholdBounds, got %v", err)
	}
}

func TestEscrowSplitCommitment_DeserializeRejectsZeroDIDLen(t *testing.T) {
	buf := make([]byte, 36)
	buf[32] = 3
	buf[33] = 5
	// didLen = 0
	if _, err := DeserializeEscrowSplitCommitment(buf); !errors.Is(err, ErrEscrowCommitmentDealerDID) {
		t.Fatalf("didLen=0: want ErrEscrowCommitmentDealerDID, got %v", err)
	}
}

func TestEscrowSplitCommitment_DeserializeRejectsOffCurvePoint(t *testing.T) {
	c := buildSyntheticEscrowCommitment(t, 3, 5)
	wire, err := SerializeEscrowSplitCommitment(c)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	// First commitment point offset = 34 + 2 + len(DealerDID).
	offset := 36 + len(c.DealerDID)
	curve := secp256k1.S256()
	p := curve.Params().P
	pb := p.Bytes()
	for i := 0; i < 32; i++ {
		wire[offset+1+i] = 0
	}
	copy(wire[offset+1+32-len(pb):offset+1+32], pb)
	if _, err := DeserializeEscrowSplitCommitment(wire); !errors.Is(err, ErrEscrowCommitmentPointOffCurve) {
		t.Fatalf("x==P: want ErrEscrowCommitmentPointOffCurve, got %v", err)
	}
}
