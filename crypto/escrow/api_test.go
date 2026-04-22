// Package escrow — api_test.go tests the top-level escrow API:
// Split, Reconstruct, zeroization primitives, and the internal
// GF(256) arithmetic helpers.
package escrow

import (
	"bytes"
	"errors"
	"testing"
)

// -------------------------------------------------------------------------------------------------
// Split — argument validation
// -------------------------------------------------------------------------------------------------

func TestSplit_RejectsWrongSecretSize(t *testing.T) {
	// Not 32 bytes.
	_, _, err := Split(make([]byte, 16), 3, 5)
	if err == nil {
		t.Fatal("expected error for wrong-size secret, got nil")
	}
}

func TestSplit_RejectsNilSecret(t *testing.T) {
	_, _, err := Split(nil, 3, 5)
	if err == nil {
		t.Fatal("expected error for nil secret, got nil")
	}
}

func TestSplit_RejectsMBelowTwo(t *testing.T) {
	secret := newTestSecret(t, 0x01)
	// M=1 is degenerate.
	_, _, err := Split(secret, 1, 5)
	if err == nil {
		t.Fatal("expected error for M=1, got nil")
	}
}

func TestSplit_RejectsNBelowTwo(t *testing.T) {
	secret := newTestSecret(t, 0x02)
	_, _, err := Split(secret, 2, 1)
	if err == nil {
		t.Fatal("expected error for N=1, got nil")
	}
}

func TestSplit_RejectsMGreaterThanN(t *testing.T) {
	secret := newTestSecret(t, 0x03)
	_, _, err := Split(secret, 5, 3)
	if err == nil {
		t.Fatal("expected error for M>N, got nil")
	}
}

func TestSplit_RejectsNAbove255(t *testing.T) {
	secret := newTestSecret(t, 0x04)
	_, _, err := Split(secret, 2, 256)
	if err == nil {
		t.Fatal("expected error for N>255, got nil")
	}
}

// -------------------------------------------------------------------------------------------------
// Split — structural properties of the produced shares
// -------------------------------------------------------------------------------------------------

func TestSplit_ProducesNSharesWithCorrectFields(t *testing.T) {
	secret := newTestSecret(t, 0x10)
	m, n := 3, 5
	shares, splitID, err := Split(secret, m, n)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	if len(shares) != n {
		t.Fatalf("len(shares) = %d, want %d", len(shares), n)
	}
	// SplitID must be non-zero (random per Split call).
	if zeroArray32(splitID) {
		t.Fatal("Split returned zero SplitID")
	}

	seenIdx := make(map[byte]bool)
	for i, s := range shares {
		if s.Version != VersionV1 {
			t.Errorf("share[%d].Version = 0x%02x, want VersionV1", i, s.Version)
		}
		if s.Threshold != byte(m) {
			t.Errorf("share[%d].Threshold = %d, want %d", i, s.Threshold, m)
		}
		if s.Index == 0 {
			t.Errorf("share[%d].Index = 0 (reserved)", i)
		}
		if seenIdx[s.Index] {
			t.Errorf("share[%d].Index = %d is a duplicate", i, s.Index)
		}
		seenIdx[s.Index] = true
		if !bytes.Equal(s.SplitID[:], splitID[:]) {
			t.Errorf("share[%d].SplitID != returned splitID", i)
		}
		if !zeroArray32(s.BlindingFactor) {
			t.Errorf("share[%d].BlindingFactor nonzero (V1 requires zero)", i)
		}
		if !zeroArray32(s.CommitmentHash) {
			t.Errorf("share[%d].CommitmentHash nonzero (V1 requires zero)", i)
		}
	}
}

func TestSplit_GeneratesUniqueSplitIDsAcrossCalls(t *testing.T) {
	secret := newTestSecret(t, 0x20)
	_, id1, err := Split(secret, 3, 5)
	if err != nil {
		t.Fatalf("Split call 1: %v", err)
	}
	_, id2, err := Split(secret, 3, 5)
	if err != nil {
		t.Fatalf("Split call 2: %v", err)
	}
	if bytes.Equal(id1[:], id2[:]) {
		t.Fatal("two Split calls produced the same SplitID — must be random per-call")
	}
}

// -------------------------------------------------------------------------------------------------
// Reconstruct — happy path
// -------------------------------------------------------------------------------------------------

func TestReconstruct_RoundTripAtThreshold(t *testing.T) {
	secret := newTestSecret(t, 0x30)
	m, n := 3, 5
	shares, _ := splitTestSecret(t, secret, m, n)

	// Use exactly M shares.
	recovered, err := Reconstruct(shares[:m])
	if err != nil {
		t.Fatalf("Reconstruct: %v", err)
	}
	if len(recovered) != SecretSize {
		t.Fatalf("recovered size = %d, want %d", len(recovered), SecretSize)
	}
	if !bytes.Equal(recovered, secret) {
		t.Fatal("Reconstruct did not recover the original secret at threshold")
	}
}

func TestReconstruct_RoundTripAboveThreshold(t *testing.T) {
	secret := newTestSecret(t, 0x40)
	shares, _ := splitTestSecret(t, secret, 3, 5)

	// Use all 5 shares.
	recovered, err := Reconstruct(shares)
	if err != nil {
		t.Fatalf("Reconstruct: %v", err)
	}
	if !bytes.Equal(recovered, secret) {
		t.Fatal("Reconstruct did not recover the original secret above threshold")
	}
}

func TestReconstruct_RoundTripWithDifferentShareSubsets(t *testing.T) {
	// Any M-of-N subset must reconstruct the same secret.
	secret := newTestSecret(t, 0x50)
	shares, _ := splitTestSecret(t, secret, 3, 5)

	subsets := [][]int{
		{0, 1, 2},
		{0, 2, 4},
		{1, 3, 4},
		{2, 3, 4},
	}
	for _, subset := range subsets {
		chosen := make([]Share, len(subset))
		for i, idx := range subset {
			chosen[i] = shares[idx]
		}
		recovered, err := Reconstruct(chosen)
		if err != nil {
			t.Fatalf("Reconstruct subset %v: %v", subset, err)
		}
		if !bytes.Equal(recovered, secret) {
			t.Fatalf("subset %v reconstructed a different secret", subset)
		}
	}
}

// -------------------------------------------------------------------------------------------------
// Reconstruct — rejection modes (delegated to VerifyShareSet)
// -------------------------------------------------------------------------------------------------

func TestReconstruct_RejectsBelowThreshold(t *testing.T) {
	secret := newTestSecret(t, 0x60)
	shares, _ := splitTestSecret(t, secret, 3, 5)
	_, err := Reconstruct(shares[:2])
	if !errors.Is(err, ErrBelowThreshold) {
		t.Fatalf("got %v, want ErrBelowThreshold", err)
	}
}

func TestReconstruct_RejectsEmpty(t *testing.T) {
	_, err := Reconstruct(nil)
	if !errors.Is(err, ErrEmptyShareSet) {
		t.Fatalf("got %v, want ErrEmptyShareSet", err)
	}
}

func TestReconstruct_RejectsSplitIDMismatch(t *testing.T) {
	secret1 := newTestSecret(t, 0x70)
	secret2 := newTestSecret(t, 0x80)
	a, _ := splitTestSecret(t, secret1, 3, 5)
	b, _ := splitTestSecret(t, secret2, 3, 5)
	mixed := []Share{a[0], a[1], b[2]}
	_, err := Reconstruct(mixed)
	if !errors.Is(err, ErrSplitIDMismatch) {
		t.Fatalf("got %v, want ErrSplitIDMismatch", err)
	}
}

// -------------------------------------------------------------------------------------------------
// Zeroization primitives
// -------------------------------------------------------------------------------------------------

func TestZeroBytes_ClearsFullSlice(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	ZeroBytes(b)
	for i, v := range b {
		if v != 0 {
			t.Fatalf("ZeroBytes: b[%d] = %d, want 0", i, v)
		}
	}
}

func TestZeroBytes_NilSliceIsNoOp(t *testing.T) {
	// Must not panic.
	ZeroBytes(nil)
}

func TestZeroBytes_EmptySliceIsNoOp(t *testing.T) {
	ZeroBytes([]byte{})
}

func TestZeroArray32_ClearsFullArray(t *testing.T) {
	var a [32]byte
	for i := range a {
		a[i] = byte(i + 1)
	}
	ZeroArray32(&a)
	if !zeroArray32(a) {
		t.Fatal("ZeroArray32 did not clear all bytes")
	}
}

func TestZeroArray32_NilPointerIsNoOp(t *testing.T) {
	// Must not panic — defensive behavior for elision-proof primitive.
	ZeroArray32(nil)
}

// -------------------------------------------------------------------------------------------------
// ZeroizeShare / ZeroizeShares
// -------------------------------------------------------------------------------------------------

func TestZeroizeShare_ClearsAllFields(t *testing.T) {
	s := validV1Share(1, 3)
	ZeroizeShare(&s)
	if s.Version != 0 {
		t.Errorf("Version not zeroed: got 0x%02x", s.Version)
	}
	if s.Threshold != 0 {
		t.Errorf("Threshold not zeroed: got %d", s.Threshold)
	}
	if s.Index != 0 {
		t.Errorf("Index not zeroed: got %d", s.Index)
	}
	if !zeroArray32(s.Value) {
		t.Error("Value not zeroed")
	}
	if !zeroArray32(s.SplitID) {
		t.Error("SplitID not zeroed")
	}
	if !zeroArray32(s.BlindingFactor) {
		t.Error("BlindingFactor not zeroed")
	}
	if !zeroArray32(s.CommitmentHash) {
		t.Error("CommitmentHash not zeroed")
	}
}

func TestZeroizeShare_NilPointerIsNoOp(t *testing.T) {
	ZeroizeShare(nil)
}

func TestZeroizeShares_ClearsAllInSlice(t *testing.T) {
	shares := []Share{validV1Share(1, 3), validV1Share(2, 3), validV1Share(3, 3)}
	ZeroizeShares(shares)
	for i, s := range shares {
		if s.Index != 0 {
			t.Errorf("shares[%d].Index not zeroed", i)
		}
		if !zeroArray32(s.Value) {
			t.Errorf("shares[%d].Value not zeroed", i)
		}
	}
}

func TestZeroizeShares_EmptySliceIsNoOp(t *testing.T) {
	ZeroizeShares(nil)
	ZeroizeShares([]Share{})
}

// -------------------------------------------------------------------------------------------------
// GF(256) arithmetic — spot-check against Rijndael known values
// -------------------------------------------------------------------------------------------------

func TestGF256Mul_KnownValues(t *testing.T) {
	// Canonical Rijndael test vectors (GF(2^8) with reduction poly 0x11B).
	cases := []struct {
		a, b, want byte
	}{
		{0x00, 0xFF, 0x00},
		{0xFF, 0x00, 0x00},
		{0x01, 0xFF, 0xFF}, // 1 is the multiplicative identity
		{0xFF, 0x01, 0xFF},
		{0x53, 0xCA, 0x01}, // 0x53 and 0xCA are inverses in GF(2^8)
		{0x57, 0x83, 0xC1}, // classic AES example
	}
	for _, c := range cases {
		got := gf256Mul(c.a, c.b)
		if got != c.want {
			t.Errorf("gf256Mul(0x%02x, 0x%02x) = 0x%02x, want 0x%02x", c.a, c.b, got, c.want)
		}
	}
}

func TestGF256Mul_Commutative(t *testing.T) {
	// a*b == b*a for all a,b in GF(2^8).
	for a := 0; a < 256; a++ {
		for b := 0; b < 256; b++ {
			if gf256Mul(byte(a), byte(b)) != gf256Mul(byte(b), byte(a)) {
				t.Fatalf("gf256Mul not commutative at a=0x%02x b=0x%02x", a, b)
			}
		}
	}
}

func TestGF256Inv_SelfInverseAtOne(t *testing.T) {
	if gf256Inv(1) != 1 {
		t.Fatalf("gf256Inv(1) = 0x%02x, want 0x01", gf256Inv(1))
	}
}

func TestGF256Inv_MultiplicativeInverseProperty(t *testing.T) {
	// a * inv(a) == 1 for all a in [1, 255].
	for a := 1; a < 256; a++ {
		inv := gf256Inv(byte(a))
		prod := gf256Mul(byte(a), inv)
		if prod != 1 {
			t.Fatalf("gf256Mul(0x%02x, gf256Inv(0x%02x)=0x%02x) = 0x%02x, want 0x01",
				a, a, inv, prod)
		}
	}
}

// -------------------------------------------------------------------------------------------------
// Lagrange interpolation
// -------------------------------------------------------------------------------------------------

func TestLagrangeInterpolateGF256_RecoversConstant(t *testing.T) {
	// Evaluate a simple polynomial f(x) = 7 (constant) at x=1,2,3.
	// Interpolating back at x=0 must yield 7.
	xs := []byte{1, 2, 3}
	ys := []byte{7, 7, 7}
	got := lagrangeInterpolateGF256(xs, ys, 0)
	if got != 7 {
		t.Fatalf("lagrangeInterpolateGF256 constant poly: got 0x%02x, want 0x07", got)
	}
}

func TestLagrangeInterpolateGF256_RecoversDegreeOne(t *testing.T) {
	// f(x) = 5 + 3*x (in GF(256)). f(1)=6, f(2)=3 (5 XOR gf256Mul(3,2))
	// Verify: gf256Mul(3, 1) = 3, so f(1) = 5 XOR 3 = 6.
	//         gf256Mul(3, 2) = 6, so f(2) = 5 XOR 6 = 3.
	// Interpolating at x=0 gives constant term 5.
	y1 := byte(5) ^ gf256Mul(3, 1)
	y2 := byte(5) ^ gf256Mul(3, 2)
	xs := []byte{1, 2}
	ys := []byte{y1, y2}
	got := lagrangeInterpolateGF256(xs, ys, 0)
	if got != 5 {
		t.Fatalf("lagrangeInterpolateGF256 linear poly at x=0: got 0x%02x, want 0x05", got)
	}
}
