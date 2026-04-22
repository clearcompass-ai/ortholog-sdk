package vss

import (
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"
	"testing"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// fixedSecret returns a known 32-byte secret for round-trip tests.
// Hex chosen to be obviously not all-zero and visually distinct from
// any natural curve constant.
func fixedSecret() [SecretSize]byte {
	var s [SecretSize]byte
	copy(s[:], []byte("ortholog-vss-pedersen-test-2025!"))
	return s
}

// ─────────────────────────────────────────────────────────────────
// Round-trip
// ─────────────────────────────────────────────────────────────────

func TestPedersen_RoundTrip_3of5(t *testing.T) {
	secret := fixedSecret()
	shares, commitments, err := Split(secret, 3, 5)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	if len(shares) != 5 {
		t.Fatalf("len(shares) = %d, want 5", len(shares))
	}
	if commitments.Threshold() != 3 {
		t.Fatalf("commitment threshold = %d, want 3", commitments.Threshold())
	}

	// Every share must verify against the published commitments.
	for _, s := range shares {
		if err := Verify(s, commitments); err != nil {
			t.Fatalf("Verify share %d: %v", s.Index, err)
		}
	}

	got, err := Reconstruct(shares[:3], commitments)
	if err != nil {
		t.Fatalf("Reconstruct: %v", err)
	}
	if got != secret {
		t.Fatalf("round-trip mismatch:\n got %x\nwant %x", got, secret)
	}
}

func TestPedersen_RoundTrip_AllSubsets_2of3(t *testing.T) {
	secret := fixedSecret()
	shares, commitments, err := Split(secret, 2, 3)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	subsets := [][]int{
		{0, 1},
		{0, 2},
		{1, 2},
	}
	for _, idx := range subsets {
		subset := []Share{shares[idx[0]], shares[idx[1]]}
		got, err := Reconstruct(subset, commitments)
		if err != nil {
			t.Fatalf("subset %v: %v", idx, err)
		}
		if got != secret {
			t.Fatalf("subset %v: round-trip mismatch", idx)
		}
	}
}

func TestPedersen_LargerSubsetReconstructsCorrectly(t *testing.T) {
	// Reconstruct with 4 of a 3-of-5 split — the extra share should
	// not change the result (Lagrange ignores it: we trim to M).
	secret := fixedSecret()
	shares, commitments, err := Split(secret, 3, 5)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	got, err := Reconstruct(shares[:4], commitments)
	if err != nil {
		t.Fatalf("Reconstruct(4 shares): %v", err)
	}
	if got != secret {
		t.Fatalf("over-quorum reconstruct mismatch")
	}
}

// ─────────────────────────────────────────────────────────────────
// Threshold enforcement
// ─────────────────────────────────────────────────────────────────

func TestPedersen_BelowQuorumRejected(t *testing.T) {
	secret := fixedSecret()
	shares, commitments, err := Split(secret, 3, 5)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	_, err = Reconstruct(shares[:2], commitments)
	if !errors.Is(err, ErrShareCountBelowQuorum) {
		t.Fatalf("Reconstruct(2 of 3-quorum): want ErrShareCountBelowQuorum, got %v", err)
	}
}

func TestPedersen_DuplicateIndicesRejected(t *testing.T) {
	secret := fixedSecret()
	shares, commitments, err := Split(secret, 3, 5)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	dup := []Share{shares[0], shares[0], shares[2]}
	_, err = Reconstruct(dup, commitments)
	if !errors.Is(err, ErrDuplicateIndex) {
		t.Fatalf("duplicate index: want ErrDuplicateIndex, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────
// Single-share verification — local fault detection
// ─────────────────────────────────────────────────────────────────

// TestPedersen_VerifyDetectsTamperedValue is the headline VSS
// property: a single shareholder, with no quorum, can detect a
// faulty share.
func TestPedersen_VerifyDetectsTamperedValue(t *testing.T) {
	shares, commitments, err := Split(fixedSecret(), 3, 5)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	bad := shares[0]
	bad.Value[0] ^= 0x01 // flip one bit
	if err := Verify(bad, commitments); !errors.Is(err, ErrCommitmentMismatch) {
		t.Fatalf("tampered Value: want ErrCommitmentMismatch, got %v", err)
	}
}

func TestPedersen_VerifyDetectsTamperedBlinding(t *testing.T) {
	shares, commitments, err := Split(fixedSecret(), 3, 5)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	bad := shares[0]
	bad.BlindingFactor[0] ^= 0x01
	if err := Verify(bad, commitments); !errors.Is(err, ErrCommitmentMismatch) {
		t.Fatalf("tampered BlindingFactor: want ErrCommitmentMismatch, got %v", err)
	}
}

func TestPedersen_VerifyDetectsTamperedIndex(t *testing.T) {
	shares, commitments, err := Split(fixedSecret(), 3, 5)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	// Re-label share[0] (index 1) as if it were share[1] (index 2).
	// The (Value, BlindingFactor) it carries does not satisfy the
	// commitment equation at index 2, so Verify rejects.
	bad := shares[0]
	bad.Index = 2
	if err := Verify(bad, commitments); !errors.Is(err, ErrCommitmentMismatch) {
		t.Fatalf("tampered Index: want ErrCommitmentMismatch, got %v", err)
	}
}

func TestPedersen_VerifyRejectsZeroIndex(t *testing.T) {
	shares, commitments, _ := Split(fixedSecret(), 3, 5)
	bad := shares[0]
	bad.Index = 0
	if err := Verify(bad, commitments); !errors.Is(err, ErrShareIndexOutOfRange) {
		t.Fatalf("Index=0: want ErrShareIndexOutOfRange, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────
// Commitment-hash binding
// ─────────────────────────────────────────────────────────────────

// TestPedersen_RejectsCrossSplitMixing: shares from one split must
// not Verify under another split's commitments. This is the core
// anti-mixing property: even if both splits used the same M and N,
// the per-share CommitmentHash differs and Verify rejects before
// any commitment math runs.
func TestPedersen_RejectsCrossSplitMixing(t *testing.T) {
	sharesA, _, err := Split(fixedSecret(), 3, 5)
	if err != nil {
		t.Fatalf("Split A: %v", err)
	}
	var otherSecret [SecretSize]byte
	copy(otherSecret[:], []byte("a-completely-different-secret!!!"))
	_, commitmentsB, err := Split(otherSecret, 3, 5)
	if err != nil {
		t.Fatalf("Split B: %v", err)
	}
	if err := Verify(sharesA[0], commitmentsB); !errors.Is(err, ErrCommitmentHashMismatch) {
		t.Fatalf("A-share with B-commitments: want ErrCommitmentHashMismatch, got %v", err)
	}
}

// TestPedersen_RejectsTamperedCommitments: flipping a bit in any
// commitment point changes the CommitmentHash, which the share's
// pinned hash no longer matches.
func TestPedersen_RejectsTamperedCommitments(t *testing.T) {
	shares, commitments, err := Split(fixedSecret(), 3, 5)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	tampered := Commitments{Points: make([][]byte, len(commitments.Points))}
	for i, p := range commitments.Points {
		tampered.Points[i] = append([]byte(nil), p...)
	}
	tampered.Points[1][33] ^= 0x01 // flip a bit in the middle of the second point
	if err := Verify(shares[0], tampered); !errors.Is(err, ErrCommitmentHashMismatch) {
		t.Fatalf("tampered commitments: want ErrCommitmentHashMismatch, got %v", err)
	}
}

// TestPedersen_RejectsCorruptCommitmentPoint: a commitment vector
// containing a non-curve point at one slot must fail verification
// with ErrInvalidCommitmentPoint, NOT ErrCommitmentHashMismatch.
//
// We have to bypass the hash check by building shares whose
// CommitmentHash matches the corrupt vector's hash; the easiest
// way is to call Hash() on the corrupt vector and copy the result
// into the share — that's a contrived attack scenario but it
// proves the on-curve guard is reachable.
func TestPedersen_RejectsCorruptCommitmentPoint(t *testing.T) {
	shares, commitments, err := Split(fixedSecret(), 3, 5)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	corrupt := Commitments{Points: make([][]byte, len(commitments.Points))}
	for i, p := range commitments.Points {
		corrupt.Points[i] = append([]byte(nil), p...)
	}
	// Replace point 1 with a 65-byte uncompressed encoding of (1, 1)
	// — well-formed wire shape, off curve.
	corrupt.Points[1] = make([]byte, 65)
	corrupt.Points[1][0] = 0x04
	corrupt.Points[1][32] = 0x01
	corrupt.Points[1][64] = 0x01

	bad := shares[0]
	bad.CommitmentHash = corrupt.Hash() // bypass the hash gate

	err = Verify(bad, corrupt)
	if !errors.Is(err, ErrInvalidCommitmentPoint) {
		t.Fatalf("corrupt point: want ErrInvalidCommitmentPoint, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────
// Input validation
// ─────────────────────────────────────────────────────────────────

func TestPedersen_SplitRejectsBelowMinThreshold(t *testing.T) {
	_, _, err := Split(fixedSecret(), 1, 5)
	if !errors.Is(err, ErrInvalidThreshold) {
		t.Fatalf("M=1: want ErrInvalidThreshold, got %v", err)
	}
}

func TestPedersen_SplitRejectsThresholdAboveShares(t *testing.T) {
	_, _, err := Split(fixedSecret(), 5, 3)
	if !errors.Is(err, ErrInvalidShareCount) {
		t.Fatalf("M>N: want ErrInvalidShareCount, got %v", err)
	}
}

func TestPedersen_SplitRejectsTooManyShares(t *testing.T) {
	_, _, err := Split(fixedSecret(), 3, MaxShares+1)
	if !errors.Is(err, ErrInvalidShareCount) {
		t.Fatalf("N>MaxShares: want ErrInvalidShareCount, got %v", err)
	}
}

func TestPedersen_SplitRejectsZeroSecret(t *testing.T) {
	_, _, err := Split([SecretSize]byte{}, 3, 5)
	if err == nil {
		t.Fatal("zero secret: want error, got nil")
	}
}

// ─────────────────────────────────────────────────────────────────
// Hiding property — sanity check
// ─────────────────────────────────────────────────────────────────

// TestPedersen_CommitmentsDifferAcrossSplits: two splits of the
// SAME secret produce DIFFERENT commitment vectors (because the
// blinding polynomial is fresh-random each call). This is the
// observable consequence of the hiding property: an observer
// watching the commitments cannot link two splits to the same
// secret.
func TestPedersen_CommitmentsDifferAcrossSplits(t *testing.T) {
	secret := fixedSecret()
	_, c1, err := Split(secret, 3, 5)
	if err != nil {
		t.Fatalf("Split 1: %v", err)
	}
	_, c2, err := Split(secret, 3, 5)
	if err != nil {
		t.Fatalf("Split 2: %v", err)
	}
	if c1.Hash() == c2.Hash() {
		t.Fatal("two splits of the same secret produced identical commitments — randomness is broken or hiding is lost")
	}
}

// ─────────────────────────────────────────────────────────────────
// Internal helpers — coverage for padScalar / evalPoly
// ─────────────────────────────────────────────────────────────────

func TestPadScalar_ShortValuePadded(t *testing.T) {
	got := padScalar(big.NewInt(1))
	if len(got) != 32 {
		t.Fatalf("len = %d, want 32", len(got))
	}
	if got[31] != 1 {
		t.Fatalf("expected last byte 1, got %d", got[31])
	}
	for i := 0; i < 31; i++ {
		if got[i] != 0 {
			t.Fatalf("byte %d non-zero in padding", i)
		}
	}
}

func TestPadScalar_FullWidthValuePreserved(t *testing.T) {
	want := make([]byte, 32)
	for i := range want {
		want[i] = 0xAA
	}
	got := padScalar(new(big.Int).SetBytes(want))
	if len(got) != 32 {
		t.Fatalf("len = %d, want 32", len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("byte %d: got 0x%02x, want 0x%02x", i, got[i], want[i])
		}
	}
}

func TestEvalPoly_KnownValues(t *testing.T) {
	// f(x) = 5 + 3x + 2x^2 evaluated mod n.
	// f(2) = 5 + 6 + 8 = 19.
	n := secp256k1.S256().Params().N
	coeffs := []*big.Int{big.NewInt(5), big.NewInt(3), big.NewInt(2)}
	got := evalPoly(coeffs, big.NewInt(2), n)
	if got.Cmp(big.NewInt(19)) != 0 {
		t.Fatalf("f(2) = %s, want 19", got.Text(10))
	}
}

func TestRandScalar_NonZero(t *testing.T) {
	n := secp256k1.S256().Params().N
	for i := 0; i < 32; i++ {
		k, err := randScalar(rand.Reader, n)
		if err != nil {
			t.Fatalf("randScalar iter %d: %v", i, err)
		}
		if k.Sign() == 0 {
			t.Fatalf("randScalar returned zero on iter %d", i)
		}
		if k.Cmp(n) >= 0 {
			t.Fatalf("randScalar returned >= n on iter %d", i)
		}
	}
}

// ─────────────────────────────────────────────────────────────────
// Smoke test: commitment point well-formedness
// ─────────────────────────────────────────────────────────────────

// TestPedersen_AllCommitmentPointsOnCurve confirms every published
// commitment is a valid secp256k1 point. A commitment off the
// curve would produce undefined ScalarMult behaviour during
// Verify; the on-curve check inside Verify catches it but here we
// also confirm Split produces well-formed output.
func TestPedersen_AllCommitmentPointsOnCurve(t *testing.T) {
	_, commitments, err := Split(fixedSecret(), 3, 5)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	curve := secp256k1.S256()
	for i, p := range commitments.Points {
		x, y := elliptic.Unmarshal(curve, p)
		if x == nil {
			t.Fatalf("commitment %d does not unmarshal", i)
		}
		if !curve.IsOnCurve(x, y) {
			t.Fatalf("commitment %d not on curve", i)
		}
	}
}
