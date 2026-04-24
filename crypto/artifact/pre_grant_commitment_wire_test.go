package artifact

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math/big"
	"testing"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/clearcompass-ai/ortholog-sdk/storage"
)

// ─────────────────────────────────────────────────────────────────────
// Deterministic test fixtures
// ─────────────────────────────────────────────────────────────────────

// syntheticCompressedPoint returns compressed(k·G) on secp256k1 for a
// scalar k supplied as a small integer. Deterministic and cheap —
// suitable for building commitment-set fixtures without running VSS.
func syntheticCompressedPoint(t *testing.T, k int64) [33]byte {
	t.Helper()
	c := secp256k1.S256()
	x, y := c.ScalarBaseMult(padBigInt(big.NewInt(k)))
	var out [33]byte
	copy(out[:], compressedPoint(x, y))
	return out
}

// canonicalPREFixture pins the (grantor, recipient, artifactCID)
// triple used across Group 3.2 tests. Matches the Group 2 fixture at
// crypto/artifact/testdata/pre_grant_split_id_vector.json so the
// golden SplitID can be recomputed deterministically.
func canonicalPREFixture(t *testing.T) (string, string, storage.CID, [32]byte) {
	t.Helper()
	grantor := "did:web:example.com:grantor"
	recipient := "did:web:example.com:recipient"
	digest := sha256.Sum256([]byte("artifact/1"))
	cid := storage.CID{Algorithm: storage.AlgoSHA256, Digest: digest[:]}
	splitID := ComputePREGrantSplitID(grantor, recipient, cid)
	return grantor, recipient, cid, splitID
}

// buildSyntheticCommitment constructs a PREGrantCommitment whose
// CommitmentSet is M synthetic (i+1)·G compressed points. The
// SplitID is the canonical fixture SplitID unless overridden.
func buildSyntheticCommitment(t *testing.T, M, N int) PREGrantCommitment {
	t.Helper()
	_, _, _, splitID := canonicalPREFixture(t)
	set := make([][33]byte, M)
	for i := 0; i < M; i++ {
		set[i] = syntheticCompressedPoint(t, int64(i+1))
	}
	return PREGrantCommitment{
		SplitID:       splitID,
		M:             byte(M),
		N:             byte(N),
		CommitmentSet: set,
	}
}

// ─────────────────────────────────────────────────────────────────────
// Round-trip serialization
// ─────────────────────────────────────────────────────────────────────

// TestPREGrantCommitment_RoundTrip covers Serialize→Deserialize across
// a range of (M, N) combinations.
func TestPREGrantCommitment_RoundTrip(t *testing.T) {
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
		orig := buildSyntheticCommitment(t, M, N)
		wire, err := SerializePREGrantCommitment(orig)
		if err != nil {
			t.Fatalf("Serialize M=%d N=%d: %v", M, N, err)
		}
		if len(wire) != PREGrantCommitmentWireLen(M) {
			t.Fatalf("M=%d: wire length = %d, want %d", M, len(wire), PREGrantCommitmentWireLen(M))
		}
		got, err := DeserializePREGrantCommitment(wire)
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
// Size cap
// ─────────────────────────────────────────────────────────────────────

// TestPREGrantCommitment_SizeCap_M255 pins the 8,449-byte maximum at
// M=255 (34 + 33*255).
func TestPREGrantCommitment_SizeCap_M255(t *testing.T) {
	if PREGrantCommitmentMaxWireLen != 8449 {
		t.Fatalf("PREGrantCommitmentMaxWireLen = %d, want 8449", PREGrantCommitmentMaxWireLen)
	}
	c := buildSyntheticCommitment(t, 255, 255)
	wire, err := SerializePREGrantCommitment(c)
	if err != nil {
		t.Fatalf("Serialize M=255: %v", err)
	}
	if len(wire) != 8449 {
		t.Fatalf("M=255 wire length = %d, want 8449", len(wire))
	}
	if len(wire) != PREGrantCommitmentWireLen(255) {
		t.Fatalf("PREGrantCommitmentWireLen(255) = %d, want %d",
			PREGrantCommitmentWireLen(255), len(wire))
	}
	if len(wire) != PREGrantCommitmentMaxWireLen {
		t.Fatalf("M=255 wire length %d != max %d", len(wire), PREGrantCommitmentMaxWireLen)
	}
	// Round-trip at the cap.
	if _, err := DeserializePREGrantCommitment(wire); err != nil {
		t.Fatalf("Deserialize M=255: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Golden vector — pinned serialization bytes
// ─────────────────────────────────────────────────────────────────────

// TestPREGrantCommitment_GoldenVector pins the exact wire hex for a
// deterministic commitment: canonical PRE SplitID fixture, M=3 N=5,
// CommitmentSet = compressed(1·G), compressed(2·G), compressed(3·G).
//
// Any change to the layout, the compressed-point encoding, or the
// SplitID derivation fails this test.
func TestPREGrantCommitment_GoldenVector(t *testing.T) {
	c := buildSyntheticCommitment(t, 3, 5)
	wire, err := SerializePREGrantCommitment(c)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	const want = "c700139613f359d253e95b2a47cbdb566a89412df785e4cb2cb7a3223961087903050279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f8179802c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee502f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
	got := hex.EncodeToString(wire)
	if got != want {
		t.Fatalf("golden mismatch\n  got:  %s\n  want: %s", got, want)
	}
	if len(wire) != 133 {
		t.Fatalf("M=3 wire length = %d, want 133", len(wire))
	}
}

// ─────────────────────────────────────────────────────────────────────
// Serialize-side rejection paths
// ─────────────────────────────────────────────────────────────────────

// TestPREGrantCommitment_SerializeRejectsThresholdBounds covers M<2,
// M>N, N>255. This is the wire-side companion to the verify-side
// threshold-bounds tests.
func TestPREGrantCommitment_SerializeRejectsThresholdBounds(t *testing.T) {
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
			c := PREGrantCommitment{
				M: byte(tc.M),
				N: byte(tc.N),
			}
			if tc.M >= 2 && tc.M <= 255 {
				c.CommitmentSet = make([][33]byte, tc.M)
				for i := range c.CommitmentSet {
					c.CommitmentSet[i] = syntheticCompressedPoint(t, int64(i+1))
				}
			}
			_, err := SerializePREGrantCommitment(c)
			if !errors.Is(err, ErrCommitmentThresholdBounds) {
				t.Fatalf("want ErrCommitmentThresholdBounds, got %v", err)
			}
		})
	}
}

// TestPREGrantCommitment_SerializeRejectsSetLengthMismatch asserts
// that len(CommitmentSet) != M rejects at serialize.
func TestPREGrantCommitment_SerializeRejectsSetLengthMismatch(t *testing.T) {
	c := buildSyntheticCommitment(t, 3, 5)
	c.CommitmentSet = c.CommitmentSet[:2] // short
	_, err := SerializePREGrantCommitment(c)
	if !errors.Is(err, ErrCommitmentSetLength) {
		t.Fatalf("short set: want ErrCommitmentSetLength, got %v", err)
	}
	c2 := buildSyntheticCommitment(t, 3, 5)
	c2.CommitmentSet = append(c2.CommitmentSet, syntheticCompressedPoint(t, 4)) // long
	_, err = SerializePREGrantCommitment(c2)
	if !errors.Is(err, ErrCommitmentSetLength) {
		t.Fatalf("long set: want ErrCommitmentSetLength, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Deserialize-side rejection paths
// ─────────────────────────────────────────────────────────────────────

// TestPREGrantCommitment_DeserializeRejectsShortBuffer asserts that
// a buffer shorter than the header is rejected.
func TestPREGrantCommitment_DeserializeRejectsShortBuffer(t *testing.T) {
	for _, n := range []int{0, 1, 31, 33} {
		buf := make([]byte, n)
		_, err := DeserializePREGrantCommitment(buf)
		if !errors.Is(err, ErrCommitmentWireLength) {
			t.Fatalf("len=%d: want ErrCommitmentWireLength, got %v", n, err)
		}
	}
}

// TestPREGrantCommitment_DeserializeRejectsWrongLength asserts that
// a buffer whose length does not match 34 + 33*M is rejected.
func TestPREGrantCommitment_DeserializeRejectsWrongLength(t *testing.T) {
	c := buildSyntheticCommitment(t, 3, 5)
	wire, err := SerializePREGrantCommitment(c)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	// Drop the last byte — length no longer matches M-derived expected.
	short := wire[:len(wire)-1]
	if _, err := DeserializePREGrantCommitment(short); !errors.Is(err, ErrCommitmentWireLength) {
		t.Fatalf("short: want ErrCommitmentWireLength, got %v", err)
	}
	// Add a trailing byte.
	long := append(append([]byte{}, wire...), 0x00)
	if _, err := DeserializePREGrantCommitment(long); !errors.Is(err, ErrCommitmentWireLength) {
		t.Fatalf("long: want ErrCommitmentWireLength, got %v", err)
	}
}

// TestPREGrantCommitment_DeserializeRejectsBadThreshold asserts
// that the on-wire M and N bytes are validated at deserialize.
func TestPREGrantCommitment_DeserializeRejectsBadThreshold(t *testing.T) {
	// Build a short buffer where M=0.
	buf := make([]byte, 34)
	buf[32] = 0 // M=0
	buf[33] = 5 // N=5
	if _, err := DeserializePREGrantCommitment(buf); !errors.Is(err, ErrCommitmentThresholdBounds) {
		t.Fatalf("M=0: want ErrCommitmentThresholdBounds, got %v", err)
	}
	// M=6, N=5
	buf[32] = 6
	if _, err := DeserializePREGrantCommitment(buf); !errors.Is(err, ErrCommitmentThresholdBounds) {
		t.Fatalf("M>N: want ErrCommitmentThresholdBounds, got %v", err)
	}
}

// TestPREGrantCommitment_DeserializeRejectsOffCurvePoint asserts
// that a wire buffer whose commitment-set contains an off-curve
// compressed point rejects at deserialize. The forced off-curve
// encoding here uses the secp256k1 field prime P as the x coordinate,
// which is outside the field and therefore rejected by decompressPoint.
func TestPREGrantCommitment_DeserializeRejectsOffCurvePoint(t *testing.T) {
	c := buildSyntheticCommitment(t, 3, 5)
	wire, err := SerializePREGrantCommitment(c)
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}
	// Overwrite the first commitment point's x coordinate with P.
	curve := secp256k1.S256()
	p := curve.Params().P
	pb := p.Bytes()
	offset := PREGrantCommitmentHeaderLen
	// Keep the 0x02 prefix, replace the 32-byte x with bytes of P.
	for i := 0; i < 32; i++ {
		wire[offset+1+i] = 0
	}
	copy(wire[offset+1+32-len(pb):offset+1+32], pb)
	if _, err := DeserializePREGrantCommitment(wire); !errors.Is(err, ErrCommitmentPointOffCurve) {
		t.Fatalf("x==P: want ErrCommitmentPointOffCurve, got %v", err)
	}
}
