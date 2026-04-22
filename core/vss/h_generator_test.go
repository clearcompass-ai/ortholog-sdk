package vss

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"math/big"
	"testing"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// TestHGenerator_OnCurve confirms the derived H lies on secp256k1.
// The bedrock invariant: a point not on the curve cannot serve as
// a Pedersen second generator (every commitment would be invalid).
func TestHGenerator_OnCurve(t *testing.T) {
	x, y, err := HGenerator()
	if err != nil {
		t.Fatalf("HGenerator: %v", err)
	}
	if !secp256k1.S256().IsOnCurve(x, y) {
		t.Fatal("HGenerator returned a point not on secp256k1")
	}
}

// TestHGenerator_NotInfinity rejects the identity / point-at-infinity
// case. (The try-and-increment loop can't actually produce infinity —
// it picks finite x-coordinates — but the assertion exists so a
// future reorganisation of the derivation that introduces an
// infinity case is caught at the test boundary.)
func TestHGenerator_NotInfinity(t *testing.T) {
	x, y, err := HGenerator()
	if err != nil {
		t.Fatalf("HGenerator: %v", err)
	}
	if x.Sign() == 0 && y.Sign() == 0 {
		t.Fatal("HGenerator returned point at infinity")
	}
}

// TestHGenerator_Deterministic locks in the cached/fresh-derivation
// equivalence. HGenerator() and a fresh deriveHGenerator() must
// return identical coordinates — sync.Once provides the cache;
// this test proves the cache is not silently substituting a
// different value.
func TestHGenerator_Deterministic(t *testing.T) {
	cachedX, cachedY, err := HGenerator()
	if err != nil {
		t.Fatalf("HGenerator: %v", err)
	}
	freshX, freshY, err := deriveHGenerator()
	if err != nil {
		t.Fatalf("deriveHGenerator: %v", err)
	}
	if cachedX.Cmp(freshX) != 0 || cachedY.Cmp(freshY) != 0 {
		t.Fatalf("derived H mismatch — cache is inconsistent\n cached: (%s, %s)\n  fresh: (%s, %s)",
			cachedX.Text(16), cachedY.Text(16), freshX.Text(16), freshY.Text(16))
	}
}

// TestHGenerator_DistinctFromG asserts H != G. Identical generators
// would collapse Pedersen commitments to plain Schnorr commitments
// and lose the hiding property. (Probability of collision is
// astronomically small but the assertion costs nothing and locks
// the property in the test surface.)
func TestHGenerator_DistinctFromG(t *testing.T) {
	hX, hY, err := HGenerator()
	if err != nil {
		t.Fatalf("HGenerator: %v", err)
	}
	gX := secp256k1.S256().Params().Gx
	gY := secp256k1.S256().Params().Gy
	if hX.Cmp(gX) == 0 && hY.Cmp(gY) == 0 {
		t.Fatal("H == G — Pedersen hiding broken")
	}
}

// TestHGenerator_FrozenSeed locks the seed string and the derived
// coordinates as paired constants. Changing either rotates H and
// invalidates every commitment ever produced. The test catches
// accidental seed mutation in code review.
//
// The expected coordinates below are computed from
// HGeneratorSeed = "ortholog/core/vss/pedersen/h-generator/v1" via
// the procedure documented in HGeneratorDoc. They are recorded as
// the canonical values for v1 of the seed; if they drift, either
// the seed changed (ROTATION — needs explicit migration) or the
// derivation changed (BUG — backport the fix and update the
// constants together with a CHANGES entry).
func TestHGenerator_FrozenSeed(t *testing.T) {
	if HGeneratorSeed != "ortholog/core/vss/pedersen/h-generator/v1" {
		t.Fatalf("HGeneratorSeed mutated: %q", HGeneratorSeed)
	}
	x, y, err := HGenerator()
	if err != nil {
		t.Fatalf("HGenerator: %v", err)
	}
	// Belt-and-braces: re-derive from scratch to confirm the
	// constants below match a fresh run, not just a cached value.
	freshX, freshY, err := deriveHGenerator()
	if err != nil {
		t.Fatalf("deriveHGenerator: %v", err)
	}
	if x.Cmp(freshX) != 0 || y.Cmp(freshY) != 0 {
		t.Fatalf("cached vs fresh mismatch")
	}
	// Hash the (x || y) coordinates and lock the digest. We pin
	// the hash rather than the raw hex so the test fails loudly on
	// either coordinate changing without forcing reviewers to
	// eyeball two 64-character hex strings on every diff.
	var coords [64]byte
	xBytes := x.Bytes()
	yBytes := y.Bytes()
	copy(coords[32-len(xBytes):32], xBytes)
	copy(coords[64-len(yBytes):], yBytes)
	digest := sha256.Sum256(coords[:])
	got := hex.EncodeToString(digest[:])
	// Frozen on first publication of v1 seed. If this digest
	// changes, EITHER:
	//   (a) HGeneratorSeed changed — that's a v1 → v2 rotation
	//       and every commitment under v1 is now invalid; ship a
	//       new seed constant alongside a migration plan.
	//   (b) The derivation changed — bug fix; backport and update
	//       the constant together with a CHANGES entry.
	const want = "48be341b5b443243fe774d74b829b8c64598d288d2999f386b4130643eb2ab09"
	if got != want {
		t.Fatalf("H digest changed:\n got %s\nwant %s\n(see test docstring for triage)", got, want)
	}
}

// TestCandidateX_FirstFew ensures the candidate generator is
// stable byte-for-byte across runs. The procedure is just SHA-256;
// drift here means either the seed string or the counter encoding
// has changed.
func TestCandidateX_FirstFew(t *testing.T) {
	p := secp256k1.S256().Params().P
	// Counter 0 candidate.
	got := candidateX(0, p)
	expected := expectedCandidateX(0, p)
	if got.Cmp(expected) != 0 {
		t.Fatalf("counter=0: got %s, want %s", got.Text(16), expected.Text(16))
	}
	// Counter 1 candidate is different from counter 0.
	c0 := candidateX(0, p)
	c1 := candidateX(1, p)
	if c0.Cmp(c1) == 0 {
		t.Fatal("counter=0 and counter=1 produce the same x — counter encoding is broken")
	}
}

// expectedCandidateX recomputes the candidate independently of
// candidateX to catch a refactor that breaks the formula.
func expectedCandidateX(counter uint32, p *big.Int) *big.Int {
	var ctrBytes [4]byte
	binary.BigEndian.PutUint32(ctrBytes[:], counter)
	h := sha256.New()
	h.Write([]byte(HGeneratorSeed))
	h.Write(ctrBytes[:])
	x := new(big.Int).SetBytes(h.Sum(nil))
	return x.Mod(x, p)
}

// TestLiftX_RejectsOffCurveX confirms liftX returns (nil, false)
// for an x with no y on the curve. We pick x = 0; on secp256k1,
// y^2 = 0^3 + 7 = 7, and 7 is not a quadratic residue mod the
// secp256k1 field prime, so the lift fails.
func TestLiftX_RejectsOffCurveX(t *testing.T) {
	curve := secp256k1.S256()
	x := big.NewInt(0)
	y, ok := liftX(x, curve)
	if ok {
		t.Fatalf("liftX(0): want (_, false), got y=%s", y.Text(16))
	}
}

// TestLiftX_AcceptsOnCurveX with x = generator G's x coordinate.
// G is on the curve by definition; liftX must accept and return a
// y matching one of the two valid roots.
func TestLiftX_AcceptsOnCurveX(t *testing.T) {
	curve := secp256k1.S256()
	gX := curve.Params().Gx
	gY := curve.Params().Gy
	y, ok := liftX(gX, curve)
	if !ok {
		t.Fatal("liftX(Gx): want (_, true), got false")
	}
	pMinusY := new(big.Int).Sub(curve.Params().P, gY)
	if y.Cmp(gY) != 0 && y.Cmp(pMinusY) != 0 {
		t.Fatalf("liftX(Gx) returned a y that matches neither Gy nor (p - Gy)")
	}
	// Canonical-y rule: must return the smaller of the two.
	canonical := gY
	if pMinusY.Cmp(gY) < 0 {
		canonical = pMinusY
	}
	if y.Cmp(canonical) != 0 {
		t.Fatalf("liftX did not return the canonical (smaller) y")
	}
}
