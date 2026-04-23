// Package vss — testdata_test.go loads the Phase A golden fixtures
// and checks live derivation against them. The fixtures in
// testdata/ are the cross-implementation interop anchor: a future
// Rust or TypeScript port of core/vss MUST reproduce these bytes
// exactly. Drift here is a portability-breaking change and MUST be
// accompanied by a seed-rotation ADR.
package vss

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// hGeneratorFixture mirrors testdata/h_generator.json. Only the
// fields we assert against are extracted; descriptive fields
// (description, procedure, notes) are ignored.
type hGeneratorFixture struct {
	Seed     string `json:"seed"`
	Curve    string `json:"curve"`
	Expected struct {
		TerminatingCounter int    `json:"terminating_counter"`
		X                  string `json:"x_hex"`
		Y                  string `json:"y_hex"`
		XYSha256           string `json:"xy_sha256_hex"`
	} `json:"expected"`
}

func loadHGeneratorFixture(t *testing.T) hGeneratorFixture {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "h_generator.json"))
	if err != nil {
		t.Fatalf("read h_generator.json: %v", err)
	}
	var fx hGeneratorFixture
	if err := json.Unmarshal(data, &fx); err != nil {
		t.Fatalf("unmarshal h_generator.json: %v", err)
	}
	return fx
}

// TestFixture_HGeneratorSeedMatches asserts the fixture's seed
// equals the HGeneratorSeed constant the code actually uses.
// Catches the case where one drifts without the other.
func TestFixture_HGeneratorSeedMatches(t *testing.T) {
	fx := loadHGeneratorFixture(t)
	if fx.Seed != HGeneratorSeed {
		t.Fatalf("fixture seed = %q, HGeneratorSeed = %q", fx.Seed, HGeneratorSeed)
	}
	if fx.Curve != "secp256k1" {
		t.Fatalf("fixture curve = %q, want secp256k1", fx.Curve)
	}
}

// TestFixture_HGeneratorCoordinates checks HGenerator() against
// the fixture's locked x and y. This is the interop gate: any
// alternative implementation of the derivation must hit the same
// coordinates byte-for-byte.
func TestFixture_HGeneratorCoordinates(t *testing.T) {
	fx := loadHGeneratorFixture(t)
	x, y, err := HGenerator()
	if err != nil {
		t.Fatalf("HGenerator: %v", err)
	}

	wantX, err := hex.DecodeString(fx.Expected.X)
	if err != nil {
		t.Fatalf("bad fixture x_hex: %v", err)
	}
	wantY, err := hex.DecodeString(fx.Expected.Y)
	if err != nil {
		t.Fatalf("bad fixture y_hex: %v", err)
	}

	gotX := padScalar(x)
	gotY := padScalar(y)
	if !equalBytes(gotX, wantX) {
		t.Fatalf("x mismatch:\n got %x\nwant %x", gotX, wantX)
	}
	if !equalBytes(gotY, wantY) {
		t.Fatalf("y mismatch:\n got %x\nwant %x", gotY, wantY)
	}

	// Cross-check: SHA-256 of (x || y) matches the fixture AND the
	// constant locked in TestHGenerator_FrozenSeed. Three independent
	// paths must agree.
	var xy [64]byte
	copy(xy[:32], gotX)
	copy(xy[32:], gotY)
	digest := sha256.Sum256(xy[:])
	gotDigest := hex.EncodeToString(digest[:])
	if gotDigest != fx.Expected.XYSha256 {
		t.Fatalf("xy digest mismatch:\n got %s\nwant %s", gotDigest, fx.Expected.XYSha256)
	}
}

// TestFixture_HGeneratorTerminatingCounter locks the counter value
// at which try-and-increment succeeds for HGeneratorSeed. If a
// future refactor alters candidateX / liftX / the seed encoding,
// this value will drift — and that's a regression: either a bug,
// or a seed-rotation (v1 -> v2 migration) that needs an ADR.
func TestFixture_HGeneratorTerminatingCounter(t *testing.T) {
	fx := loadHGeneratorFixture(t)
	curve := secp256k1.S256()
	for counter := uint32(0); counter < HGeneratorMaxAttempts; counter++ {
		x := candidateX(counter, curve.Params().P)
		if _, ok := liftX(x, curve); ok {
			if int(counter) != fx.Expected.TerminatingCounter {
				t.Fatalf("terminating counter = %d, fixture says %d",
					counter, fx.Expected.TerminatingCounter)
			}
			return
		}
	}
	t.Fatalf("derivation did not terminate within %d attempts", HGeneratorMaxAttempts)
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ─────────────────────────────────────────────────────────────────
// testdata/split_vector.json — end-to-end Split round-trip anchor
// ─────────────────────────────────────────────────────────────────

type splitFixture struct {
	Input struct {
		SecretHex string `json:"secret_hex"`
		M         int    `json:"m"`
		N         int    `json:"n"`
		DRBGSeed  string `json:"drbg_seed"`
	} `json:"input"`
	Expected struct {
		CommitmentSetCompressedHex []string `json:"commitment_set_compressed_hex"`
		CommitmentHashHex          string   `json:"commitment_hash_hex"`
		Shares                     []struct {
			Index             int    `json:"index"`
			ValueHex          string `json:"value_hex"`
			BlindingFactorHex string `json:"blinding_factor_hex"`
			CommitmentHashHex string `json:"commitment_hash_hex"`
		} `json:"shares"`
	} `json:"expected"`
}

// drbgReader: deterministic io.Reader driven by SHA-256(seed ||
// BE_uint64(counter)). Used only for test-vector reproducibility.
// NOT suitable for production — provides no forward secrecy and
// the seed is public.
type drbgReader struct {
	seed    []byte
	counter uint64
	buf     []byte
}

func newDRBG(seed string) *drbgReader { return &drbgReader{seed: []byte(seed)} }

func (r *drbgReader) Read(p []byte) (int, error) {
	for len(r.buf) < len(p) {
		var ctr [8]byte
		binary.BigEndian.PutUint64(ctr[:], r.counter)
		h := sha256.New()
		h.Write(r.seed)
		h.Write(ctr[:])
		r.buf = append(r.buf, h.Sum(nil)...)
		r.counter++
	}
	n := copy(p, r.buf[:len(p)])
	r.buf = r.buf[n:]
	return n, nil
}

func loadSplitFixture(t *testing.T) splitFixture {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "split_vector.json"))
	if err != nil {
		t.Fatalf("read split_vector.json: %v", err)
	}
	var fx splitFixture
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return fx
}

// TestFixture_SplitVectorGolden is the cross-implementation anchor
// for the Split primitive. Feeds the library's splitWithReader
// (internal) with a deterministic DRBG, asserts byte-exact match
// against the committed JSON fixture.
//
// If this test fails after a refactor of Split that changed the
// order of coefficient sampling or the commitment-hash layout,
// the fixture is stale. Regenerate via a deliberate update;
// any future port must then match the new values.
func TestFixture_SplitVectorGolden(t *testing.T) {
	fx := loadSplitFixture(t)

	secretBytes, err := hex.DecodeString(fx.Input.SecretHex)
	if err != nil {
		t.Fatalf("secret hex: %v", err)
	}
	if len(secretBytes) != SecretSize {
		t.Fatalf("fixture secret length = %d, want %d", len(secretBytes), SecretSize)
	}
	var secret [SecretSize]byte
	copy(secret[:], secretBytes)

	r := newDRBG(fx.Input.DRBGSeed)
	shares, commits, err := splitWithReader(secret, fx.Input.M, fx.Input.N, r)
	if err != nil {
		t.Fatalf("splitWithReader: %v", err)
	}
	if len(shares) != fx.Input.N {
		t.Fatalf("share count = %d, want %d", len(shares), fx.Input.N)
	}
	if commits.Threshold() != fx.Input.M {
		t.Fatalf("commit threshold = %d, want %d", commits.Threshold(), fx.Input.M)
	}

	// Commitments: compare compressed form.
	for j, pt := range commits.Points {
		gotX, gotY, err := unmarshalOnCurve(secp256k1Curve(), pt)
		if err != nil {
			t.Fatalf("commit %d: %v", j, err)
		}
		gotCompressed := hex.EncodeToString(compressedPoint(gotX, gotY))
		if gotCompressed != fx.Expected.CommitmentSetCompressedHex[j] {
			t.Fatalf("commit %d mismatch:\n got %s\nwant %s",
				j, gotCompressed, fx.Expected.CommitmentSetCompressedHex[j])
		}
	}

	// Commitment hash (the value shares carry and that reconstruction
	// gates on).
	gotCH := hex.EncodeToString(func() []byte { h := commits.Hash(); return h[:] }())
	if gotCH != fx.Expected.CommitmentHashHex {
		t.Fatalf("commitment hash mismatch:\n got %s\nwant %s", gotCH, fx.Expected.CommitmentHashHex)
	}

	// Shares.
	for i, s := range shares {
		want := fx.Expected.Shares[i]
		if int(s.Index) != want.Index {
			t.Fatalf("share %d: Index = %d, want %d", i, s.Index, want.Index)
		}
		if hex.EncodeToString(s.Value[:]) != want.ValueHex {
			t.Fatalf("share %d: Value = %x, want %s", i, s.Value[:], want.ValueHex)
		}
		if hex.EncodeToString(s.BlindingFactor[:]) != want.BlindingFactorHex {
			t.Fatalf("share %d: BlindingFactor = %x, want %s", i, s.BlindingFactor[:], want.BlindingFactorHex)
		}
		if hex.EncodeToString(s.CommitmentHash[:]) != want.CommitmentHashHex {
			t.Fatalf("share %d: CommitmentHash = %x, want %s", i, s.CommitmentHash[:], want.CommitmentHashHex)
		}
	}

	// End-to-end sanity: round-trip from the golden shares reconstructs
	// the golden secret. Three different 3-share subsets to exercise
	// Lagrange over non-contiguous indices.
	for _, subset := range [][]int{{0, 1, 2}, {0, 2, 4}, {1, 3, 4}} {
		selected := []Share{shares[subset[0]], shares[subset[1]], shares[subset[2]]}
		got, err := Reconstruct(selected, commits)
		if err != nil {
			t.Fatalf("Reconstruct subset %v: %v", subset, err)
		}
		if got != secret {
			t.Fatalf("Reconstruct subset %v: got %x, want %x", subset, got, secret)
		}
	}
}

// secp256k1Curve is a tiny shim so callers in this file don't
// need to import the curve package directly — keeps the import
// block tight.
func secp256k1Curve() *secp256k1.KoblitzCurve { return secp256k1.S256() }
