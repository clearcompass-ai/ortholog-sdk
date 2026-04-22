// Package vss — testdata_test.go loads the Phase A golden fixtures
// and checks live derivation against them. The fixtures in
// testdata/ are the cross-implementation interop anchor: a future
// Rust or TypeScript port of core/vss MUST reproduce these bytes
// exactly. Drift here is a portability-breaking change and MUST be
// accompanied by a seed-rotation ADR.
package vss

import (
	"crypto/sha256"
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
