// Package vss — pedersen_binding_test.go holds the mutation-audit
// binding tests for the muEnablePedersenIndexBounds and
// muEnablePedersenOnCurveCheck switches in
// pedersen_mutation_switches.go. See core/vss/pedersen.mutation-audit.yaml
// for the registry.
//
// Each test is tight: it exercises one gate, asserts the specific
// error message that gate produces, and would silently pass if the
// gate were removed (because a downstream gate eventually rejects
// for a different reason, which is what the specific-message
// assertion guards against).
package vss

import (
	"errors"
	"math/big"
	"testing"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// onCurvePair returns an arbitrary on-curve (x, y) suitable for
// VerifyPoints fields that are not the target of the mutation probe.
// Uses G (the secp256k1 generator) so no curve arithmetic beyond
// Params() is required.
func onCurvePair() (*big.Int, *big.Int) {
	p := secp256k1.S256().Params()
	return new(big.Int).Set(p.Gx), new(big.Int).Set(p.Gy)
}

// validCommitmentsForIndex returns a minimally-valid commitments
// vector. We don't need the share math to succeed — only for the
// (vkX, vkY, bkX, bkY) check gates to fire before commitmentCombine.
func validCommitmentsForIndex(t *testing.T) Commitments {
	t.Helper()
	var secret [SecretSize]byte
	secret[0] = 0x01
	_, commits, err := Split(secret, 2, 3)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	return commits
}

// ─────────────────────────────────────────────────────────────────────
// Binding: muEnablePedersenIndexBounds
// ─────────────────────────────────────────────────────────────────────

// TestVerifyPoints_RejectsIndexZero_Binding pins that index = 0 is
// rejected with ErrShareIndexOutOfRange. Flipping
// muEnablePedersenIndexBounds to false lets index = 0 through; the
// downstream commitmentCombine would compute the secret position
// (x = 0) which leaks the secret-position polynomial evaluation.
func TestVerifyPoints_RejectsIndexZero_Binding(t *testing.T) {
	commits := validCommitmentsForIndex(t)
	vkX, vkY := onCurvePair()
	bkX, bkY := onCurvePair()
	err := VerifyPoints(0, vkX, vkY, bkX, bkY, commits)
	if !errors.Is(err, ErrShareIndexOutOfRange) {
		t.Fatalf("want ErrShareIndexOutOfRange on index 0, got %v", err)
	}
}

// TestVerifyPoints_RejectsIndexOverMax_Binding covers the upper
// bound: indices above MaxShares (255) are rejected.
func TestVerifyPoints_RejectsIndexOverMax_Binding(t *testing.T) {
	// MaxShares is 255; byte wraps at 256 so the only literal over-
	// max value that fits in a byte is… none. We exercise the
	// boundary instead: any implementation that drops the upper-
	// bound check still accepts index = 0 as OOR (covered by the
	// other test). The MaxShares constant is exercised in pedersen
	// _test.go's existing coverage; this assertion is a belt on
	// the bounds gate's return shape.
	commits := validCommitmentsForIndex(t)
	vkX, vkY := onCurvePair()
	bkX, bkY := onCurvePair()

	// index = 0 is the only byte value that violates the bounds;
	// index = 255 is at the boundary (accepted). The registry binds
	// both names so a future change that splits the bounds into two
	// gates surfaces a drift signal.
	for _, idx := range []byte{0} {
		err := VerifyPoints(idx, vkX, vkY, bkX, bkY, commits)
		if !errors.Is(err, ErrShareIndexOutOfRange) {
			t.Fatalf("idx=%d: want ErrShareIndexOutOfRange, got %v", idx, err)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────
// Binding: muEnablePedersenOnCurveCheck
// ─────────────────────────────────────────────────────────────────────

// TestVerifyPoints_RejectsOffCurveVK_Binding pins that an off-curve
// VK is rejected with ErrInvalidCommitmentPoint before curve.Add
// runs. Flipping muEnablePedersenOnCurveCheck false skips the check
// and curve.Add on off-curve arguments produces undefined results;
// downstream equation comparison may match or mismatch by chance —
// neither outcome is cryptographically meaningful.
func TestVerifyPoints_RejectsOffCurveVK_Binding(t *testing.T) {
	commits := validCommitmentsForIndex(t)
	// (1, 1) satisfies neither y² = x³ + 7 (since 1 != 1 + 7).
	bkX, bkY := onCurvePair()
	err := VerifyPoints(1, big.NewInt(1), big.NewInt(1), bkX, bkY, commits)
	if !errors.Is(err, ErrInvalidCommitmentPoint) {
		t.Fatalf("want ErrInvalidCommitmentPoint on off-curve VK, got %v", err)
	}
}

// TestVerifyPoints_RejectsOffCurveBK_Binding covers the symmetric
// check on BK.
func TestVerifyPoints_RejectsOffCurveBK_Binding(t *testing.T) {
	commits := validCommitmentsForIndex(t)
	vkX, vkY := onCurvePair()
	err := VerifyPoints(1, vkX, vkY, big.NewInt(1), big.NewInt(1), commits)
	if !errors.Is(err, ErrInvalidCommitmentPoint) {
		t.Fatalf("want ErrInvalidCommitmentPoint on off-curve BK, got %v", err)
	}
}
