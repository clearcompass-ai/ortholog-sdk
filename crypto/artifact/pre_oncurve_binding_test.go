package artifact

import (
	"errors"
	"math/big"
	"strings"
	"testing"
)

// TestPRE_VerifyCFrag_RejectsOffCurveVK_Binding is the binding
// test for muEnableOnCurveGate. Produces a structurally valid
// CFrag (passes gateCFragStructural) and then moves VK to
// coordinates that are NOT on secp256k1 ((1, 1) since y²=1 but
// x³+7=8). The on-curve gate's job is to reject early with a
// specific error: `ErrInvalidCFragFormat` wrapping the text
// "VK not on curve".
//
// Switch ON  → gateCFragOnCurve fires; error contains "VK not on curve".
// Switch OFF → gateCFragOnCurve is a no-op; DLEQ runs on off-curve
//              VK and fails with a different error (challenge
//              mismatch, not an on-curve rejection).
//
// The test asserts BOTH conditions: a non-nil error AND the
// specific "not on curve" substring. The second condition is what
// makes the switch mutation-audit-bound — it's the difference
// between "off-curve inputs are rejected by SOME gate" and
// "off-curve inputs are rejected by the on-curve gate
// specifically", which is exactly what the mutation audit must
// prove.
//
// Distinction from TestPRE_DecryptFrags_RejectsMalformedCFrags:
// that test supplies a zero-value CFrag whose nil fields fail the
// structural gate BEFORE the on-curve gate runs. This test passes
// structural by construction and isolates the on-curve check.
func TestPRE_VerifyCFrag_RejectsOffCurveVK_Binding(t *testing.T) {
	g := buildTestGrant(t, 3, 5)
	cf := produceCFrag(t, g.kfrags[0], g.capsule, g.commitments)

	cf.VKX = big.NewInt(1)
	cf.VKY = big.NewInt(1)

	err := PRE_VerifyCFrag(cf, g.capsule, g.commitments)
	if err == nil {
		t.Fatal("expected rejection for VK=(1,1), got nil")
	}
	if !errors.Is(err, ErrInvalidCFragFormat) {
		t.Fatalf("want ErrInvalidCFragFormat, got %v", err)
	}
	if !strings.Contains(err.Error(), "VK not on curve") {
		t.Fatalf("want on-curve-gate error message, got %q (muEnableOnCurveGate not load-bearing — a different gate caught the off-curve point)", err.Error())
	}
}

// TestPRE_VerifyCFrag_RejectsOffCurveEPrime_Binding is the
// corresponding binding test for the E' coordinate. Same
// specific-error-message discipline as the VK variant above.
func TestPRE_VerifyCFrag_RejectsOffCurveEPrime_Binding(t *testing.T) {
	g := buildTestGrant(t, 3, 5)
	cf := produceCFrag(t, g.kfrags[0], g.capsule, g.commitments)

	cf.EPrimeX = big.NewInt(1)
	cf.EPrimeY = big.NewInt(1)

	err := PRE_VerifyCFrag(cf, g.capsule, g.commitments)
	if err == nil {
		t.Fatal("expected rejection for E'=(1,1), got nil")
	}
	if !errors.Is(err, ErrInvalidCFragFormat) {
		t.Fatalf("want ErrInvalidCFragFormat, got %v", err)
	}
	if !strings.Contains(err.Error(), "E' not on curve") {
		t.Fatalf("want on-curve-gate error message, got %q (muEnableOnCurveGate not load-bearing)", err.Error())
	}
}
