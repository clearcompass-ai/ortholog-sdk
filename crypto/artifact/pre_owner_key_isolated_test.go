package artifact

import (
	"strings"
	"testing"
)

// TestPRE_DecryptFrags_RejectsOffCurveOwnerKey_Isolated closes the
// isolated-coverage gap documented on
// TestPRE_DecryptFrags_RejectsMalformedCFrags: this test builds a
// legitimately-verifying CFrag set (every gate 1–4 passes) and
// swaps in an off-curve pkOwner so only gateOwnerKeyValid can
// reject. Phase C Subgroup 5.1.3.
//
// With the gate enabled, PRE_DecryptFrags returns the specific
// "not on the secp256k1 curve" error before any ScalarMult runs on
// the off-curve coordinates. Without the gate, ScalarMult on an
// off-curve point is undefined behaviour; this test pins that the
// specific rejection path fires at this specific stage.
//
// Gate ordering sanity (from pre.go):
//
//  1. gateDecryptInputs         — cfrags non-nil, capsule non-nil
//  2. gateCommitmentsPresent    — commitments.Threshold() > 0
//  3. gateSufficientCFrags      — len(cfrags) >= threshold
//  4. gateAllCFragsVerify       — PRE_VerifyCFrag on each
//  5. gateOwnerKeyValid         — pkOwner parses + on-curve
//
// The test constructs (1)–(4) as valid so only (5) can fire.
func TestPRE_DecryptFrags_RejectsOffCurveOwnerKey_Isolated(t *testing.T) {
	g := buildTestGrant(t, 3, 5)
	cfrags := firstMCFrags(t, g)

	// Sanity: each CFrag verifies against the grant's commitments.
	// If this loop ever fails, the test's premise (gates 1–4 pass)
	// is broken and the assertion below is meaningless.
	for i, cf := range cfrags {
		if err := PRE_VerifyCFrag(cf, g.capsule, g.commitments); err != nil {
			t.Fatalf("precondition: cfrag %d does not verify: %v", i, err)
		}
	}

	// Swap in an off-curve pkOwner. offCurveUncompressed is the
	// 65-byte 0x04 || X=1 || Y=1 encoding — elliptic.Unmarshal
	// accepts the wire shape; IsOnCurve rejects the geometry.
	badOwner := offCurveUncompressed()

	skRecipient := g.recipient.sk

	_, err := PRE_DecryptFrags(
		skRecipient,
		cfrags,
		g.capsule,
		g.ciphertext,
		badOwner,
		g.commitments,
	)
	if err == nil {
		t.Fatal("PRE_DecryptFrags: expected rejection on off-curve owner key, got nil")
	}
	// gateOwnerKeyValid rejects with either of two messages depending
	// on which check fires first:
	//   - "invalid owner public key" — elliptic.Unmarshal returned nil
	//     (the stdlib's own on-curve validation rejected the wire
	//     encoding)
	//   - "not on the secp256k1 curve" — Unmarshal accepted but the
	//     belt-and-braces IsOnCurve check rejected (reachable for
	//     inputs that confuse Unmarshal but fail the pure equation)
	//
	// Both are inside gateOwnerKeyValid; either proves the gate is
	// load-bearing. Without the gate, ScalarMult would run on off-
	// curve coordinates with undefined results.
	msg := err.Error()
	if !strings.Contains(msg, "not on the secp256k1 curve") &&
		!strings.Contains(msg, "invalid owner public key") {
		t.Fatalf("want gateOwnerKeyValid rejection, got %q", msg)
	}
}
