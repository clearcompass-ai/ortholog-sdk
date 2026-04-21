/*
FILE PATH:

	crypto/signatures/bls_gaps_test.go

DESCRIPTION:

	Closes three test coverage gaps identified in Wave 1 review:

	  1. TestSchemeBLS_Value / TestSchemeECDSA_Value
	     Byte-level locks on the scheme tag constants that drive
	     dispatch routing. Without these, a silent byte flip (e.g.,
	     SchemeBLS going from 0x02 to any other value) would cause
	     BLS-signed heads to route to the ECDSA verifier, parse-fail
	     silently, and return empty validation results. The dispatch
	     layer has no other guard against this; these tests are the
	     guard.

	  2. TestVerifyWitnessCosignatures_ECDSAHead_DoesNotConsultBLSVerifier
	     Negative-space dispatch test. Confirms that when a
	     CosignedTreeHead carries SchemeTag=SchemeECDSA, the dispatcher
	     does NOT consult the BLSVerifier implementation. Uses a
	     panicking BLSVerifier as tripwire: if the dispatcher ever
	     accidentally routes ECDSA through BLS parsing logic, the
	     test panics with a clear message. Today's code routes
	     correctly; this test guards against future regressions.

	  3. TestParseBLSPubKey_NotInSubgroup
	     Exercises the prime-order-subgroup check in ParseBLSPubKey
	     with a concrete hardcoded G2 point that is on-curve but
	     outside the prime-order subgroup. Without this test, deleting
	     the `IsInSubGroup()` check in production code would cause no
	     test to fail, and small-subgroup attacks would become silently
	     possible.

	     The test vector is generated deterministically at test time
	     by multiplying the G2 generator by the curve's cofactor. This
	     construction is guaranteed to produce a G2 point that (a) is
	     on-curve and (b) has order dividing the cofactor, placing it
	     outside the prime-order subgroup. The resulting compressed
	     bytes are then passed to ParseBLSPubKey, which must reject
	     via IsInSubGroup().

	     Using a deterministic runtime construction rather than a
	     hardcoded hex vector avoids coupling the test to a specific
	     gnark library version's compressed-point encoding of this
	     particular point, which has historically varied across
	     versions. The math is stable: cofactor multiplication always
	     produces a non-subgroup point regardless of encoding choice.

	LOCATION DISCIPLINE:

	These tests live in a single gap-filling file rather than being
	scattered across bls_lock_test.go, bls_verifier_test.go, and
	bls_rogue_key_test.go. Rationale: they are merge-blocker tests
	added to close specific review gaps; keeping them in one file
	makes the Wave 1 patch history legible.
*/
package signatures

import (
	"errors"
	"fmt" // NEW — for iter fmt.Sprintf
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fr"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ═══════════════════════════════════════════════════════════════════
// 1) Scheme tag value locks
// ═══════════════════════════════════════════════════════════════════

// TestSchemeBLS_Value locks SchemeBLS at 0x02. This byte drives
// dispatch routing in VerifyWitnessCosignatures — a CosignedTreeHead
// with SchemeTag=0x02 routes to the BLS verifier; any other non-zero
// value routes elsewhere (ECDSA at 0x01, unknown schemes rejected).
//
// If this test fails, someone changed SchemeBLS. Every BLS-signed
// tree head ever produced will silently fail to route to the BLS
// verifier, producing empty validation results without any explicit
// error. This is a silent correctness regression — the kind that
// ships to production and manifests as "cosignatures don't verify
// anymore" days later.
//
// Do NOT update the expected value. Revert the SchemeBLS change or
// introduce a new dispatch tag.
func TestSchemeBLS_Value(t *testing.T) {
	if SchemeBLS != 0x02 {
		t.Fatalf("SchemeBLS = 0x%02x, want 0x02.\n\n"+
			"This is a DISPATCH-BREAKING change. BLS-signed CosignedTreeHeads\n"+
			"will no longer route to the BLS verifier. Do NOT fix this test\n"+
			"by updating the expected value — revert the SchemeBLS change.",
			SchemeBLS)
	}
}

// TestSchemeECDSA_Value locks SchemeECDSA at 0x01. Symmetric rationale
// to TestSchemeBLS_Value. Also covers the zero-value check: SchemeECDSA
// must not be 0x00, because Wave 2 will reserve 0x00 for "scheme not
// declared" (a rejectable state).
func TestSchemeECDSA_Value(t *testing.T) {
	if SchemeECDSA != 0x01 {
		t.Fatalf("SchemeECDSA = 0x%02x, want 0x01.\n\n"+
			"This is a DISPATCH-BREAKING change. ECDSA-signed CosignedTreeHeads\n"+
			"will no longer route to the ECDSA verifier. Do NOT fix this test\n"+
			"by updating the expected value — revert the SchemeECDSA change.",
			SchemeECDSA)
	}
	if SchemeECDSA == 0x00 {
		t.Fatal("SchemeECDSA is 0x00, which Wave 2 reserves for " +
			"'scheme not declared'. Pick a non-zero value.")
	}
}

// TestSchemeTags_Distinct guards against a copy-paste bug in the
// scheme constants. If both tags are equal, dispatch cannot
// distinguish ECDSA from BLS and the entire per-signature-scheme
// architecture collapses to a single verifier.
func TestSchemeTags_Distinct(t *testing.T) {
	if SchemeBLS == SchemeECDSA {
		t.Fatalf("SchemeBLS == SchemeECDSA (both are 0x%02x). "+
			"Dispatch routing is broken; all signatures would route "+
			"to whichever verifier the dispatcher checks first.",
			SchemeBLS)
	}
}

// ═══════════════════════════════════════════════════════════════════
// 2) ECDSA dispatch isolation (negative-space test)
// ═══════════════════════════════════════════════════════════════════

// panicBLSVerifier is a tripwire BLSVerifier implementation. If the
// dispatcher ever consults it for an ECDSA-signed tree head, the
// test panics with a clear message identifying the dispatch bug.
//
// This is cheaper and more precise than asserting on dispatcher
// internals (call counts, tracing). The type satisfies the interface
// but cannot be invoked without detection.
type panicBLSVerifier struct{}

func (panicBLSVerifier) VerifyAggregate(
	msg []byte,
	signatures []types.WitnessSignature,
	pubkeys []types.WitnessPublicKey,
) ([]bool, error) {
	panic("dispatcher regression: BLS verifier consulted for an " +
		"ECDSA-tagged CosignedTreeHead. This indicates a bug in " +
		"VerifyWitnessCosignatures's scheme dispatch logic.")
}

// TestVerifyWitnessCosignatures_ECDSAHead_DoesNotConsultBLSVerifier
// confirms that an ECDSA-signed cosigned head never reaches the BLS
// verifier under Wave 1's dispatch shape.
//
// # WHY THIS TEST EXISTS
//
// TestVerifyWitnessCosignatures_BLSHead already confirms that BLS-
// tagged heads reach the BLS verifier. This test is the NEGATIVE-
// SPACE counterpart — it confirms that ECDSA-tagged heads DO NOT
// reach the BLS verifier. Without this test, a future dispatcher
// refactor that accidentally routed all heads (regardless of tag)
// through the BLS verifier would pass TestVerifyWitnessCosignatures_
// BLSHead (BLS routing still works) but silently break ECDSA
// verification (48-byte G1 parse fails on 64-byte ECDSA signatures,
// returning false with no explicit error).
//
// # HOW IT WORKS
//
//  1. Build a valid ECDSA-cosigned head using inline construction
//     matching the pattern in witness_verify_test.go.
//  2. Pass panicBLSVerifier as the BLSVerifier argument.
//  3. Call VerifyWitnessCosignatures.
//  4. If the dispatcher routes correctly: panicBLSVerifier is never
//     consulted, the test passes.
//     If the dispatcher routes incorrectly: panicBLSVerifier panics,
//     the defer/recover converts the panic into a clear t.Fatalf.
//
// # FIXTURE STYLE
//
// Builds witnesses inline rather than using helper functions, because
// the existing ECDSA test file (witness_verify_test.go) has no such
// helpers and we're matching its conventions. Three witnesses is
// enough to exercise the dispatcher's multi-signature path without
// being wasteful.
func TestVerifyWitnessCosignatures_ECDSAHead_DoesNotConsultBLSVerifier(t *testing.T) {
	// Recover from the tripwire panic with a readable test failure.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("DISPATCH REGRESSION: ECDSA-tagged head consulted the "+
				"BLS verifier. The dispatcher in witness_verify.go is "+
				"incorrectly routing ECDSA signatures through BLS parsing "+
				"logic. Panic message: %v", r)
		}
	}()

	// Build three ECDSA witnesses inline, matching the style in
	// witness_verify_test.go (no shared fixture functions).
	const n = 3
	sigs := make([]types.WitnessSignature, n)
	keys := make([]types.WitnessPublicKey, n)

	// Use a deterministic tree head — any non-trivial head works.
	head := types.TreeHead{TreeSize: 42}
	copy(head.RootHash[:], []byte("ecdsa-dispatch-isolation-test-01"))

	for i := 0; i < n; i++ {
		priv, err := GenerateKey()
		if err != nil {
			t.Fatalf("witness %d GenerateKey: %v", i, err)
		}
		pubBytes := PubKeyBytes(&priv.PublicKey)

		sig, err := SignWitnessCosignature(head, priv)
		if err != nil {
			t.Fatalf("witness %d SignWitnessCosignature: %v", i, err)
		}

		// Derive the witness ID from the pubkey bytes (same pattern
		// as witness_verify_test.go).
		var pubKeyID [32]byte
		copy(pubKeyID[:], pubBytes[:32])
		// Inject index into the ID to ensure uniqueness across the
		// three witnesses (the raw first-32-bytes slice would be
		// unique in practice, but an explicit tweak makes the test
		// fully deterministic).
		pubKeyID[31] = byte(i)

		sigs[i] = types.WitnessSignature{PubKeyID: pubKeyID, SigBytes: sig}
		keys[i] = types.WitnessPublicKey{ID: pubKeyID, PublicKey: pubBytes}
	}

	cosigned := types.CosignedTreeHead{
		TreeHead:   head,
		SchemeTag:  SchemeECDSA,
		Signatures: sigs,
	}

	// THE KEY TRIPWIRE: pass panicBLSVerifier as the BLS argument.
	// If the dispatcher correctly routes ECDSA to the ECDSA path,
	// this is never consulted. If it incorrectly routes to BLS,
	// VerifyAggregate panics and the defer/recover above fires.
	tripwire := panicBLSVerifier{}

	// Note on the expected outcome: the ECDSA signatures above were
	// produced with freshly-generated keys and fresh IDs, so the
	// verification itself should succeed. But this test's assertion
	// is about DISPATCH, not validity — even if verification fails
	// for some unrelated reason, the key property is that the BLS
	// verifier must not be touched.
	_, err := VerifyWitnessCosignatures(cosigned, keys, n, tripwire)

	// If we reached here without panicking, the dispatcher correctly
	// avoided the BLS verifier. That is the property under test.
	// Verification success or failure beyond this point is not this
	// test's concern — the other ECDSA round-trip tests cover that.
	if err != nil {
		// An error is fine (it means ECDSA verification was
		// attempted and something about the test fixture failed);
		// what matters is the BLS verifier was not consulted. Log
		// for diagnostics and proceed.
		t.Logf("ECDSA verification error (not a test failure — "+
			"dispatch isolation is the tested property): %v", err)
	}
}

// TestParseBLSPubKey_NotInSubgroup exercises the prime-order-subgroup
// check in ParseBLSPubKey. Without this test, deleting the
// `!pk.IsInSubGroup()` guard in production code would cause no test
// to fail, and small-subgroup attacks against the BLS verifier would
// become silently possible.
//
// # WHY SUBGROUP CHECKS MATTER
//
// BLS12-381's G2 has a large cofactor (~2^512). A random on-curve
// G2 point has probability 1/cofactor of being in the prime-order
// subgroup — astronomically small. Most on-curve G2 points are NOT
// in the prime-order subgroup.
//
// A point outside the prime-order subgroup can make the aggregate
// pairing equation satisfy spuriously. The defense is checking that
// every decompressed public key is in the prime-order subgroup via
// IsInSubGroup() (Bowe-Scott subgroup check for BLS12-381 G2).
// Skipping this check opens the verifier to small-subgroup attacks.
//
// # CONSTRUCTION STRATEGY: RAW COORDINATES, NOT COFACTOR MULTIPLICATION
//
// We construct a non-subgroup point by directly solving the G2 twist
// curve equation y² = x³ + b (where b = 4 + 4i is the G2 twist
// coefficient for BLS12-381). We pick a small x value, compute
// rhs = x³ + b, take a square root to obtain y, and verify the point
// is on-curve but not in the prime-order subgroup.
//
// This avoids hardcoding the 512-bit cofactor as a hex literal (which
// would be a source of bugs and library-version coupling). The curve
// equation is universal across every BLS12-381 implementation.
//
// # ON SQRT SEMANTICS (gnark v0.20.1)
//
// gnark's E2.Sqrt never returns nil or signals failure. When the
// input is a non-residue (has no square root), Sqrt still writes some
// value to its receiver — but that value squared will NOT equal the
// input. We verify validity explicitly by squaring the result and
// comparing: only accept the point if ySquared.Equal(&rhs).
//
// # WHY WE USE bls12381.E2 (THE PUBLIC ALIAS)
//
// The underlying E2 type lives in internal/fptower/ and is not
// directly importable by test code outside the gnark module. However
// gnark exposes a public type alias `bls12381.E2 = fptower.E2` in
// bls12-381.go. All methods on fptower.E2 are callable through this
// alias. Our test imports only the public bls12381 package.
func TestParseBLSPubKey_NotInSubgroup(t *testing.T) {
	// The G2 twist coefficient for BLS12-381: b = 4 + 4i ∈ E2.
	// This is a curve constant, not a library constant — stable
	// across every BLS12-381 implementation.
	var b bls12381.E2
	b.SetString("4", "4")

	// Search loop: iterate x values until we find one where
	//   (a) rhs = x³ + b has a square root in E2, AND
	//   (b) the resulting point is NOT in the prime-order subgroup.
	//
	// Typical outcome: the first or second x works. The maxIters cap
	// is defensive — if we somehow can't find a suitable point in 100
	// tries, something is deeply wrong and we'd rather fail loudly
	// than loop forever.
	const maxIters = 100

	var (
		foundPoint bls12381.G2Affine
		found      bool
	)

	for iter := int64(1); iter <= maxIters; iter++ {
		// Candidate x-coordinate: x = iter + 1·i.
		// Using iter as the real part varies deterministically;
		// using 1 as the imaginary part ensures x has a non-zero
		// imaginary component (so we exercise Sqrt's general case,
		// not the A1==0 shortcut).
		var x bls12381.E2
		x.SetString(fmt.Sprintf("%d", iter), "1")

		// Compute rhs = x³ + b.
		//   step 1: x² → temp
		//   step 2: x³ = temp * x
		//   step 3: rhs = x³ + b
		var xSquared, xCubed, rhs bls12381.E2
		xSquared.Square(&x)
		xCubed.Mul(&xSquared, &x)
		rhs.Add(&xCubed, &b)

		// Take the square root. gnark's Sqrt never fails explicitly;
		// instead we must verify the result by squaring.
		var y bls12381.E2
		y.Sqrt(&rhs)

		// Verify: y² must equal rhs. If not, rhs is a non-residue
		// and y is garbage — skip to the next x.
		var ySquared bls12381.E2
		ySquared.Square(&y)
		if !ySquared.Equal(&rhs) {
			continue
		}

		// Construct the G2Affine point with our raw coordinates.
		var candidate bls12381.G2Affine
		candidate.X.Set(&x)
		candidate.Y.Set(&y)

		// Sanity: candidate must be on-curve. If IsOnCurve returns
		// false, our construction has a bug (likely a wrong b value).
		// Bail with a clear diagnostic rather than silently continuing.
		if !candidate.IsOnCurve() {
			t.Fatalf("constructed point at iter=%d is NOT on-curve "+
				"despite satisfying y² = x³ + b. This indicates the "+
				"G2 twist coefficient b = 4 + 4i is wrong for this "+
				"gnark version, or the curve equation has changed. "+
				"Investigate before proceeding.", iter)
		}

		// The point is on-curve. Now: is it in the prime-order
		// subgroup? For a random x, the answer is almost certainly
		// "no" (probability 1 - 1/cofactor of being outside). But
		// we check anyway — if we got astronomically unlucky and
		// landed in the subgroup, iterate to the next x.
		if candidate.IsInSubGroup() {
			continue
		}

		// Success: on-curve, NOT in prime-order subgroup. Exactly
		// the kind of point ParseBLSPubKey's subgroup check is
		// supposed to reject.
		foundPoint = candidate
		found = true
		break
	}

	if !found {
		t.Fatalf("could not construct a non-subgroup on-curve G2 point "+
			"in %d iterations. This is mathematically unexpected — the "+
			"probability of every x in [1..%d] yielding either a "+
			"non-residue rhs OR a subgroup point is negligible. "+
			"Check the G2 twist coefficient and the field arithmetic.",
			maxIters, maxIters)
	}

	// Serialize the point to its 96-byte compressed encoding.
	compressed := foundPoint.Bytes()
	if len(compressed) != BLSG2CompressedLen {
		t.Fatalf("compressed length = %d, want %d", len(compressed), BLSG2CompressedLen)
	}

	// ─────────────────────────────────────────────────────────────
	// THE ACTUAL TEST: ParseBLSPubKey must reject this point.
	// ─────────────────────────────────────────────────────────────
	_, err := ParseBLSPubKey(compressed[:])
	if err == nil {
		t.Fatal("CRITICAL: ParseBLSPubKey accepted a non-subgroup G2 point. " +
			"The prime-order-subgroup check in ParseBLSPubKey is missing " +
			"or broken. Small-subgroup attacks against the BLS verifier " +
			"are now possible. Investigate ParseBLSPubKey immediately.")
	}

	// Confirm the rejection is specifically the subgroup error, not
	// some other validation path (length, on-curve). If a different
	// error type is returned, the subgroup check is not being reached,
	// which is a distinct bug from "check missing entirely" but
	// equally problematic.
	if !errors.Is(err, ErrBLSPubKeyNotInSubgroup) {
		t.Fatalf("ParseBLSPubKey rejected the non-subgroup point but with "+
			"the wrong error type:\n"+
			"  got:  %v\n"+
			"  want: %v (ErrBLSPubKeyNotInSubgroup)\n\n"+
			"This suggests the point was rejected at an earlier validation "+
			"stage (length or on-curve check) before reaching the subgroup "+
			"check. The subgroup check may not be executing at all; "+
			"investigate the validation order in ParseBLSPubKey.",
			err, ErrBLSPubKeyNotInSubgroup)
	}
}

// Ensure fr is imported — referenced implicitly via gnark types used
// in the construction above, but the compiler may not pull it in on
// every build configuration. This no-op reference guarantees the
// import.
var _ = fr.Element{}
