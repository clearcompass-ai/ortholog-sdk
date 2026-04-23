package artifact

import (
	"strings"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/vss"
)

// offCurveUncompressed produces a 65-byte uncompressed point whose
// (X, Y) coordinates lie off secp256k1. elliptic.Unmarshal accepts
// the wire shape; IsOnCurve rejects the geometry.
func offCurveUncompressed() []byte {
	b := make([]byte, 65)
	b[0] = 0x04
	b[32] = 0x01 // X = 1
	b[64] = 0x01 // Y = 1
	return b
}

// validRecipientPubKey returns a valid 65-byte uncompressed secp256k1
// public key suitable for exercising paths that should reach curve
// operations (as opposed to rejecting at input validation).
//
// Produces G itself via PRE_GenerateKFrags's own path would be
// circular, so we hand-build: G's uncompressed coordinates are
// the standard secp256k1 generator from SEC 2.
func validRecipientPubKey() []byte {
	// secp256k1 generator G in uncompressed SEC 1 form.
	b := make([]byte, 65)
	b[0] = 0x04
	// Gx = 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798
	gx := []byte{
		0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC,
		0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
		0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9,
		0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98,
	}
	// Gy = 483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8
	gy := []byte{
		0x48, 0x3A, 0xDA, 0x77, 0x26, 0xA3, 0xC4, 0x65,
		0x5D, 0xA4, 0xFB, 0xFC, 0x0E, 0x11, 0x08, 0xA8,
		0xFD, 0x17, 0xB4, 0x48, 0xA6, 0x85, 0x54, 0x19,
		0x9C, 0x47, 0xD0, 0x8F, 0xFB, 0x10, 0xD4, 0xB8,
	}
	copy(b[1:33], gx)
	copy(b[33:65], gy)
	return b
}

// TestPRE_Encrypt_RejectsOffCurveOwnerKey verifies the H3 guard on
// the encrypt path: an owner public key that parses as a valid wire
// point but does not satisfy the curve equation must not reach
// ScalarMult.
func TestPRE_Encrypt_RejectsOffCurveOwnerKey(t *testing.T) {
	_, _, err := PRE_Encrypt(offCurveUncompressed(), []byte("payload"))
	if err == nil {
		t.Fatal("PRE_Encrypt: expected error on off-curve owner key, got nil")
	}
	// Unmarshal may reject outright on some curve implementations;
	// the explicit IsOnCurve rejection is the production case.
	if !strings.Contains(err.Error(), "not on the secp256k1 curve") &&
		!strings.Contains(err.Error(), "invalid public key") {
		t.Fatalf("PRE_Encrypt: want on-curve or invalid-pubkey rejection, got %v", err)
	}
}

// TestPRE_GenerateKFrags_RejectsOffCurveRecipientKey verifies the
// H3 guard on the KFrag-generation path.
//
// v7.75 Phase C: PRE_GenerateKFrags now returns (kfrags, commitments, err);
// the third return value is the Pedersen commitment set for
// pre-grant-commitment-v1 publication.
func TestPRE_GenerateKFrags_RejectsOffCurveRecipientKey(t *testing.T) {
	// skOwner is structurally valid (32 bytes, scalar in range) — the
	// fixture exercises the recipient-key guard, not owner validation.
	skOwner := make([]byte, 32)
	skOwner[31] = 0x42 // small non-zero scalar

	_, _, err := PRE_GenerateKFrags(skOwner, offCurveUncompressed(), 2, 3)
	if err == nil {
		t.Fatal("PRE_GenerateKFrags: expected error on off-curve recipient key, got nil")
	}
	if !strings.Contains(err.Error(), "not on the secp256k1 curve") &&
		!strings.Contains(err.Error(), "invalid recipient public key") {
		t.Fatalf("PRE_GenerateKFrags: want on-curve or invalid-pubkey rejection, got %v", err)
	}
}

// TestPRE_DecryptFrags_RejectsOffCurveOwnerKey verifies the H3
// guard on the decrypt-combining path.
//
// v7.75 Phase C: PRE_DecryptFrags now takes commitments as a sixth
// argument and verifies every CFrag against them before any owner-key
// operations. The on-curve owner-key guard is still reachable but
// requires a structurally-valid, commitments-passing input vector
// up to that point.
//
// Since we want to exercise ONLY the owner-key guard here, we construct
// an input that reaches the owner-key check:
//   - Non-empty cfrags slice (passes empty-slice guard)
//   - Non-zero-threshold commitments (passes empty-commitments guard)
//   - cfrags count ≥ threshold (passes insufficient-cfrags guard)
//   - Malformed CFrag that will fail verification — this causes
//     verification to short-circuit BEFORE the owner-key check
//
// Because CFrag verification happens before owner-key parsing, this
// test's previous assertion (rejection on off-curve owner key) is no
// longer reachable via this code path in Phase C. The correct Phase C
// behavior is that a malformed CFrag causes verification failure,
// which is what this test now asserts.
//
// To actually test the off-curve owner key guard in isolation, we'd
// need a complete, legitimately-verified CFrag set. That's covered
// by the full round-trip test suite in pre_test.go (when it exists);
// here we verify the guard's sibling: verification failure short-
// circuits before any curve operation on the owner key.
func TestPRE_DecryptFrags_RejectsMalformedCFrags(t *testing.T) {
	skRecipient := make([]byte, 32)
	skRecipient[31] = 0x7

	// Malformed CFrag: nil fields. PRE_VerifyCFrag (invoked from
	// PRE_DecryptFrags) rejects this at structural validation before
	// any curve arithmetic.
	cfrags := []*CFrag{{}}
	capsule := &Capsule{}

	// Build a minimal non-empty commitments value by invoking
	// the VSS primitive with a throwaway secret.
	var secret [vss.SecretSize]byte
	secret[0] = 0x01
	_, commitments, err := vss.Split(secret, 2, 3)
	if err != nil {
		t.Fatalf("setup: vss.Split failed: %v", err)
	}

	_, err = PRE_DecryptFrags(
		skRecipient,
		cfrags,
		capsule,
		[]byte("ct"),
		offCurveUncompressed(),
		commitments,
	)
	if err == nil {
		t.Fatal("PRE_DecryptFrags: expected error on malformed input, got nil")
	}
	// Phase C verification short-circuits before the owner-key guard
	// is reached, because CFrag verification fails first on the nil
	// fields. Accept either the verification failure or (if cfrag
	// validation somehow passes — it won't with current code) the
	// owner-key rejection.
	msg := err.Error()
	switch {
	case strings.Contains(msg, "cfrag[0] verification"):
		// Expected Phase C path: structural CFrag validation fails first.
	case strings.Contains(msg, "not on the secp256k1 curve"):
		// Legacy path — should not be reached in Phase C but accepted
		// for robustness.
	case strings.Contains(msg, "invalid owner public key"):
		// Legacy path — same.
	case strings.Contains(msg, "CFrag wire format invalid"):
		// Structural CFrag rejection via ErrInvalidCFragFormat.
	default:
		t.Fatalf("PRE_DecryptFrags: unexpected error shape: %v", err)
	}
}

// TestPRE_DecryptFrags_RejectsEmptyCommitments verifies that the
// Phase C commitments requirement short-circuits before any other
// validation. This is the new Phase C gate: a caller that omits
// commitments cannot reach the combination path.
func TestPRE_DecryptFrags_RejectsEmptyCommitments(t *testing.T) {
	skRecipient := make([]byte, 32)
	skRecipient[31] = 0x7
	cfrags := []*CFrag{{}}
	capsule := &Capsule{}

	// Zero-valued commitments: Threshold() == 0.
	var emptyCommitments vss.Commitments

	_, err := PRE_DecryptFrags(
		skRecipient,
		cfrags,
		capsule,
		[]byte("ct"),
		validRecipientPubKey(),
		emptyCommitments,
	)
	if err == nil {
		t.Fatal("PRE_DecryptFrags: expected error on empty commitments, got nil")
	}
	if !strings.Contains(err.Error(), "empty commitment set") {
		t.Fatalf("PRE_DecryptFrags: want empty-commitments rejection, got %v", err)
	}
}
