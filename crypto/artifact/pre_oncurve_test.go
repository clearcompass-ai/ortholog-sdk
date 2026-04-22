package artifact

import (
	"strings"
	"testing"
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
func TestPRE_GenerateKFrags_RejectsOffCurveRecipientKey(t *testing.T) {
	// skOwner is structurally valid (32 bytes, scalar in range) — the
	// fixture exercises the recipient-key guard, not owner validation.
	skOwner := make([]byte, 32)
	skOwner[31] = 0x42 // small non-zero scalar

	_, err := PRE_GenerateKFrags(skOwner, offCurveUncompressed(), 2, 3)
	if err == nil {
		t.Fatal("PRE_GenerateKFrags: expected error on off-curve recipient key, got nil")
	}
	if !strings.Contains(err.Error(), "not on the secp256k1 curve") &&
		!strings.Contains(err.Error(), "invalid recipient public key") {
		t.Fatalf("PRE_GenerateKFrags: want on-curve or invalid-pubkey rejection, got %v", err)
	}
}

// TestPRE_DecryptFrags_RejectsOffCurveOwnerKey verifies the H3
// guard on the decrypt-combining path. The CFrag slice and capsule
// are never dereferenced: the owner-key check short-circuits earlier.
func TestPRE_DecryptFrags_RejectsOffCurveOwnerKey(t *testing.T) {
	skRecipient := make([]byte, 32)
	skRecipient[31] = 0x7
	// At least one CFrag is required to pass the early empty-slice guard.
	cfrags := []*CFrag{{}}
	capsule := &Capsule{}

	_, err := PRE_DecryptFrags(skRecipient, cfrags, capsule, []byte("ct"), offCurveUncompressed())
	if err == nil {
		t.Fatal("PRE_DecryptFrags: expected error on off-curve owner key, got nil")
	}
	if !strings.Contains(err.Error(), "not on the secp256k1 curve") &&
		!strings.Contains(err.Error(), "invalid owner public key") {
		t.Fatalf("PRE_DecryptFrags: want on-curve or invalid-pubkey rejection, got %v", err)
	}
}
