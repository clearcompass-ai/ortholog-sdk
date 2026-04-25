// Package signatures — entry_verify_binding_test.go holds the
// binding tests for the three mutation-audit switches in
// entry_verify_mutation_switches.go. See
// crypto/signatures/entry_verify.mutation-audit.yaml for the
// registry.
package signatures

import (
	"crypto/sha256"
	"errors"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────
// Binding: muEnableEntrySignatureVerify
// ─────────────────────────────────────────────────────────────────────

// TestVerifyEntry_RejectsBadSignature_Binding pins that VerifyEntry
// rejects a tampered signature with ErrSignatureVerificationFailed.
// With the gate on, ecdsa.Verify catches the corruption. With the
// gate off, the verify step is bypassed and the function returns
// nil — silently accepting a forged signature.
func TestVerifyEntry_RejectsBadSignature_Binding(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	hash := sha256.Sum256([]byte("entry payload"))
	sig, err := SignEntry(hash, priv)
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}
	// Tamper with the signature: flip a byte in the R component.
	sig[0] ^= 0xFF

	err = VerifyEntry(hash, sig, &priv.PublicKey)
	if !errors.Is(err, ErrSignatureVerificationFailed) {
		t.Fatalf("want ErrSignatureVerificationFailed, got %v (muEnableEntrySignatureVerify not load-bearing?)", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Binding: muEnablePubKeyOnCurve
// ─────────────────────────────────────────────────────────────────────

// TestParsePubKey_RejectsOffCurve_Binding pins that ParsePubKey
// rejects a 65-byte sequence whose (X, Y) does not satisfy the
// secp256k1 equation. With the gate on, the wrapped parse error
// from secp256k1.ParsePubKey surfaces. With the gate off, the
// error is suppressed and the function returns (nil, nil) —
// downstream consumers nil-deref or silently fail closed.
func TestParsePubKey_RejectsOffCurve_Binding(t *testing.T) {
	// 65-byte uncompressed encoding (0x04 || X || Y) where (1, 1)
	// is not on secp256k1 (y² = 1 != 1³ + 7).
	offCurve := make([]byte, 65)
	offCurve[0] = 0x04
	offCurve[32] = 0x01 // X = 1
	offCurve[64] = 0x01 // Y = 1

	pk, err := ParsePubKey(offCurve)
	if err == nil {
		t.Fatalf("ParsePubKey accepted off-curve key (pk=%v); muEnablePubKeyOnCurve not load-bearing?", pk)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Binding: muEnableSignatureLength
// ─────────────────────────────────────────────────────────────────────

// TestVerifyEntry_RejectsBadLength_Binding pins that VerifyEntry
// rejects a signature whose length is not 64 with
// ErrInvalidRawSignatureLength. With the gate off, the length
// check is bypassed and the function attempts ecdsa.Verify on a
// padded/truncated decoding — semantics ECDSA does not specify.
func TestVerifyEntry_RejectsBadLength_Binding(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	hash := sha256.Sum256([]byte("entry payload"))

	// 63 bytes — too short.
	short := make([]byte, 63)
	short[0] = 0x01 // non-zero R MSB so we don't trip ErrZeroSignatureComponent first
	short[31] = 0x01
	err = VerifyEntry(hash, short, &priv.PublicKey)
	if !errors.Is(err, ErrInvalidRawSignatureLength) {
		t.Fatalf("63-byte sig: want ErrInvalidRawSignatureLength, got %v", err)
	}

	// 65 bytes — too long.
	long := make([]byte, 65)
	long[0] = 0x01
	long[31] = 0x01
	err = VerifyEntry(hash, long, &priv.PublicKey)
	if !errors.Is(err, ErrInvalidRawSignatureLength) {
		t.Fatalf("65-byte sig: want ErrInvalidRawSignatureLength, got %v", err)
	}
}
