// Package lifecycle — delegation_key_test.go tests the artifact-scoped
// delegation key mechanism. The structural property under test:
//
//	The Master Identity Key NEVER touches PRE crypto. Only a derived
//	ephemeral sk_del does. If a recipient and M proxies collude, they
//	extract sk_del (disposable, single-artifact scope) — not sk_owner.
package lifecycle

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"math/big"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/escrow"
	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// -------------------------------------------------------------------------------------------------
// GenerateDelegationKey — argument validation
// -------------------------------------------------------------------------------------------------

func TestGenerateDelegationKey_RejectsEmptyOwnerPubKey(t *testing.T) {
	_, _, err := GenerateDelegationKey(nil)
	if err == nil {
		t.Fatal("expected error for nil owner pubkey, got nil")
	}
}

func TestGenerateDelegationKey_RejectsMalformedOwnerPubKey(t *testing.T) {
	_, _, err := GenerateDelegationKey([]byte{0x01, 0x02, 0x03})
	if err == nil {
		t.Fatal("expected error for malformed owner pubkey, got nil")
	}
}

// -------------------------------------------------------------------------------------------------
// GenerateDelegationKey — output shape
// -------------------------------------------------------------------------------------------------

func TestGenerateDelegationKey_PkDelIs65ByteUncompressed(t *testing.T) {
	ownerPub, _ := freshUncompressedPubKey(t)
	pkDel, _, err := GenerateDelegationKey(ownerPub)
	if err != nil {
		t.Fatalf("GenerateDelegationKey: %v", err)
	}
	if len(pkDel) != 65 {
		t.Fatalf("len(pkDel) = %d, want 65", len(pkDel))
	}
	if pkDel[0] != 0x04 {
		t.Fatalf("pkDel[0] = 0x%02x, want 0x04 (uncompressed prefix)", pkDel[0])
	}
}

func TestGenerateDelegationKey_PkDelIsOnCurve(t *testing.T) {
	ownerPub, _ := freshUncompressedPubKey(t)
	pkDel, _, err := GenerateDelegationKey(ownerPub)
	if err != nil {
		t.Fatalf("GenerateDelegationKey: %v", err)
	}
	c := secp256k1.S256()
	x, y := elliptic.Unmarshal(c, pkDel)
	if x == nil {
		t.Fatal("pkDel does not decode to a valid point")
	}
	if !c.IsOnCurve(x, y) {
		t.Fatal("pkDel decodes but is not on the secp256k1 curve")
	}
}

func TestGenerateDelegationKey_WrappedSkDelHasECIESOverhead(t *testing.T) {
	ownerPub, _ := freshUncompressedPubKey(t)
	_, wrapped, err := GenerateDelegationKey(ownerPub)
	if err != nil {
		t.Fatalf("GenerateDelegationKey: %v", err)
	}
	// ECIES wrapping a 32-byte skDel: 65 (eph pubkey) + 12 (nonce) +
	// 32 (ciphertext) + 16 (GCM tag) = 125 bytes.
	if len(wrapped) < 93 {
		t.Fatalf("wrappedSkDel len = %d, want >= 93 (ECIES minimum overhead)", len(wrapped))
	}
}

// -------------------------------------------------------------------------------------------------
// UnwrapDelegationKey — argument validation
// -------------------------------------------------------------------------------------------------

func TestUnwrapDelegationKey_RejectsWrongOwnerKeyLength(t *testing.T) {
	_, err := UnwrapDelegationKey([]byte("any"), make([]byte, 31))
	if err == nil {
		t.Fatal("expected error for 31-byte owner key, got nil")
	}
}

func TestUnwrapDelegationKey_RejectsZeroScalar(t *testing.T) {
	_, err := UnwrapDelegationKey([]byte("any"), make([]byte, 32))
	if err == nil {
		t.Fatal("expected error for zero owner scalar, got nil")
	}
}

func TestUnwrapDelegationKey_RejectsScalarEqualToN(t *testing.T) {
	n := secp256k1.S256().Params().N
	badScalar := make([]byte, 32)
	nBytes := n.Bytes()
	copy(badScalar[32-len(nBytes):], nBytes)
	_, err := UnwrapDelegationKey([]byte("any"), badScalar)
	if err == nil {
		t.Fatal("expected error for scalar == N, got nil")
	}
}

// -------------------------------------------------------------------------------------------------
// Round-trip: Generate → Unwrap
// -------------------------------------------------------------------------------------------------

func TestDelegationKey_RoundTrip(t *testing.T) {
	ownerPubBytes, ownerPriv := freshUncompressedPubKey(t)

	pkDel, wrapped, err := GenerateDelegationKey(ownerPubBytes)
	if err != nil {
		t.Fatalf("GenerateDelegationKey: %v", err)
	}

	ownerScalar := padScalarTo32(ownerPriv.D)
	skDel, err := UnwrapDelegationKey(wrapped, ownerScalar)
	if err != nil {
		t.Fatalf("UnwrapDelegationKey: %v", err)
	}
	if len(skDel) != 32 {
		t.Fatalf("skDel len = %d, want 32", len(skDel))
	}

	// skDel * G must equal pkDel (confirms the returned scalar IS the
	// private counterpart of the published pkDel).
	c := secp256k1.S256()
	gotX, gotY := c.ScalarBaseMult(skDel)
	pkDelX, pkDelY := elliptic.Unmarshal(c, pkDel)
	if pkDelX == nil {
		t.Fatal("pkDel does not decode")
	}
	if gotX.Cmp(pkDelX) != 0 || gotY.Cmp(pkDelY) != 0 {
		t.Fatal("skDel * G != pkDel — round-trip produced the wrong scalar")
	}
}

// -------------------------------------------------------------------------------------------------
// Anti-collusion structural property
// -------------------------------------------------------------------------------------------------

// TestDelegationKey_SkDelIsNotSkOwner asserts the core structural fix:
// the delegation private key is a fresh ephemeral scalar, NOT the owner's
// master private key. Any collusion that leaks sk_del must not leak
// sk_owner. If this test fails, the anti-collusion design is broken.
func TestDelegationKey_SkDelIsNotSkOwner(t *testing.T) {
	ownerPubBytes, ownerPriv := freshUncompressedPubKey(t)

	_, wrapped, err := GenerateDelegationKey(ownerPubBytes)
	if err != nil {
		t.Fatalf("GenerateDelegationKey: %v", err)
	}

	ownerScalar := padScalarTo32(ownerPriv.D)
	skDel, err := UnwrapDelegationKey(wrapped, ownerScalar)
	if err != nil {
		t.Fatalf("UnwrapDelegationKey: %v", err)
	}

	if bytes.Equal(skDel, ownerScalar) {
		t.Fatal("sk_del == sk_owner — collusion-key-extraction fix is broken")
	}
}

// -------------------------------------------------------------------------------------------------
// Wrong-key unwrap
// -------------------------------------------------------------------------------------------------

func TestUnwrapDelegationKey_RejectsWrongOwnerKey(t *testing.T) {
	alicePubBytes, _ := freshUncompressedPubKey(t)
	_, wrapped, err := GenerateDelegationKey(alicePubBytes)
	if err != nil {
		t.Fatalf("GenerateDelegationKey: %v", err)
	}

	_, bob := freshUncompressedPubKey(t)
	bobScalar := padScalarTo32(bob.D)

	_, err = UnwrapDelegationKey(wrapped, bobScalar)
	if err == nil {
		t.Fatal("expected error when wrong owner key unwraps, got nil")
	}
}

func TestUnwrapDelegationKey_RejectsTamperedCiphertext(t *testing.T) {
	ownerPubBytes, ownerPriv := freshUncompressedPubKey(t)
	_, wrapped, err := GenerateDelegationKey(ownerPubBytes)
	if err != nil {
		t.Fatalf("GenerateDelegationKey: %v", err)
	}
	wrapped[len(wrapped)-5] ^= 0x01
	_, err = UnwrapDelegationKey(wrapped, padScalarTo32(ownerPriv.D))
	if err == nil {
		t.Fatal("expected error for tampered wrapped key, got nil")
	}
}

// -------------------------------------------------------------------------------------------------
// padScalarTo32 (unexported helper in delegation_key.go)
// -------------------------------------------------------------------------------------------------

func TestPadScalarTo32_PadsShortScalar(t *testing.T) {
	b := big.NewInt(1)
	out := padScalarTo32(b)
	if len(out) != 32 {
		t.Fatalf("len = %d, want 32", len(out))
	}
	for i := 0; i < 31; i++ {
		if out[i] != 0 {
			t.Fatalf("byte %d = 0x%02x, want 0x00", i, out[i])
		}
	}
	if out[31] != 0x01 {
		t.Fatalf("byte 31 = 0x%02x, want 0x01", out[31])
	}
}

func TestPadScalarTo32_HandlesExactly32Bytes(t *testing.T) {
	b := new(big.Int).SetBytes(bytes.Repeat([]byte{0xFF}, 32))
	out := padScalarTo32(b)
	if len(out) != 32 {
		t.Fatalf("len = %d, want 32", len(out))
	}
	if !bytes.Equal(out, bytes.Repeat([]byte{0xFF}, 32)) {
		t.Fatal("32-byte scalar modified during padding")
	}
}

// -------------------------------------------------------------------------------------------------
// ORTHO-BUG-014 — unwrapped scalar range check
// -------------------------------------------------------------------------------------------------
//
// A corrupted or malicious escrow node could return 32 well-formed
// bytes that decode to 0 or a value >= N. Either silently corrupts
// every downstream cryptographic operation. UnwrapDelegationKey must
// reject both.

// unwrapOutOfRangeScalarHelper encrypts the given out-of-range scalar
// to a fresh owner pubkey and runs UnwrapDelegationKey against the
// result. Returns the owner scalar and the unwrap error so the caller
// can assert rejection.
func unwrapOutOfRangeScalarHelper(t *testing.T, badScalar []byte) error {
	t.Helper()
	ownerPubBytes, ownerPriv := freshUncompressedPubKey(t)
	// Parse owner pub so EncryptForNode can consume it.
	x, y := elliptic.Unmarshal(secp256k1.S256(), ownerPubBytes) //nolint:staticcheck // test uses secp256k1 unmarshal
	if x == nil {
		t.Fatal("failed to unmarshal owner pubkey")
	}
	pub := &ecdsa.PublicKey{Curve: secp256k1.S256(), X: x, Y: y}
	wrapped, err := escrow.EncryptForNode(badScalar, pub)
	if err != nil {
		t.Fatalf("EncryptForNode: %v", err)
	}
	_, err = UnwrapDelegationKey(wrapped, padScalarTo32(ownerPriv.D))
	return err
}

func TestUnwrapDelegationKey_RejectsUnwrappedZeroScalar(t *testing.T) {
	bad := make([]byte, 32) // all zeros → scalar == 0
	err := unwrapOutOfRangeScalarHelper(t, bad)
	if err == nil {
		t.Fatal("expected rejection of zero unwrapped scalar (ORTHO-BUG-014), got nil")
	}
}

func TestUnwrapDelegationKey_RejectsUnwrappedScalarEqualToN(t *testing.T) {
	n := secp256k1.S256().Params().N
	bad := make([]byte, 32)
	nBytes := n.Bytes()
	copy(bad[32-len(nBytes):], nBytes)
	err := unwrapOutOfRangeScalarHelper(t, bad)
	if err == nil {
		t.Fatal("expected rejection of unwrapped scalar == N (ORTHO-BUG-014), got nil")
	}
}

func TestUnwrapDelegationKey_RejectsUnwrappedScalarAboveN(t *testing.T) {
	// N + 1 — above the curve order.
	n := new(big.Int).Add(secp256k1.S256().Params().N, big.NewInt(1))
	bad := make([]byte, 32)
	nBytes := n.Bytes()
	copy(bad[32-len(nBytes):], nBytes)
	err := unwrapOutOfRangeScalarHelper(t, bad)
	if err == nil {
		t.Fatal("expected rejection of unwrapped scalar > N (ORTHO-BUG-014), got nil")
	}
}
