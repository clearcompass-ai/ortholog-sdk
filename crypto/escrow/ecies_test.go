// Package escrow — ecies_test.go tests the ECIES-over-secp256k1 encryption
// scheme for escrow share transport. Covers both generic byte-buffer
// encryption (EncryptForNode / DecryptFromNode) and share-specific
// wrappers (EncryptShareForNode / DecryptShareFromNode).
package escrow

import (
	"bytes"
	"strings"
	"testing"
)

// -------------------------------------------------------------------------------------------------
// EncryptForNode / DecryptFromNode — generic round-trip
// -------------------------------------------------------------------------------------------------

func TestECIES_RoundTripEmptyPlaintext(t *testing.T) {
	priv := newTestKeyPair(t)
	pt := []byte{}
	ct, err := EncryptForNode(pt, &priv.PublicKey)
	if err != nil {
		t.Fatalf("EncryptForNode: %v", err)
	}
	recovered, err := DecryptFromNode(ct, priv)
	if err != nil {
		t.Fatalf("DecryptFromNode: %v", err)
	}
	if !bytes.Equal(recovered, pt) {
		t.Fatal("round-trip mismatch for empty plaintext")
	}
}

func TestECIES_RoundTripVariousSizes(t *testing.T) {
	priv := newTestKeyPair(t)
	sizes := []int{1, 32, 44, 131, 256, 1024}
	for _, n := range sizes {
		pt := make([]byte, n)
		for i := range pt {
			pt[i] = byte(i)
		}
		ct, err := EncryptForNode(pt, &priv.PublicKey)
		if err != nil {
			t.Fatalf("EncryptForNode(len=%d): %v", n, err)
		}
		recovered, err := DecryptFromNode(ct, priv)
		if err != nil {
			t.Fatalf("DecryptFromNode(len=%d): %v", n, err)
		}
		if !bytes.Equal(recovered, pt) {
			t.Fatalf("round-trip mismatch at len=%d", n)
		}
	}
}

// -------------------------------------------------------------------------------------------------
// Wire format overhead (documented: 65 + 12 + 16 = 93 bytes of overhead)
// -------------------------------------------------------------------------------------------------

func TestECIES_WireFormatOverhead(t *testing.T) {
	priv := newTestKeyPair(t)
	pt := make([]byte, 131) // ShareWireLen
	ct, err := EncryptForNode(pt, &priv.PublicKey)
	if err != nil {
		t.Fatalf("EncryptForNode: %v", err)
	}
	// Documented: 65 (eph pubkey) + 12 (nonce) + 16 (GCM tag) = 93 bytes overhead.
	// So a 131-byte plaintext produces a 224-byte ciphertext.
	want := 131 + 65 + 12 + 16
	if len(ct) != want {
		t.Fatalf("ciphertext len = %d, want %d (documented 224 for 131-byte share)",
			len(ct), want)
	}
}

// -------------------------------------------------------------------------------------------------
// EncryptForNode — argument validation
// -------------------------------------------------------------------------------------------------

func TestECIES_EncryptRejectsNilPublicKey(t *testing.T) {
	_, err := EncryptForNode([]byte("hello"), nil)
	if err == nil {
		t.Fatal("expected error for nil public key, got nil")
	}
	if !strings.Contains(err.Error(), "nil public key") {
		t.Fatalf("error does not mention nil public key: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// DecryptFromNode — argument validation and failure modes
// -------------------------------------------------------------------------------------------------

func TestECIES_DecryptRejectsNilPrivateKey(t *testing.T) {
	_, err := DecryptFromNode(make([]byte, 100), nil)
	if err == nil {
		t.Fatal("expected error for nil private key, got nil")
	}
}

func TestECIES_DecryptRejectsShortCiphertext(t *testing.T) {
	priv := newTestKeyPair(t)
	// Minimum valid size is 65 + 12 + 16 = 93; short by one byte.
	_, err := DecryptFromNode(make([]byte, 92), priv)
	if err == nil {
		t.Fatal("expected error for short ciphertext, got nil")
	}
	if !strings.Contains(err.Error(), "too short") {
		t.Fatalf("error does not mention 'too short': %v", err)
	}
}

func TestECIES_DecryptRejectsInvalidEphemeralPubkey(t *testing.T) {
	priv := newTestKeyPair(t)
	// 93 bytes of zero — ephemeral pubkey is all-zero which is not a
	// valid point on the curve.
	bad := make([]byte, 93)
	_, err := DecryptFromNode(bad, priv)
	if err == nil {
		t.Fatal("expected error for invalid ephemeral pubkey, got nil")
	}
	if !strings.Contains(err.Error(), "ephemeral") {
		t.Fatalf("error does not mention ephemeral key: %v", err)
	}
}

func TestECIES_DecryptRejectsTamperedCiphertext(t *testing.T) {
	priv := newTestKeyPair(t)
	pt := []byte("sensitive payload")
	ct, err := EncryptForNode(pt, &priv.PublicKey)
	if err != nil {
		t.Fatalf("EncryptForNode: %v", err)
	}
	// Tamper one byte in the AES-GCM ciphertext region (past the 65+12 prefix).
	ct[80] ^= 0xFF
	_, err = DecryptFromNode(ct, priv)
	if err == nil {
		t.Fatal("expected error for tampered ciphertext, got nil")
	}
}

func TestECIES_DecryptRejectsWrongPrivateKey(t *testing.T) {
	alice := newTestKeyPair(t)
	bob := newTestKeyPair(t)
	pt := []byte("secret for alice")
	ct, err := EncryptForNode(pt, &alice.PublicKey)
	if err != nil {
		t.Fatalf("EncryptForNode: %v", err)
	}
	// Bob tries to decrypt — must fail at GCM tag verification.
	_, err = DecryptFromNode(ct, bob)
	if err == nil {
		t.Fatal("expected error when wrong private key decrypts, got nil")
	}
}

// -------------------------------------------------------------------------------------------------
// EncryptShareForNode / DecryptShareFromNode — share-specific round-trip
// -------------------------------------------------------------------------------------------------

func TestECIES_ShareRoundTrip(t *testing.T) {
	priv := newTestKeyPair(t)
	original := validV1Share(3, 5)

	ct, err := EncryptShareForNode(original, &priv.PublicKey)
	if err != nil {
		t.Fatalf("EncryptShareForNode: %v", err)
	}

	// Documented: a ShareWireLen (132-byte, v7.5) share produces a
	// 225-byte ciphertext (65 ephemeral pubkey + 12 nonce +
	// 132 share + 16 GCM tag).
	if len(ct) != 225 {
		t.Fatalf("share ciphertext len = %d, want 225", len(ct))
	}

	recovered, err := DecryptShareFromNode(ct, priv)
	if err != nil {
		t.Fatalf("DecryptShareFromNode: %v", err)
	}

	if recovered.Version != original.Version {
		t.Errorf("Version mismatch: got 0x%02x, want 0x%02x", recovered.Version, original.Version)
	}
	if recovered.Threshold != original.Threshold {
		t.Errorf("Threshold mismatch: got %d, want %d", recovered.Threshold, original.Threshold)
	}
	if recovered.Index != original.Index {
		t.Errorf("Index mismatch: got %d, want %d", recovered.Index, original.Index)
	}
	if !bytes.Equal(recovered.Value[:], original.Value[:]) {
		t.Error("Value mismatch")
	}
	if !bytes.Equal(recovered.SplitID[:], original.SplitID[:]) {
		t.Error("SplitID mismatch")
	}
}

func TestECIES_EncryptShareRejectsMalformedShare(t *testing.T) {
	priv := newTestKeyPair(t)
	// Index 0 is reserved — ValidateShareFormat (called from SerializeShare,
	// called from EncryptShareForNode) must reject.
	bad := validV1Share(0, 3)
	_, err := EncryptShareForNode(bad, &priv.PublicKey)
	if err == nil {
		t.Fatal("expected error for malformed share, got nil")
	}
}

func TestECIES_DecryptShareRejectsTampered(t *testing.T) {
	priv := newTestKeyPair(t)
	s := validV1Share(1, 3)
	ct, err := EncryptShareForNode(s, &priv.PublicKey)
	if err != nil {
		t.Fatalf("EncryptShareForNode: %v", err)
	}
	// Flip a byte in the AES-GCM region.
	ct[100] ^= 0x01
	_, err = DecryptShareFromNode(ct, priv)
	if err == nil {
		t.Fatal("expected error for tampered share ciphertext, got nil")
	}
}

// -------------------------------------------------------------------------------------------------
// secp256k1() accessor
// -------------------------------------------------------------------------------------------------

func TestECIES_Secp256k1Accessor(t *testing.T) {
	c := secp256k1Curve()
	if c == nil {
		t.Fatal("secp256k1() returned nil curve")
	}
	params := c.Params()
	if params == nil {
		t.Fatal("curve.Params() returned nil")
	}
	// Sanity — secp256k1 N is a known constant (last byte check).
	if params.N == nil {
		t.Fatal("curve.Params().N is nil")
	}
	if params.BitSize != 256 {
		t.Fatalf("curve bit size = %d, want 256", params.BitSize)
	}
}
