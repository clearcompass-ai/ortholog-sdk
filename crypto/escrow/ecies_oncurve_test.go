package escrow

import (
	"crypto/ecdsa"
	"math/big"
	"strings"
	"testing"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// TestEncryptForNode_RejectsNilCoordinates ensures a partially-
// constructed ECDSA public key cannot bypass validation and reach
// ScalarMult with nil X/Y (which would panic inside the curve math).
func TestEncryptForNode_RejectsNilCoordinates(t *testing.T) {
	pub := &ecdsa.PublicKey{Curve: secp256k1.S256(), X: nil, Y: nil}
	_, err := EncryptForNode([]byte("payload"), pub)
	if err == nil {
		t.Fatal("EncryptForNode: expected error on nil coordinates, got nil")
	}
	if !strings.Contains(err.Error(), "nil coordinate") {
		t.Fatalf("EncryptForNode: want 'nil coordinate' error, got %v", err)
	}
}

// TestEncryptForNode_RejectsOffCurvePoint verifies the H3 guard:
// passing a point that is not on secp256k1 returns a clear error
// instead of silently feeding an invalid ECDH input into the KDF,
// which would yield a deterministic-but-poisoned shared secret.
func TestEncryptForNode_RejectsOffCurvePoint(t *testing.T) {
	// (1, 1) is not a secp256k1 point. Any sufficiently random pair
	// works; (1, 1) is the obvious inspection-friendly choice.
	pub := &ecdsa.PublicKey{
		Curve: secp256k1.S256(),
		X:     big.NewInt(1),
		Y:     big.NewInt(1),
	}
	if secp256k1.S256().IsOnCurve(pub.X, pub.Y) {
		t.Fatal("test fixture broken: (1,1) unexpectedly on curve")
	}
	_, err := EncryptForNode([]byte("payload"), pub)
	if err == nil {
		t.Fatal("EncryptForNode: expected error for off-curve public key, got nil")
	}
	if !strings.Contains(err.Error(), "not on the secp256k1 curve") {
		t.Fatalf("EncryptForNode: want 'not on the secp256k1 curve' error, got %v", err)
	}
}

// TestDecryptFromNode_RejectsOffCurveEphemeral covers the parallel
// H3 guard on the decrypt path: a crafted ciphertext that unmarshals
// to an off-curve ephemeral point must be rejected before it feeds
// ScalarMult with the node's private key.
func TestDecryptFromNode_RejectsOffCurveEphemeral(t *testing.T) {
	priv, err := ecdsa.GenerateKey(secp256k1.S256(), noiseReader{})
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// Construct a 65-byte "uncompressed" point whose coordinates are
	// (1, 1): leading 0x04, 32-byte X=1, 32-byte Y=1. elliptic.Unmarshal
	// parses this successfully on third-party curves (the format is
	// valid); IsOnCurve then rejects it.
	bad := make([]byte, 65)
	bad[0] = 0x04
	bad[32] = 0x01
	bad[64] = 0x01

	// Append a plausible-sized tail (nonce + GCM tag) so the length
	// guard does not short-circuit before the IsOnCurve check.
	ct := append(bad, make([]byte, 12+16)...)

	_, err = DecryptFromNode(ct, priv)
	if err == nil {
		t.Fatal("DecryptFromNode: expected error on off-curve ephemeral, got nil")
	}
	// Either the IsOnCurve rejection fires, or the upstream
	// Unmarshal fails first — both outcomes prevent the unsafe
	// ScalarMult and are acceptable.
	if !strings.Contains(err.Error(), "not on the secp256k1 curve") &&
		!strings.Contains(err.Error(), "invalid ephemeral public key") {
		t.Fatalf("DecryptFromNode: want on-curve or unmarshal rejection, got %v", err)
	}
}

// noiseReader is a deterministic byte source for test key generation.
// Not secure — test fixtures only.
type noiseReader struct{}

func (noiseReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(i * 7) //nolint:gosec // deterministic test fixture
	}
	return len(p), nil
}
