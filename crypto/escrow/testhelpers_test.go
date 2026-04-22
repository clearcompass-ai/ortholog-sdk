// Package escrow — testhelpers_test.go provides shared fixtures for
// the crypto/escrow test suite. Internal (package escrow) so test files
// can touch unexported identifiers like zeroArray32.
package escrow

import (
	"crypto/ecdsa"
	"crypto/rand"
	"testing"

	"github.com/dustinxie/ecc"
)

// newTestSecret returns a 32-byte deterministic-looking secret for
// Split testing. Must be exactly SecretSize bytes. Not secret — just
// a fixture.
func newTestSecret(t *testing.T, seed byte) []byte {
	t.Helper()
	s := make([]byte, SecretSize)
	for i := range s {
		s[i] = seed + byte(i)
	}
	return s
}

// newTestKeyPair returns a fresh secp256k1 keypair using the package's
// own curve accessor. Errors fail the test immediately.
func newTestKeyPair(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(ecc.P256k1(), rand.Reader)
	if err != nil {
		t.Fatalf("newTestKeyPair: generate secp256k1 key: %v", err)
	}
	return priv
}

// validV1Share builds a V1 share that passes ValidateShareFormat. All
// V2-only fields left zero. SplitID filled with a non-zero distinct pattern.
func validV1Share(index, threshold byte) Share {
	var splitID [32]byte
	for i := range splitID {
		splitID[i] = 0xAB // any non-zero pattern
	}
	var value [32]byte
	for i := range value {
		value[i] = byte(i) + 1 // non-zero pattern
	}
	return Share{
		Version:   VersionV1,
		Threshold: threshold,
		Index:     index,
		Value:     value,
		SplitID:   splitID,
		// BlindingFactor and CommitmentHash left zero (V1 requirement)
	}
}

// splitTestSecret is a convenience wrapper: Split a secret into N
// shares with threshold M, failing the test on error.
func splitTestSecret(t *testing.T, secret []byte, m, n int) ([]Share, [32]byte) {
	t.Helper()
	shares, splitID, err := Split(secret, m, n)
	if err != nil {
		t.Fatalf("splitTestSecret: Split(_, %d, %d): %v", m, n, err)
	}
	if len(shares) != n {
		t.Fatalf("splitTestSecret: got %d shares, want %d", len(shares), n)
	}
	return shares, splitID
}
