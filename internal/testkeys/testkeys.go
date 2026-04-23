// Package testkeys provides shared secp256k1 keypair helpers for
// tests across the SDK. Centralizing this logic prevents drift in
// the scalar-to-bytes and point-to-bytes conversions that PRE and
// signature code rely on.
//
// This package is under internal/ so it cannot be imported by SDK
// consumers — it exists solely to serve our own test suites.
//
// The shapes returned here match the v7.75 on-wire conventions:
//
//	SK bytes — 32-byte big-endian scalar (the format PRE_GenerateKFrags,
//	           PRE_DecryptFrags, and PRE_Decrypt expect for their sk
//	           parameters).
//
//	PK bytes — 65-byte SEC 1 uncompressed point (0x04 || X || Y), the
//	           format PRE_Encrypt and PRE_GenerateKFrags expect for their
//	           pk parameters, matching elliptic.Unmarshal.
package testkeys

import (
	"crypto/elliptic"
	"testing"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
)

// Keypair is a secp256k1 keypair in the byte shapes the PRE primitive
// functions consume.
type Keypair struct {
	// SK is a 32-byte big-endian scalar. Never contains leading
	// zero-stripping; always exactly 32 bytes.
	SK []byte

	// PK is a 65-byte SEC 1 uncompressed point: 0x04 || X || Y, with
	// X and Y each padded to 32 bytes. Matches the format produced by
	// elliptic.Marshal on secp256k1 and consumed by elliptic.Unmarshal.
	PK []byte
}

// New generates a new random secp256k1 keypair via
// signatures.GenerateKey and returns it in the byte shapes PRE
// primitive functions expect.
//
// Fatals the test on error — test helpers should not propagate
// cryptographic setup failures.
func New(t *testing.T) Keypair {
	t.Helper()

	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("testkeys: signatures.GenerateKey: %v", err)
	}

	// Pad the scalar D to exactly 32 bytes, big-endian. big.Int.Bytes
	// strips leading zeros; PRE functions expect a fixed 32-byte
	// width.
	sk := make([]byte, 32)
	dBytes := priv.D.Bytes()
	copy(sk[32-len(dBytes):], dBytes)

	// Marshal to 65-byte uncompressed SEC 1, the same encoding used
	// throughout the SDK's test suite and internally unmarshaled by
	// the artifact package.
	pk := elliptic.Marshal(secp256k1.S256(), priv.PublicKey.X, priv.PublicKey.Y)

	return Keypair{SK: sk, PK: pk}
}
