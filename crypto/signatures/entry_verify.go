/*
FILE PATH:
    crypto/signatures/entry_verify.go

DESCRIPTION:
    Low-level ECDSA secp256k1 primitives used for Ortholog entry signing and
    witness cosignature verification.

KEY ARCHITECTURAL DECISIONS:
    - VerifyEntry is a PURE secp256k1 primitive. It does NOT dispatch on DID
      method, algorithm ID, or any higher-level concept. Higher-level verifiers
      (did/verify.go and friends) call this function as one of several building
      blocks.
    - Signatures are 64-byte raw R || S format, NOT the 65-byte Ethereum
      r || s || v format. Entry signatures produced by the SDK do not carry
      a recovery byte because they are verified against a known public key,
      not recovered.
    - Low-S normalization is enforced on signing to eliminate signature
      malleability. Verification accepts both low-S and high-S signatures for
      compatibility with signatures produced outside this package.
    - Witness cosignature verification (crypto/signatures/witness_verify.go)
      calls VerifyEntry directly. DO NOT change the signature of this function
      without updating witness_verify.go.

OVERVIEW:
    SignEntry   -> 64-byte low-S signature over a 32-byte hash
    VerifyEntry -> error if signature/hash/pubkey do not verify
    GenerateKey / PubKeyBytes / ParsePubKey -> convenience helpers for tests
                                               and DID document construction

KEY DEPENDENCIES:
    - github.com/dustinxie/ecc: secp256k1 curve implementation
*/
package signatures

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	"github.com/dustinxie/ecc"
)

// -------------------------------------------------------------------------------------------------
// 1) Curve
// -------------------------------------------------------------------------------------------------

// Secp256k1 returns the secp256k1 elliptic curve used for Ortholog entry
// signatures, delegation keys, witness cosignatures, and ECIES escrow.
func Secp256k1() elliptic.Curve { return ecc.P256k1() }

// -------------------------------------------------------------------------------------------------
// 2) SignEntry / VerifyEntry
// -------------------------------------------------------------------------------------------------

// SignEntry produces a 64-byte low-S ECDSA signature (R || S) over the given
// 32-byte hash using the provided private key.
func SignEntry(hash [32]byte, privkey *ecdsa.PrivateKey) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, privkey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("signatures: sign: %w", err)
	}
	// Normalize to Low-S (s <= N/2) to eliminate malleability.
	halfN := new(big.Int).Rsh(privkey.Curve.Params().N, 1)
	if s.Cmp(halfN) > 0 {
		s.Sub(privkey.Curve.Params().N, s)
	}
	sig := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)
	return sig, nil
}

// VerifyEntry verifies a 64-byte (R || S) ECDSA signature over a 32-byte hash.
//
// This is the primitive called by witness cosignature verification and by
// higher-level did:key / did:web verifiers for secp256k1 keys.
func VerifyEntry(hash [32]byte, sig []byte, pubkey *ecdsa.PublicKey) error {
	if len(sig) != 64 {
		return errors.New("signatures: entry signature must be 64 bytes (R || S)")
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:64])
	if r.Sign() == 0 || s.Sign() == 0 {
		return errors.New("signatures: signature contains zero component")
	}
	if !ecdsa.Verify(pubkey, hash[:], r, s) {
		return errors.New("signatures: ECDSA secp256k1 verification failed")
	}
	return nil
}

// -------------------------------------------------------------------------------------------------
// 3) Key and pubkey helpers
// -------------------------------------------------------------------------------------------------

// GenerateKey generates a fresh secp256k1 private key.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(Secp256k1(), rand.Reader)
}

// PubKeyBytes returns the 65-byte uncompressed (0x04 || X || Y) encoding of
// the given secp256k1 public key.
func PubKeyBytes(pub *ecdsa.PublicKey) []byte {
	return elliptic.Marshal(Secp256k1(), pub.X, pub.Y)
}

// ParsePubKey parses a 65-byte uncompressed secp256k1 public key.
func ParsePubKey(data []byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.Unmarshal(Secp256k1(), data)
	if x == nil {
		return nil, errors.New("signatures: invalid secp256k1 public key bytes")
	}
	return &ecdsa.PublicKey{Curve: Secp256k1(), X: x, Y: y}, nil
}
