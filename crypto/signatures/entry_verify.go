// Package signatures provides entry and witness signature operations.
package signatures

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"

	"github.com/dustinxie/ecc"
)

// Secp256k1 returns the secp256k1 elliptic curve (y² = x³ + 7).
// This is the curve mandated by the protocol for entry signatures
// (SDK-D2 algorithm 0x0001).
func Secp256k1() elliptic.Curve {
	return ecc.P256k1()
}

// SignEntry signs a canonical hash with an ECDSA secp256k1 private key.
// Returns a 64-byte signature (R || S) with low-S normalization (ecc.LowerS).
// Low-S prevents signature malleability: if S > N/2, it is replaced with N - S.
// The signature is external to the canonical hash (pilot Exp 7).
func SignEntry(hash [32]byte, key *ecdsa.PrivateKey) ([]byte, error) {
	sig, err := ecc.SignBytes(key, hash[:], ecc.LowerS)
	if err != nil {
		return nil, err
	}
	if len(sig) != 64 {
		return nil, errors.New("unexpected signature length from ecc.SignBytes")
	}
	return sig, nil
}

// VerifyEntry verifies a 64-byte ECDSA secp256k1 signature over a canonical hash.
// Accepts both low-S and high-S signatures.
func VerifyEntry(hash [32]byte, sig []byte, pubkey *ecdsa.PublicKey) error {
	if len(sig) != 64 {
		return errors.New("signature must be 64 bytes (R || S)")
	}
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:64])
	if r.Sign() == 0 || s.Sign() == 0 {
		return errors.New("signature contains zero component")
	}
	if !ecdsa.Verify(pubkey, hash[:], r, s) {
		return errors.New("ECDSA secp256k1 signature verification failed")
	}
	return nil
}

// GenerateKey generates a new ECDSA secp256k1 key pair.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(Secp256k1(), rand.Reader)
}

// PubKeyBytes returns the uncompressed public key bytes (65 bytes: 0x04 || X || Y).
func PubKeyBytes(pub *ecdsa.PublicKey) []byte {
	return elliptic.Marshal(Secp256k1(), pub.X, pub.Y)
}

// ParsePubKey parses uncompressed secp256k1 public key bytes (65 bytes).
func ParsePubKey(data []byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.Unmarshal(Secp256k1(), data)
	if x == nil {
		return nil, errors.New("invalid secp256k1 public key bytes")
	}
	return &ecdsa.PublicKey{Curve: Secp256k1(), X: x, Y: y}, nil
}
