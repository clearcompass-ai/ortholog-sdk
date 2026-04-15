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

func Secp256k1() elliptic.Curve { return ecc.P256k1() }

func SignEntry(hash [32]byte, privkey *ecdsa.PrivateKey) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, privkey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("signatures: sign: %w", err)
	}

	// Normalize to Low-S (s <= N/2).
	// Go's ecdsa.Sign does not guarantee Low-S. Without this,
	// ~50% of signatures have s > N/2. Both are mathematically
	// valid, but canonical form eliminates signature malleability.
	halfN := new(big.Int).Rsh(privkey.Curve.Params().N, 1)
	if s.Cmp(halfN) > 0 {
		s.Sub(privkey.Curve.Params().N, s)
	}

	// Serialize R || S, each zero-padded to 32 bytes.
	sig := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	copy(sig[32-len(rBytes):32], rBytes)
	copy(sig[64-len(sBytes):64], sBytes)
	return sig, nil
}
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

func GenerateKey() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(Secp256k1(), rand.Reader) }

func PubKeyBytes(pub *ecdsa.PublicKey) []byte { return elliptic.Marshal(Secp256k1(), pub.X, pub.Y) }

func ParsePubKey(data []byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.Unmarshal(Secp256k1(), data)
	if x == nil {
		return nil, errors.New("invalid secp256k1 public key bytes")
	}
	return &ecdsa.PublicKey{Curve: Secp256k1(), X: x, Y: y}, nil
}
