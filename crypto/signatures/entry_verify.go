package signatures

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"
	"github.com/dustinxie/ecc"
)

func Secp256k1() elliptic.Curve { return ecc.P256k1() }

func SignEntry(hash [32]byte, key *ecdsa.PrivateKey) ([]byte, error) {
	sig, err := ecc.SignBytes(key, hash[:], ecc.LowerS)
	if err != nil { return nil, err }
	if len(sig) != 64 { return nil, errors.New("unexpected signature length from ecc.SignBytes") }
	return sig, nil
}

func VerifyEntry(hash [32]byte, sig []byte, pubkey *ecdsa.PublicKey) error {
	if len(sig) != 64 { return errors.New("signature must be 64 bytes (R || S)") }
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:64])
	if r.Sign() == 0 || s.Sign() == 0 { return errors.New("signature contains zero component") }
	if !ecdsa.Verify(pubkey, hash[:], r, s) { return errors.New("ECDSA secp256k1 signature verification failed") }
	return nil
}

func GenerateKey() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(Secp256k1(), rand.Reader) }

func PubKeyBytes(pub *ecdsa.PublicKey) []byte { return elliptic.Marshal(Secp256k1(), pub.X, pub.Y) }

func ParsePubKey(data []byte) (*ecdsa.PublicKey, error) {
	x, y := elliptic.Unmarshal(Secp256k1(), data)
	if x == nil { return nil, errors.New("invalid secp256k1 public key bytes") }
	return &ecdsa.PublicKey{Curve: Secp256k1(), X: x, Y: y}, nil
}
