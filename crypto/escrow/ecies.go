// Package escrow — ecies.go implements ECIES (Elliptic Curve Integrated Encryption Scheme)
// over secp256k1 for per-node Shamir share encryption.
//
// Same curve as entry signatures, witness cosignatures, and Umbral PRE.
// Uses ECDH + SHA-256 KDF + AES-256-GCM.
//
// The escrow assembly flow: SplitGF256 produces plaintext shares, then each
// share is encrypted for its escrow node's public key via EncryptForNode.
// Reconstruction: DecryptFromNode recovers the share, then ReconstructGF256.
package escrow

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"

	"github.com/dustinxie/ecc"
)

func secp256k1() elliptic.Curve { return ecc.P256k1() }

// EncryptForNode encrypts plaintext for a specific escrow node's secp256k1 public key.
// Uses ECIES: ephemeral ECDH → SHA-256 KDF → AES-256-GCM.
//
// Wire format: [65 bytes ephemeral pubkey][12 bytes nonce][ciphertext+tag]
// Total overhead: 65 + 12 + 16 (GCM tag) = 93 bytes.
// For a 34-byte share (ShareWireLen): output is 127 bytes.
func EncryptForNode(plaintext []byte, nodePubKey *ecdsa.PublicKey) ([]byte, error) {
	if nodePubKey == nil {
		return nil, errors.New("escrow/ecies: nil public key")
	}
	curve := secp256k1()

	// Generate ephemeral key pair.
	ephPriv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("escrow/ecies: generating ephemeral key: %w", err)
	}

	// ECDH: shared point = ephPriv * nodePubKey.
	// Fix 2: pad scalar to 32 bytes — big.Int.Bytes() strips leading zeros,
	// which would produce a different ScalarMult input on ~1/256 of keys.
	sx, sy := curve.ScalarMult(nodePubKey.X, nodePubKey.Y, padScalar(ephPriv.D))
	if sx == nil {
		return nil, errors.New("escrow/ecies: ECDH produced point at infinity")
	}

	// KDF: SHA-256(shared_x || shared_y) → 32-byte AES key.
	// Fix 2: pad coordinates to 32 bytes — if sx or sy has leading zero bytes
	// (~1/256 per coordinate), unpadded Bytes() produces 31 bytes, yielding a
	// different KDF input than a correctly padded implementation (e.g., HSM).
	var sharedBytes []byte
	sharedBytes = append(sharedBytes, padCoord(sx)...)
	sharedBytes = append(sharedBytes, padCoord(sy)...)
	aesKey := sha256.Sum256(sharedBytes)

	// AES-256-GCM encrypt.
	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return nil, fmt.Errorf("escrow/ecies: creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("escrow/ecies: creating GCM: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("escrow/ecies: generating nonce: %w", err)
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)

	// Serialize: [65-byte uncompressed ephemeral pubkey][12-byte nonce][ciphertext+tag]
	ephPub := elliptic.Marshal(curve, ephPriv.PublicKey.X, ephPriv.PublicKey.Y)
	result := make([]byte, 0, len(ephPub)+len(nonce)+len(ct))
	result = append(result, ephPub...)
	result = append(result, nonce...)
	result = append(result, ct...)
	return result, nil
}

// DecryptFromNode decrypts ECIES ciphertext using the escrow node's private key.
// Reverses the EncryptForNode wire format.
func DecryptFromNode(ciphertext []byte, nodePrivKey *ecdsa.PrivateKey) ([]byte, error) {
	if nodePrivKey == nil {
		return nil, errors.New("escrow/ecies: nil private key")
	}
	curve := secp256k1()

	// Parse ephemeral public key (65 bytes uncompressed).
	if len(ciphertext) < 65+12+16 { // pubkey + nonce + minimum GCM tag
		return nil, errors.New("escrow/ecies: ciphertext too short")
	}
	ephX, ephY := elliptic.Unmarshal(curve, ciphertext[:65])
	if ephX == nil {
		return nil, errors.New("escrow/ecies: invalid ephemeral public key")
	}

	// ECDH: shared point = nodePriv * ephPub.
	// Fix 2: pad scalar to 32 bytes (see EncryptForNode comment).
	sx, sy := curve.ScalarMult(ephX, ephY, padScalar(nodePrivKey.D))
	if sx == nil {
		return nil, errors.New("escrow/ecies: ECDH produced point at infinity")
	}

	// KDF: same as encryption — pad coordinates to 32 bytes.
	var sharedBytes []byte
	sharedBytes = append(sharedBytes, padCoord(sx)...)
	sharedBytes = append(sharedBytes, padCoord(sy)...)
	aesKey := sha256.Sum256(sharedBytes)

	// AES-256-GCM decrypt.
	block, err := aes.NewCipher(aesKey[:])
	if err != nil {
		return nil, fmt.Errorf("escrow/ecies: creating cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("escrow/ecies: creating GCM: %w", err)
	}

	nonce := ciphertext[65 : 65+gcm.NonceSize()]
	ct := ciphertext[65+gcm.NonceSize():]

	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("escrow/ecies: decryption failed: %w", err)
	}
	return plaintext, nil
}

// EncryptShareForNode encrypts a serialized Shamir share for an escrow node.
// Convenience wrapper: serializes the share, then ECIES-encrypts.
func EncryptShareForNode(share Share, nodePubKey *ecdsa.PublicKey) ([]byte, error) {
	if len(share.Value) != 32 {
		return nil, fmt.Errorf("escrow/ecies: share value must be 32 bytes, got %d", len(share.Value))
	}
	wireBytes, err := SerializeShare(share)
	if err != nil {
		return nil, fmt.Errorf("escrow/ecies: serializing share: %w", err)
	}
	return EncryptForNode(wireBytes, nodePubKey)
}

// DecryptShareFromNode decrypts an ECIES-encrypted Shamir share.
// Convenience wrapper: ECIES-decrypts, then deserializes.
func DecryptShareFromNode(encrypted []byte, nodePrivKey *ecdsa.PrivateKey) (Share, error) {
	wireBytes, err := DecryptFromNode(encrypted, nodePrivKey)
	if err != nil {
		return Share{}, fmt.Errorf("escrow/ecies: %w", err)
	}
	return DeserializeShare(wireBytes)
}

// padScalar pads a big.Int to 32 bytes for secp256k1 scalar operations.
// Prevents big.Int.Bytes() from stripping leading zero bytes, which would
// alter ScalarMult input and produce a different ECDH shared point.
func padScalar(b *big.Int) []byte {
	buf := b.Bytes()
	if len(buf) >= 32 {
		return buf[:32]
	}
	padded := make([]byte, 32)
	copy(padded[32-len(buf):], buf)
	return padded
}

// padCoord pads an elliptic curve coordinate to 32 bytes for KDF input.
// Same rationale as padScalar: a coordinate with leading zero bytes would
// produce a shorter Bytes() output, yielding a different KDF-derived AES key
// than a correctly padded implementation (SEC 1 v2 §4.1 field element encoding).
func padCoord(c *big.Int) []byte {
	buf := c.Bytes()
	if len(buf) >= 32 {
		return buf[:32]
	}
	padded := make([]byte, 32)
	copy(padded[32-len(buf):], buf)
	return padded
}
