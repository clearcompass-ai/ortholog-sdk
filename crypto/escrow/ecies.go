// Package escrow — ecies.go implements ECIES (Elliptic Curve Integrated Encryption Scheme)
// over secp256k1 for per-node Shamir share encryption.
//
// Same curve as entry signatures, witness cosignatures, and Umbral PRE.
// Uses ECDH + SHA-256 KDF + AES-256-GCM.
//
// The escrow assembly flow: Split produces plaintext shares, then each share
// is encrypted for its escrow node's public key via EncryptForNode.
// Reconstruction: DecryptFromNode recovers the share, then Reconstruct.
//
// Zeroization policy: every function in this file that handles secret
// material (AES keys, ECDH shared bytes, plaintext share wire bytes) clears
// those buffers via escrow.ZeroBytes before returning. This hardens against
// in-process memory disclosure (debuggers, co-process scans, paging to disk).
// ZeroBytes is defined in api.go and is the single authoritative zeroization
// primitive used throughout the package.
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

// EncryptForNode encrypts plaintext for a specific escrow node's secp256k1
// public key. Uses ECIES: ephemeral ECDH → SHA-256 KDF → AES-256-GCM.
//
// Wire format: [65 bytes ephemeral pubkey][12 bytes nonce][ciphertext+tag]
// Total overhead: 65 + 12 + 16 (GCM tag) = 93 bytes.
// For a 131-byte share (ShareWireLen, V1/V2): output is 224 bytes.
//
// Internal secret buffers (AES key, ECDH shared bytes, scalar/coord
// byte slices) are zeroized before return.
func EncryptForNode(plaintext []byte, nodePubKey *ecdsa.PublicKey) ([]byte, error) {
	if nodePubKey == nil {
		return nil, errors.New("escrow/ecies: nil public key")
	}
	curve := secp256k1()
	// Validate the recipient point lies on the curve before it feeds
	// ScalarMult. An off-curve point yields an undefined ECDH result
	// and would poison the KDF input.
	if nodePubKey.X == nil || nodePubKey.Y == nil {
		return nil, errors.New("escrow/ecies: public key has nil coordinate")
	}
	if !curve.IsOnCurve(nodePubKey.X, nodePubKey.Y) {
		return nil, errors.New("escrow/ecies: public key is not on the secp256k1 curve")
	}

	// Generate ephemeral key pair. ephPriv.D is secret; we zeroize the
	// padded-scalar byte slice we derive from it. The big.Int inside
	// ephPriv is effectively short-lived (function-scoped allocation
	// that will be GC'd shortly after return) but we still cannot
	// explicitly zero big.Int internals from Go user code.
	ephPriv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("escrow/ecies: generating ephemeral key: %w", err)
	}

	// ECDH: shared point = ephPriv * nodePubKey.
	// pad scalar to 32 bytes — big.Int.Bytes() strips leading zeros,
	// which would produce a different ScalarMult input on ~1/256 of keys.
	scalar := padScalar(ephPriv.D)
	defer ZeroBytes(scalar)

	sx, sy := curve.ScalarMult(nodePubKey.X, nodePubKey.Y, scalar)
	if sx == nil {
		return nil, errors.New("escrow/ecies: ECDH produced point at infinity")
	}

	// KDF: SHA-256(shared_x || shared_y) → 32-byte AES key.
	// pad coordinates to 32 bytes — SEC 1 v2 §4.1 field element encoding.
	sxBytes := padCoord(sx)
	syBytes := padCoord(sy)
	defer ZeroBytes(sxBytes)
	defer ZeroBytes(syBytes)

	sharedBytes := make([]byte, 0, 64)
	sharedBytes = append(sharedBytes, sxBytes...)
	sharedBytes = append(sharedBytes, syBytes...)
	defer ZeroBytes(sharedBytes)

	aesKey := sha256.Sum256(sharedBytes)
	defer ZeroArray32(&aesKey)

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
	// gcm.Seal produces the ciphertext+tag; the plaintext is the caller's
	// and we do NOT zero it (the caller owns its lifecycle).
	ct := gcm.Seal(nil, nonce, plaintext, nil)

	// Serialize: [65-byte uncompressed ephemeral pubkey][12-byte nonce][ciphertext+tag]
	ephPub := elliptic.Marshal(curve, ephPriv.PublicKey.X, ephPriv.PublicKey.Y)
	result := make([]byte, 0, len(ephPub)+len(nonce)+len(ct))
	result = append(result, ephPub...)
	result = append(result, nonce...)
	result = append(result, ct...)
	return result, nil
}

// DecryptFromNode decrypts ECIES ciphertext using the escrow node's
// private key. Reverses the EncryptForNode wire format.
//
// Internal secret buffers (AES key, ECDH shared bytes, scalar/coord
// byte slices) are zeroized before return. The returned plaintext
// slice is the caller's property and is NOT zeroized — callers that
// handle secret plaintext (e.g., DecryptShareFromNode) must zeroize
// before discarding.
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
	// Third-party curve implementations do not uniformly perform
	// on-curve validation in Unmarshal; do it explicitly so a crafted
	// ciphertext cannot smuggle an off-curve point into ScalarMult.
	if !curve.IsOnCurve(ephX, ephY) {
		return nil, errors.New("escrow/ecies: ephemeral public key is not on the secp256k1 curve")
	}

	// ECDH: shared point = nodePriv * ephPub.
	scalar := padScalar(nodePrivKey.D)
	defer ZeroBytes(scalar)

	sx, sy := curve.ScalarMult(ephX, ephY, scalar)
	if sx == nil {
		return nil, errors.New("escrow/ecies: ECDH produced point at infinity")
	}

	// KDF: same as encryption.
	sxBytes := padCoord(sx)
	syBytes := padCoord(sy)
	defer ZeroBytes(sxBytes)
	defer ZeroBytes(syBytes)

	sharedBytes := make([]byte, 0, 64)
	sharedBytes = append(sharedBytes, sxBytes...)
	sharedBytes = append(sharedBytes, syBytes...)
	defer ZeroBytes(sharedBytes)

	aesKey := sha256.Sum256(sharedBytes)
	defer ZeroArray32(&aesKey)

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

// EncryptShareForNode encrypts a serialized share for an escrow node.
// Convenience wrapper: serializes the share, ECIES-encrypts, then
// zeroizes the transient plaintext wire buffer before returning.
//
// The intermediate wireBytes buffer holds the full 131-byte plaintext
// share, including the Value scalar. Zeroizing it before return closes
// the transient-plaintext window that previously existed in this
// function.
func EncryptShareForNode(share Share, nodePubKey *ecdsa.PublicKey) ([]byte, error) {
	wireBytes, err := SerializeShare(share)
	if err != nil {
		return nil, fmt.Errorf("escrow/ecies: serializing share: %w", err)
	}
	// wireBytes contains the plaintext share. It is consumed by
	// EncryptForNode (copied into the AES-GCM ciphertext) and then
	// zeroized before leaving this function.
	defer ZeroBytes(wireBytes)

	return EncryptForNode(wireBytes, nodePubKey)
}

// DecryptShareFromNode decrypts an ECIES-encrypted share.
// Convenience wrapper: ECIES-decrypts, deserializes, then zeroizes the
// transient plaintext wire buffer before returning.
func DecryptShareFromNode(encrypted []byte, nodePrivKey *ecdsa.PrivateKey) (Share, error) {
	wireBytes, err := DecryptFromNode(encrypted, nodePrivKey)
	if err != nil {
		return Share{}, fmt.Errorf("escrow/ecies: %w", err)
	}
	// wireBytes contains the plaintext share. It is consumed by
	// DeserializeShare (copied into the returned Share's fields) and
	// then zeroized before leaving this function. The returned Share
	// remains the caller's responsibility.
	defer ZeroBytes(wireBytes)

	return DeserializeShare(wireBytes)
}

// padScalar pads a big.Int to 32 bytes for secp256k1 scalar operations.
// Prevents big.Int.Bytes() from stripping leading zero bytes, which would
// alter ScalarMult input and produce a different ECDH shared point.
//
// The returned slice may contain secret material (when called on a
// private scalar). Callers are responsible for zeroizing it via
// ZeroBytes before releasing the reference.
func padScalar(b *big.Int) []byte {
	buf := b.Bytes()
	if len(buf) >= 32 {
		return buf[:32]
	}
	padded := make([]byte, 32)
	copy(padded[32-len(buf):], buf)
	// Zero the intermediate buf from big.Int.Bytes() — it holds the
	// same secret bytes without the padding.
	ZeroBytes(buf)
	return padded
}

// padCoord pads an elliptic curve coordinate to 32 bytes for KDF input.
// Same rationale as padScalar: a coordinate with leading zero bytes would
// produce a shorter Bytes() output, yielding a different KDF-derived AES
// key than a correctly padded implementation (SEC 1 v2 §4.1 field element
// encoding).
//
// ECDH shared-point coordinates are secret-derived (they combine the
// ephemeral scalar with the peer's public key). The returned slice must
// be zeroized by the caller via ZeroBytes before release.
func padCoord(c *big.Int) []byte {
	buf := c.Bytes()
	if len(buf) >= 32 {
		return buf[:32]
	}
	padded := make([]byte, 32)
	copy(padded[32-len(buf):], buf)
	ZeroBytes(buf)
	return padded
}
