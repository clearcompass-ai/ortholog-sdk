/*
FILE PATH:
    crypto/signatures/verify_primitives.go

DESCRIPTION:
    Per-algorithm signature verification primitives. Each function takes a
    public key in its canonical encoding and a signature, and returns an error
    if verification fails.

KEY ARCHITECTURAL DECISIONS:
    - One function per (curve, encoding, message-construction) tuple. No
      polymorphic "verify any signature" function — the caller must know which
      algorithm they expect. This prevents downgrade attacks where a verifier
      accepts a weaker algorithm than expected.
    - Secp256k1 verification is exposed in three variants:
        * VerifySecp256k1Raw:    wallet signed the 32-byte canonical hash directly
        * VerifySecp256k1EIP191: wallet signed via personal_sign
        * VerifySecp256k1EIP712: wallet signed the typed-data digest
      Each is a separate function. The did:pkh verifier dispatches on algoID.
    - All three secp256k1 variants accept a 65-byte Ethereum-format signature
      (r || s || v) and do ecrecover + address compare, not pubkey-based verify.
      For did:pkh the DID *is* the address, so address-equality is the only
      meaningful check.
    - Ed25519 and P-256 verification use the stdlib implementations directly.
      No dependency creep.
    - Low-S enforcement is NOT applied in the EIP-191/EIP-712 paths. Ethereum
      wallets do not enforce low-S on user-visible signatures, and rejecting
      high-S here would reject legitimate wallet signatures. (Entry signatures
      produced by SDK keys in entry_verify.go DO enforce low-S — that's a
      different path.)

OVERVIEW:
    did:pkh verifier calls:
        expected_addr := 20 bytes from did:pkh:eip155:1:0x...
        switch algoID {
            case SigAlgoECDSA:  err = VerifySecp256k1Raw(expected_addr, hash, sig)
            case SigAlgoEIP191: err = VerifySecp256k1EIP191(expected_addr, hash, sig)
            case SigAlgoEIP712: err = VerifySecp256k1EIP712(expected_addr, hash, sig)
        }

    did:key verifier calls:
        switch multicodec_prefix {
            case 0xe701: err = VerifySecp256k1Compressed(pubBytes, hash, sig)
            case 0xed01: err = VerifyEd25519(pubBytes, message, sig)
            case 0x1200: err = VerifyP256(pubBytes, hash, sig)
        }

KEY DEPENDENCIES:
    - crypto/signatures/ethereum_primitives.go: keccak, recover, address
    - crypto/signatures/eip191.go: EIP-191 digest
    - crypto/signatures/eip712.go: EIP-712 digest
    - crypto/ed25519 (stdlib): Ed25519 verification
    - crypto/ecdsa, crypto/elliptic (stdlib): ECDSA P-256 verification
*/
package signatures

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"errors"
	"fmt"
	"math/big"
)

// -------------------------------------------------------------------------------------------------
// 1) Errors
// -------------------------------------------------------------------------------------------------

// ErrAddressMismatch is returned when the address recovered from an
// ecrecover-based verification does not match the expected address.
var ErrAddressMismatch = errors.New("signatures: recovered address does not match expected")

// ErrSignatureVerificationFailed is a generic verification failure used by
// primitives that produce false rather than an explicit error.
var ErrSignatureVerificationFailed = errors.New("signatures: signature verification failed")

// ErrInvalidPublicKey is returned when public key bytes cannot be parsed.
var ErrInvalidPublicKey = errors.New("signatures: invalid public key")

// -------------------------------------------------------------------------------------------------
// 2) Secp256k1 address-based verification (for did:pkh)
// -------------------------------------------------------------------------------------------------

// VerifySecp256k1Raw verifies that the 65-byte signature over the raw 32-byte
// canonical hash recovers to the expected Ethereum address.
//
// Use when the wallet signed the canonical hash directly (automated signers,
// KMS-backed EOAs). The wallet did NOT apply EIP-191 or EIP-712 wrapping.
func VerifySecp256k1Raw(expected [EthereumAddressLen]byte, canonicalHash [32]byte, sig []byte) error {
	return recoverAndCompare(expected, canonicalHash, sig)
}

// VerifySecp256k1EIP191 verifies that the 65-byte signature produced via
// personal_sign over the canonical hash recovers to the expected address.
//
// Use for standard wallet sign-in flows (MetaMask, Rainbow, WalletConnect).
func VerifySecp256k1EIP191(expected [EthereumAddressLen]byte, canonicalHash [32]byte, sig []byte) error {
	digest := EIP191Digest(canonicalHash[:])
	return recoverAndCompare(expected, digest, sig)
}

// VerifySecp256k1EIP712 verifies that the 65-byte signature produced via
// eth_signTypedData_v4 against the Ortholog entry typed data recovers to the
// expected address.
//
// Use for high-stakes signatures where the wallet displays structured typed
// data rather than a plaintext message.
func VerifySecp256k1EIP712(expected [EthereumAddressLen]byte, canonicalHash [32]byte, sig []byte) error {
	digest := EntrySigningDigest(canonicalHash)
	return recoverAndCompare(expected, digest, sig)
}

// recoverAndCompare is the shared ecrecover-and-check-address path used by
// the three did:pkh verifiers above.
func recoverAndCompare(expected [EthereumAddressLen]byte, digest [32]byte, sig []byte) error {
	pub, err := RecoverSecp256k1(digest, sig)
	if err != nil {
		return err
	}
	addr, err := AddressFromPubkey(pub)
	if err != nil {
		return err
	}
	if addr != expected {
		return fmt.Errorf("%w: expected 0x%x, got 0x%x", ErrAddressMismatch, expected, addr)
	}
	return nil
}

// -------------------------------------------------------------------------------------------------
// 3) Secp256k1 pubkey-based verification (for did:key with secp256k1 multicodec)
// -------------------------------------------------------------------------------------------------

// VerifySecp256k1Compressed verifies an ECDSA signature over the given hash
// against a 33-byte compressed secp256k1 public key.
//
// Used by the did:key verifier for the secp256k1 multicodec (0xe701). The
// signature format is raw 64-byte (R || S), NOT the 65-byte Ethereum format.
// For 65-byte Ethereum signatures, use the did:pkh path instead.
func VerifySecp256k1Compressed(compressedPub []byte, hash [32]byte, sig []byte) error {
	uncompressed, err := DecompressSecp256k1Pubkey(compressedPub)
	if err != nil {
		return err
	}
	pub, err := ParsePubKey(uncompressed)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidPublicKey, err)
	}
	// Reuse the 64-byte (r || s) verification path from entry_verify.go.
	return VerifyEntry(hash, sig, pub)
}

// -------------------------------------------------------------------------------------------------
// 4) Ed25519 verification (for did:key with Ed25519 multicodec)
// -------------------------------------------------------------------------------------------------

// Ed25519PublicKeyLen is the byte length of an Ed25519 public key.
const Ed25519PublicKeyLen = ed25519.PublicKeySize

// Ed25519SignatureLen is the byte length of an Ed25519 signature.
const Ed25519SignatureLen = ed25519.SignatureSize

// VerifyEd25519 verifies an Ed25519 signature over the given message.
//
// Unlike ECDSA, Ed25519 signs the full message (not a hash). The caller passes
// the canonical bytes that were signed; verification fails loudly if either
// the public key or signature is the wrong length.
func VerifyEd25519(pubKey []byte, message []byte, sig []byte) error {
	if len(pubKey) != Ed25519PublicKeyLen {
		return fmt.Errorf("%w: Ed25519 pubkey must be %d bytes, got %d",
			ErrInvalidPublicKey, Ed25519PublicKeyLen, len(pubKey))
	}
	if len(sig) != Ed25519SignatureLen {
		return fmt.Errorf("signatures: Ed25519 signature must be %d bytes, got %d",
			Ed25519SignatureLen, len(sig))
	}
	if !ed25519.Verify(ed25519.PublicKey(pubKey), message, sig) {
		return ErrSignatureVerificationFailed
	}
	return nil
}

// -------------------------------------------------------------------------------------------------
// 5) P-256 verification (for did:key with P-256 multicodec, e.g. passkeys)
// -------------------------------------------------------------------------------------------------

// VerifyP256 verifies an ECDSA signature over the given 32-byte hash against
// a 33-byte compressed P-256 (secp256r1) public key.
//
// Signature is 64-byte raw (R || S). WebAuthn/passkey signatures are typically
// ASN.1-DER encoded; the caller is responsible for decoding before calling
// this function.
func VerifyP256(compressedPub []byte, hash [32]byte, sig []byte) error {
	if len(compressedPub) != CompressedPubkeyLen {
		return fmt.Errorf("%w: P-256 compressed pubkey must be %d bytes, got %d",
			ErrInvalidPublicKey, CompressedPubkeyLen, len(compressedPub))
	}
	if len(sig) != 64 {
		return fmt.Errorf("signatures: P-256 signature must be 64 bytes (R || S), got %d", len(sig))
	}

	curve := elliptic.P256()
	x, y := elliptic.UnmarshalCompressed(curve, compressedPub)
	if x == nil {
		return fmt.Errorf("%w: P-256 compressed pubkey failed to unmarshal", ErrInvalidPublicKey)
	}
	pub := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}

	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:64])
	if r.Sign() == 0 || s.Sign() == 0 {
		return errors.New("signatures: P-256 signature contains zero component")
	}
	if !ecdsa.Verify(pub, hash[:], r, s) {
		return ErrSignatureVerificationFailed
	}
	return nil
}
