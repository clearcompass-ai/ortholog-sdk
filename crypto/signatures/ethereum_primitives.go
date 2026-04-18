/*
FILE PATH:
    crypto/signatures/ethereum_primitives.go

DESCRIPTION:
    Ethereum-compatible cryptographic primitives: Keccak256 hashing, secp256k1
    public key recovery from signatures, and Ethereum address derivation.

KEY ARCHITECTURAL DECISIONS:
    - Keccak256 via golang.org/x/crypto/sha3.NewLegacyKeccak256. This is the
      original Keccak (pre-SHA-3 standardization) which Ethereum uses. SHA3-256
      produces different output and is NOT compatible.
    - Signature recovery via github.com/decred/dcrd/dcrec/secp256k1/v4. Chosen
      over go-ethereum/crypto to avoid pulling the entire Ethereum client as a
      dependency. Decred's implementation is the upstream for btcec/v2 and is
      battle-tested.
    - Ethereum signature format is 65 bytes: r (32) || s (32) || v (1). v is
      either 0/1 or 27/28 depending on convention. We accept both.
    - Address is last 20 bytes of Keccak256(uncompressed_pubkey[1:]). The 0x04
      uncompressed prefix byte is dropped before hashing.
    - All functions fail loudly on malformed input. No silent fallbacks.

OVERVIEW:
    Three primitives compose the Ethereum signature verification path:
        1. Keccak256(bytes) -> [32]byte            (used in EIP-191 / EIP-712)
        2. RecoverSecp256k1(digest, sig65) -> pub  (ecrecover)
        3. AddressFromPubkey(uncompressed) -> [20]byte
    The did:pkh verifier composes all three:
        digest    := eip191 or eip712 over canonical hash
        pub       := RecoverSecp256k1(digest, signature)
        address   := AddressFromPubkey(pub)
        compare address to the one encoded in did:pkh:eip155:1:0x...

KEY DEPENDENCIES:
    - golang.org/x/crypto/sha3:             Keccak256 legacy variant
    - github.com/decred/dcrd/dcrec/secp256k1/v4: Curve operations + recovery
*/
package signatures

import (
	"errors"
	"fmt"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	decredecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

// -------------------------------------------------------------------------------------------------
// 1) Errors
// -------------------------------------------------------------------------------------------------

// ErrInvalidSignatureLength is returned when an Ethereum-format signature is
// not exactly 65 bytes (r || s || v).
var ErrInvalidSignatureLength = errors.New("signatures/ethereum: signature must be 65 bytes (r || s || v)")

// ErrInvalidRecoveryID is returned when v is not 0, 1, 27, or 28.
var ErrInvalidRecoveryID = errors.New("signatures/ethereum: invalid recovery id (v must be 0, 1, 27, or 28)")

// ErrInvalidUncompressedPubkey is returned when pubkey bytes are not a valid
// 65-byte uncompressed secp256k1 point.
var ErrInvalidUncompressedPubkey = errors.New("signatures/ethereum: invalid uncompressed public key (must be 65 bytes, 0x04 prefix)")

// -------------------------------------------------------------------------------------------------
// 2) Constants
// -------------------------------------------------------------------------------------------------

// UncompressedPubkeyLen is the length of a secp256k1 uncompressed public key
// with the 0x04 prefix byte.
const UncompressedPubkeyLen = 65

// CompressedPubkeyLen is the length of a secp256k1 compressed public key
// (0x02 or 0x03 prefix + 32-byte X coordinate).
const CompressedPubkeyLen = 33

// EthereumAddressLen is the length of an Ethereum address.
const EthereumAddressLen = 20

// EthereumSignatureLen is the length of an Ethereum signature (r || s || v).
const EthereumSignatureLen = 65

// -------------------------------------------------------------------------------------------------
// 3) Keccak256
// -------------------------------------------------------------------------------------------------

// Keccak256 computes the legacy Keccak-256 hash used by Ethereum.
//
// NOTE: This is NOT SHA3-256. Ethereum uses the pre-standardization Keccak
// variant. Using sha3.New256() instead would produce different hashes and
// break signature verification.
func Keccak256(data ...[]byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	for _, d := range data {
		// sha3.Hash.Write never returns an error per the stdlib contract.
		_, _ = h.Write(d)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// -------------------------------------------------------------------------------------------------
// 4) Signature recovery (ecrecover)
// -------------------------------------------------------------------------------------------------

// RecoverSecp256k1 recovers the uncompressed 65-byte public key from an
// Ethereum-format signature (r || s || v) over a 32-byte digest.
//
// v may be 0, 1, 27, or 28. Values >= 27 are normalized by subtracting 27.
//
// Returns the 65-byte uncompressed public key (0x04 || X || Y).
func RecoverSecp256k1(digest [32]byte, sig []byte) ([]byte, error) {
	if len(sig) != EthereumSignatureLen {
		return nil, fmt.Errorf("%w: got %d bytes", ErrInvalidSignatureLength, len(sig))
	}

	v := sig[64]
	if v >= 27 {
		v -= 27
	}
	if v > 1 {
		return nil, fmt.Errorf("%w: got %d", ErrInvalidRecoveryID, sig[64])
	}

	// Decred's RecoverCompact expects: [v+27 || r || s] (65 bytes).
	// This is the Bitcoin compact signature convention, which differs from
	// Ethereum's [r || s || v] byte ordering.
	compact := make([]byte, 65)
	compact[0] = v + 27
	copy(compact[1:33], sig[0:32])
	copy(compact[33:65], sig[32:64])

	pub, _, err := decredecdsa.RecoverCompact(compact, digest[:])
	if err != nil {
		return nil, fmt.Errorf("signatures/ethereum: recover: %w", err)
	}

	return pub.SerializeUncompressed(), nil
}

// -------------------------------------------------------------------------------------------------
// 5) Address derivation
// -------------------------------------------------------------------------------------------------

// AddressFromPubkey derives an Ethereum address from a 65-byte uncompressed
// secp256k1 public key. The address is the last 20 bytes of
// Keccak256(pubkey_without_0x04_prefix).
//
// Input MUST be 65 bytes with a 0x04 prefix byte. Any other format is
// rejected with ErrInvalidUncompressedPubkey.
func AddressFromPubkey(pub []byte) ([EthereumAddressLen]byte, error) {
	var out [EthereumAddressLen]byte
	if len(pub) != UncompressedPubkeyLen || pub[0] != 0x04 {
		return out, ErrInvalidUncompressedPubkey
	}
	h := Keccak256(pub[1:])
	copy(out[:], h[12:])
	return out, nil
}

// -------------------------------------------------------------------------------------------------
// 6) Public key compression helpers
// -------------------------------------------------------------------------------------------------

// CompressSecp256k1Pubkey compresses a 65-byte uncompressed secp256k1 public
// key into 33-byte compressed form (used in did:key encoding).
func CompressSecp256k1Pubkey(uncompressed []byte) ([]byte, error) {
	if len(uncompressed) != UncompressedPubkeyLen || uncompressed[0] != 0x04 {
		return nil, ErrInvalidUncompressedPubkey
	}
	pub, err := secp256k1.ParsePubKey(uncompressed)
	if err != nil {
		return nil, fmt.Errorf("signatures/ethereum: parse uncompressed: %w", err)
	}
	return pub.SerializeCompressed(), nil
}

// DecompressSecp256k1Pubkey decompresses a 33-byte compressed secp256k1 public
// key into 65-byte uncompressed form (for use with ecdsa.PublicKey).
func DecompressSecp256k1Pubkey(compressed []byte) ([]byte, error) {
	if len(compressed) != CompressedPubkeyLen {
		return nil, fmt.Errorf("signatures/ethereum: compressed pubkey must be %d bytes, got %d",
			CompressedPubkeyLen, len(compressed))
	}
	pub, err := secp256k1.ParsePubKey(compressed)
	if err != nil {
		return nil, fmt.Errorf("signatures/ethereum: parse compressed: %w", err)
	}
	return pub.SerializeUncompressed(), nil
}
