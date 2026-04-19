/*
FILE PATH:

	crypto/signatures/entry_verify.go

DESCRIPTION:

	SDK-native secp256k1 primitives. Six exports, each tightly scoped:

	  Secp256k1()                   — elliptic.Curve accessor (used by
	                                  elliptic.Marshal call sites in tests)
	  GenerateKey()                 — fresh secp256k1 *ecdsa.PrivateKey
	  ParsePubKey(bytes)            — bytes → *ecdsa.PublicKey
	  PubKeyBytes(pub)              — *ecdsa.PublicKey → 65-byte uncompressed
	  VerifyEntry(hash, sig, pub)   — verify 64-byte raw (R || S) ECDSA sig
	  SignEntry(hash, privkey)      — produce 64-byte low-S raw (R || S) ECDSA sig

	Entry-level multi-sig VERIFICATION (iterating entry.Signatures and
	routing each to a DID-method verifier) lives in did/verifier_registry.go
	as VerifierRegistry.VerifyEntry(entry). It is NOT in this file
	because entry verification depends on the DID method registry, and
	crypto/signatures cannot import did/ without creating a cycle
	(did/creation.go already imports crypto/signatures for key-pair
	creation primitives).

	The two VerifyEntry identifiers do not collide:
	  - signatures.VerifyEntry is a free function in package signatures
	  - (*did.VerifierRegistry).VerifyEntry is a method on a type in
	    package did
	Go's package-qualified identifier scoping keeps them distinct.

KEY ARCHITECTURAL DECISIONS:
  - Curve accessor Secp256k1() returns elliptic.Curve, not the concrete
    decred *KoblitzCurve, so callers (tests, elliptic.Marshal) depend
    on the stdlib interface rather than the decred package type. The
    concrete type still satisfies the interface; the return type just
    hides the dependency from callers.
  - GenerateKey delegates to decred's secp256k1.GeneratePrivateKey and
    converts via ToECDSA(). The resulting *ecdsa.PrivateKey is wired
    with decred's curve implementation, so ecdsa.Sign / ecdsa.Verify
    work on it the same way they work on stdlib P-256 keys.
  - ParsePubKey accepts both 65-byte uncompressed (0x04 prefix) and
    33-byte compressed (0x02/0x03 prefix) forms via decred's parser.
  - PubKeyBytes produces the 65-byte uncompressed form with 0x04
    prefix. Left-pads X and Y to exactly 32 bytes each; big.Int.Bytes()
    omits leading zeros, which would break fixed-width consumers like
    AddressFromPubkey that slice at specific offsets.
  - VerifyEntry enforces 64-byte signature length strictly and rejects
    signatures with zero R or S. Does NOT enforce low-S on verify —
    wallet and KMS-backed signers may produce high-S form legitimately.
  - SignEntry normalizes S to the low half of the curve order.
    Low-S closes the malleability class where (r, s) and (r, n-s)
    both verify but produce distinct byte representations.
  - Wallet-format signatures (65-byte r||s||v) are NOT produced here.
    Wallets produce them externally; tests simulate them via
    tests/web3_helpers_test.go. This file is the SDK-native raw
    64-byte signing path only.

OVERVIEW:

	V6 entry signing flow (SDK-native ECDSA signer):

	  entry, _ := envelope.NewUnsignedEntry(header, payload)
	  hash := sha256.Sum256(envelope.SigningPayload(entry))
	  sig, _ := signatures.SignEntry(hash, privkey)
	  entry.Signatures = []envelope.Signature{{
	      SignerDID: header.SignerDID,
	      AlgoID:    envelope.SigAlgoECDSA,
	      Bytes:     sig,
	  }}
	  _ = entry.Validate()
	  canonical := envelope.Serialize(entry)

	V6 entry verification flow:

	  entry, _ := envelope.Deserialize(canonical)
	  err := registry.VerifyEntry(entry)  // did/verifier_registry.go

	The registry dispatches each entry.Signatures[i] to the DID-method-
	specific verifier, which ultimately calls back into this package's
	VerifyEntry (for 64-byte raw ECDSA) or into verify_primitives.go
	(for Ethereum-format sigs, Ed25519, P-256).

KEY DEPENDENCIES:
  - crypto/ecdsa, crypto/elliptic, crypto/rand, math/big (standard library)
  - github.com/decred/dcrd/dcrec/secp256k1/v4: curve implementation,
    key generation, pubkey parsing
  - (no envelope or did imports — prevents import cycle through did)
*/
package signatures

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// -------------------------------------------------------------------------------------------------
// 1) Errors
// -------------------------------------------------------------------------------------------------

// ErrInvalidRawSignatureLength is returned by VerifyEntry when the supplied
// signature is not exactly 64 bytes. Distinct from ErrInvalidSignatureLength
// (in ethereum_primitives.go) which is specific to the 65-byte
// Ethereum-format requirement.
var ErrInvalidRawSignatureLength = errors.New("signatures: raw ECDSA signature must be 64 bytes (R || S)")

// ErrZeroSignatureComponent is returned by VerifyEntry when R or S is zero.
// Zero components make verification behavior implementation-defined under
// most ECDSA specifications; rejecting them closed is the safe choice.
var ErrZeroSignatureComponent = errors.New("signatures: signature contains zero R or S component")

// -------------------------------------------------------------------------------------------------
// 2) Secp256k1 — elliptic.Curve accessor
// -------------------------------------------------------------------------------------------------

// Secp256k1 returns the secp256k1 curve as an elliptic.Curve. Callers use
// this with stdlib helpers like elliptic.Marshal / elliptic.Unmarshal and
// any code that needs an elliptic.Curve value for point operations.
//
// Wraps decred's secp256k1.S256(), which returns a *KoblitzCurve that
// satisfies elliptic.Curve.
//
// Callers:
//   - tests/pre_test.go (elliptic.Marshal call sites)
//   - tests/phase6_part_a_test.go (curve parameter for ECDSA setup)
//   - tests/phase6_part_b_test.go (elliptic.Marshal for recipient keys)
func Secp256k1() elliptic.Curve {
	return secp256k1.S256()
}

// -------------------------------------------------------------------------------------------------
// 3) GenerateKey — fresh secp256k1 keypair
// -------------------------------------------------------------------------------------------------

// GenerateKey produces a fresh secp256k1 *ecdsa.PrivateKey using
// crypto/rand as the entropy source. The returned key's Curve field is
// decred's secp256k1 implementation, so it works directly with stdlib
// ecdsa.Sign / ecdsa.Verify and with this package's SignEntry /
// VerifyEntry.
//
// Equivalent to did:key secp256k1 generation at the primitive level —
// did/creation.go GenerateDIDKeySecp256k1 calls this and then wraps the
// pubkey in the did:key format.
//
// Callers:
//   - did/creation.go GenerateDIDKeySecp256k1 (wrapping for did:key)
//   - did/creation.go GenerateRawKey (raw keypair for tests + delegation)
//   - any test or bootstrap code needing a fresh SDK-native keypair
func GenerateKey() (*ecdsa.PrivateKey, error) {
	priv, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("signatures: generate secp256k1 key: %w", err)
	}
	return priv.ToECDSA(), nil
}

// -------------------------------------------------------------------------------------------------
// 4) ParsePubKey — bytes to *ecdsa.PublicKey (secp256k1)
// -------------------------------------------------------------------------------------------------

// ParsePubKey parses secp256k1 public key bytes (either 65-byte uncompressed
// with 0x04 prefix, or 33-byte compressed with 0x02/0x03 prefix) into an
// *ecdsa.PublicKey whose Curve field is decred's secp256k1 implementation.
//
// The returned key is compatible with stdlib ecdsa.Sign / ecdsa.Verify
// because decred's secp256k1 curve satisfies elliptic.Curve.
//
// Callers:
//   - crypto/signatures/witness_verify.go (verifyECDSACosignatures)
//   - crypto/signatures/verify_primitives.go (VerifySecp256k1Compressed)
//   - did/key_verifier.go for did:key secp256k1 keys
func ParsePubKey(bytes []byte) (*ecdsa.PublicKey, error) {
	if len(bytes) == 0 {
		return nil, errors.New("signatures: ParsePubKey requires non-empty bytes")
	}
	pk, err := secp256k1.ParsePubKey(bytes)
	if err != nil {
		return nil, fmt.Errorf("signatures: parse secp256k1 pubkey: %w", err)
	}
	return pk.ToECDSA(), nil
}

// -------------------------------------------------------------------------------------------------
// 5) PubKeyBytes — *ecdsa.PublicKey to 65-byte uncompressed
// -------------------------------------------------------------------------------------------------

// PubKeyBytes serializes an *ecdsa.PublicKey (secp256k1) to its 65-byte
// uncompressed wire form: 0x04 || X (32 bytes, BE, zero-padded) ||
// Y (32 bytes, BE, zero-padded).
//
// Fixed-width serialization is load-bearing: consumers like
// AddressFromPubkey in ethereum_primitives.go take slices at specific
// byte offsets (e.g., pub[1:] to skip the 0x04 prefix). big.Int.Bytes()
// omits leading zero bytes, which would shift those offsets for keys
// whose X or Y coordinate has a high-bit-zero MSB.
//
// Callers:
//   - tests/web3_helpers_test.go didPKHForKey
//   - did/creation.go GenerateDIDKeySecp256k1 (compressing via 65-byte form)
//   - did/creation.go GenerateRawKey (raw keypair + 65-byte pubkey)
//   - any code deriving Ethereum addresses from an ecdsa.PublicKey
func PubKeyBytes(pub *ecdsa.PublicKey) []byte {
	if pub == nil || pub.X == nil || pub.Y == nil {
		// Empty-but-non-nil slice is safer than a panic here — the
		// caller's next step (AddressFromPubkey) will reject an
		// all-zero prefix byte and surface a clear error.
		return make([]byte, 65)
	}
	out := make([]byte, 65)
	out[0] = 0x04
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()
	// Left-pad to 32 bytes each. For a 32-byte value xBytes, the copy
	// lands at out[1:33]. For a shorter value (e.g., 30 bytes due to
	// leading-zero stripping), the copy lands at out[3:33], leaving
	// out[1:3] as the zero initial bytes we want.
	copy(out[33-len(xBytes):33], xBytes)
	copy(out[65-len(yBytes):65], yBytes)
	return out
}

// -------------------------------------------------------------------------------------------------
// 6) VerifyEntry — 64-byte raw (R || S) ECDSA verification
// -------------------------------------------------------------------------------------------------

// VerifyEntry verifies a 64-byte raw ECDSA signature (R || S) over the
// given 32-byte digest against the provided public key.
//
// Signature layout:
//   - bytes [0:32] = R (big-endian)
//   - bytes [32:64] = S (big-endian)
//
// Rejects:
//   - nil public key (wrapped ErrInvalidPublicKey)
//   - signature length != 64 (ErrInvalidRawSignatureLength)
//   - R or S equal to zero (ErrZeroSignatureComponent)
//   - cryptographic verification failure (ErrSignatureVerificationFailed)
//
// Does NOT enforce low-S on the verify path. Wallet signatures and
// KMS-backed signers may not produce low-S form; rejecting high-S on
// verify would reject otherwise-valid signatures. Low-S is enforced on
// SignEntry's output to prevent malleability-based replay of SDK-produced
// signatures, but the verify path accepts either form.
//
// Callers:
//   - crypto/signatures/witness_verify.go verifyECDSACosignatures
//   - crypto/signatures/verify_primitives.go VerifySecp256k1Compressed
//   - did/key_verifier.go (via VerifySecp256k1Compressed) for did:key
func VerifyEntry(hash [32]byte, sig []byte, pub *ecdsa.PublicKey) error {
	if pub == nil {
		return fmt.Errorf("%w: nil public key", ErrInvalidPublicKey)
	}
	if len(sig) != 64 {
		return fmt.Errorf("%w: got %d bytes", ErrInvalidRawSignatureLength, len(sig))
	}

	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:64])
	if r.Sign() == 0 || s.Sign() == 0 {
		return ErrZeroSignatureComponent
	}

	if !ecdsa.Verify(pub, hash[:], r, s) {
		return ErrSignatureVerificationFailed
	}
	return nil
}

// -------------------------------------------------------------------------------------------------
// 7) SignEntry — SDK-native raw ECDSA signing with low-S normalization
// -------------------------------------------------------------------------------------------------

// SignEntry produces a 64-byte low-S raw ECDSA signature (R || S) over
// the given 32-byte hash using the provided secp256k1 private key.
//
// The hash input is expected to be sha256(envelope.SigningPayload(entry))
// for v6 entry signing. Callers can also use SignEntry for other 32-byte
// digests (e.g., signed-request envelope hashes in
// exchange/auth/signed_request.go).
//
// Low-S normalization: secp256k1 signatures are malleable — both (r, s)
// and (r, n-s mod n) verify against the same public key over the same
// digest. We normalize S to the low half of the curve order by replacing
// any high-S result with its low-S counterpart. This ensures signature
// byte values are deterministic for a given (key, hash) pair up to the
// RFC 6979 nonce, preventing malleability-based replay across distinct
// binary representations of the semantically identical signature.
//
// Output format: exactly 64 bytes. R in bytes [0:32], S in bytes [32:64],
// both big-endian, zero-padded on the left to 32 bytes each.
//
// Errors:
//   - nil privkey → explicit error (programmer mistake)
//   - RNG failure inside ecdsa.Sign → wrapped
//   - scalar exceeds 32 bytes → explicit error (indicates the privkey is
//     not on a 256-bit curve, i.e., programmer wired the wrong key type)
func SignEntry(hash [32]byte, privkey *ecdsa.PrivateKey) ([]byte, error) {
	if privkey == nil {
		return nil, errors.New("signatures: SignEntry requires non-nil private key")
	}

	r, s, err := ecdsa.Sign(rand.Reader, privkey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("signatures: ECDSA sign: %w", err)
	}

	// Normalize S to the low half of the curve order.
	curveOrder := privkey.Curve.Params().N
	halfOrder := new(big.Int).Rsh(curveOrder, 1)
	if s.Cmp(halfOrder) > 0 {
		s = new(big.Int).Sub(curveOrder, s)
	}

	// Fixed-width 32-byte serialization. big.Int.Bytes() omits leading
	// zero bytes; the wire format requires exactly 32 bytes per scalar,
	// so we left-pad into a zero-initialized buffer.
	out := make([]byte, 64)
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	if len(rBytes) > 32 || len(sBytes) > 32 {
		return nil, fmt.Errorf("signatures: scalar exceeds 32 bytes (r=%d, s=%d) — curve mismatch?",
			len(rBytes), len(sBytes))
	}
	copy(out[32-len(rBytes):32], rBytes)
	copy(out[64-len(sBytes):64], sBytes)
	return out, nil
}
