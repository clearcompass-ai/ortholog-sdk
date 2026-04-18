/*
FILE PATH:
    did/key_verifier.go

DESCRIPTION:
    SignatureVerifier implementation for did:key. Parses the multicodec-
    encoded public key out of the identifier and dispatches to the
    appropriate per-curve verification primitive.

KEY ARCHITECTURAL DECISIONS:
    - did:key verification is pubkey-based. The public key lives in the
      identifier itself. No resolution, no ambiguity, no key selection.
    - Three curves are supported, each with a strict (curve, algoID) pairing:
        Ed25519    requires SigAlgoEd25519 only
        secp256k1  requires SigAlgoECDSA only (raw 64-byte R || S)
        P-256      requires SigAlgoECDSA only (raw 64-byte R || S)
      EIP-191 and EIP-712 are REJECTED for did:key. Those algorithms are
      address-based (ecrecover), but did:key has no address — it has a
      pubkey. Mixing them is a category error, so we fail loudly.
    - Ed25519 signs the full message; secp256k1 and P-256 sign a 32-byte
      hash. The verifier enforces the correct message shape per curve.
      For the hash-based curves, message MUST be exactly 32 bytes.
    - Signature length enforcement is delegated to the primitive functions
      (they each know their expected length) — we do not duplicate that
      check here.

OVERVIEW:
    Given did:key:z6Mk..., message, sig, algoID:
        1. ParseDIDKey -> (pubKey bytes, verificationMethodType string)
        2. Switch on verificationMethodType:
            Ed25519     -> require algoID == SigAlgoEd25519, verify
            Secp256k1   -> require algoID == SigAlgoECDSA, verify against hash
            P-256       -> require algoID == SigAlgoECDSA, verify against hash
        3. Any mismatch between curve and algoID fails loudly.

KEY DEPENDENCIES:
    - did/key_resolver.go: ParseDIDKey, verification method type constants
    - crypto/signatures/verify_primitives.go: per-curve primitives
    - core/envelope/signature_wire.go: SigAlgo* constants
*/
package did

import (
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
)

// -------------------------------------------------------------------------------------------------
// 1) Constants
// -------------------------------------------------------------------------------------------------

// keyHashedMessageLen is the required message length for hash-based curves
// under did:key (secp256k1 and P-256). The message is the 32-byte canonical
// entry hash.
const keyHashedMessageLen = 32

// -------------------------------------------------------------------------------------------------
// 2) KeyVerifier
// -------------------------------------------------------------------------------------------------

// KeyVerifier verifies signatures for did:key identifiers by parsing the
// embedded public key and dispatching on curve type.
type KeyVerifier struct{}

// NewKeyVerifier returns a did:key signature verifier.
func NewKeyVerifier() *KeyVerifier {
	return &KeyVerifier{}
}

// Verify verifies sig as a signature produced by the holder of did over
// message, using the algorithm identified by algoID.
//
// The expected (curve, algoID) pairs are:
//   Ed25519   + SigAlgoEd25519 : sig over full message bytes
//   secp256k1 + SigAlgoECDSA   : sig over 32-byte message (canonical hash)
//   P-256     + SigAlgoECDSA   : sig over 32-byte message (canonical hash)
//
// Any other combination returns ErrAlgorithmNotSupported.
func (v *KeyVerifier) Verify(did string, message []byte, sig []byte, algoID uint16) error {
	pubKey, vmType, err := ParseDIDKey(did)
	if err != nil {
		return err
	}

	switch vmType {

	case VerificationMethodEd25519:
		if algoID != envelope.SigAlgoEd25519 {
			return fmt.Errorf(
				"%w: did:key Ed25519 requires SigAlgoEd25519 (0x0002), got 0x%04x",
				ErrAlgorithmNotSupported, algoID)
		}
		return signatures.VerifyEd25519(pubKey, message, sig)

	case VerificationMethodSecp256k1:
		if algoID != envelope.SigAlgoECDSA {
			return fmt.Errorf(
				"%w: did:key secp256k1 requires SigAlgoECDSA (0x0001), got 0x%04x",
				ErrAlgorithmNotSupported, algoID)
		}
		if len(message) != keyHashedMessageLen {
			return fmt.Errorf(
				"did/key: secp256k1 message must be %d bytes (canonical hash), got %d",
				keyHashedMessageLen, len(message))
		}
		var hash [keyHashedMessageLen]byte
		copy(hash[:], message)
		return signatures.VerifySecp256k1Compressed(pubKey, hash, sig)

	case VerificationMethodP256:
		if algoID != envelope.SigAlgoECDSA {
			return fmt.Errorf(
				"%w: did:key P-256 requires SigAlgoECDSA (0x0001), got 0x%04x",
				ErrAlgorithmNotSupported, algoID)
		}
		if len(message) != keyHashedMessageLen {
			return fmt.Errorf(
				"did/key: P-256 message must be %d bytes (canonical hash), got %d",
				keyHashedMessageLen, len(message))
		}
		var hash [keyHashedMessageLen]byte
		copy(hash[:], message)
		return signatures.VerifyP256(pubKey, hash, sig)

	default:
		return fmt.Errorf(
			"did/key: internal: ParseDIDKey returned unsupported verification type %q",
			vmType)
	}
}
