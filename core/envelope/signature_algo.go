/*
FILE PATH:

	core/envelope/signature_algo.go

DESCRIPTION:

	Authoritative registry of signature algorithm identifiers and the single
	validator that gates wire-format acceptance. Under v6 this file is the
	only place that enumerates which cryptographic algorithms the protocol
	recognizes on the wire.

KEY ARCHITECTURAL DECISIONS:
  - Algorithm IDs are uint16 with registered values. Allocation is
    additive-only: removing or repurposing an ID is a breaking protocol
    change and must go through the version lifecycle (version_policy.go).
  - No length table. v5 carried a SignatureLengthForAlgorithm lookup
    because the wire format inferred signature length from the algorithm
    tag. v6 carries an explicit sigLen uint32 in the wire (see
    signatures_section.go), which means variable-length signatures
    (JWZ, future BLS aggregates, post-quantum schemes) are purely
    additive — no length table, no disambiguation logic, no ambiguity
    surface.
  - ValidateAlgorithmID is called symmetrically on encode and decode by
    signatures_section.go. Unknown IDs are rejected at both ends; there
    is no path by which a bytes-level entry bearing an unregistered
    algorithm ID can be produced by Serialize or accepted by Deserialize.
  - SigAlgoJWZ (0x0005) is allocated for Polygon ID / Iden3 JWZ proofs
    (ZK proofs over BabyJubJub, variable-length JSON-serialized).
    Verifier implementation lives in a separate DID-method verifier
    (e.g., did:polygonid) registered on VerifierRegistry; this file
    allocates the ID only.

OVERVIEW:

	Consumers call ValidateAlgorithmID(algoID) before encoding a signature
	block or after decoding one. The function is a total map over uint16
	with a fixed registered set. Callers that want to know whether a given
	algorithm uses a fixed or variable signature length ask the algorithm's
	verifier directly — this file does not encode that distinction because
	the wire format no longer depends on it.

KEY DEPENDENCIES:
  - errors (standard library): sentinel error construction
  - fmt (standard library): wrapped error formatting
*/
package envelope

import (
	"errors"
	"fmt"
)

// -------------------------------------------------------------------------------------------------
// 1) Registered algorithm IDs
// -------------------------------------------------------------------------------------------------

// Registered signature algorithm identifiers. Values are permanent.
// Allocation follows a simple rule: the next free uint16. Gaps are not
// reserved for future use; they indicate a past allocation that was
// withdrawn during the version's lifecycle. No such gaps exist at v6.
const (
	// SigAlgoECDSA is ECDSA over secp256k1 with 64-byte raw (R || S)
	// signature over the canonical entry hash. Used by SDK-native signers
	// and KMS-backed signers that produce raw signatures without recovery.
	SigAlgoECDSA uint16 = 0x0001

	// SigAlgoEd25519 is Ed25519 with 64-byte signature over the canonical
	// entry bytes (Ed25519 signs the full message, not a hash).
	SigAlgoEd25519 uint16 = 0x0002

	// SigAlgoEIP191 is ECDSA over secp256k1 with 65-byte Ethereum-format
	// signature (r || s || v) produced by wallet personal_sign / eth_sign
	// over the canonical entry hash wrapped with the EIP-191 v=0x45 prefix.
	SigAlgoEIP191 uint16 = 0x0003

	// SigAlgoEIP712 is ECDSA over secp256k1 with 65-byte Ethereum-format
	// signature (r || s || v) produced by wallet eth_signTypedData_v4
	// against the Ortholog EIP-712 typed-data schema committing to the
	// canonical entry hash.
	SigAlgoEIP712 uint16 = 0x0004

	// SigAlgoJWZ is a JSON Web Zero-Knowledge proof (Iden3 / Polygon ID).
	// Variable-length JSON-serialized ZK proof; length is carried in the
	// wire's sigLen field. Verification is performed by a did:polygonid
	// or did:iden3 verifier registered on the VerifierRegistry.
	SigAlgoJWZ uint16 = 0x0005
)

// -------------------------------------------------------------------------------------------------
// 2) Validation errors
// -------------------------------------------------------------------------------------------------

// ErrUnknownAlgorithmID is returned when a signature algorithm ID is not
// one of the registered values. Wrapped by encode and decode paths with
// contextual information (the offending ID in hex).
var ErrUnknownAlgorithmID = errors.New("envelope: unknown signature algorithm ID")

// -------------------------------------------------------------------------------------------------
// 3) ValidateAlgorithmID — symmetric encode/decode gate
// -------------------------------------------------------------------------------------------------

// ValidateAlgorithmID returns nil if algoID is one of the registered values
// (SigAlgoECDSA, SigAlgoEd25519, SigAlgoEIP191, SigAlgoEIP712, SigAlgoJWZ),
// or a wrapped ErrUnknownAlgorithmID otherwise.
//
// Called on every signature encode and decode by signatures_section.go.
// The asymmetry of accepting one set of IDs on write and a different set
// on read would create a wire-format split; this function's single
// implementation guarantees that cannot happen.
//
// Total function over uint16. Never panics. Never allocates on the happy
// path (the switch falls through to nil without constructing a return
// value).
func ValidateAlgorithmID(algoID uint16) error {
	switch algoID {
	case SigAlgoECDSA, SigAlgoEd25519, SigAlgoEIP191, SigAlgoEIP712, SigAlgoJWZ:
		return nil
	default:
		return fmt.Errorf("%w: 0x%04x", ErrUnknownAlgorithmID, algoID)
	}
}
