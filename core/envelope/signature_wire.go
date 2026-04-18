/*
FILE PATH:

	core/envelope/signature_wire.go

DESCRIPTION:

	Wire format for signature algorithm identification and signature attachment
	to canonical entry bytes. Defines the SigAlgoID namespace and is the single
	authority on which algorithm IDs are acceptable on the wire.

KEY ARCHITECTURAL DECISIONS:
  - Algorithm IDs are uint16 registered values. Adding a new algorithm means
    allocating a new ID and extending ValidateAlgorithmID. Removing or
    changing the meaning of an existing ID is a breaking protocol change.
  - Four algorithms are supported at v5:
    0x0001 ECDSA secp256k1 raw     (R || S,       64 bytes) — SDK signers
    0x0002 Ed25519                 (sig,          64 bytes) — non-EVM keys
    0x0003 ECDSA secp256k1 EIP-191 (r || s || v,  65 bytes) — personal_sign
    0x0004 ECDSA secp256k1 EIP-712 (r || s || v,  65 bytes) — typed-data
  - ValidateAlgorithmID is enforced SYMMETRICALLY on both encode and decode.
    AppendSignature rejects unknown IDs at write time; ReadSignature and
    StripSignature reject them at read time. There is no path by which an
    entry bearing an unregistered algorithm ID can be produced by this
    package and later accepted. Non-permissive by construction.
  - AppendSignature additionally enforces that the supplied signature bytes
    are exactly the length the algorithm requires. A 64-byte signature
    tagged 0x0004 (EIP-712, expects 65) is a programmer bug, not a runtime
    condition — it is rejected at the first opportunity with an explicit
    error rather than encoded into a wire that will later fail to decode.
  - MustAppendSignature is the panic-on-error convenience for callers whose
    algoID and signature length are compile-time constants.
  - StripSignature reverse-engineers the canonical prefix without knowing
    its length up front, by reading the algorithm ID from the trailer and
    using SignatureLengthForAlgorithm to determine the boundary. Ambiguous
    framings (both 64- and 65-byte interpretations valid) are rejected —
    never silently resolved.

OVERVIEW:

	AppendSignature packs [canonical || algo_id_be || sig] into the entry
	wire format, rejecting unregistered IDs or length-mismatched signatures.
	ReadSignature reverses this when the canonical length is known.
	StripSignature reverses it when only the wire is available. The
	algorithm ID is stored big-endian immediately after the canonical bytes;
	signature bytes follow.

KEY DEPENDENCIES:
  - (none beyond standard library)
*/
package envelope

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// -------------------------------------------------------------------------------------------------
// 1) Algorithm ID constants
// -------------------------------------------------------------------------------------------------

// Signature algorithm identifiers. Registered values; do not change meaning.
const (
	// SigAlgoECDSA is ECDSA over secp256k1 with 64-byte raw (R || S)
	// signature over the canonical entry hash. Used by SDK-native signers
	// and KMS-backed signers that produce raw signatures.
	SigAlgoECDSA uint16 = 0x0001

	// SigAlgoEd25519 is Ed25519 with 64-byte signature over the canonical
	// entry bytes (Ed25519 signs the full message, not a hash).
	SigAlgoEd25519 uint16 = 0x0002

	// SigAlgoEIP191 is ECDSA over secp256k1 with 65-byte Ethereum-format
	// signature (r || s || v) produced by wallet personal_sign / eth_sign
	// over the canonical entry hash wrapped with the EIP-191 v=0x45 prefix.
	SigAlgoEIP191 uint16 = 0x0003

	// SigAlgoEIP712 is ECDSA over secp256k1 with 65-byte Ethereum-format
	// signature (r || s || v) produced by wallet eth_signTypedData_v4 against
	// the Ortholog EIP-712 typed-data schema committing to the canonical
	// entry hash.
	SigAlgoEIP712 uint16 = 0x0004
)

// sigLenRaw64 and sigLenEthereum65 are the two distinct signature lengths
// produced under the registered algorithms at v5. Named constants so that
// future additions can be reasoned about by audit rather than by grep.
const (
	sigLenRaw64      = 64
	sigLenEthereum65 = 65
)

// -------------------------------------------------------------------------------------------------
// 2) Errors
// -------------------------------------------------------------------------------------------------

// ErrUnknownAlgorithmID is returned when a signature algorithm ID is not one
// of the registered values. Wrapped by the encode and decode paths with
// contextual information.
var ErrUnknownAlgorithmID = errors.New("envelope: unknown signature algorithm ID")

// ErrSignatureLengthMismatch is returned when a supplied signature's length
// does not match the length required by its algorithm ID.
var ErrSignatureLengthMismatch = errors.New("envelope: signature length does not match algorithm")

// ErrWireTooShort is returned when the wire bytes are too short to contain
// a valid algorithm ID + signature trailer under any registered algorithm.
var ErrWireTooShort = errors.New("envelope: wire too short to contain signature trailer")

// ErrAmbiguousFraming is returned by StripSignature when the trailing bytes
// admit more than one valid interpretation — an encoding collision that
// must be rejected rather than silently resolved.
var ErrAmbiguousFraming = errors.New("envelope: ambiguous signature framing")

// -------------------------------------------------------------------------------------------------
// 3) Validation
// -------------------------------------------------------------------------------------------------

// ValidateAlgorithmID returns nil if algoID is one of the registered values,
// or a wrapped ErrUnknownAlgorithmID otherwise.
//
// Called on every encode and decode. Callers outside this package should
// prefer the higher-level AppendSignature / ReadSignature / StripSignature
// entry points, which compose this check with length enforcement.
func ValidateAlgorithmID(algoID uint16) error {
	switch algoID {
	case SigAlgoECDSA, SigAlgoEd25519, SigAlgoEIP191, SigAlgoEIP712:
		return nil
	default:
		return fmt.Errorf("%w: 0x%04x", ErrUnknownAlgorithmID, algoID)
	}
}

// SignatureLengthForAlgorithm returns the expected signature length in bytes
// for the given algorithm ID, or 0 if the algorithm is not registered.
//
// A return value of 0 means "unknown algorithm." Callers MUST NOT treat 0
// as a valid length — it is a sentinel indicating the algorithm is not part
// of the registered namespace.
func SignatureLengthForAlgorithm(algoID uint16) int {
	switch algoID {
	case SigAlgoECDSA, SigAlgoEd25519:
		return sigLenRaw64
	case SigAlgoEIP191, SigAlgoEIP712:
		return sigLenEthereum65
	}
	return 0
}

// -------------------------------------------------------------------------------------------------
// 4) Encode
// -------------------------------------------------------------------------------------------------

// AppendSignature produces wire-format entry bytes by appending the algorithm
// ID (big-endian uint16) and signature bytes to the canonical entry bytes.
//
// Rejects:
//   - Unregistered algorithm IDs (wraps ErrUnknownAlgorithmID)
//   - Signatures whose length does not match the algorithm's requirement
//     (wraps ErrSignatureLengthMismatch)
//
// The check here is symmetric with the check in ReadSignature: any wire
// bytes this function produces will pass the read-side validation, and
// conversely, any wire bytes that would fail the read-side validation
// cannot be produced by this function.
func AppendSignature(canonical []byte, algoID uint16, sig []byte) ([]byte, error) {
	if err := ValidateAlgorithmID(algoID); err != nil {
		return nil, err
	}
	expected := SignatureLengthForAlgorithm(algoID)
	if len(sig) != expected {
		return nil, fmt.Errorf(
			"%w: algorithm 0x%04x requires %d bytes, got %d",
			ErrSignatureLengthMismatch, algoID, expected, len(sig))
	}

	out := make([]byte, 0, len(canonical)+2+len(sig))
	out = append(out, canonical...)
	var algoBytes [2]byte
	binary.BigEndian.PutUint16(algoBytes[:], algoID)
	out = append(out, algoBytes[:]...)
	out = append(out, sig...)
	return out, nil
}

// MustAppendSignature is the panic-on-error form of AppendSignature. Intended
// for call sites where the algoID is a compile-time constant and the signature
// length is structurally guaranteed — a failure here is a programmer bug, not
// a runtime condition.
//
// Tests and wire-format round-trip helpers are the canonical callers.
// Production entry-building code should prefer AppendSignature and surface
// the error.
func MustAppendSignature(canonical []byte, algoID uint16, sig []byte) []byte {
	out, err := AppendSignature(canonical, algoID, sig)
	if err != nil {
		panic(err)
	}
	return out
}

// -------------------------------------------------------------------------------------------------
// 5) Decode — canonical length known
// -------------------------------------------------------------------------------------------------

// ReadSignature parses the algorithm ID and signature bytes from the tail of
// wire-format entry bytes, given the length of the leading canonical portion.
//
// Rejects unregistered algorithm IDs and length mismatches. Symmetric with
// AppendSignature.
func ReadSignature(wire []byte, canonicalLen int) (algoID uint16, sig []byte, err error) {
	if canonicalLen < 0 {
		return 0, nil, fmt.Errorf("envelope: negative canonicalLen %d", canonicalLen)
	}
	if canonicalLen+2 > len(wire) {
		return 0, nil, fmt.Errorf(
			"%w: wire length %d, canonicalLen %d + 2-byte algo",
			ErrWireTooShort, len(wire), canonicalLen)
	}
	algoID = binary.BigEndian.Uint16(wire[canonicalLen : canonicalLen+2])
	if err := ValidateAlgorithmID(algoID); err != nil {
		return 0, nil, err
	}
	sig = wire[canonicalLen+2:]
	expected := SignatureLengthForAlgorithm(algoID)
	if len(sig) != expected {
		return 0, nil, fmt.Errorf(
			"%w: algorithm 0x%04x requires %d bytes, trailer has %d",
			ErrSignatureLengthMismatch, algoID, expected, len(sig))
	}
	return algoID, sig, nil
}

// -------------------------------------------------------------------------------------------------
// 6) Decode — canonical length unknown
// -------------------------------------------------------------------------------------------------

// StripSignature splits wire-format entry bytes into their three components:
// the canonical prefix, the algorithm ID, and the signature bytes. Inverse
// of AppendSignature.
//
// The signature length is inferred from the algorithm ID encoded immediately
// before the signature bytes. Both 64-byte signature algorithms (SigAlgoECDSA,
// SigAlgoEd25519) and 65-byte ones (SigAlgoEIP191, SigAlgoEIP712) are
// recognized.
//
// Returns an error if:
//   - the wire is too short to contain any valid framing (ErrWireTooShort),
//   - no registered algorithm ID appears at either candidate offset, or
//   - both candidate offsets yield a registered algorithm ID — an encoding
//     collision that MUST be rejected rather than silently resolved to one
//     interpretation (ErrAmbiguousFraming).
func StripSignature(wire []byte) (canonical []byte, algoID uint16, sig []byte, err error) {
	type match struct {
		algoOff int
		algoID  uint16
		sigLen  int
	}
	var matches []match

	for _, sigLen := range []int{sigLenRaw64, sigLenEthereum65} {
		if len(wire) < 2+sigLen {
			continue
		}
		algoOff := len(wire) - sigLen - 2
		id := binary.BigEndian.Uint16(wire[algoOff : algoOff+2])
		if SignatureLengthForAlgorithm(id) == sigLen {
			matches = append(matches, match{algoOff: algoOff, algoID: id, sigLen: sigLen})
		}
	}

	switch len(matches) {
	case 0:
		return nil, 0, nil, fmt.Errorf(
			"%w: %d bytes, no registered algorithm ID at trailer offset",
			ErrWireTooShort, len(wire))
	case 1:
		m := matches[0]
		return wire[:m.algoOff], m.algoID, wire[m.algoOff+2:], nil
	default:
		return nil, 0, nil, fmt.Errorf(
			"%w: both 64-byte and 65-byte interpretations yield registered algorithms",
			ErrAmbiguousFraming)
	}
}
