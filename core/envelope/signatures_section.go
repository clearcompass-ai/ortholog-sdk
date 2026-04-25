/*
FILE PATH:

	core/envelope/signatures_section.go

DESCRIPTION:

	Wire-format codec for the signatures section that Serialize appends
	to every v6 canonical entry. Defines the Signature struct and the
	encode/decode helpers that Serialize and Deserialize invoke.

KEY ARCHITECTURAL DECISIONS:
  - The signatures section is length-prefixed at every level. uint16
    signature count, uint16 DID length, uint16 algoID, uint32 sig
    length. No length inference from content — v5's length-by-tag
    design created an ambiguity surface that v6 eliminates by
    construction.
  - Explicit per-sig length field (uint32) admits variable-length
    algorithms without any wire format change. SigAlgoJWZ (Polygon ID,
    1-4KB typical) fits natively. Future algorithms are purely
    additive: allocate an algoID in signature_algo.go, register a
    verifier on VerifierRegistry, done.
  - MaxSignatureBytes caps per-signature byte length at 48 KiB. Rationale:
    Tessera bundle ceiling is 65535 bytes for the whole entry
    (c2sp.org/tlog-tiles uint16 prefix). A realistic entry uses 1-2 KB
    for header + payload, leaving ~63 KiB for signatures. A single sig
    capped at 48 KiB admits the largest realistic JWZ proof (4 KB) with
    room for cosignatures, while preventing pathological one-sig entries
    from exhausting the bundle budget.
  - MaxSignaturesPerEntry caps the signature list at 64. Entry-level
    multi-sig (user + court cosign + witness attestation) fits
    comfortably; the cap prevents DoS via unbounded sig-list expansion
    and aligns with the 64-signer limit on witness cosignature tree
    heads (witness_verify.go scheme).
  - DID field validation: non-empty, ASCII, length-bounded. Consistent
    with validateHeaderForWrite's SignerDID checks in serialize.go.
    DIDs are ASCII per W3C spec; non-ASCII is a malformed input.
  - Decode is strict. Unknown algoIDs reject. Length mismatches reject.
    Zero-sig sections reject (entries without signatures are invalid;
    see serialize.go Validate invariant). Overlong sections reject.
    There is no forward-compatibility skip-unknown semantics at v6 —
    the section parser is a total parser over its input, and any byte
    it cannot interpret is a bug it surfaces immediately.
  - Insertion order preservation. Signatures are serialized in slice
    order and round-trip preserving that order. The protocol semantics
    treat Signatures[0] as the primary signer (equal to Header.SignerDID
    by invariant); subsequent entries are cosigners in submitter-declared
    order. No canonicalizing sort — reordering would defeat the
    "primary signer first" invariant.

OVERVIEW:

	On encode: Serialize calls AppendSignaturesSection(buf, sigs) after
	the payload. Each Signature contributes [uint16 didLen || did ||
	uint16 algoID || uint32 sigLen || sig]. The section is prefixed with
	a uint16 signature count.

	On decode: Deserialize calls ReadSignaturesSection(region) on the
	bytes after the payload. Returns []Signature or a wrapped error.
	The section MUST consume the region exactly — trailing bytes are
	a framing error, not a forward-compat signal.

	The SigningPayload of an entry (preamble + header + payload) is what
	each signer signs. Serialize(entry) returns SigningPayload(entry) ||
	signaturesSection(entry.Signatures). The Merkle leaf hash
	(tessera_compat.EntryLeafHash) therefore commits to both the signing
	payload and the signatures present at submission — the transparency
	property v5 silently lacked.

KEY DEPENDENCIES:
  - signature_algo.go: ValidateAlgorithmID gates every algoID on both
    encode and decode.
  - bytes, encoding/binary, errors, fmt, io (standard library).
*/
package envelope

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// -------------------------------------------------------------------------------------------------
// 1) Signature struct
// -------------------------------------------------------------------------------------------------

// Signature carries a single cryptographic proof over an entry's
// SigningPayload. Every v6 entry carries at least one; entries with
// cosignatures carry multiple (user primary + court cosign + witness
// attestation, in submitter-declared order).
//
// Invariant enforced by Entry.Validate: Signatures[0].SignerDID must equal
// Entry.Header.SignerDID. The primary signature is from the authorizing
// party; additional signatures are cosigners.
type Signature struct {
	// SignerDID is the DID whose key produced this signature. For
	// Signatures[0] this equals Header.SignerDID by invariant. For
	// cosignatures, this is the cosigner's DID (e.g., did:pkh for a
	// court key, did:polygonid for a ZK-identity cosigner).
	//
	// Non-empty, ASCII, length-bounded by MaxSignerDIDLen. DIDs are ASCII
	// per W3C spec.
	SignerDID string

	// AlgoID is one of the registered SigAlgo* constants. Validated at
	// encode and decode by ValidateAlgorithmID.
	AlgoID uint16

	// Bytes is the signature's wire bytes. Length semantics are
	// algorithm-specific (64 bytes for raw ECDSA/Ed25519, 65 bytes for
	// EIP-191/EIP-712, variable for JWZ). The wire carries an explicit
	// length, so this field is not length-constrained by algorithm here.
	//
	// Capped at MaxSignatureBytes (48 KiB) to prevent bundle-size
	// exhaustion.
	Bytes []byte
}

// -------------------------------------------------------------------------------------------------
// 2) Section caps and framing constants
// -------------------------------------------------------------------------------------------------

const (
	// MaxSignerDIDLen caps the DID string length at 2048 bytes. DIDs in
	// practice are well under 200 bytes (did:pkh:eip155:1:0x...40hex is
	// ~60 bytes; did:polygonid identifiers are ~80 bytes; did:web paths
	// can be longer but rarely exceed 512). The cap is defensive, not
	// typical.
	MaxSignerDIDLen = 2048

	// MaxSignatureBytes caps per-signature byte length at 48 KiB. See
	// architectural decision note at file head.
	MaxSignatureBytes = 49152

	// MaxSignaturesPerEntry caps the signature list length at 64.
	// Production entries carry 1-3 signatures; the cap is a DoS guard.
	MaxSignaturesPerEntry = 64
)

// -------------------------------------------------------------------------------------------------
// 3) Section framing errors
// -------------------------------------------------------------------------------------------------

var (
	// ErrMalformedSignaturesSection is the parent error for any
	// section-level decode failure. Wraps specific sub-errors for
	// diagnostics.
	ErrMalformedSignaturesSection = errors.New("envelope: malformed signatures section")

	// ErrEmptySignatureList is returned when a decoded section carries
	// zero signatures. v7 entries must have at least one signature;
	// a zero-count section is rejected at the wire level.
	ErrEmptySignatureList = errors.New("envelope: signatures section has zero signatures")

	// ErrTooManySignatures is returned when a decoded section carries
	// more than MaxSignaturesPerEntry signatures.
	ErrTooManySignatures = errors.New("envelope: signatures section exceeds MaxSignaturesPerEntry")

	// ErrSignatureBytesTooLarge is returned when an individual signature's
	// length exceeds MaxSignatureBytes.
	ErrSignatureBytesTooLarge = errors.New("envelope: signature bytes exceed MaxSignatureBytes")

	// ErrSignerDIDEmpty is returned when a decoded signature carries an
	// empty SignerDID.
	ErrSignerDIDEmpty = errors.New("envelope: signature SignerDID is empty")

	// ErrSignatureSignerDIDTooLong is returned when a Signature's
	// SignerDID exceeds MaxSignerDIDLen. Distinct from
	// ErrHeaderSignerDIDTooLong (serialize.go), which fires for the
	// ControlHeader.SignerDID at write-time validation.
	ErrSignatureSignerDIDTooLong = errors.New("envelope: signature SignerDID exceeds MaxSignerDIDLen")
	// ErrSignerDIDNonASCII is returned when a decoded signature's SignerDID
	// contains non-ASCII bytes.
	ErrSignerDIDNonASCII = errors.New("envelope: signature SignerDID contains non-ASCII bytes")

	// ErrTrailingBytes is returned when the signatures section has bytes
	// remaining after the declared signature count is consumed. There is
	// no forward-compat skip semantics at v6.
	ErrTrailingBytes = errors.New("envelope: signatures section has trailing bytes after declared count")
)

// -------------------------------------------------------------------------------------------------
// 4) Validate — pre-encode invariant check
// -------------------------------------------------------------------------------------------------

// validateSignatureForEncode checks a Signature's fields before the
// section encoder writes them to the wire. Rejects empty DIDs, non-ASCII
// DIDs, overlong DIDs, unregistered algoIDs, and overlong sig bytes.
//
// Symmetric with the decode-side checks in readSignature: any Signature
// that validates here produces wire bytes that will decode successfully,
// and any decoded Signature has fields that satisfy these invariants.
func validateSignatureForEncode(s Signature) error {
	if s.SignerDID == "" {
		return ErrSignerDIDEmpty
	}
	if len(s.SignerDID) > MaxSignerDIDLen {
		return fmt.Errorf("%w: %d > %d", ErrSignatureSignerDIDTooLong, len(s.SignerDID), MaxSignerDIDLen)
	}
	if !isASCII(s.SignerDID) {
		return ErrSignerDIDNonASCII
	}
	if err := ValidateAlgorithmID(s.AlgoID); err != nil {
		return err
	}
	if len(s.Bytes) > MaxSignatureBytes {
		return fmt.Errorf("%w: %d > %d", ErrSignatureBytesTooLarge, len(s.Bytes), MaxSignatureBytes)
	}
	return nil
}

// -------------------------------------------------------------------------------------------------
// 5) Encode — AppendSignaturesSection
// -------------------------------------------------------------------------------------------------

// AppendSignaturesSection appends the signatures section to buf and returns
// the resulting slice. Section layout:
//
//	[uint16 count] [Signature]*
//
// Each Signature:
//
//	[uint16 didLen] [did bytes] [uint16 algoID] [uint32 sigLen] [sig bytes]
//
// Returns an error if any signature fails validateSignatureForEncode, if
// the list is empty, or if the list exceeds MaxSignaturesPerEntry. A
// returned error means buf is unmodified (no partial section is written).
//
// Callers: core/envelope/serialize.go Serialize.
func AppendSignaturesSection(buf []byte, sigs []Signature) ([]byte, error) {
	if len(sigs) == 0 {
		return nil, ErrEmptySignatureList
	}
	if len(sigs) > MaxSignaturesPerEntry {
		return nil, fmt.Errorf("%w: %d > %d", ErrTooManySignatures, len(sigs), MaxSignaturesPerEntry)
	}

	// Validate all signatures before writing any bytes. This preserves
	// the invariant that a failure returns buf unmodified.
	for i, s := range sigs {
		if err := validateSignatureForEncode(s); err != nil {
			return nil, fmt.Errorf("signature[%d]: %w", i, err)
		}
	}

	// Size estimate: 2 (count) + per-sig (2 + didLen + 2 + 4 + sigLen).
	total := 2
	for _, s := range sigs {
		total += 2 + len(s.SignerDID) + 2 + 4 + len(s.Bytes)
	}
	out := make([]byte, 0, len(buf)+total)
	out = append(out, buf...)

	out = binary.BigEndian.AppendUint16(out, uint16(len(sigs)))
	for _, s := range sigs {
		out = binary.BigEndian.AppendUint16(out, uint16(len(s.SignerDID)))
		out = append(out, s.SignerDID...)
		out = binary.BigEndian.AppendUint16(out, s.AlgoID)
		out = binary.BigEndian.AppendUint32(out, uint32(len(s.Bytes)))
		out = append(out, s.Bytes...)
	}
	return out, nil
}

// -------------------------------------------------------------------------------------------------
// 6) Decode — ReadSignaturesSection
// -------------------------------------------------------------------------------------------------

// ReadSignaturesSection parses a v6 signatures section from the given
// region (the bytes after the payload in a canonical entry). The region
// MUST be exactly the signatures section — trailing bytes produce
// ErrTrailingBytes.
//
// Returns a non-nil []Signature on success (never returns a nil slice
// with nil error; v7 entries always have at least one signature).
//
// Callers: core/envelope/serialize.go Deserialize.
func ReadSignaturesSection(region []byte) ([]Signature, error) {
	r := bytes.NewReader(region)

	var count uint16
	if err := binary.Read(r, binary.BigEndian, &count); err != nil {
		return nil, fmt.Errorf("%w: reading count: %v", ErrMalformedSignaturesSection, err)
	}
	if count == 0 {
		return nil, ErrEmptySignatureList
	}
	if int(count) > MaxSignaturesPerEntry {
		return nil, fmt.Errorf("%w: %d > %d", ErrTooManySignatures, count, MaxSignaturesPerEntry)
	}

	sigs := make([]Signature, count)
	for i := range sigs {
		s, err := readSignature(r)
		if err != nil {
			return nil, fmt.Errorf("signature[%d]: %w", i, err)
		}
		sigs[i] = s
	}

	// Gate: muEnableCanonicalOrdering
	// (serialize_mutation_switches.go). Off admits trailing bytes
	// after the signatures section; two distinct byte sequences
	// would deserialize to the same Entry, breaking the canonical-
	// form contract that hashing the entry produces a unique
	// identity.
	if muEnableCanonicalOrdering {
		if r.Len() != 0 {
			return nil, fmt.Errorf("%w: %d bytes remaining after %d signatures", ErrTrailingBytes, r.Len(), count)
		}
	}

	return sigs, nil
}

// readSignature decodes a single Signature from the reader. Validates
// every field as it reads. Returns a wrapped ErrMalformedSignaturesSection
// on I/O failures and the specific sub-error on validation failures.
func readSignature(r *bytes.Reader) (Signature, error) {
	var didLen uint16
	if err := binary.Read(r, binary.BigEndian, &didLen); err != nil {
		return Signature{}, fmt.Errorf("%w: reading didLen: %v", ErrMalformedSignaturesSection, err)
	}
	if didLen == 0 {
		return Signature{}, ErrSignerDIDEmpty
	}
	if int(didLen) > MaxSignerDIDLen {
		return Signature{}, fmt.Errorf("%w: %d > %d", ErrSignatureSignerDIDTooLong, didLen, MaxSignerDIDLen)
	}

	didBytes := make([]byte, didLen)
	if _, err := io.ReadFull(r, didBytes); err != nil {
		return Signature{}, fmt.Errorf("%w: reading did bytes: %v", ErrMalformedSignaturesSection, err)
	}
	did := string(didBytes)
	if !isASCII(did) {
		return Signature{}, ErrSignerDIDNonASCII
	}

	var algoID uint16
	if err := binary.Read(r, binary.BigEndian, &algoID); err != nil {
		return Signature{}, fmt.Errorf("%w: reading algoID: %v", ErrMalformedSignaturesSection, err)
	}
	if err := ValidateAlgorithmID(algoID); err != nil {
		return Signature{}, err
	}

	var sigLen uint32
	if err := binary.Read(r, binary.BigEndian, &sigLen); err != nil {
		return Signature{}, fmt.Errorf("%w: reading sigLen: %v", ErrMalformedSignaturesSection, err)
	}
	if sigLen > MaxSignatureBytes {
		return Signature{}, fmt.Errorf("%w: %d > %d", ErrSignatureBytesTooLarge, sigLen, MaxSignatureBytes)
	}

	sigBytes := make([]byte, sigLen)
	if sigLen > 0 {
		if _, err := io.ReadFull(r, sigBytes); err != nil {
			return Signature{}, fmt.Errorf("%w: reading sig bytes: %v", ErrMalformedSignaturesSection, err)
		}
	}

	return Signature{
		SignerDID: did,
		AlgoID:    algoID,
		Bytes:     sigBytes,
	}, nil
}
