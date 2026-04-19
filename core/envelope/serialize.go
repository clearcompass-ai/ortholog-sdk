/*
FILE PATH:

	core/envelope/serialize.go

DESCRIPTION:

	Canonical wire format implementation for protocol v6. Defines the core
	entry points — NewEntry, NewUnsignedEntry, Serialize, Deserialize —
	plus the exported SigningPayload boundary that signers sign over.

KEY ARCHITECTURAL DECISIONS:
  - v6 introduces a signatures section inside the canonical wire. Every
    Serialize output carries the signatures that were present at
    submission, so the Merkle leaf hash (tessera_compat.EntryLeafHash)
    commits to both the signing content and the signatures. Under v5
    the log attested only to who authorized (Header.SignerDID); under
    v6 it additionally attests to who cryptographically signed. This
    closes the transparency gap v5 silently carried.
  - SigningPayload(e) is exported as a named boundary. It returns what
    v5 called "canonical bytes" (preamble + header + payload_len +
    payload). This is what every signer hashes before signing, and
    what every verifier hashes before verifying. Serialize(e) =
    SigningPayload(e) || signatures_section. This separation means
    signatures commit to content but content does not commit to
    signatures — signing a bare payload and then attaching multiple
    signatures is a single-pass operation.
  - Serialize is a total function. It matches the contract
    tessera_compat.go relies on (EntryIdentity, EntryLeafHash,
    MarshalBundleEntry, BundleEntries all treat Serialize as total,
    mirroring Tessera's Entry.LeafHash() / Entry.MarshalBundleData()
    signatures). Validation happens earlier, at NewEntry / Validate /
    Deserialize, via the fallible internal serializeInternal. If a
    caller skips validation and hand-constructs a malformed Entry,
    Serialize panics — producing defensive-but-invalid bytes would be
    silent corruption on the Merkle tree, and fail-loud is the correct
    response.
  - Two constructors, one strict. NewEntry requires signatures; a
    nil/empty slice is rejected. NewUnsignedEntry skips the signature
    invariant for the construction-then-sign flow used by
    builder/entry_builders.go. Callers of NewUnsignedEntry MUST append
    at least one Signature and MUST call Validate before passing the
    entry to Serialize or to the log.
  - Deserialize is strict. Unknown algoIDs reject. Malformed signatures
    section rejects. Zero-sig section rejects. The Signatures[0] DID
    invariant is enforced post-decode. There is no permissive-read path.
  - Forward compatibility within the HBL region is preserved: a v6
    parser reading a future v7 header skips unknown trailing HBL bytes,
    then reads the payload, then reads the signatures section. The HBL
    length prefix makes this safe.
  - The signatures section is NOT inside the HBL. It lives after the
    payload. A v6 parser can find it because the payload is
    length-prefixed (uint32 PayloadLen), and everything remaining is
    the signatures section.

OVERVIEW:

	Wire format (v6):

	  Preamble (6 bytes):
	    [uint16 ProtocolVersion=6] [uint32 HBL]

	  Header body (HBL bytes):
	    Fields in declaration order (see serializeHeaderBody).

	  Payload:
	    [uint32 PayloadLen] [PayloadBytes]

	  Signatures section:
	    [uint16 SigCount] [SignatureBlock]*

	    where SignatureBlock =
	      [uint16 DIDLen] [DIDBytes]
	      [uint16 AlgoID]
	      [uint32 SigLen] [SigBytes]

	SigningPayload(e) returns bytes 0 through (6 + HBL + 4 + PayloadLen).
	Serialize(e) returns SigningPayload(e) || signatures_section_bytes.

	Deserialize reads the preamble, the HBL, the payload, then treats
	the remainder as the signatures section (strict: must decode
	cleanly, must have no trailing bytes).

KEY DEPENDENCIES:
  - api.go: currentProtocolVersion, size caps
  - version_policy.go: CheckReadAllowed, CheckWriteAllowed
  - control_header.go: ControlHeader struct, AuthorityPath, KeyGenMode,
    AdmissionProofBody
  - entry.go: Entry struct
  - signature_algo.go: ValidateAlgorithmID
  - signatures_section.go: Signature struct, AppendSignaturesSection,
    ReadSignaturesSection, MaxSignaturesPerEntry
  - destination.go: ValidateDestination
*/
package envelope

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// -------------------------------------------------------------------------------------------------
// 1) Construction and validation errors
// -------------------------------------------------------------------------------------------------

var (
	ErrCanonicalTooLarge         = errors.New("envelope: canonical bytes exceed MaxCanonicalBytes (1 MiB)")
	ErrMalformedPreamble         = errors.New("envelope: malformed preamble")
	ErrMalformedHeader           = errors.New("envelope: malformed header body")
	ErrMalformedPayload          = errors.New("envelope: malformed payload")
	ErrEmptySignerDID            = errors.New("envelope: Signer_DID must not be empty")
	ErrNonASCIIDID               = errors.New("envelope: Signer_DID must be ASCII")
	ErrNonASCIIDestination       = errors.New("envelope: Destination must be ASCII")
	ErrTooManyDelegationPointers = errors.New("envelope: DelegationPointers exceeds MaxDelegationPointers")
	ErrTooManyEvidencePointers   = errors.New("envelope: EvidencePointers exceeds MaxEvidencePointers (non-snapshot)")
	ErrInvalidPresenceByte       = errors.New("envelope: presence byte must be 0 or 1")
	ErrAdmissionProofTooLarge    = errors.New("envelope: admission proof body exceeds MaxAdmissionProofBody")

	// ErrPrimarySignerMismatch is returned when Signatures[0].SignerDID
	// does not equal Header.SignerDID. The primary signature must be from
	// the authorizing party — the protocol's authority evaluation routes
	// on Header.SignerDID, and if the primary signature comes from a
	// different key the log would attest to an authorization the signer
	// did not cryptographically claim.
	ErrPrimarySignerMismatch = errors.New("envelope: Signatures[0].SignerDID must equal Header.SignerDID")

	// ErrMissingSignatures is returned when Validate runs on an entry
	// with zero signatures. NewUnsignedEntry produces such entries; the
	// caller must append signatures before Validate/Serialize.
	ErrMissingSignatures = errors.New("envelope: entry has no signatures (Signatures empty)")
)

// -------------------------------------------------------------------------------------------------
// 2) NewEntry — validating constructor for fully-signed entries
// -------------------------------------------------------------------------------------------------

// NewEntry constructs a new Entry at the currently-active protocol version
// with its full signature set. This is the constructor for callers that
// already hold every signature (primary + any cosignatures).
//
// Callers that need to construct an entry before signing (the 18 builders
// in builder/entry_builders.go) use NewUnsignedEntry instead.
//
// Overwrites header.ProtocolVersion to the active version — callers cannot
// pin a new entry to a non-active version through this API. For
// cross-version migration, deserialize the old entry, transform the
// header, and call NewEntry to produce a fresh entry at the active
// version (the roundtrip rewrites the version).
//
// Validates:
//   - Active version permits writes (defensive against policy-table
//     drift during version-transition PRs)
//   - Header invariants (non-empty SignerDID, valid destination, etc.)
//   - At least one signature
//   - Signatures[0].SignerDID == Header.SignerDID
//   - Every signature is well-formed (handled by AppendSignaturesSection
//     which runs validateSignatureForEncode)
//   - Total serialized size within MaxCanonicalBytes
func NewEntry(header ControlHeader, payload []byte, signatures []Signature) (*Entry, error) {
	active := currentProtocolVersion
	if err := CheckWriteAllowed(active); err != nil {
		// Programming error: versionPolicy out of sync with
		// currentProtocolVersion. The active version constant and the
		// policy table must agree.
		return nil, err
	}
	header.ProtocolVersion = active

	if err := validateHeaderForWrite(&header); err != nil {
		return nil, err
	}

	if len(signatures) == 0 {
		return nil, ErrMissingSignatures
	}
	if signatures[0].SignerDID != header.SignerDID {
		return nil, fmt.Errorf("%w: header=%q, signatures[0]=%q",
			ErrPrimarySignerMismatch, header.SignerDID, signatures[0].SignerDID)
	}

	entry := &Entry{
		Header:        header,
		DomainPayload: append([]byte(nil), payload...),
		Signatures:    append([]Signature(nil), signatures...),
	}

	// Dry-run the encoding through the fallible internal form. If the
	// signatures list has any encoding-level problem (unregistered
	// algoID, oversize sig bytes, DID-length violation) the error
	// surfaces here — before the entry is returned, and long before
	// Serialize (total function) is called downstream.
	out, err := serializeInternal(entry)
	if err != nil {
		return nil, err
	}
	if len(out) > MaxCanonicalBytes {
		return nil, fmt.Errorf("%w: computed size %d", ErrCanonicalTooLarge, len(out))
	}

	return entry, nil
}

// -------------------------------------------------------------------------------------------------
// 3) NewUnsignedEntry — constructor for the build-then-sign flow
// -------------------------------------------------------------------------------------------------

// NewUnsignedEntry constructs a new Entry at the currently-active protocol
// version WITHOUT requiring signatures. Used exclusively by the 18
// builders in builder/entry_builders.go, which produce entries before
// the caller obtains a signature from the signing key.
//
// The returned entry has entry.Signatures == nil. The caller MUST:
//
//  1. Compute signingHash := sha256.Sum256(envelope.SigningPayload(entry))
//  2. Sign signingHash with the primary signer's key
//  3. Append the resulting Signature to entry.Signatures
//  4. Optionally append cosigner Signatures
//  5. Call entry.Validate() to enforce the full invariant set before
//     passing to Serialize or submitting to the log
//
// This constructor validates the same header invariants as NewEntry but
// does not size-check the serialized form (signatures are not yet
// present, so size is below the eventual final size). The final size
// check runs at entry.Validate() time.
//
// Overwrites header.ProtocolVersion to the active version, identical to
// NewEntry.
func NewUnsignedEntry(header ControlHeader, payload []byte) (*Entry, error) {
	active := currentProtocolVersion
	if err := CheckWriteAllowed(active); err != nil {
		return nil, err
	}
	header.ProtocolVersion = active

	if err := validateHeaderForWrite(&header); err != nil {
		return nil, err
	}

	return &Entry{
		Header:        header,
		DomainPayload: append([]byte(nil), payload...),
		Signatures:    nil,
	}, nil
}

// -------------------------------------------------------------------------------------------------
// 4) Header write-invariant check (internal)
// -------------------------------------------------------------------------------------------------

func validateHeaderForWrite(h *ControlHeader) error {
	if h.SignerDID == "" {
		return ErrEmptySignerDID
	}
	if !isASCII(h.SignerDID) {
		return ErrNonASCIIDID
	}
	// Destination binding: required field, validated for non-empty,
	// non-whitespace, bounded length by ValidateDestination, plus ASCII
	// conformance here (DIDs are ASCII by spec; consistent with
	// SignerDID).
	if err := ValidateDestination(h.Destination); err != nil {
		return err
	}
	if !isASCII(h.Destination) {
		return ErrNonASCIIDestination
	}
	if len(h.DelegationPointers) > MaxDelegationPointers {
		return ErrTooManyDelegationPointers
	}
	if len(h.EvidencePointers) > MaxEvidencePointers && !isAuthoritySnapshotShape(h) {
		return ErrTooManyEvidencePointers
	}
	return nil
}

// -------------------------------------------------------------------------------------------------
// 5) Entry.Validate — post-construction invariant gate
// -------------------------------------------------------------------------------------------------

// Validate reports whether the Entry satisfies every write-time invariant
// required for Serialize to produce valid wire bytes. NewEntry callers
// do not need to call Validate (NewEntry already enforces these).
// NewUnsignedEntry callers MUST call Validate after appending signatures,
// before Serialize.
//
// Invariants checked:
//   - Header write invariants (validateHeaderForWrite)
//   - len(Signatures) >= 1 (ErrMissingSignatures)
//   - len(Signatures) <= MaxSignaturesPerEntry (via serializeInternal)
//   - Signatures[0].SignerDID == Header.SignerDID (ErrPrimarySignerMismatch)
//   - Per-signature validity (via AppendSignaturesSection)
//   - Total serialized size within MaxCanonicalBytes
func (e *Entry) Validate() error {
	if e == nil {
		return errors.New("envelope: nil Entry")
	}
	if err := validateHeaderForWrite(&e.Header); err != nil {
		return err
	}
	if len(e.Signatures) == 0 {
		return ErrMissingSignatures
	}
	if e.Signatures[0].SignerDID != e.Header.SignerDID {
		return fmt.Errorf("%w: header=%q, signatures[0]=%q",
			ErrPrimarySignerMismatch, e.Header.SignerDID, e.Signatures[0].SignerDID)
	}
	// Dry-run the encoding through the fallible internal form. If
	// signatures have encoding-level problems (unregistered algoID,
	// oversize sig bytes, DID-length violation), surface them here
	// before Serialize (total function) is ever called.
	out, err := serializeInternal(e)
	if err != nil {
		return err
	}
	if len(out) > MaxCanonicalBytes {
		return fmt.Errorf("%w: computed size %d", ErrCanonicalTooLarge, len(out))
	}
	return nil
}

// isASCII reports whether every byte of s is in [0x00, 0x7F].
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7F {
			return false
		}
	}
	return true
}

// isAuthoritySnapshotShape reports whether the header has the structural
// shape of a Path C authority snapshot (AuthorityScopeAuthority +
// TargetRoot + PriorAuthority). Snapshots are exempt from the evidence
// cap.
func isAuthoritySnapshotShape(h *ControlHeader) bool {
	if h.AuthorityPath == nil || *h.AuthorityPath != AuthorityScopeAuthority {
		return false
	}
	return h.TargetRoot != nil && h.PriorAuthority != nil
}

// -------------------------------------------------------------------------------------------------
// 6) SigningPayload — the signing boundary
// -------------------------------------------------------------------------------------------------

// SigningPayload returns the bytes a signer signs over. Layout:
//
//	[uint16 ProtocolVersion] [uint32 HBL] [HeaderBody] [uint32 PayloadLen] [PayloadBytes]
//
// This is identical to what v5's Serialize produced. Under v6, signers
// compute sha256(SigningPayload(entry)) and sign the digest; verifiers
// do the same.
//
// Serialize(entry) = SigningPayload(entry) || signatures_section. The
// signatures are therefore over content-that-excludes-signatures, so
// signing is a single-pass operation (no circular hash dependency).
//
// Callers: crypto/signatures/entry_verify.go (both sign and verify paths),
// tests/web3_helpers_test.go (simulated wallet signing).
func SigningPayload(e *Entry) []byte {
	body := serializeHeaderBody(&e.Header)

	total := 6 + len(body) + 4 + len(e.DomainPayload)
	out := make([]byte, 0, total)
	out = binary.BigEndian.AppendUint16(out, e.Header.ProtocolVersion)
	out = binary.BigEndian.AppendUint32(out, uint32(len(body)))
	out = append(out, body...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(e.DomainPayload)))
	out = append(out, e.DomainPayload...)
	return out
}

// -------------------------------------------------------------------------------------------------
// 7) Serialize — canonical wire output (total function)
// -------------------------------------------------------------------------------------------------

// Serialize emits the canonical wire bytes for an entry:
//
//	SigningPayload(entry) || signatures_section
//
// Total function. Matches the contract tessera_compat.go relies on
// (EntryIdentity, EntryLeafHash, MarshalBundleEntry, BundleEntries all
// treat Serialize as total, mirroring Tessera's Entry.LeafHash() /
// Entry.MarshalBundleData() signatures).
//
// The invariant that makes this total: any Entry produced by NewEntry,
// Deserialize, or NewUnsignedEntry + Validate has already been
// signature-validated. Those paths call serializeInternal up front and
// propagate any encoding error. By the time Serialize runs on an entry
// from any of those paths, encoding cannot fail.
//
// If a caller hand-constructs an Entry without going through the
// validated paths and passes it to Serialize, the signatures-section
// encoder may reject it (e.g., empty signature list, unregistered
// algoID, oversize sig bytes). In that case Serialize panics with a
// descriptive message. This is deliberate: the caller skipped
// validation, and producing defensive-but-invalid bytes would be a
// silent corruption on the Merkle tree. Fail loud, not silent.
//
// Callers that build entries by hand should call entry.Validate()
// before Serialize.
func Serialize(e *Entry) []byte {
	out, err := serializeInternal(e)
	if err != nil {
		panic(fmt.Sprintf("envelope: Serialize on invalid entry (call Validate first): %v", err))
	}
	return out
}

// serializeInternal is Serialize's fallible form used by NewEntry and
// Validate. Returns the same bytes Serialize would produce, plus any
// encoding error from the signatures section. The error path is how
// NewEntry and Validate surface "your entry has malformed signatures"
// to callers before those entries ever reach the log.
func serializeInternal(e *Entry) ([]byte, error) {
	payload := SigningPayload(e)
	return AppendSignaturesSection(payload, e.Signatures)
}

// serializeHeaderBody encodes the ControlHeader body fields in declaration
// order. Unchanged from v5 — the header body layout is stable across the
// v5→v6 transition. The only v6 wire change is the signatures section
// appended after the payload.
func serializeHeaderBody(h *ControlHeader) []byte {
	var b []byte
	b = appendLenPrefixedString(b, h.SignerDID)
	// Destination binding: written immediately after SignerDID so the
	// canonical hash includes it. An entry signed for exchange A and
	// replayed at exchange B recomputes a different hash at B and fails
	// signature verification — cross-exchange replay is cryptographically
	// impossible.
	b = appendLenPrefixedString(b, h.Destination)
	b = appendOptionalLogPosition(b, h.TargetRoot)
	b = appendOptionalLogPosition(b, h.TargetIntermediate)
	b = appendOptionalAuthorityPath(b, h.AuthorityPath)
	b = appendLogPositionList(b, h.DelegationPointers)
	b = appendOptionalString(b, h.DelegateDID)
	b = appendOptionalLogPosition(b, h.ScopePointer)
	b = appendDIDSet(b, h.SortedDIDs())
	b = appendOptionalString(b, h.AuthorityDID)
	b = appendOptionalLogPosition(b, h.PriorAuthority)
	b = appendLogPositionList(b, h.ApprovalPointers)
	b = appendLogPositionList(b, h.EvidencePointers)
	b = appendOptionalLogPosition(b, h.SchemaRef)
	b = appendOptionalKeyGenMode(b, h.KeyGenerationMode)
	b = appendUint32List(b, h.CommutativeOperations)
	b = appendLenPrefixedBytes(b, h.SubjectIdentifier)
	b = appendOptionalLogPosition(b, h.CosignatureOf)
	b = binary.BigEndian.AppendUint64(b, uint64(h.EventTime))
	b = appendAdmissionProof(b, h.AdmissionProof)
	b = appendOptionalLogPosition(b, h.AuthoritySkip)
	return b
}

// -------------------------------------------------------------------------------------------------
// 8) Deserialize — validating parser
// -------------------------------------------------------------------------------------------------

// Deserialize parses canonical bytes into an Entry. Validates preamble,
// enforces read-version policy, decodes the header body, decodes the
// payload, and decodes the signatures section.
//
// Strict at every layer:
//   - Unknown protocol version → ErrUnknownVersion
//   - Malformed preamble → ErrMalformedPreamble
//   - Malformed header body → ErrMalformedHeader (wrapped)
//   - Malformed payload → ErrMalformedPayload
//   - Malformed signatures section → ErrMalformedSignaturesSection
//   - Zero signatures → ErrEmptySignatureList
//   - Signatures[0].SignerDID != Header.SignerDID → ErrPrimarySignerMismatch
//   - Trailing bytes after signatures section → ErrTrailingBytes
//
// Tolerant of unknown trailing bytes within the HBL region — forward
// compatibility for future additive header field additions at v7. The
// signatures section is NOT in the HBL, so this tolerance does not apply
// to it; signatures section bytes must be exact.
func Deserialize(canonical []byte) (*Entry, error) {
	if len(canonical) > MaxCanonicalBytes {
		return nil, ErrCanonicalTooLarge
	}
	if len(canonical) < 6 {
		return nil, fmt.Errorf("%w: length %d < 6", ErrMalformedPreamble, len(canonical))
	}

	version := binary.BigEndian.Uint16(canonical[0:2])
	hbl := binary.BigEndian.Uint32(canonical[2:6])

	if err := CheckReadAllowed(version); err != nil {
		return nil, err
	}

	if 6+int(hbl) > len(canonical) {
		return nil, fmt.Errorf("%w: header body length %d exceeds canonical length %d",
			ErrMalformedHeader, hbl, len(canonical))
	}

	headerBytes := canonical[6 : 6+hbl]
	afterHeader := canonical[6+hbl:]

	header, err := deserializeHeaderBody(headerBytes)
	if err != nil {
		return nil, err
	}
	header.ProtocolVersion = version

	payload, afterPayload, err := deserializePayload(afterHeader)
	if err != nil {
		return nil, err
	}

	// Signatures section: everything remaining after the payload.
	// ReadSignaturesSection is strict — no trailing bytes permitted.
	sigs, err := ReadSignaturesSection(afterPayload)
	if err != nil {
		return nil, err
	}

	// Primary-signer invariant. The decoded header's SignerDID and the
	// decoded signatures list's primary DID must agree. This is the same
	// invariant NewEntry enforces; decoding is symmetric.
	if sigs[0].SignerDID != header.SignerDID {
		return nil, fmt.Errorf("%w: header=%q, signatures[0]=%q",
			ErrPrimarySignerMismatch, header.SignerDID, sigs[0].SignerDID)
	}

	return &Entry{
		Header:        *header,
		DomainPayload: payload,
		Signatures:    sigs,
	}, nil
}

func deserializeHeaderBody(body []byte) (*ControlHeader, error) {
	r := bytes.NewReader(body)
	h := &ControlHeader{}

	var err error
	if h.SignerDID, err = readLenPrefixedString(r); err != nil {
		return nil, wrapField("SignerDID", err)
	}
	// Destination binding: read immediately after SignerDID. Must be
	// non-empty on any v6 entry; the builder/serializer ensures this for
	// entries constructed through NewEntry.
	if h.Destination, err = readLenPrefixedString(r); err != nil {
		return nil, wrapField("Destination", err)
	}
	if h.TargetRoot, err = readOptionalLogPosition(r); err != nil {
		return nil, wrapField("TargetRoot", err)
	}
	if h.TargetIntermediate, err = readOptionalLogPosition(r); err != nil {
		return nil, wrapField("TargetIntermediate", err)
	}
	if h.AuthorityPath, err = readOptionalAuthorityPath(r); err != nil {
		return nil, wrapField("AuthorityPath", err)
	}
	if h.DelegationPointers, err = readLogPositionList(r); err != nil {
		return nil, wrapField("DelegationPointers", err)
	}
	if len(h.DelegationPointers) > MaxDelegationPointers {
		return nil, ErrTooManyDelegationPointers
	}
	if h.DelegateDID, err = readOptionalString(r); err != nil {
		return nil, wrapField("DelegateDID", err)
	}
	if h.ScopePointer, err = readOptionalLogPosition(r); err != nil {
		return nil, wrapField("ScopePointer", err)
	}
	dids, err := readDIDSet(r)
	if err != nil {
		return nil, wrapField("AuthoritySet", err)
	}
	if len(dids) > 0 {
		h.AuthoritySet = make(map[string]struct{}, len(dids))
		for _, d := range dids {
			h.AuthoritySet[d] = struct{}{}
		}
	}
	if h.AuthorityDID, err = readOptionalString(r); err != nil {
		return nil, wrapField("AuthorityDID", err)
	}
	if h.PriorAuthority, err = readOptionalLogPosition(r); err != nil {
		return nil, wrapField("PriorAuthority", err)
	}
	if h.ApprovalPointers, err = readLogPositionList(r); err != nil {
		return nil, wrapField("ApprovalPointers", err)
	}
	if h.EvidencePointers, err = readLogPositionList(r); err != nil {
		return nil, wrapField("EvidencePointers", err)
	}
	if h.SchemaRef, err = readOptionalLogPosition(r); err != nil {
		return nil, wrapField("SchemaRef", err)
	}
	if h.KeyGenerationMode, err = readOptionalKeyGenMode(r); err != nil {
		return nil, wrapField("KeyGenerationMode", err)
	}
	if h.CommutativeOperations, err = readUint32List(r); err != nil {
		return nil, wrapField("CommutativeOperations", err)
	}
	if h.SubjectIdentifier, err = readLenPrefixedBytes(r); err != nil {
		return nil, wrapField("SubjectIdentifier", err)
	}
	if h.CosignatureOf, err = readOptionalLogPosition(r); err != nil {
		return nil, wrapField("CosignatureOf", err)
	}
	var eventTime uint64
	if err = binary.Read(r, binary.BigEndian, &eventTime); err != nil {
		return nil, wrapField("EventTime", err)
	}
	h.EventTime = int64(eventTime)
	if h.AdmissionProof, err = readAdmissionProof(r); err != nil {
		return nil, wrapField("AdmissionProof", err)
	}
	if h.AuthoritySkip, err = readOptionalLogPosition(r); err != nil {
		return nil, wrapField("AuthoritySkip", err)
	}

	// Forward compatibility: tolerate any trailing bytes beyond the
	// fields this version knows about (future additive fields from a
	// later protocol version). These bytes are covered by the canonical
	// hash via the preamble's HBL, so they participate in entry identity,
	// but this parser does not interpret them.

	return h, nil
}

// deserializePayload reads the payload_len + payload_bytes region and
// returns the payload along with the remainder (which is the signatures
// section region). A malformed payload — length prefix exceeds available
// bytes — rejects with ErrMalformedPayload.
func deserializePayload(region []byte) (payload []byte, remainder []byte, err error) {
	if len(region) < 4 {
		return nil, nil, fmt.Errorf("%w: payload region %d < 4", ErrMalformedPayload, len(region))
	}
	payloadLen := binary.BigEndian.Uint32(region[0:4])
	if 4+int(payloadLen) > len(region) {
		return nil, nil, fmt.Errorf("%w: payload length %d exceeds region %d",
			ErrMalformedPayload, payloadLen, len(region))
	}
	payloadEnd := 4 + int(payloadLen)
	if payloadLen == 0 {
		return []byte{}, region[payloadEnd:], nil
	}
	out := make([]byte, payloadLen)
	copy(out, region[4:payloadEnd])
	return out, region[payloadEnd:], nil
}

// -------------------------------------------------------------------------------------------------
// 9) Primitive writers (append-style, total)
// -------------------------------------------------------------------------------------------------

func appendLenPrefixedString(b []byte, s string) []byte {
	if len(s) > int(^uint16(0)) {
		// Invariant violated by caller. Truncate defensively; the
		// resulting bytes will fail to deserialize, surfacing the bug
		// at read time. This is load-bearing: we do not panic here
		// because panicking during serialization would crash the
		// whole operator process; the truncation is caught by the
		// read-side length check.
		s = s[:int(^uint16(0))]
	}
	b = binary.BigEndian.AppendUint16(b, uint16(len(s)))
	b = append(b, s...)
	return b
}

func appendLenPrefixedBytes(b, v []byte) []byte {
	if len(v) > int(^uint16(0)) {
		v = v[:int(^uint16(0))]
	}
	b = binary.BigEndian.AppendUint16(b, uint16(len(v)))
	b = append(b, v...)
	return b
}

func appendOptionalString(b []byte, s *string) []byte {
	if s == nil {
		return append(b, 0)
	}
	b = append(b, 1)
	return appendLenPrefixedString(b, *s)
}

func appendOptionalLogPosition(b []byte, p *types.LogPosition) []byte {
	if p == nil {
		return append(b, 0)
	}
	b = append(b, 1)
	return appendLogPosition(b, *p)
}

func appendLogPosition(b []byte, p types.LogPosition) []byte {
	b = appendLenPrefixedString(b, p.LogDID)
	return binary.BigEndian.AppendUint64(b, p.Sequence)
}

func appendLogPositionList(b []byte, ps []types.LogPosition) []byte {
	n := len(ps)
	if n > int(^uint16(0)) {
		n = int(^uint16(0))
	}
	b = binary.BigEndian.AppendUint16(b, uint16(n))
	for i := 0; i < n; i++ {
		b = appendLogPosition(b, ps[i])
	}
	return b
}

func appendOptionalAuthorityPath(b []byte, ap *AuthorityPath) []byte {
	if ap == nil {
		return append(b, 0)
	}
	return append(b, 1, byte(*ap))
}

func appendOptionalKeyGenMode(b []byte, m *KeyGenMode) []byte {
	if m == nil {
		return append(b, 0)
	}
	return append(b, 1, byte(*m))
}

func appendDIDSet(b []byte, dids []string) []byte {
	n := len(dids)
	if n > int(^uint16(0)) {
		n = int(^uint16(0))
	}
	b = binary.BigEndian.AppendUint16(b, uint16(n))
	for i := 0; i < n; i++ {
		b = appendLenPrefixedString(b, dids[i])
	}
	return b
}

func appendUint32List(b []byte, vs []uint32) []byte {
	n := len(vs)
	if n > int(^uint16(0)) {
		n = int(^uint16(0))
	}
	b = binary.BigEndian.AppendUint16(b, uint16(n))
	for i := 0; i < n; i++ {
		b = binary.BigEndian.AppendUint32(b, vs[i])
	}
	return b
}

// -------------------------------------------------------------------------------------------------
// 10) Admission Proof — length-prefixed body (SDK-3 isolation, unchanged from v5)
// -------------------------------------------------------------------------------------------------

func appendAdmissionProof(b []byte, p *AdmissionProofBody) []byte {
	if p == nil {
		b = append(b, 0)
		return binary.BigEndian.AppendUint16(b, 0)
	}
	b = append(b, 1)

	// Build body into a temporary slice to measure.
	body := make([]byte, 0, 128)
	body = append(body, p.Mode, p.Difficulty, p.HashFunc)
	body = binary.BigEndian.AppendUint64(body, p.Epoch)
	if p.SubmitterCommit == nil {
		body = append(body, 0)
		body = append(body, make([]byte, 32)...) // fixed-width zero slot (SDK-4)
	} else {
		body = append(body, 1)
		body = append(body, p.SubmitterCommit[:]...)
	}
	body = binary.BigEndian.AppendUint64(body, p.Nonce)
	body = append(body, p.Hash[:]...)

	if len(body) > MaxAdmissionProofBody {
		body = body[:MaxAdmissionProofBody]
	}
	b = binary.BigEndian.AppendUint16(b, uint16(len(body)))
	return append(b, body...)
}

func readAdmissionProof(r *bytes.Reader) (*AdmissionProofBody, error) {
	presence, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if presence != 0 && presence != 1 {
		return nil, ErrInvalidPresenceByte
	}

	var bodyLen uint16
	if err := binary.Read(r, binary.BigEndian, &bodyLen); err != nil {
		return nil, err
	}
	if presence == 0 {
		if bodyLen != 0 {
			return nil, fmt.Errorf("envelope: AdmissionProof absent but body_length=%d", bodyLen)
		}
		return nil, nil
	}
	if bodyLen > MaxAdmissionProofBody {
		return nil, ErrAdmissionProofTooLarge
	}
	if int(bodyLen) > r.Len() {
		return nil, fmt.Errorf("envelope: AdmissionProof body_length %d exceeds remaining %d",
			bodyLen, r.Len())
	}

	// Bounded sub-reader — isolates admission proof from Authority_Skip.
	bodyBytes := make([]byte, bodyLen)
	if _, err := io.ReadFull(r, bodyBytes); err != nil {
		return nil, err
	}
	sub := bytes.NewReader(bodyBytes)

	p := &AdmissionProofBody{}
	if p.Mode, err = sub.ReadByte(); err != nil {
		return nil, err
	}
	if p.Difficulty, err = sub.ReadByte(); err != nil {
		return nil, err
	}
	if p.HashFunc, err = sub.ReadByte(); err != nil {
		return nil, err
	}
	if err := binary.Read(sub, binary.BigEndian, &p.Epoch); err != nil {
		return nil, err
	}
	commitPresence, err := sub.ReadByte()
	if err != nil {
		return nil, err
	}
	commitBytes := make([]byte, 32)
	if _, err := io.ReadFull(sub, commitBytes); err != nil {
		return nil, err
	}
	switch commitPresence {
	case 0:
		for _, v := range commitBytes {
			if v != 0 {
				return nil, fmt.Errorf("envelope: commit_present=0 but slot non-zero")
			}
		}
	case 1:
		var c [32]byte
		copy(c[:], commitBytes)
		p.SubmitterCommit = &c
	default:
		return nil, ErrInvalidPresenceByte
	}
	if err := binary.Read(sub, binary.BigEndian, &p.Nonce); err != nil {
		return nil, err
	}
	if _, err := io.ReadFull(sub, p.Hash[:]); err != nil {
		return nil, err
	}
	return p, nil
}

// -------------------------------------------------------------------------------------------------
// 11) Primitive readers
// -------------------------------------------------------------------------------------------------

func readLenPrefixedString(r *bytes.Reader) (string, error) {
	var n uint16
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return "", err
	}
	if n == 0 {
		return "", nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

func readLenPrefixedBytes(r *bytes.Reader) ([]byte, error) {
	var n uint16
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func readOptionalString(r *bytes.Reader) (*string, error) {
	presence, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	switch presence {
	case 0:
		return nil, nil
	case 1:
		s, err := readLenPrefixedString(r)
		if err != nil {
			return nil, err
		}
		return &s, nil
	default:
		return nil, ErrInvalidPresenceByte
	}
}

func readOptionalLogPosition(r *bytes.Reader) (*types.LogPosition, error) {
	presence, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	switch presence {
	case 0:
		return nil, nil
	case 1:
		p, err := readLogPosition(r)
		if err != nil {
			return nil, err
		}
		return &p, nil
	default:
		return nil, ErrInvalidPresenceByte
	}
}

func readLogPosition(r *bytes.Reader) (types.LogPosition, error) {
	did, err := readLenPrefixedString(r)
	if err != nil {
		return types.LogPosition{}, err
	}
	var seq uint64
	if err := binary.Read(r, binary.BigEndian, &seq); err != nil {
		return types.LogPosition{}, err
	}
	return types.LogPosition{LogDID: did, Sequence: seq}, nil
}

func readLogPositionList(r *bytes.Reader) ([]types.LogPosition, error) {
	var n uint16
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	out := make([]types.LogPosition, n)
	for i := range out {
		p, err := readLogPosition(r)
		if err != nil {
			return nil, err
		}
		out[i] = p
	}
	return out, nil
}

func readOptionalAuthorityPath(r *bytes.Reader) (*AuthorityPath, error) {
	presence, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	switch presence {
	case 0:
		return nil, nil
	case 1:
		v, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		ap := AuthorityPath(v)
		return &ap, nil
	default:
		return nil, ErrInvalidPresenceByte
	}
}

func readOptionalKeyGenMode(r *bytes.Reader) (*KeyGenMode, error) {
	presence, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	switch presence {
	case 0:
		return nil, nil
	case 1:
		v, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		m := KeyGenMode(v)
		return &m, nil
	default:
		return nil, ErrInvalidPresenceByte
	}
}

func readDIDSet(r *bytes.Reader) ([]string, error) {
	var n uint16
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	out := make([]string, n)
	for i := range out {
		s, err := readLenPrefixedString(r)
		if err != nil {
			return nil, err
		}
		out[i] = s
	}
	return out, nil
}

func readUint32List(r *bytes.Reader) ([]uint32, error) {
	var n uint16
	if err := binary.Read(r, binary.BigEndian, &n); err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	out := make([]uint32, n)
	for i := range out {
		if err := binary.Read(r, binary.BigEndian, &out[i]); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func wrapField(field string, err error) error {
	return fmt.Errorf("%w: field %s: %v", ErrMalformedHeader, field, err)
}
