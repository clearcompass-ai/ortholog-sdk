/*
Package envelope — serialize.go implements the canonical wire format.

Three entry points:

  NewEntry(header, payload) → (*Entry, error)
    Validating constructor. Sets header.ProtocolVersion = currentProtocolVersion.
    Enforces write-version policy, size caps, and structural invariants.
    Only way to obtain an Entry at the ACTIVE protocol version.

  Serialize(e) → []byte
    Total function. Emits canonical bytes at e.Header.ProtocolVersion.
    Trusts caller: if the Entry was produced by NewEntry, always succeeds.
    Hand-constructed entries with malformed fields produce bad bytes —
    rejected at Deserialize, at operator admission, or at signature check.

  Deserialize(b) → (*Entry, error)
    Validating parser. Enforces read-version policy, preamble structure,
    and per-field decoding. Populates Header.ProtocolVersion from the wire.

Wire format (v5):

  Preamble (6 bytes, bytes 0–5, permanent):
    [uint16 Protocol_Version] [uint32 Header_Body_Length]

  Header body (HBL bytes):
    Fields in declaration order. V5 adds DomainManifestVersion at the end
    (1 presence byte + 6 fixed-width bytes). Admission proof is length-
    prefixed to isolate it from Authority_Skip (SDK-3 guarantee).

  Payload: [uint32 Payload_Length] [Payload_Bytes]

Forward compatibility: deserializers tolerate unknown trailing bytes within
the HBL region. A v5 parser reading a future v6 entry consumes its known
fields, skips any remaining HBL bytes, and reads the payload normally.
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

// ─────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────

var (
	ErrCanonicalTooLarge          = errors.New("envelope: canonical bytes exceed MaxCanonicalBytes (1 MiB)")
	ErrMalformedPreamble          = errors.New("envelope: malformed preamble")
	ErrMalformedHeader            = errors.New("envelope: malformed header body")
	ErrMalformedPayload           = errors.New("envelope: malformed payload")
	ErrEmptySignerDID             = errors.New("envelope: Signer_DID must not be empty")
	ErrNonASCIIDID                = errors.New("envelope: Signer_DID must be ASCII")
	ErrTooManyDelegationPointers  = errors.New("envelope: DelegationPointers exceeds MaxDelegationPointers")
	ErrTooManyEvidencePointers    = errors.New("envelope: EvidencePointers exceeds MaxEvidencePointers (non-snapshot)")
	ErrInvalidPresenceByte        = errors.New("envelope: presence byte must be 0 or 1")
	ErrAdmissionProofTooLarge     = errors.New("envelope: admission proof body exceeds MaxAdmissionProofBody")
	ErrManifestVersionNonZeroSlot = errors.New("envelope: DomainManifestVersion absent but slot bytes non-zero")
)

// ─────────────────────────────────────────────────────────────────────────
// NewEntry — validating constructor
// ─────────────────────────────────────────────────────────────────────────

// NewEntry constructs a new Entry at the currently-active protocol version.
// Validates structural invariants and size caps. Overwrites
// header.ProtocolVersion to the active version — callers cannot pin a new
// entry to a non-ACTIVE version through this API. For cross-version
// migration, deserialize the old entry, transform the header, and call
// NewEntry to produce a fresh entry at the active version.
func NewEntry(header ControlHeader, payload []byte) (*Entry, error) {
	active := currentProtocolVersion
	if err := CheckWriteAllowed(active); err != nil {
		// Programming error: versionPolicy out of sync with currentProtocolVersion.
		return nil, err
	}
	header.ProtocolVersion = active

	if err := validateHeaderForWrite(&header); err != nil {
		return nil, err
	}

	entry := &Entry{
		Header:        header,
		DomainPayload: append([]byte(nil), payload...),
	}

	// Size check: serialize and measure. This also guarantees Serialize
	// will succeed on this entry (all invariants that Serialize implicitly
	// depends on have been verified).
	if size := len(Serialize(entry)); size > MaxCanonicalBytes {
		return nil, fmt.Errorf("%w: computed size %d", ErrCanonicalTooLarge, size)
	}

	return entry, nil
}

func validateHeaderForWrite(h *ControlHeader) error {
	if h.SignerDID == "" {
		return ErrEmptySignerDID
	}
	if !isASCII(h.SignerDID) {
		return ErrNonASCIIDID
	}
	if len(h.DelegationPointers) > MaxDelegationPointers {
		return ErrTooManyDelegationPointers
	}
	if len(h.EvidencePointers) > MaxEvidencePointers && !isAuthoritySnapshotShape(h) {
		return ErrTooManyEvidencePointers
	}
	return nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 0x7F {
			return false
		}
	}
	return true
}

// isAuthoritySnapshotShape reports whether the header has the structural
// shape of a Path C authority snapshot (AuthorityScopeAuthority + TargetRoot
// + PriorAuthority). Snapshots are exempt from the evidence cap.
func isAuthoritySnapshotShape(h *ControlHeader) bool {
	if h.AuthorityPath == nil || *h.AuthorityPath != AuthorityScopeAuthority {
		return false
	}
	return h.TargetRoot != nil && h.PriorAuthority != nil
}

// ─────────────────────────────────────────────────────────────────────────
// Serialize — total function
// ─────────────────────────────────────────────────────────────────────────

// Serialize emits the canonical wire bytes for an entry. Total function:
// never returns an error. Entries constructed via NewEntry always serialize
// to a valid byte sequence within MaxCanonicalBytes.
//
// Emits at the entry's Header.ProtocolVersion. For entries from NewEntry,
// this is always currentProtocolVersion. Hand-constructed entries emit at
// whatever version the caller set.
func Serialize(e *Entry) []byte {
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

func serializeHeaderBody(h *ControlHeader) []byte {
	var b []byte
	b = appendLenPrefixedString(b, h.SignerDID)
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

	// v5+: DomainManifestVersion. A v5 writer always serializes this slot.
	// Forward compat: a v5 parser reading a v6 entry would see this slot
	// followed by unknown trailing bytes it skips.
	if h.ProtocolVersion >= 5 {
		b = appendOptionalManifestVersion(b, h.DomainManifestVersion)
	}

	return b
}

// ─────────────────────────────────────────────────────────────────────────
// Deserialize — validating parser
// ─────────────────────────────────────────────────────────────────────────

// Deserialize parses canonical bytes into an Entry. Validates preamble,
// enforces read-version policy, and decodes per-field according to the
// declared protocol version.
//
// Tolerant of unknown trailing bytes within the HBL region — forward
// compatibility for future additive field additions.
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
	payloadRegion := canonical[6+hbl:]

	header, err := deserializeHeaderBody(headerBytes, version)
	if err != nil {
		return nil, err
	}
	header.ProtocolVersion = version

	payload, err := deserializePayload(payloadRegion)
	if err != nil {
		return nil, err
	}

	return &Entry{Header: *header, DomainPayload: payload}, nil
}

func deserializeHeaderBody(body []byte, version uint16) (*ControlHeader, error) {
	r := bytes.NewReader(body)
	h := &ControlHeader{}

	var err error
	if h.SignerDID, err = readLenPrefixedString(r); err != nil {
		return nil, wrapField("SignerDID", err)
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

	// v5+: DomainManifestVersion.
	if version >= 5 {
		if r.Len() < 1+manifestVersionBytes {
			return nil, fmt.Errorf("%w: v5 entry missing DomainManifestVersion field", ErrMalformedHeader)
		}
		if h.DomainManifestVersion, err = readOptionalManifestVersion(r); err != nil {
			return nil, wrapField("DomainManifestVersion", err)
		}
	}

	// Forward compatibility: tolerate any trailing bytes (future additive fields).
	// These bytes are covered by the canonical hash via the preamble's HBL.
	// We do not attempt to interpret them.

	return h, nil
}

func deserializePayload(region []byte) ([]byte, error) {
	if len(region) < 4 {
		return nil, fmt.Errorf("%w: payload region %d < 4", ErrMalformedPayload, len(region))
	}
	payloadLen := binary.BigEndian.Uint32(region[0:4])
	if 4+int(payloadLen) > len(region) {
		return nil, fmt.Errorf("%w: payload length %d exceeds region %d",
			ErrMalformedPayload, payloadLen, len(region))
	}
	if payloadLen == 0 {
		return []byte{}, nil
	}
	out := make([]byte, payloadLen)
	copy(out, region[4:4+payloadLen])
	return out, nil
}

// ─────────────────────────────────────────────────────────────────────────
// Primitive writers (append-style, total)
// ─────────────────────────────────────────────────────────────────────────

func appendLenPrefixedString(b []byte, s string) []byte {
	if len(s) > int(^uint16(0)) {
		// Invariant violated by caller. Truncate defensively; the resulting
		// bytes will fail to deserialize, surfacing the bug at read time.
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

// ─────────────────────────────────────────────────────────────────────────
// Admission Proof (length-prefixed body — SDK-3 isolation)
// ─────────────────────────────────────────────────────────────────────────

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
		// Caller-side invariant violation. Truncate; bytes will fail to deserialize.
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

// ─────────────────────────────────────────────────────────────────────────
// DomainManifestVersion (NEW in v5) — fixed-width slot
// ─────────────────────────────────────────────────────────────────────────

func appendOptionalManifestVersion(b []byte, v *[3]uint16) []byte {
	if v == nil {
		b = append(b, 0)
		return append(b, make([]byte, manifestVersionBytes)...) // zero-filled
	}
	b = append(b, 1)
	b = binary.BigEndian.AppendUint16(b, v[0])
	b = binary.BigEndian.AppendUint16(b, v[1])
	b = binary.BigEndian.AppendUint16(b, v[2])
	return b
}

func readOptionalManifestVersion(r *bytes.Reader) (*[3]uint16, error) {
	presence, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if presence != 0 && presence != 1 {
		return nil, ErrInvalidPresenceByte
	}
	slot := make([]byte, manifestVersionBytes)
	if _, err := io.ReadFull(r, slot); err != nil {
		return nil, err
	}
	if presence == 0 {
		for _, v := range slot {
			if v != 0 {
				return nil, ErrManifestVersionNonZeroSlot
			}
		}
		return nil, nil
	}
	var out [3]uint16
	out[0] = binary.BigEndian.Uint16(slot[0:2])
	out[1] = binary.BigEndian.Uint16(slot[2:4])
	out[2] = binary.BigEndian.Uint16(slot[4:6])
	return &out, nil
}

// ─────────────────────────────────────────────────────────────────────────
// Primitive readers
// ─────────────────────────────────────────────────────────────────────────

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
