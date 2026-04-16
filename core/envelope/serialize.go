// FILE PATH:
//     core/envelope/serialize.go
//
// DESCRIPTION:
//     Binary serialization and deserialization for Ortholog entries. Produces
//     and consumes the canonical wire format: a 6-byte preamble followed by
//     a length-prefixed Control Header body and a length-prefixed Domain
//     Payload. Every variable-width field is explicitly length-prefixed; every
//     fixed-width field uses big-endian byte order.
//
// KEY ARCHITECTURAL DECISIONS:
//     - Admission proof body is length-prefixed with a uint16. This eliminates
//       the historical corruption class where adding a field to the admission
//       proof would silently shift every subsequent header field. A reader
//       that encounters an admission proof body longer than it knows how to
//       parse consumes the full length and moves on, leaving subsequent
//       fields correctly aligned. A reader that encounters a body shorter
//       than it expects detects the truncation immediately and errors.
//     - Fixed-length buffer approach for hash input. The admission proof
//       body carries: mode(1) || nonce(8) || did_len(2) || did(N) ||
//       difficulty(4) || epoch(8) || commit_present(1) || commit(0 or 32).
//       The commit slot is present as raw bytes only when the presence
//       flag is 1; the hash input layout in crypto/admission zero-fills
//       its commit slot when absent, but the wire layout elides those
//       bytes to avoid wasting 32 bytes per entry that doesn't use commits.
//     - Strict protocol version enforcement. Deserialize rejects any entry
//       whose version is not currentProtocolVersion. No partial or forward-
//       compatible parsing modes.
//     - Sub-reader pattern for length-prefixed bodies. readAdmissionProof
//       reads the length prefix, slices exactly that many bytes into a
//       bounded sub-reader, and parses within the sub-reader. Any extra
//       bytes beyond what the current code expects are consumed by the
//       outer reader advancing past the full length, keeping future
//       additions from corrupting adjacent fields.
//
// OVERVIEW:
//     Wire format of a full entry:
//
//       version(2) || header_body_length(4) || header_body(H) ||
//       payload_length(4) || payload(P)
//
//     Wire format of the header body:
//
//       signer_did || subject_identifier || target_root ||
//       target_intermediate || authority_path || delegate_did ||
//       authority_set || authority_did || schema_ref ||
//       evidence_pointers || key_generation_mode ||
//       commutative_operations || delegation_pointers ||
//       scope_pointer || approval_pointers || prior_authority ||
//       cosignature_of || event_time || admission_proof ||
//       authority_skip
//
//     The admission proof sub-body (inside its uint16 length prefix) is:
//
//       mode(1) || [if Mode B] nonce(8) || did_len(2) || did(N) ||
//                 difficulty(4) || epoch(8) ||
//                 commit_present(1) || [if present] commit(32)
//
// KEY DEPENDENCIES:
//     - types/log_position.go: LogPosition type used in position fields.
//     - types/admission.go: AdmissionProof and AdmissionMode.
//     - core/envelope/api.go: currentProtocolVersion constant.
//     - core/envelope/control_header.go: ControlHeader struct.
package envelope

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// -------------------------------------------------------------------------------------------------
// 1) Top-level serialize / deserialize
// -------------------------------------------------------------------------------------------------

// Serialize encodes an Entry to its canonical wire bytes. The Entry's
// ProtocolVersion is written as-is; callers obtain Entry values via
// NewEntry, which sets ProtocolVersion to currentProtocolVersion.
func Serialize(e *Entry) []byte {
	hb := serializeHeaderBody(&e.Header)
	total := 6 + len(hb) + 4 + len(e.DomainPayload)
	buf := make([]byte, 0, total)
	buf = appendUint16(buf, e.Header.ProtocolVersion)
	buf = appendUint32(buf, uint32(len(hb)))
	buf = append(buf, hb...)
	buf = appendUint32(buf, uint32(len(e.DomainPayload)))
	buf = append(buf, e.DomainPayload...)
	return buf
}

// serializeHeaderBody writes every Control Header field in canonical order.
// Field order is wire-format-stable: reordering is a breaking change.
func serializeHeaderBody(h *ControlHeader) []byte {
	var buf []byte
	buf = appendDID(buf, h.SignerDID)
	buf = appendBytes(buf, h.SubjectIdentifier)
	buf = appendOptionalPosition(buf, h.TargetRoot)
	buf = appendOptionalPosition(buf, h.TargetIntermediate)
	buf = appendOptionalEnum(buf, h.AuthorityPath)
	buf = appendOptionalDID(buf, h.DelegateDID)
	buf = appendAuthoritySet(buf, h.AuthoritySet)
	buf = appendOptionalDID(buf, h.AuthorityDID)
	buf = appendOptionalPosition(buf, h.SchemaRef)
	buf = appendPositionSlice(buf, h.EvidencePointers)
	buf = appendOptionalKeyGenMode(buf, h.KeyGenerationMode)
	buf = appendUint32Slice(buf, h.CommutativeOperations)
	buf = appendPositionSlice(buf, h.DelegationPointers)
	buf = appendOptionalPosition(buf, h.ScopePointer)
	buf = appendPositionSlice(buf, h.ApprovalPointers)
	buf = appendOptionalPosition(buf, h.PriorAuthority)
	buf = appendOptionalPosition(buf, h.CosignatureOf)
	buf = appendInt64(buf, h.EventTime)
	buf = appendAdmissionProof(buf, h.AdmissionProof)
	buf = appendOptionalPosition(buf, h.AuthoritySkip)
	return buf
}

// Deserialize decodes canonical wire bytes into an Entry. Returns an error
// for any structural inconsistency: wrong protocol version, truncated
// preamble, truncated header body, truncated payload, or header body bytes
// unaccounted-for after parsing all fields.
func Deserialize(data []byte) (*Entry, error) {
	if len(data) < 6 {
		return nil, errors.New("entry too short for preamble")
	}
	version := binary.BigEndian.Uint16(data[0:2])
	hbl := binary.BigEndian.Uint32(data[2:6])
	if version != currentProtocolVersion {
		return nil, fmt.Errorf("unsupported protocol version %d (expected %d)", version, currentProtocolVersion)
	}
	if uint32(len(data)) < 6+hbl+4 {
		return nil, errors.New("entry too short for header body + payload length")
	}
	headerBody := data[6 : 6+hbl]

	r := &reader{data: headerBody}
	var h ControlHeader
	h.ProtocolVersion = version

	var err error
	if h.SignerDID, err = r.readDID(); err != nil {
		return nil, fmt.Errorf("Signer_DID: %w", err)
	}
	if h.SubjectIdentifier, err = r.readBytes(); err != nil {
		return nil, fmt.Errorf("Subject_Identifier: %w", err)
	}
	if h.TargetRoot, err = r.readOptionalPosition(); err != nil {
		return nil, fmt.Errorf("Target_Root: %w", err)
	}
	if h.TargetIntermediate, err = r.readOptionalPosition(); err != nil {
		return nil, fmt.Errorf("Target_Intermediate: %w", err)
	}
	if h.AuthorityPath, err = r.readOptionalAuthorityPath(); err != nil {
		return nil, fmt.Errorf("Authority_Path: %w", err)
	}
	if h.DelegateDID, err = r.readOptionalDID(); err != nil {
		return nil, fmt.Errorf("Delegate_DID: %w", err)
	}
	if h.AuthoritySet, err = r.readAuthoritySet(); err != nil {
		return nil, fmt.Errorf("Authority_Set: %w", err)
	}
	if h.AuthorityDID, err = r.readOptionalDID(); err != nil {
		return nil, fmt.Errorf("Authority_DID: %w", err)
	}
	if h.SchemaRef, err = r.readOptionalPosition(); err != nil {
		return nil, fmt.Errorf("Schema_Ref: %w", err)
	}
	if h.EvidencePointers, err = r.readPositionSlice(); err != nil {
		return nil, fmt.Errorf("Evidence_Pointers: %w", err)
	}
	if h.KeyGenerationMode, err = r.readOptionalKeyGenMode(); err != nil {
		return nil, fmt.Errorf("Key_Generation_Mode: %w", err)
	}
	if h.CommutativeOperations, err = r.readUint32Slice(); err != nil {
		return nil, fmt.Errorf("Commutative_Operations: %w", err)
	}
	if h.DelegationPointers, err = r.readPositionSlice(); err != nil {
		return nil, fmt.Errorf("Delegation_Pointers: %w", err)
	}
	if h.ScopePointer, err = r.readOptionalPosition(); err != nil {
		return nil, fmt.Errorf("Scope_Pointer: %w", err)
	}
	if h.ApprovalPointers, err = r.readPositionSlice(); err != nil {
		return nil, fmt.Errorf("Approval_Pointers: %w", err)
	}
	if h.PriorAuthority, err = r.readOptionalPosition(); err != nil {
		return nil, fmt.Errorf("Prior_Authority: %w", err)
	}
	if h.CosignatureOf, err = r.readOptionalPosition(); err != nil {
		return nil, fmt.Errorf("Cosignature_Of: %w", err)
	}
	if h.EventTime, err = r.readInt64(); err != nil {
		return nil, fmt.Errorf("Event_Time: %w", err)
	}
	if h.AdmissionProof, err = r.readAdmissionProof(); err != nil {
		return nil, fmt.Errorf("Admission_Proof: %w", err)
	}
	if h.AuthoritySkip, err = r.readOptionalPosition(); err != nil {
		return nil, fmt.Errorf("Authority_Skip: %w", err)
	}

	if r.pos != len(r.data) {
		return nil, fmt.Errorf("header body consumed %d bytes but HBL is %d", r.pos, len(r.data))
	}

	payloadStart := 6 + hbl
	if uint32(len(data)) < payloadStart+4 {
		return nil, errors.New("truncated payload length")
	}
	payloadLen := binary.BigEndian.Uint32(data[payloadStart : payloadStart+4])
	payloadDataStart := payloadStart + 4
	if uint32(len(data)) < payloadDataStart+payloadLen {
		return nil, errors.New("truncated payload data")
	}
	var payload []byte
	if payloadLen > 0 {
		payload = make([]byte, payloadLen)
		copy(payload, data[payloadDataStart:payloadDataStart+payloadLen])
	}
	return &Entry{Header: h, DomainPayload: payload}, nil
}

// -------------------------------------------------------------------------------------------------
// 2) Primitive appenders
// -------------------------------------------------------------------------------------------------

func appendUint16(buf []byte, v uint16) []byte {
	return append(buf, byte(v>>8), byte(v))
}

func appendUint32(buf []byte, v uint32) []byte {
	return append(buf, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func appendUint64(buf []byte, v uint64) []byte {
	return append(buf,
		byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
		byte(v>>24), byte(v>>16), byte(v>>8), byte(v),
	)
}

func appendInt64(buf []byte, v int64) []byte { return appendUint64(buf, uint64(v)) }

func appendDID(buf []byte, did string) []byte {
	b := []byte(did)
	buf = appendUint16(buf, uint16(len(b)))
	return append(buf, b...)
}

func appendOptionalDID(buf []byte, did *string) []byte {
	if did == nil {
		return appendUint16(buf, 0)
	}
	return appendDID(buf, *did)
}

func appendPosition(buf []byte, p types.LogPosition) []byte {
	buf = appendDID(buf, p.LogDID)
	return appendUint64(buf, p.Sequence)
}

func appendOptionalPosition(buf []byte, p *types.LogPosition) []byte {
	if p == nil {
		return append(buf, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	}
	return appendPosition(buf, *p)
}

func appendOptionalEnum(buf []byte, ap *AuthorityPath) []byte {
	if ap == nil {
		return append(buf, 0)
	}
	return append(buf, byte(*ap))
}

func appendOptionalKeyGenMode(buf []byte, k *KeyGenMode) []byte {
	if k == nil {
		return append(buf, 0)
	}
	return append(buf, byte(*k))
}

func appendBytes(buf []byte, data []byte) []byte {
	buf = appendUint32(buf, uint32(len(data)))
	return append(buf, data...)
}

func appendPositionSlice(buf []byte, positions []types.LogPosition) []byte {
	buf = appendUint16(buf, uint16(len(positions)))
	for _, p := range positions {
		buf = appendPosition(buf, p)
	}
	return buf
}

func appendUint32Slice(buf []byte, values []uint32) []byte {
	buf = appendUint16(buf, uint16(len(values)))
	for _, v := range values {
		buf = appendUint32(buf, v)
	}
	return buf
}

func appendAuthoritySet(buf []byte, set map[string]struct{}) []byte {
	if len(set) == 0 {
		return appendUint16(buf, 0)
	}
	dids := make([]string, 0, len(set))
	for did := range set {
		dids = append(dids, did)
	}
	sort.Strings(dids)
	buf = appendUint16(buf, uint16(len(dids)))
	for _, did := range dids {
		buf = appendDID(buf, did)
	}
	return buf
}

// -------------------------------------------------------------------------------------------------
// 3) AdmissionProof serialization
// -------------------------------------------------------------------------------------------------

// appendAdmissionProof writes a length-prefixed admission proof body.
// The outer uint16 length prefix lets future readers skip unknown
// trailing bytes; current readers validate that they consumed exactly
// the advertised length.
//
// Body layout for Mode B:
//
//	mode(1) || nonce(8) || did_len(2) || did(N) ||
//	difficulty(4) || epoch(8) ||
//	commit_present(1) || [if present] commit(32)
//
// When the admission proof is nil (e.g., Mode A entries), we write a
// zero length prefix with no body. This is the canonical representation
// of "no admission proof".
func appendAdmissionProof(buf []byte, ap *types.AdmissionProof) []byte {
	if ap == nil {
		return appendUint16(buf, 0)
	}

	// Build the body first so we can prefix it with its exact length.
	var body []byte
	body = append(body, byte(ap.Mode))
	switch ap.Mode {
	case types.AdmissionModeA:
		// Mode A has no further fields. Body is a single mode byte.
	case types.AdmissionModeB:
		body = appendUint64(body, ap.Nonce)
		body = appendDID(body, ap.TargetLog)
		body = appendUint32(body, ap.Difficulty)
		body = appendUint64(body, ap.Epoch)
		if ap.SubmitterCommit != nil {
			body = append(body, 1)
			body = append(body, ap.SubmitterCommit[:]...)
		} else {
			body = append(body, 0)
		}
	default:
		// Unreachable after NewEntry validation, but if we ever serialize
		// an unvalidated proof, we emit just the mode byte and let the
		// receiver reject it. Fail-loud behavior at parse time.
	}

	if len(body) > 0xFFFF {
		// An admission proof body exceeding 65535 bytes is pathological
		// (the commit is 32 bytes, the DID is bounded to 65535 bytes,
		// and fixed-width fields sum to 24 bytes). This branch exists
		// only as a guard against a future protocol error where someone
		// adds an unbounded field to the proof body.
		panic(fmt.Sprintf("admission proof body length %d exceeds uint16 max", len(body)))
	}
	buf = appendUint16(buf, uint16(len(body)))
	return append(buf, body...)
}

// -------------------------------------------------------------------------------------------------
// 4) Reader primitive and AdmissionProof deserialization
// -------------------------------------------------------------------------------------------------

// reader is a bounded sequential byte reader over a fixed input slice.
// The pos field is the next byte to read; remaining() reports how many
// bytes are still available.
type reader struct {
	data []byte
	pos  int
}

func (r *reader) remaining() int { return len(r.data) - r.pos }

func (r *reader) readUint8() (uint8, error) {
	if r.remaining() < 1 {
		return 0, errors.New("unexpected end of data reading uint8")
	}
	v := r.data[r.pos]
	r.pos++
	return v, nil
}

func (r *reader) readUint16() (uint16, error) {
	if r.remaining() < 2 {
		return 0, errors.New("unexpected end of data reading uint16")
	}
	v := binary.BigEndian.Uint16(r.data[r.pos : r.pos+2])
	r.pos += 2
	return v, nil
}

func (r *reader) readUint32() (uint32, error) {
	if r.remaining() < 4 {
		return 0, errors.New("unexpected end of data reading uint32")
	}
	v := binary.BigEndian.Uint32(r.data[r.pos : r.pos+4])
	r.pos += 4
	return v, nil
}

func (r *reader) readUint64() (uint64, error) {
	if r.remaining() < 8 {
		return 0, errors.New("unexpected end of data reading uint64")
	}
	v := binary.BigEndian.Uint64(r.data[r.pos : r.pos+8])
	r.pos += 8
	return v, nil
}

func (r *reader) readInt64() (int64, error) {
	v, err := r.readUint64()
	return int64(v), err
}

func (r *reader) readDID() (string, error) {
	length, err := r.readUint16()
	if err != nil {
		return "", err
	}
	if r.remaining() < int(length) {
		return "", errors.New("unexpected end of data reading DID bytes")
	}
	did := string(r.data[r.pos : r.pos+int(length)])
	r.pos += int(length)
	return did, nil
}

func (r *reader) readOptionalDID() (*string, error) {
	did, err := r.readDID()
	if err != nil {
		return nil, err
	}
	if did == "" {
		return nil, nil
	}
	return &did, nil
}

func (r *reader) readPosition() (types.LogPosition, error) {
	did, err := r.readDID()
	if err != nil {
		return types.LogPosition{}, err
	}
	seq, err := r.readUint64()
	if err != nil {
		return types.LogPosition{}, err
	}
	return types.LogPosition{LogDID: did, Sequence: seq}, nil
}

func (r *reader) readOptionalPosition() (*types.LogPosition, error) {
	p, err := r.readPosition()
	if err != nil {
		return nil, err
	}
	if p.IsNull() {
		return nil, nil
	}
	return &p, nil
}

func (r *reader) readPositionSlice() ([]types.LogPosition, error) {
	count, err := r.readUint16()
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, nil
	}
	result := make([]types.LogPosition, count)
	for i := uint16(0); i < count; i++ {
		result[i], err = r.readPosition()
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

func (r *reader) readBytes() ([]byte, error) {
	length, err := r.readUint32()
	if err != nil {
		return nil, err
	}
	if length == 0 {
		return nil, nil
	}
	if r.remaining() < int(length) {
		return nil, errors.New("unexpected end of data reading bytes")
	}
	result := make([]byte, length)
	copy(result, r.data[r.pos:r.pos+int(length)])
	r.pos += int(length)
	return result, nil
}

func (r *reader) readOptionalAuthorityPath() (*AuthorityPath, error) {
	v, err := r.readUint8()
	if err != nil {
		return nil, err
	}
	if v == 0 {
		return nil, nil
	}
	ap := AuthorityPath(v)
	return &ap, nil
}

func (r *reader) readOptionalKeyGenMode() (*KeyGenMode, error) {
	v, err := r.readUint8()
	if err != nil {
		return nil, err
	}
	if v == 0 {
		return nil, nil
	}
	k := KeyGenMode(v)
	return &k, nil
}

func (r *reader) readAuthoritySet() (map[string]struct{}, error) {
	count, err := r.readUint16()
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, nil
	}
	set := make(map[string]struct{}, count)
	for i := uint16(0); i < count; i++ {
		did, err := r.readDID()
		if err != nil {
			return nil, err
		}
		set[did] = struct{}{}
	}
	return set, nil
}

func (r *reader) readUint32Slice() ([]uint32, error) {
	count, err := r.readUint16()
	if err != nil {
		return nil, err
	}
	if count == 0 {
		return nil, nil
	}
	result := make([]uint32, count)
	for i := uint16(0); i < count; i++ {
		result[i], err = r.readUint32()
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

// readAdmissionProof parses a length-prefixed admission proof body.
// The outer length prefix governs how many bytes this method consumes
// from the parent reader, regardless of how many bytes the mode-specific
// body actually contains. This makes admission proof evolution safe:
// adding fields to the body increases its length but cannot corrupt
// any field serialized after the admission proof.
func (r *reader) readAdmissionProof() (*types.AdmissionProof, error) {
	bodyLen, err := r.readUint16()
	if err != nil {
		return nil, err
	}
	if bodyLen == 0 {
		return nil, nil
	}
	if r.remaining() < int(bodyLen) {
		return nil, errors.New("truncated admission proof body")
	}
	// Advance the outer reader past the full advertised length, then
	// parse within a sub-reader bounded to exactly bodyLen bytes. Any
	// bytes the current parser does not recognize are effectively
	// skipped without corrupting subsequent header fields.
	sub := &reader{data: r.data[r.pos : r.pos+int(bodyLen)]}
	r.pos += int(bodyLen)

	mode, err := sub.readUint8()
	if err != nil {
		return nil, err
	}

	ap := &types.AdmissionProof{Mode: types.AdmissionMode(mode)}
	switch ap.Mode {
	case types.AdmissionModeA:
		// No further fields.
	case types.AdmissionModeB:
		if ap.Nonce, err = sub.readUint64(); err != nil {
			return nil, fmt.Errorf("admission proof nonce: %w", err)
		}
		if ap.TargetLog, err = sub.readDID(); err != nil {
			return nil, fmt.Errorf("admission proof target_log: %w", err)
		}
		if ap.Difficulty, err = sub.readUint32(); err != nil {
			return nil, fmt.Errorf("admission proof difficulty: %w", err)
		}
		if ap.Epoch, err = sub.readUint64(); err != nil {
			return nil, fmt.Errorf("admission proof epoch: %w", err)
		}
		presence, err := sub.readUint8()
		if err != nil {
			return nil, fmt.Errorf("admission proof commit_present: %w", err)
		}
		switch presence {
		case 0:
			// commit absent
		case 1:
			if sub.remaining() < 32 {
				return nil, errors.New("admission proof commit truncated")
			}
			var commit [32]byte
			copy(commit[:], sub.data[sub.pos:sub.pos+32])
			sub.pos += 32
			ap.SubmitterCommit = &commit
		default:
			return nil, fmt.Errorf("admission proof commit_present invalid: %d", presence)
		}
	default:
		return nil, fmt.Errorf("unrecognized admission mode %d", ap.Mode)
	}

	return ap, nil
}
