package envelope

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// Serialize produces the canonical byte representation of an entry.
// Two compliant implementations serializing the same logical entry produce identical bytes.
// Format: [6-byte preamble][header body][uint32 payload length][payload bytes]
func Serialize(e *Entry) []byte {
	// Serialize header body to temp buffer first to measure HBL.
	hb := serializeHeaderBody(&e.Header)

	// Total size: 6 (preamble) + len(hb) + 4 (payload len) + len(payload)
	total := 6 + len(hb) + 4 + len(e.DomainPayload)
	buf := make([]byte, 0, total)

	// 6-byte preamble: [uint16 Protocol_Version][uint32 HBL]
	buf = appendUint16(buf, e.Header.ProtocolVersion)
	buf = appendUint32(buf, uint32(len(hb)))

	// Header body
	buf = append(buf, hb...)

	// Domain Payload: uint32 length prefix + opaque bytes
	buf = appendUint32(buf, uint32(len(e.DomainPayload)))
	buf = append(buf, e.DomainPayload...)

	return buf
}

// serializeHeaderBody serializes all header body fields in declaration order.
// Signer_DID first, Authority_Skip last.
func serializeHeaderBody(h *ControlHeader) []byte {
	var buf []byte

	// 1. Signer_DID
	buf = appendDID(buf, h.SignerDID)

	// 2. Subject_Identifier (opaque bytes)
	buf = appendBytes(buf, h.SubjectIdentifier)

	// 3. Target_Root
	buf = appendOptionalPosition(buf, h.TargetRoot)

	// 4. Target_Intermediate
	buf = appendOptionalPosition(buf, h.TargetIntermediate)

	// 5. Authority_Path (enum)
	buf = appendOptionalEnum(buf, h.AuthorityPath)

	// 6. Delegate_DID
	buf = appendOptionalDID(buf, h.DelegateDID)

	// 7. Authority_Set (sorted by raw UTF-8 bytes)
	buf = appendAuthoritySet(buf, h.AuthoritySet)

	// 8. Authority_DID
	buf = appendOptionalDID(buf, h.AuthorityDID)

	// 9. Schema_Ref
	buf = appendOptionalPosition(buf, h.SchemaRef)

	// 10. Evidence_Pointers
	buf = appendPositionSlice(buf, h.EvidencePointers)

	// 11. Key_Generation_Mode (enum)
	buf = appendOptionalKeyGenMode(buf, h.KeyGenerationMode)

	// 12. Commutative_Operations ([]uint32)
	buf = appendUint32Slice(buf, h.CommutativeOperations)

	// 13. Delegation_Pointers
	buf = appendPositionSlice(buf, h.DelegationPointers)

	// 14. Scope_Pointer
	buf = appendOptionalPosition(buf, h.ScopePointer)

	// 15. Approval_Pointers
	buf = appendPositionSlice(buf, h.ApprovalPointers)

	// 16. Prior_Authority
	buf = appendOptionalPosition(buf, h.PriorAuthority)

	// 17. Cosignature_Of
	buf = appendOptionalPosition(buf, h.CosignatureOf)

	// 18. Event_Time (int64 Unix microseconds)
	buf = appendInt64(buf, h.EventTime)

	// 19. Admission_Proof
	buf = appendAdmissionProof(buf, h.AdmissionProof)

	// 20. Authority_Skip
	buf = appendOptionalPosition(buf, h.AuthoritySkip)

	return buf
}

// Deserialize parses canonical bytes into an Entry.
// Validates preamble, parses v3 fields, supports cross-version forward compat.
func Deserialize(data []byte) (*Entry, error) {
	if len(data) < 6 {
		return nil, errors.New("entry too short for preamble")
	}

	version := binary.BigEndian.Uint16(data[0:2])
	hbl := binary.BigEndian.Uint32(data[2:6])

	if version != currentProtocolVersion {
		// Cross-version: we can still parse if we skip unknown fields.
		// For now, only v3 is supported.
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

	// Parse fields in declaration order.
	h.SignerDID, err = r.readDID()
	if err != nil {
		return nil, fmt.Errorf("Signer_DID: %w", err)
	}

	h.SubjectIdentifier, err = r.readBytes()
	if err != nil {
		return nil, fmt.Errorf("Subject_Identifier: %w", err)
	}

	h.TargetRoot, err = r.readOptionalPosition()
	if err != nil {
		return nil, fmt.Errorf("Target_Root: %w", err)
	}

	h.TargetIntermediate, err = r.readOptionalPosition()
	if err != nil {
		return nil, fmt.Errorf("Target_Intermediate: %w", err)
	}

	h.AuthorityPath, err = r.readOptionalAuthorityPath()
	if err != nil {
		return nil, fmt.Errorf("Authority_Path: %w", err)
	}

	h.DelegateDID, err = r.readOptionalDID()
	if err != nil {
		return nil, fmt.Errorf("Delegate_DID: %w", err)
	}

	h.AuthoritySet, err = r.readAuthoritySet()
	if err != nil {
		return nil, fmt.Errorf("Authority_Set: %w", err)
	}

	h.AuthorityDID, err = r.readOptionalDID()
	if err != nil {
		return nil, fmt.Errorf("Authority_DID: %w", err)
	}

	h.SchemaRef, err = r.readOptionalPosition()
	if err != nil {
		return nil, fmt.Errorf("Schema_Ref: %w", err)
	}

	h.EvidencePointers, err = r.readPositionSlice()
	if err != nil {
		return nil, fmt.Errorf("Evidence_Pointers: %w", err)
	}

	h.KeyGenerationMode, err = r.readOptionalKeyGenMode()
	if err != nil {
		return nil, fmt.Errorf("Key_Generation_Mode: %w", err)
	}

	h.CommutativeOperations, err = r.readUint32Slice()
	if err != nil {
		return nil, fmt.Errorf("Commutative_Operations: %w", err)
	}

	h.DelegationPointers, err = r.readPositionSlice()
	if err != nil {
		return nil, fmt.Errorf("Delegation_Pointers: %w", err)
	}

	h.ScopePointer, err = r.readOptionalPosition()
	if err != nil {
		return nil, fmt.Errorf("Scope_Pointer: %w", err)
	}

	h.ApprovalPointers, err = r.readPositionSlice()
	if err != nil {
		return nil, fmt.Errorf("Approval_Pointers: %w", err)
	}

	h.PriorAuthority, err = r.readOptionalPosition()
	if err != nil {
		return nil, fmt.Errorf("Prior_Authority: %w", err)
	}

	h.CosignatureOf, err = r.readOptionalPosition()
	if err != nil {
		return nil, fmt.Errorf("Cosignature_Of: %w", err)
	}

	h.EventTime, err = r.readInt64()
	if err != nil {
		return nil, fmt.Errorf("Event_Time: %w", err)
	}

	h.AdmissionProof, err = r.readAdmissionProof()
	if err != nil {
		return nil, fmt.Errorf("Admission_Proof: %w", err)
	}

	h.AuthoritySkip, err = r.readOptionalPosition()
	if err != nil {
		return nil, fmt.Errorf("Authority_Skip: %w", err)
	}

	// Same-version consistency check: consumed must equal HBL.
	if r.pos != len(r.data) {
		return nil, fmt.Errorf("header body consumed %d bytes but HBL is %d", r.pos, len(r.data))
	}

	// Read Domain Payload after header body.
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

// ── Serialization helpers ──────────────────────────────────────────────

func appendUint16(buf []byte, v uint16) []byte {
	return append(buf, byte(v>>8), byte(v))
}

func appendUint32(buf []byte, v uint32) []byte {
	return append(buf, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func appendUint64(buf []byte, v uint64) []byte {
	return append(buf, byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
		byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func appendInt64(buf []byte, v int64) []byte {
	return appendUint64(buf, uint64(v))
}

// appendDID serializes a DID: uint16 length + UTF-8 bytes.
func appendDID(buf []byte, did string) []byte {
	b := []byte(did)
	buf = appendUint16(buf, uint16(len(b)))
	return append(buf, b...)
}

// appendOptionalDID serializes a *string DID: null = uint16(0).
func appendOptionalDID(buf []byte, did *string) []byte {
	if did == nil {
		return appendUint16(buf, 0)
	}
	return appendDID(buf, *did)
}

// appendPosition serializes a LogPosition: DID (length-prefixed) + uint64 sequence.
// Null LogPosition = 10 zero bytes.
func appendPosition(buf []byte, p types.LogPosition) []byte {
	buf = appendDID(buf, p.LogDID)
	buf = appendUint64(buf, p.Sequence)
	return buf
}

// appendOptionalPosition serializes *LogPosition: nil -> null (10 zero bytes).
func appendOptionalPosition(buf []byte, p *types.LogPosition) []byte {
	if p == nil {
		// Null LogPosition: uint16(0) for DID len + uint64(0) for seq = 10 zero bytes.
		return append(buf, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
	}
	return appendPosition(buf, *p)
}

// appendOptionalEnum serializes *AuthorityPath: nil -> uint8(0).
func appendOptionalEnum(buf []byte, ap *AuthorityPath) []byte {
	if ap == nil {
		return append(buf, 0)
	}
	return append(buf, byte(*ap))
}

// appendOptionalKeyGenMode serializes *KeyGenMode: nil -> uint8(0).
func appendOptionalKeyGenMode(buf []byte, k *KeyGenMode) []byte {
	if k == nil {
		return append(buf, 0)
	}
	return append(buf, byte(*k))
}

// appendBytes serializes opaque bytes: uint32 length + raw bytes.
func appendBytes(buf []byte, data []byte) []byte {
	buf = appendUint32(buf, uint32(len(data)))
	return append(buf, data...)
}

// appendPositionSlice serializes []LogPosition: uint16 count + elements.
func appendPositionSlice(buf []byte, positions []types.LogPosition) []byte {
	buf = appendUint16(buf, uint16(len(positions)))
	for _, p := range positions {
		buf = appendPosition(buf, p)
	}
	return buf
}

// appendUint32Slice serializes []uint32: uint16 count + big-endian elements.
func appendUint32Slice(buf []byte, values []uint32) []byte {
	buf = appendUint16(buf, uint16(len(values)))
	for _, v := range values {
		buf = appendUint32(buf, v)
	}
	return buf
}

// appendAuthoritySet serializes Authority_Set as sorted DID array.
// Sorted by raw UTF-8 bytes for determinism.
func appendAuthoritySet(buf []byte, set map[string]struct{}) []byte {
	if len(set) == 0 {
		return appendUint16(buf, 0)
	}
	// Sort deterministically by raw UTF-8 bytes.
	dids := make([]string, 0, len(set))
	for did := range set {
		dids = append(dids, did)
	}
	sort.Strings(dids) // Strings sorts by UTF-8 byte values.
	buf = appendUint16(buf, uint16(len(dids)))
	for _, did := range dids {
		buf = appendDID(buf, did)
	}
	return buf
}

// appendAdmissionProof serializes AdmissionProof: uint8 mode + fields.
func appendAdmissionProof(buf []byte, ap *types.AdmissionProof) []byte {
	if ap == nil {
		return append(buf, 0) // Mode A: null
	}
	buf = append(buf, byte(ap.Mode))
	if ap.Mode == types.AdmissionModeB {
		buf = appendUint64(buf, ap.Nonce)
		buf = appendDID(buf, ap.TargetLog)
		buf = appendUint32(buf, ap.Difficulty)
	}
	return buf
}

// ── Deserialization reader ─────────────────────────────────────────────

type reader struct {
	data []byte
	pos  int
}

func (r *reader) remaining() int {
	return len(r.data) - r.pos
}

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

func (r *reader) readAdmissionProof() (*types.AdmissionProof, error) {
	mode, err := r.readUint8()
	if err != nil {
		return nil, err
	}
	if mode == 0 {
		return nil, nil // Mode A: null
	}
	ap := &types.AdmissionProof{Mode: types.AdmissionMode(mode)}
	if ap.Mode == types.AdmissionModeB {
		ap.Nonce, err = r.readUint64()
		if err != nil {
			return nil, err
		}
		ap.TargetLog, err = r.readDID()
		if err != nil {
			return nil, err
		}
		ap.Difficulty, err = r.readUint32()
		if err != nil {
			return nil, err
		}
	}
	return ap, nil
}
