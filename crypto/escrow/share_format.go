package escrow

import (
	"errors"
	"fmt"
)

// Field tag constants (Decision 48).
const (
	FieldTagGF256 byte = 0x01 // GF(256) over AES irreducible polynomial 0x11B
	FieldTagZp    byte = 0x02 // Z_p where p = 2^256 - 189 (not implemented in SDK v1)
)

// MaxShareValueLen is the maximum share value length.
// For 32-byte secrets (AES-256 keys), shares are 32 bytes.
const MaxShareValueLen = 256

// ShareWireLen is the fixed wire length for a 32-byte share: 1 (tag) + 1 (index) + 32 (value).
const ShareWireLen = 34

// Share is a single Shamir share with field tag for cross-field safety.
type Share struct {
	FieldTag byte   // 0x01 = GF(256). Mandatory for reconstruction safety.
	Index    byte   // Share index (1-based, 0 reserved for secret)
	Value    []byte // Share value (same length as original secret)
}

// SerializeShare serializes a 32-byte share to the 34-byte wire format.
// Format: [1 byte field tag][1 byte index][32 bytes value]
func SerializeShare(s Share) ([]byte, error) {
	if len(s.Value) != 32 {
		return nil, fmt.Errorf("share value must be 32 bytes for wire format, got %d", len(s.Value))
	}
	if s.FieldTag != FieldTagGF256 {
		return nil, fmt.Errorf("unsupported field tag 0x%02x", s.FieldTag)
	}
	if s.Index == 0 {
		return nil, errors.New("share index 0 is reserved")
	}
	buf := make([]byte, ShareWireLen)
	buf[0] = s.FieldTag
	buf[1] = s.Index
	copy(buf[2:], s.Value)
	return buf, nil
}

// DeserializeShare parses a 34-byte wire share.
// Validates the field tag against recognized values.
func DeserializeShare(data []byte) (Share, error) {
	if len(data) != ShareWireLen {
		return Share{}, fmt.Errorf("expected %d bytes, got %d", ShareWireLen, len(data))
	}
	tag := data[0]
	if tag != FieldTagGF256 {
		return Share{}, fmt.Errorf("unrecognized field tag 0x%02x", tag)
	}
	idx := data[1]
	if idx == 0 {
		return Share{}, errors.New("share index 0 is reserved")
	}
	value := make([]byte, 32)
	copy(value, data[2:])
	return Share{FieldTag: tag, Index: idx, Value: value}, nil
}
