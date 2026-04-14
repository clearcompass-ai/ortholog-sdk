package escrow

import (
	"errors"
	"fmt"
)

const (
	FieldTagGF256 byte = 0x01
	FieldTagZp    byte = 0x02
)

const MaxShareValueLen = 256
const ShareWireLen = 34

type Share struct {
	FieldTag byte
	Index    byte
	Value    []byte
}

func SerializeShare(s Share) ([]byte, error) {
	if len(s.Value) != 32 { return nil, fmt.Errorf("share value must be 32 bytes, got %d", len(s.Value)) }
	if s.FieldTag != FieldTagGF256 { return nil, fmt.Errorf("unsupported field tag 0x%02x", s.FieldTag) }
	if s.Index == 0 { return nil, errors.New("share index 0 is reserved") }
	buf := make([]byte, ShareWireLen)
	buf[0] = s.FieldTag; buf[1] = s.Index; copy(buf[2:], s.Value)
	return buf, nil
}

func DeserializeShare(data []byte) (Share, error) {
	if len(data) != ShareWireLen { return Share{}, fmt.Errorf("expected %d bytes, got %d", ShareWireLen, len(data)) }
	if data[0] != FieldTagGF256 { return Share{}, fmt.Errorf("unrecognized field tag 0x%02x", data[0]) }
	if data[1] == 0 { return Share{}, errors.New("share index 0 is reserved") }
	value := make([]byte, 32); copy(value, data[2:])
	return Share{FieldTag: data[0], Index: data[1], Value: value}, nil
}
