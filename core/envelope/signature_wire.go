package envelope

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	SigAlgoECDSA   uint16 = 0x0001
	SigAlgoEd25519 uint16 = 0x0002
)

func AppendSignature(canonical []byte, algoID uint16, sig []byte) []byte {
	result := make([]byte, len(canonical)+2+4+len(sig))
	copy(result, canonical)
	off := len(canonical)
	binary.BigEndian.PutUint16(result[off:], algoID)
	off += 2
	binary.BigEndian.PutUint32(result[off:], uint32(len(sig)))
	off += 4
	copy(result[off:], sig)
	return result
}

func StripSignature(wire []byte) (canonical []byte, algoID uint16, sig []byte, err error) {
	if len(wire) < 16 {
		return nil, 0, nil, errors.New("wire data too short to contain signature envelope")
	}
	if len(wire) < 6 {
		return nil, 0, nil, errors.New("wire data too short for preamble")
	}
	hbl := binary.BigEndian.Uint32(wire[2:6])
	payloadLenStart := uint32(6) + hbl
	if uint32(len(wire)) < payloadLenStart+4 {
		return nil, 0, nil, errors.New("wire data too short for payload length")
	}
	payloadLen := binary.BigEndian.Uint32(wire[payloadLenStart : payloadLenStart+4])
	canonicalEnd := payloadLenStart + 4 + payloadLen
	if uint32(len(wire)) < canonicalEnd+6 {
		return nil, 0, nil, errors.New("wire data too short for signature envelope")
	}
	canonical = wire[:canonicalEnd]
	algoID = binary.BigEndian.Uint16(wire[canonicalEnd : canonicalEnd+2])
	sigLen := binary.BigEndian.Uint32(wire[canonicalEnd+2 : canonicalEnd+6])
	sigStart := canonicalEnd + 6
	if uint32(len(wire)) < sigStart+sigLen {
		return nil, 0, nil, errors.New("wire data too short for signature bytes")
	}
	sig = wire[sigStart : sigStart+sigLen]
	return canonical, algoID, sig, nil
}

func ValidateAlgorithmID(algoID uint16) error {
	switch algoID {
	case SigAlgoECDSA, SigAlgoEd25519:
		return nil
	default:
		return fmt.Errorf("unknown signature algorithm ID 0x%04x", algoID)
	}
}
