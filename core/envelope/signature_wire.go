package envelope

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Signature algorithm registry (SDK-D2).
const (
	SigAlgoECDSA   uint16 = 0x0001 // ECDSA secp256k1
	SigAlgoEd25519 uint16 = 0x0002 // Ed25519
)

// AppendSignature appends the signature envelope after canonical bytes (SDK-D2).
// Wire format: [canonical_bytes][uint16 sig_algorithm_id][uint32 sig_length][sig_bytes]
// The canonical hash covers only canonical_bytes (bytes 0 through end of Domain Payload).
// The signature covers the canonical hash.
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

// StripSignature extracts canonical bytes and signature data from the wire format.
// Returns canonical bytes (for builder), algorithm ID, raw signature, and any error.
// The operator calls this at admission before passing canonical bytes to the builder.
func StripSignature(wire []byte) (canonical []byte, algoID uint16, sig []byte, err error) {
	// Minimum: 6 (preamble) + 0 (empty header body) + 4 (payload len) + 0 (payload) + 2 (algo) + 4 (siglen) + 0 (sig)
	if len(wire) < 16 {
		return nil, 0, nil, errors.New("wire data too short to contain signature envelope")
	}

	// Parse the entry structure to find where canonical bytes end.
	// Read preamble to get HBL.
	if len(wire) < 6 {
		return nil, 0, nil, errors.New("wire data too short for preamble")
	}
	hbl := binary.BigEndian.Uint32(wire[2:6])

	// Payload starts at 6 + HBL.
	payloadLenStart := uint32(6) + hbl
	if uint32(len(wire)) < payloadLenStart+4 {
		return nil, 0, nil, errors.New("wire data too short for payload length")
	}
	payloadLen := binary.BigEndian.Uint32(wire[payloadLenStart : payloadLenStart+4])

	// Canonical bytes end after payload.
	canonicalEnd := payloadLenStart + 4 + payloadLen
	if uint32(len(wire)) < canonicalEnd+6 { // +2 algo +4 siglen minimum
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

// ValidateAlgorithmID checks that the algorithm ID is in the registry.
func ValidateAlgorithmID(algoID uint16) error {
	switch algoID {
	case SigAlgoECDSA, SigAlgoEd25519:
		return nil
	default:
		return fmt.Errorf("unknown signature algorithm ID 0x%04x", algoID)
	}
}
