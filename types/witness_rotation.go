package types

// WitnessRotation represents a witness set rotation message.
// K-of-N current quorum signs new set. Dual-signed for scheme transitions.
type WitnessRotation struct {
	CurrentSetHash [32]byte           // Hash of current witness public key set
	NewSet         []WitnessPublicKey // The new witness set

	// Current scheme signatures (always present)
	SchemeTagOld        byte               // Current scheme: 0x01 ECDSA or 0x02 BLS
	CurrentSignatures   []WitnessSignature // K-of-N from current set under current scheme

	// New scheme signatures (present only during scheme transition)
	SchemeTagNew      byte               // New scheme (0 if no transition)
	NewSignatures     []WitnessSignature // K-of-N from current set under new scheme keys
}

// WitnessPublicKey identifies a witness and their public key material.
type WitnessPublicKey struct {
	ID        [32]byte // SHA-256 of the raw public key bytes
	PublicKey []byte   // Raw public key bytes (scheme-specific format)
}

// IsDualSigned returns true if this rotation transitions between signature schemes.
func (r WitnessRotation) IsDualSigned() bool {
	return r.SchemeTagNew != 0 && r.SchemeTagNew != r.SchemeTagOld
}
