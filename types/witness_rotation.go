package types

type WitnessRotation struct {
	CurrentSetHash    [32]byte
	NewSet            []WitnessPublicKey
	SchemeTagOld      byte
	CurrentSignatures []WitnessSignature
	SchemeTagNew      byte
	NewSignatures     []WitnessSignature
}

type WitnessPublicKey struct {
	ID        [32]byte
	PublicKey []byte
}

func (r WitnessRotation) IsDualSigned() bool {
	return r.SchemeTagNew != 0 && r.SchemeTagNew != r.SchemeTagOld
}
