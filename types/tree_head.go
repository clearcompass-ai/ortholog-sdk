package types

type TreeHead struct {
	RootHash [32]byte
	TreeSize uint64
}

type CosignedTreeHead struct {
	TreeHead
	SchemeTag  byte
	Signatures []WitnessSignature
}

type WitnessSignature struct {
	PubKeyID [32]byte
	SigBytes []byte
}

func WitnessCosignMessage(head TreeHead) [40]byte {
	var msg [40]byte
	copy(msg[0:32], head.RootHash[:])
	msg[32] = byte(head.TreeSize >> 56)
	msg[33] = byte(head.TreeSize >> 48)
	msg[34] = byte(head.TreeSize >> 40)
	msg[35] = byte(head.TreeSize >> 32)
	msg[36] = byte(head.TreeSize >> 24)
	msg[37] = byte(head.TreeSize >> 16)
	msg[38] = byte(head.TreeSize >> 8)
	msg[39] = byte(head.TreeSize)
	return msg
}
