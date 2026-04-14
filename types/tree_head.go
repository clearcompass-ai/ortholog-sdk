package types

// TreeHead is the root hash and size of a Merkle tree at a point in time.
type TreeHead struct {
	RootHash [32]byte
	TreeSize uint64
}

// CosignedTreeHead is a TreeHead with witness cosignatures.
// The scheme tag determines verification dispatch (ECDSA or BLS).
type CosignedTreeHead struct {
	TreeHead
	SchemeTag  byte               // 0x01 = ECDSA secp256k1, 0x02 = BLS12-381
	Signatures []WitnessSignature // K-of-N cosignatures
}

// WitnessSignature is a single witness cosignature with identifier.
type WitnessSignature struct {
	PubKeyID [32]byte // SHA-256 of witness public key (identifier)
	SigBytes []byte   // Scheme-dependent signature bytes
}

// WitnessCosignMessage returns the canonical 40-byte message that witnesses sign (SDK-D14).
// Format: [SHA-256 root_hash (32 bytes)][uint64 tree_size (8 bytes)] big-endian.
// No prefix, no padding.
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
