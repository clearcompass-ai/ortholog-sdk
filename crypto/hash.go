package crypto

import (
	"crypto/sha256"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
)

func CanonicalHash(entry *envelope.Entry) [32]byte {
	return sha256.Sum256(envelope.Serialize(entry))
}

func HashBytes(data []byte) [32]byte {
	return sha256.Sum256(data)
}
