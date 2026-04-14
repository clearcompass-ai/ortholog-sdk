// Package crypto provides all cryptographic operations for the Ortholog protocol.
package crypto

import (
	"crypto/sha256"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
)

// CanonicalHash computes SHA-256 over the complete canonical serialization.
// Covers: 6-byte preamble + header body + Domain Payload.
// This hash is the entry's cryptographic identity for all protocol references:
// Merkle leaf computation, Hashcash binding, Cosignature_Of verification,
// Evidence_Pointers resolution, cross-log anchors, commutative sort.
// Hash computed BEFORE signing (pilot Exp 7).
func CanonicalHash(entry *envelope.Entry) [32]byte {
	return sha256.Sum256(envelope.Serialize(entry))
}

// HashBytes computes SHA-256 over arbitrary bytes.
func HashBytes(data []byte) [32]byte {
	return sha256.Sum256(data)
}
