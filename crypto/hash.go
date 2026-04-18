// Package crypto provides general-purpose cryptographic primitives that
// are not Entry-specific. For Entry canonical hashing, see the envelope
// package instead.
package crypto

import "crypto/sha256"

// HashBytes returns SHA-256 of arbitrary bytes.
//
// For Entry canonical hashes, do NOT use this function. Use the
// Tessera-aligned primitives in the envelope package:
//
//   - envelope.EntryIdentity(entry)      — dedup key (SHA-256 of canonical bytes)
//   - envelope.EntryLeafHash(entry)      — RFC 6962 Merkle leaf hash for Tessera
//   - envelope.MarshalBundleEntry(entry) — c2sp.org/tlog-tiles bundle framing
//
// Mixing HashBytes with Entry canonical bytes would bypass destination-
// binding validation and produce plain SHA-256 where RFC 6962 is required
// for Merkle proofs. Use envelope.* for anything Entry-shaped.
func HashBytes(data []byte) [32]byte {
	return sha256.Sum256(data)
}
