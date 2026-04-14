package types

import "time"

// EntryWithMetadata wraps an entry with operator-assigned metadata.
// Returned by the EntryFetcher interface. The entry fetcher contract
// guarantees all returned entries have had signatures verified at
// admission (SDK-D5).
type EntryWithMetadata struct {
	// CanonicalBytes is the complete serialized entry (preamble + header body + payload).
	// This is what gets hashed for canonical_hash.
	CanonicalBytes []byte

	// LogTime is operator-assigned at admission (SDK-D1, Decision 50).
	// Outside the canonical hash. The protocol's timing reference for all
	// duration-based evaluations: maturation, activation delay, time-locks.
	LogTime time.Time

	// Position is the entry's location on the log.
	Position LogPosition

	// SignatureAlgoID is the algorithm used to sign this entry (SDK-D2).
	// 0x0001 = ECDSA secp256k1, 0x0002 = Ed25519.
	// Stripped before builder sees the entry.
	SignatureAlgoID uint16

	// SignatureBytes is the raw signature, stripped at admission.
	// Stored for audit trail and re-verification, never passed to builder.
	SignatureBytes []byte
}
