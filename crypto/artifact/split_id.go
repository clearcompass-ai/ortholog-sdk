// Package artifact — split_id.go pins the canonical PRE Grant SplitID
// derivation per ADR-005 §2. Exported so lifecycle builders,
// verifiers, and recipient-side lookup primitives all compute the
// same bytes.
package artifact

import (
	"github.com/clearcompass-ai/ortholog-sdk/crypto"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
)

// PREGrantSplitIDDST is the domain-separation tag for the PRE Grant
// SplitID construction, pinned by ADR-005 §2. The "-v1" suffix exists
// so a future construction migration (for example, a post-quantum
// commitment scheme that changes the underlying derivation) can rev
// the DST — "-v2" — without breaking the universal length-prefix
// rule itself. The rule is permanent; the DST constant is versioned.
//
// Any implementation emitting or verifying PRE grant SplitIDs under
// a different DST is non-conforming.
const PREGrantSplitIDDST = "ORTHOLOG-V7.75-PRE-GRANT-SPLIT-ID-v1"

// ComputePREGrantSplitID derives the deterministic SplitID for a PRE
// grant, per ADR-005 §2:
//
//	SplitID = LengthPrefixed(
//	    "ORTHOLOG-V7.75-PRE-GRANT-SPLIT-ID-v1",
//	    grantorDID,
//	    recipientDID,
//	    artifactCID.Bytes(),
//	)
//
// The tuple (grantorDID, recipientDID, artifactCID) is the minimal
// public context under which a recipient or proxy can locate the
// on-log commitment entry without out-of-band discovery. Because the
// derivation is deterministic, a malicious dealer cannot produce two
// distinct commitment entries for the same tuple: the second attempt
// is either rejected at admission by schema uniqueness or treated as
// cryptographic evidence of equivocation by verifiers.
//
// # artifactCID.Bytes() is mandatory
//
// The third field is artifactCID.Bytes(), not artifactCID.Digest.
// storage.CID supports algorithm agility via RegisterAlgorithm, which
// means two CIDs under different algorithm tags can carry identical
// 32-byte digests while representing cryptographically distinct
// content addresses. Bytes() returns algorithm_byte || digest — the
// authoritative wire form that encodes the algorithm tag as part of
// the identifier. Hashing only Digest would allow such a pair of
// CIDs to produce colliding SplitIDs, which in turn would cause
// commitment-entry lookup to return the wrong commitment for the
// wrong artifact. This is a normative mandate, not a stylistic
// preference.
//
// # Caller-normalizes contract
//
// Both DIDs are expected to be NFC-normalized at the caller
// boundary. The helper operates on raw bytes; if two callers pass
// different byte sequences for what they consider "the same" DID,
// they get different SplitIDs. ADR-005 §2 documents the discipline.
func ComputePREGrantSplitID(grantorDID, recipientDID string, artifactCID storage.CID) [32]byte {
	return crypto.LengthPrefixed(
		PREGrantSplitIDDST,
		[]byte(grantorDID),
		[]byte(recipientDID),
		artifactCID.Bytes(),
	)
}
