package smt

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// DeriveKey computes the SMT leaf key for a log position (Decision 29).
// SMT_Key = SHA-256(serialized log_position).
// One rule for all leaves. No exceptions.
//
// When the builder creates a leaf (root entity, no Target_Root), the key is
// SHA-256(entry's own log_position). When a subsequent entry targets it
// (Target_Root = that position), the builder computes SHA-256(Target_Root).
func DeriveKey(pos types.LogPosition) [32]byte {
	// Serialize LogPosition: length-prefixed DID + uint64 sequence.
	did := []byte(pos.LogDID)
	buf := make([]byte, 2+len(did)+8)
	binary.BigEndian.PutUint16(buf[0:2], uint16(len(did)))
	copy(buf[2:2+len(did)], did)
	binary.BigEndian.PutUint64(buf[2+len(did):], pos.Sequence)
	return sha256.Sum256(buf)
}
