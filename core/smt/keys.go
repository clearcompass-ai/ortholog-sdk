package smt

import (
	"crypto/sha256"
	"encoding/binary"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

func DeriveKey(pos types.LogPosition) [32]byte {
	did := []byte(pos.LogDID)
	buf := make([]byte, 2+len(did)+8)
	binary.BigEndian.PutUint16(buf[0:2], uint16(len(did)))
	copy(buf[2:2+len(did)], did)
	binary.BigEndian.PutUint64(buf[2+len(did):], pos.Sequence)
	return sha256.Sum256(buf)
}
