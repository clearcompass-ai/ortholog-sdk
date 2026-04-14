package admission

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
)

type HashFunc uint8
const (
	HashSHA256   HashFunc = 0
	HashArgon2id HashFunc = 1
)

type Argon2idParams struct { Time uint32; Memory uint32; Threads uint8 }
func DefaultArgon2idParams() Argon2idParams { return Argon2idParams{Time: 1, Memory: 64 * 1024, Threads: 4} }

type MemoryHardHasher func(input []byte, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte
var globalMemoryHardHasher MemoryHardHasher
func SetMemoryHardHasher(h MemoryHardHasher) { globalMemoryHardHasher = h }

func GenerateStamp(entryHash [32]byte, logDID string, difficulty uint32, hashFunc HashFunc, argonParams *Argon2idParams) (uint64, error) {
	if difficulty == 0 || difficulty > 256 { return 0, fmt.Errorf("difficulty must be 1-256, got %d", difficulty) }
	if logDID == "" { return 0, errors.New("log DID must not be empty") }
	logDIDBytes := []byte(logDID)
	for nonce := uint64(0); ; nonce++ {
		h := computeStampHash(entryHash, nonce, logDIDBytes, hashFunc, argonParams)
		if hasLeadingZeros(h[:], difficulty) { return nonce, nil }
		if nonce == ^uint64(0) { return 0, errors.New("exhausted nonce space") }
	}
}

func VerifyStamp(entryHash [32]byte, nonce uint64, logDID string, difficulty uint32, hashFunc HashFunc, argonParams *Argon2idParams) error {
	if difficulty == 0 || difficulty > 256 { return fmt.Errorf("difficulty must be 1-256, got %d", difficulty) }
	if logDID == "" { return errors.New("log DID must not be empty") }
	h := computeStampHash(entryHash, nonce, []byte(logDID), hashFunc, argonParams)
	if !hasLeadingZeros(h[:], difficulty) { return errors.New("stamp hash does not meet difficulty target") }
	return nil
}

func computeStampHash(entryHash [32]byte, nonce uint64, logDID []byte, hashFunc HashFunc, argonParams *Argon2idParams) [32]byte {
	input := make([]byte, 32+8+len(logDID))
	copy(input[0:32], entryHash[:]); binary.BigEndian.PutUint64(input[32:40], nonce); copy(input[40:], logDID)
	if hashFunc == HashArgon2id && globalMemoryHardHasher != nil {
		params := DefaultArgon2idParams()
		if argonParams != nil { params = *argonParams }
		result := globalMemoryHardHasher(input, entryHash[:], params.Time, params.Memory, params.Threads, 32)
		var h [32]byte; copy(h[:], result); return h
	}
	return sha256.Sum256(input)
}

func hasLeadingZeros(hash []byte, n uint32) bool {
	remaining := n
	for _, b := range hash {
		if remaining == 0 { return true }
		lz := uint32(bits.LeadingZeros8(b))
		if lz >= remaining { return true }
		if lz < 8 { return false }
		remaining -= 8
	}
	return remaining == 0
}
