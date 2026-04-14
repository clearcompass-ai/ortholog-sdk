// Package admission implements log admission control mechanisms.
package admission

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
)

// HashFunc selects the hash function for Mode B stamps.
type HashFunc uint8

const (
	HashSHA256  HashFunc = 0 // SHA-256 (default)
	HashArgon2id HashFunc = 1 // Argon2id (memory-hard, recommended by spec)
)

// Argon2idParams configures Argon2id difficulty parameters.
type Argon2idParams struct {
	Time    uint32 // Number of iterations
	Memory  uint32 // Memory in KiB
	Threads uint8  // Parallelism
}

// DefaultArgon2idParams returns conservative defaults for Mode B stamps.
func DefaultArgon2idParams() Argon2idParams {
	return Argon2idParams{Time: 1, Memory: 64 * 1024, Threads: 4}
}

// MemoryHardHasher abstracts memory-hard hash computation (Argon2id).
// Set via SetMemoryHardHasher before using HashArgon2id mode.
// Typical implementation: golang.org/x/crypto/argon2.IDKey
type MemoryHardHasher func(input []byte, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte

var globalMemoryHardHasher MemoryHardHasher

// SetMemoryHardHasher sets the Argon2id implementation.
// Must be called before using HashArgon2id mode.
func SetMemoryHardHasher(h MemoryHardHasher) {
	globalMemoryHardHasher = h
}

// GenerateStamp generates a Mode B compute stamp by brute-forcing a nonce
// until the hash falls below the difficulty target.
// The stamp is bound to the target log DID (prevents compute-once-broadcast-everywhere).
// Returns the nonce that satisfies the difficulty requirement.
func GenerateStamp(entryHash [32]byte, logDID string, difficulty uint32, hashFunc HashFunc, argonParams *Argon2idParams) (uint64, error) {
	if difficulty == 0 || difficulty > 256 {
		return 0, fmt.Errorf("difficulty must be 1-256, got %d", difficulty)
	}
	if logDID == "" {
		return 0, errors.New("log DID must not be empty")
	}

	logDIDBytes := []byte(logDID)
	for nonce := uint64(0); ; nonce++ {
		h := computeStampHash(entryHash, nonce, logDIDBytes, hashFunc, argonParams)
		if hasLeadingZeros(h[:], difficulty) {
			return nonce, nil
		}
		if nonce == ^uint64(0) {
			return 0, errors.New("exhausted nonce space without finding valid stamp")
		}
	}
}

// VerifyStamp verifies a Mode B compute stamp in O(1).
// The stamp must be bound to the expected log DID and below the difficulty target.
func VerifyStamp(entryHash [32]byte, nonce uint64, logDID string, difficulty uint32, hashFunc HashFunc, argonParams *Argon2idParams) error {
	if difficulty == 0 || difficulty > 256 {
		return fmt.Errorf("difficulty must be 1-256, got %d", difficulty)
	}
	if logDID == "" {
		return errors.New("log DID must not be empty")
	}

	logDIDBytes := []byte(logDID)
	h := computeStampHash(entryHash, nonce, logDIDBytes, hashFunc, argonParams)
	if !hasLeadingZeros(h[:], difficulty) {
		return errors.New("stamp hash does not meet difficulty target")
	}
	return nil
}

// computeStampHash computes SHA-256(entryHash || nonce || logDID) or the
// Argon2id equivalent. The stamp is bound to the target log DID.
func computeStampHash(entryHash [32]byte, nonce uint64, logDID []byte, hashFunc HashFunc, argonParams *Argon2idParams) [32]byte {
	// Build input: entryHash (32) || nonce (8) || logDID (variable)
	input := make([]byte, 32+8+len(logDID))
	copy(input[0:32], entryHash[:])
	binary.BigEndian.PutUint64(input[32:40], nonce)
	copy(input[40:], logDID)

	switch hashFunc {
	case HashArgon2id:
		if globalMemoryHardHasher == nil {
			return sha256.Sum256(input) // Fallback if not configured.
		}
		params := DefaultArgon2idParams()
		if argonParams != nil {
			params = *argonParams
		}
		// Use entryHash as salt (unique per entry).
		result := globalMemoryHardHasher(input, entryHash[:], params.Time, params.Memory, params.Threads, 32)
		var h [32]byte
		copy(h[:], result)
		return h
	default: // SHA-256
		return sha256.Sum256(input)
	}
}

// hasLeadingZeros checks if the hash has at least `n` leading zero bits.
func hasLeadingZeros(hash []byte, n uint32) bool {
	remaining := n
	for _, b := range hash {
		if remaining == 0 {
			return true
		}
		lz := uint32(bits.LeadingZeros8(b))
		if lz >= remaining {
			return true
		}
		if lz < 8 {
			return false
		}
		remaining -= 8
	}
	return remaining == 0
}
