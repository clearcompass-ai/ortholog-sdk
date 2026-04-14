/*
FILE PATH:
    storage/cid.go

DESCRIPTION:
    Content Identifier (CID) type carrying the hash algorithm tag and digest.
    Makes explicit what Push(data) → CID already implies: the CID is a
    verifiable commitment to the stored bytes.

KEY ARCHITECTURAL DECISIONS:
    - Multihash format: 1-byte algorithm tag + raw digest. Compact, extensible.
    - Default algorithm: SHA-256 (tag 0x12, matching multihash convention).
    - CID.Verify(data) is the ONLY correct way to check storage integrity.
      Raw string comparison is necessary but not sufficient — Verify re-hashes.
    - String encoding: "alg:hex(digest)" (e.g., "sha256:abcd..."). Human-readable,
      grep-friendly, compatible with existing InMemoryCAS format.
    - Bytes encoding: [tag][digest]. Compact for wire/storage. No length prefix
      needed because digest length is determined by algorithm tag.
    - Registry is a package-level map: SDK ships SHA-256, operators can register
      domain-specific algorithms at startup.

OVERVIEW:
    Compute(data) → CID using default algorithm.
    ComputeWith(data, algorithm) → CID using specified algorithm.
    CID.Verify(data) → bool: re-hashes and compares.
    CID.String() → canonical string encoding.
    ParseCID(s) → CID from canonical string.
    CID.Bytes() → compact byte encoding.
    ParseCIDBytes(b) → CID from compact bytes.

KEY DEPENDENCIES:
    - crypto/sha256: default hash algorithm
*/
package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// -------------------------------------------------------------------------------------------------
// 1) Algorithm Registry
// -------------------------------------------------------------------------------------------------

// HashAlgorithm identifies a hash algorithm in the CID.
type HashAlgorithm byte

const (
	// AlgoSHA256 is SHA-256 (multihash code 0x12). The protocol default.
	AlgoSHA256 HashAlgorithm = 0x12
)

// algorithmName maps tag → human-readable name for String() encoding.
var algorithmName = map[HashAlgorithm]string{
	AlgoSHA256: "sha256",
}

// algorithmFromName maps name → tag for ParseCID.
var algorithmFromName = map[string]HashAlgorithm{
	"sha256": AlgoSHA256,
}

// algorithmDigestSize maps tag → expected digest length in bytes.
var algorithmDigestSize = map[HashAlgorithm]int{
	AlgoSHA256: 32,
}

// algorithmHashFunc maps tag → hash function for Compute and Verify.
var algorithmHashFunc = map[HashAlgorithm]func([]byte) []byte{
	AlgoSHA256: func(data []byte) []byte {
		h := sha256.Sum256(data)
		return h[:]
	},
}

// RegisterAlgorithm adds a hash algorithm to the registry. Call at startup
// before any CID operations. Not thread-safe (init-time only).
func RegisterAlgorithm(tag HashAlgorithm, name string, digestSize int, hashFunc func([]byte) []byte) {
	algorithmName[tag] = name
	algorithmFromName[name] = tag
	algorithmDigestSize[tag] = digestSize
	algorithmHashFunc[tag] = hashFunc
}

// -------------------------------------------------------------------------------------------------
// 2) CID Type
// -------------------------------------------------------------------------------------------------

// CID is a content identifier: a hash algorithm tag plus the digest of the
// content it addresses. Two backends storing the same bytes produce the same CID.
type CID struct {
	Algorithm HashAlgorithm
	Digest    []byte // Raw digest bytes, length determined by Algorithm.
}

// Compute creates a CID for data using the default algorithm (SHA-256).
func Compute(data []byte) CID {
	return ComputeWith(data, AlgoSHA256)
}

// ComputeWith creates a CID for data using the specified algorithm.
// Panics if the algorithm is not registered (fail-fast, not silent fallback).
func ComputeWith(data []byte, algo HashAlgorithm) CID {
	hashFunc, ok := algorithmHashFunc[algo]
	if !ok {
		panic(fmt.Sprintf("storage/cid: unregistered algorithm 0x%02x", algo))
	}
	return CID{Algorithm: algo, Digest: hashFunc(data)}
}

// Verify re-hashes data and compares against the stored digest.
// This is the ONLY correct way to confirm storage integrity.
func (c CID) Verify(data []byte) bool {
	hashFunc, ok := algorithmHashFunc[c.Algorithm]
	if !ok {
		return false // Unknown algorithm → cannot verify → reject.
	}
	computed := hashFunc(data)
	if len(computed) != len(c.Digest) {
		return false
	}
	// Constant-time comparison to prevent timing side channels.
	var mismatch byte
	for i := range computed {
		mismatch |= computed[i] ^ c.Digest[i]
	}
	return mismatch == 0
}

// IsZero returns true if the CID has no digest (uninitialized).
func (c CID) IsZero() bool {
	return len(c.Digest) == 0
}

// Equal returns true if two CIDs are identical (same algorithm and digest).
func (c CID) Equal(other CID) bool {
	if c.Algorithm != other.Algorithm || len(c.Digest) != len(other.Digest) {
		return false
	}
	for i := range c.Digest {
		if c.Digest[i] != other.Digest[i] {
			return false
		}
	}
	return true
}

// -------------------------------------------------------------------------------------------------
// 3) String Encoding — "algorithm:hex(digest)"
// -------------------------------------------------------------------------------------------------

// String returns the canonical string encoding: "sha256:abcdef...".
// Compatible with existing InMemoryCAS key format.
func (c CID) String() string {
	name, ok := algorithmName[c.Algorithm]
	if !ok {
		name = fmt.Sprintf("0x%02x", byte(c.Algorithm))
	}
	return name + ":" + hex.EncodeToString(c.Digest)
}

// ParseCID parses a canonical string encoding back into a CID.
// Returns error for malformed strings or unregistered algorithms.
func ParseCID(s string) (CID, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return CID{}, errors.New("storage/cid: invalid format, expected 'algorithm:hex'")
	}

	algo, ok := algorithmFromName[parts[0]]
	if !ok {
		return CID{}, fmt.Errorf("storage/cid: unknown algorithm %q", parts[0])
	}

	digest, err := hex.DecodeString(parts[1])
	if err != nil {
		return CID{}, fmt.Errorf("storage/cid: invalid hex digest: %w", err)
	}

	expectedLen, ok := algorithmDigestSize[algo]
	if ok && len(digest) != expectedLen {
		return CID{}, fmt.Errorf("storage/cid: digest length %d, expected %d for %s",
			len(digest), expectedLen, parts[0])
	}

	return CID{Algorithm: algo, Digest: digest}, nil
}

// -------------------------------------------------------------------------------------------------
// 4) Bytes Encoding — [tag][digest]
// -------------------------------------------------------------------------------------------------

// Bytes returns the compact byte encoding: [1-byte tag][digest].
func (c CID) Bytes() []byte {
	buf := make([]byte, 1+len(c.Digest))
	buf[0] = byte(c.Algorithm)
	copy(buf[1:], c.Digest)
	return buf
}

// ParseCIDBytes parses compact bytes back into a CID.
func ParseCIDBytes(b []byte) (CID, error) {
	if len(b) < 2 {
		return CID{}, errors.New("storage/cid: bytes too short")
	}

	algo := HashAlgorithm(b[0])
	expectedLen, ok := algorithmDigestSize[algo]
	if !ok {
		return CID{}, fmt.Errorf("storage/cid: unknown algorithm tag 0x%02x", b[0])
	}
	if len(b)-1 != expectedLen {
		return CID{}, fmt.Errorf("storage/cid: digest length %d, expected %d", len(b)-1, expectedLen)
	}

	digest := make([]byte, expectedLen)
	copy(digest, b[1:])
	return CID{Algorithm: algo, Digest: digest}, nil
}
