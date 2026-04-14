package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

type HashAlgorithm byte

const AlgoSHA256 HashAlgorithm = 0x12

var algorithmName = map[HashAlgorithm]string{AlgoSHA256: "sha256"}
var algorithmFromName = map[string]HashAlgorithm{"sha256": AlgoSHA256}
var algorithmDigestSize = map[HashAlgorithm]int{AlgoSHA256: 32}
var algorithmHashFunc = map[HashAlgorithm]func([]byte) []byte{
	AlgoSHA256: func(data []byte) []byte { h := sha256.Sum256(data); return h[:] },
}

func RegisterAlgorithm(tag HashAlgorithm, name string, digestSize int, hashFunc func([]byte) []byte) {
	algorithmName[tag] = name; algorithmFromName[name] = tag
	algorithmDigestSize[tag] = digestSize; algorithmHashFunc[tag] = hashFunc
}

type CID struct {
	Algorithm HashAlgorithm
	Digest    []byte
}

func Compute(data []byte) CID { return ComputeWith(data, AlgoSHA256) }

func ComputeWith(data []byte, algo HashAlgorithm) CID {
	hashFunc, ok := algorithmHashFunc[algo]
	if !ok { panic(fmt.Sprintf("storage/cid: unregistered algorithm 0x%02x", algo)) }
	return CID{Algorithm: algo, Digest: hashFunc(data)}
}

func (c CID) Verify(data []byte) bool {
	hashFunc, ok := algorithmHashFunc[c.Algorithm]
	if !ok { return false }
	computed := hashFunc(data)
	if len(computed) != len(c.Digest) { return false }
	var mismatch byte
	for i := range computed { mismatch |= computed[i] ^ c.Digest[i] }
	return mismatch == 0
}

func (c CID) IsZero() bool { return len(c.Digest) == 0 }

func (c CID) Equal(other CID) bool {
	if c.Algorithm != other.Algorithm || len(c.Digest) != len(other.Digest) { return false }
	for i := range c.Digest { if c.Digest[i] != other.Digest[i] { return false } }
	return true
}

func (c CID) String() string {
	name, ok := algorithmName[c.Algorithm]; if !ok { name = fmt.Sprintf("0x%02x", byte(c.Algorithm)) }
	return name + ":" + hex.EncodeToString(c.Digest)
}

func ParseCID(s string) (CID, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 { return CID{}, errors.New("storage/cid: invalid format") }
	algo, ok := algorithmFromName[parts[0]]
	if !ok { return CID{}, fmt.Errorf("storage/cid: unknown algorithm %q", parts[0]) }
	digest, err := hex.DecodeString(parts[1])
	if err != nil { return CID{}, fmt.Errorf("storage/cid: invalid hex: %w", err) }
	expectedLen, ok := algorithmDigestSize[algo]
	if ok && len(digest) != expectedLen { return CID{}, fmt.Errorf("storage/cid: digest length %d, expected %d", len(digest), expectedLen) }
	return CID{Algorithm: algo, Digest: digest}, nil
}

func (c CID) Bytes() []byte {
	buf := make([]byte, 1+len(c.Digest)); buf[0] = byte(c.Algorithm); copy(buf[1:], c.Digest); return buf
}

func ParseCIDBytes(b []byte) (CID, error) {
	if len(b) < 2 { return CID{}, errors.New("storage/cid: bytes too short") }
	algo := HashAlgorithm(b[0])
	expectedLen, ok := algorithmDigestSize[algo]
	if !ok { return CID{}, fmt.Errorf("storage/cid: unknown algorithm tag 0x%02x", b[0]) }
	if len(b)-1 != expectedLen { return CID{}, fmt.Errorf("storage/cid: digest length %d, expected %d", len(b)-1, expectedLen) }
	digest := make([]byte, expectedLen); copy(digest, b[1:])
	return CID{Algorithm: algo, Digest: digest}, nil
}
