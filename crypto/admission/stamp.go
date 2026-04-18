// FILE PATH:
//
//	crypto/admission/stamp.go
//
// DESCRIPTION:
//
//	Authoritative implementation of Ortholog Mode B admission stamps.
//	Exposes GenerateStamp (submitter side) and VerifyStamp (operator side)
//	over a StampParams struct that carries every input the hash function
//	consumes. Implements Argon2id directly through golang.org/x/crypto —
//	no indirection, no pluggable hasher interface, no silent SHA-256
//	fallback. If HashArgon2id is requested, Argon2id is what runs.
//
// KEY ARCHITECTURAL DECISIONS:
//   - StampParams struct over positional arguments. Eight parameters to
//     a function is a readability failure; a named-field struct makes
//     every call site self-documenting and makes future additions
//     additive without breaking existing callers.
//   - Argon2id is invoked directly via argon2.IDKey. The previous
//     MemoryHardHasher indirection was hypothetical-HSM plumbing with
//     no real caller. Pluggability ships when a real HSM integration
//     ships, with its own tests.
//   - Fixed-length hash input layout. Every field occupies a fixed
//     position and width: entry_hash(32) || nonce(8) || did_len(2) ||
//     did(N) || epoch(8) || commit_present(1) || commit(32). The DID
//     is length-prefixed to eliminate DID-boundary collision classes.
//     The submitter commit slot is ALWAYS 32 bytes; the presence byte
//     distinguishes "absent" (byte=0, slot zero-filled) from
//     "present and happens to be all zeros" (byte=1, slot zero-filled).
//   - Protocol-versioned domain separation salt for Argon2id. The salt
//     is "ortholog-admission-v1" and is a program constant. It does not
//     change per-stamp; its role is to partition Argon2id outputs from
//     this protocol from outputs of any other protocol reusing the
//     same primitive.
//   - Named errors for every failure mode. Callers dispatch on errors.Is
//     to map failures to HTTP status codes or audit categories without
//     string parsing.
//   - acceptanceWindow = 0 disables the epoch check. This is the
//     intuitive spelling of "disable this feature" and removes a
//     config footgun where 0 would otherwise mean "strictest possible
//     check" (exact epoch match).
//   - Wire-byte aliases (WireByteHashSHA256, WireByteHashArgon2id) are
//     exported as uint8 constants alongside the typed HashFunc values.
//     External code that constructs envelope.AdmissionProofBody (whose
//     HashFunc field is uint8 by wire-format constraint) uses these
//     aliases to express intent without casting. The companion test in
//     wire_encoding_test.go fails the SDK build if aliases ever drift
//     from the typed constants' numeric values.
//
// OVERVIEW:
//
//	Generation flow (submitter):
//	    1. Construct StampParams with entry hash, target log, difficulty,
//	       epoch, optional commit, and hash-function selector.
//	    2. GenerateStamp iterates nonces from 0 upward, computing the
//	       stamp hash at each and returning the first nonce whose hash
//	       has the required leading zero bits.
//	    3. The returned nonce populates AdmissionProof.Nonce. The caller
//	       fills Mode, TargetLog, Difficulty, Epoch, and SubmitterCommit
//	       from the same StampParams.
//
//	Verification flow (operator):
//	    1. Operator receives an entry carrying an AdmissionProof.
//	    2. VerifyStamp validates mode, target log match, difficulty
//	       floor, and epoch window.
//	    3. If all policy checks pass, VerifyStamp recomputes the hash
//	       with the claimed nonce and confirms the leading-zero count
//	       meets the claimed difficulty.
//
//	The hash input layout is deterministic and fully described above.
//	Any change to the layout MUST be accompanied by a salt-version bump
//	(ortholog-admission-v1 → -v2) to prevent cross-version confusion.
//
// KEY DEPENDENCIES:
//   - golang.org/x/crypto/argon2: Argon2id reference implementation. This
//     is the canonical Go implementation of RFC 9106, maintained by the
//     Go team. No wrapper is needed.
//   - types/admission.go: provides the AdmissionProof wire type and
//     AdmissionMode constants.
package admission

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// -------------------------------------------------------------------------------------------------
// 1) Hash function selection
// -------------------------------------------------------------------------------------------------

// HashFunc selects the stamp hash primitive. The wire-level admission
// proof does not carry this selector; the operator publishes its chosen
// hash function via its difficulty endpoint and both sides must agree
// out-of-band.
type HashFunc uint8

const (
	// HashSHA256 uses SHA-256 for stamp hashing. Fast; appropriate when
	// the operator's threat model does not require raising submitter
	// cost relative to commodity hashing hardware.
	HashSHA256 HashFunc = 0

	// HashArgon2id uses Argon2id for stamp hashing. Memory-hard; raises
	// submitter cost relative to botnet infrastructure and narrows the
	// economic gap between honest submitters and attackers running on
	// general-purpose hardware.
	HashArgon2id HashFunc = 1
)

// -------------------------------------------------------------------------------------------------
// 1.5) HashFunc wire-byte aliases
//
// HashFunc is already a uint8, but consumers building wire bodies prefer
// to express intent without a cast. These aliases let external code write
//
//     body.HashFunc = admission.WireByteHashSHA256
//
// instead of
//
//     body.HashFunc = uint8(admission.HashSHA256)
//
// Numerically identical to the typed constants by design — both layers
// share the same encoding. The companion test in wire_encoding_test.go
// asserts uint8(HashSHA256) == WireByteHashSHA256 (and likewise for
// Argon2id) so any future renumbering of HashFunc breaks the SDK's own
// build, not the consumers'.
//
// History: pre-v0.1.1, the wire encoding had to be discovered by reading
// source. Operators routinely guessed wrong (assumed Mode B = wire byte 2
// because of "0 = absent" framing) and only learned via ProofFromWire-
// then-VerifyStamp test failures. The aliases plus the regression test
// eliminate that discovery loop.
// -------------------------------------------------------------------------------------------------

const (
	// WireByteHashSHA256 is the uint8 wire encoding of HashSHA256. Use this
	// when constructing envelope.AdmissionProofBody from external code:
	//
	//     body := &envelope.AdmissionProofBody{
	//         HashFunc: admission.WireByteHashSHA256,
	//         ...
	//     }
	WireByteHashSHA256 uint8 = uint8(HashSHA256)

	// WireByteHashArgon2id is the uint8 wire encoding of HashArgon2id. Use
	// this when constructing envelope.AdmissionProofBody from external code:
	//
	//     body := &envelope.AdmissionProofBody{
	//         HashFunc: admission.WireByteHashArgon2id,
	//         ...
	//     }
	WireByteHashArgon2id uint8 = uint8(HashArgon2id)
)

// -------------------------------------------------------------------------------------------------
// 2) Argon2id parameters
// -------------------------------------------------------------------------------------------------

// Argon2idParams configures Argon2id time, memory, and parallelism.
// Matches the parameter names from RFC 9106.
//
//	Time    — number of passes over memory; RFC 9106 calls this "t".
//	Memory  — memory in KiB; RFC 9106 calls this "m".
//	Threads — degree of parallelism; RFC 9106 calls this "p".
type Argon2idParams struct {
	Time    uint32
	Memory  uint32
	Threads uint8
}

// DefaultArgon2idParams returns the protocol's default Argon2id parameters:
// 1 pass, 64 MiB, 4 lanes. These are deliberately modest — raising them
// is an operator policy choice and must be configured per-deployment.
func DefaultArgon2idParams() Argon2idParams {
	return Argon2idParams{Time: 1, Memory: 64 * 1024, Threads: 4}
}

// -------------------------------------------------------------------------------------------------
// 3) Domain separation salt for Argon2id
// -------------------------------------------------------------------------------------------------

// argon2Salt partitions Argon2id outputs produced by this protocol from
// outputs of any other protocol that might reuse Argon2id with different
// semantics. The "v1" suffix indicates the current hash input layout;
// any layout change requires incrementing the version (-v2, -v3, …).
var argon2Salt = []byte("ortholog-admission-v1")

// -------------------------------------------------------------------------------------------------
// 4) Hash input layout constants
// -------------------------------------------------------------------------------------------------

const (
	// maxDIDLength bounds the on-wire DID length so that uint16 length
	// prefixes are always sufficient. This is also the limit enforced
	// by the envelope serializer.
	maxDIDLength = 65535

	// commitLength is the fixed width of the submitter commit slot in
	// the hash input. Always 32 bytes; zero-filled when absent.
	commitLength = 32

	// difficultyMin and difficultyMax bound acceptable leading-zero-bit
	// counts. Difficulty=0 would be trivially satisfied by any hash
	// (no work required); difficulty>256 is unreachable for a 256-bit
	// hash output.
	difficultyMin = 1
	difficultyMax = 256
)

// -------------------------------------------------------------------------------------------------
// 5) Epoch binding defaults and helpers
// -------------------------------------------------------------------------------------------------

const (
	// DefaultEpochWindowSeconds is the protocol's default epoch width.
	// 300 seconds = 5 minutes provides enough tolerance for typical
	// submitter-operator clock skew while keeping the replay window
	// short enough to limit stamp harvesting.
	DefaultEpochWindowSeconds uint64 = 300

	// DefaultEpochAcceptanceWindow is the protocol's default tolerance
	// in epochs. ±1 epoch at the default width gives ±5 minutes of
	// clock-skew tolerance.
	DefaultEpochAcceptanceWindow uint64 = 1
)

// CurrentEpoch returns the current epoch index: floor(unix_seconds / windowSeconds).
// Returns 0 when epoch binding is disabled (windowSeconds == 0) or when the
// system clock is pre-Unix-epoch (indicating misconfiguration). The pre-epoch
// guard is deliberate: a negative Unix timestamp converted to uint64 would
// produce a near-MaxUint64 value and silently pass any reasonable acceptance
// window check, which is the opposite of what the operator wants.
func CurrentEpoch(windowSeconds uint64) uint64 {
	if windowSeconds == 0 {
		return 0
	}
	now := time.Now().Unix()
	if now < 0 {
		return 0
	}
	return uint64(now) / windowSeconds
}

// absDiff returns |a - b| without risking overflow on unsigned subtraction.
func absDiff(a, b uint64) uint64 {
	if a > b {
		return a - b
	}
	return b - a
}

// -------------------------------------------------------------------------------------------------
// 6) Named errors
// -------------------------------------------------------------------------------------------------

var (
	// ErrStampDifficultyOutOfRange indicates a difficulty value outside
	// the inclusive range [1, 256].
	ErrStampDifficultyOutOfRange = errors.New("admission: stamp difficulty out of range (must be 1..256)")

	// ErrStampEmptyLogDID indicates a missing or empty TargetLog.
	ErrStampEmptyLogDID = errors.New("admission: stamp target log DID must not be empty")

	// ErrStampLogDIDTooLong indicates a TargetLog exceeding the uint16-
	// prefix-addressable maximum of 65535 bytes.
	ErrStampLogDIDTooLong = errors.New("admission: stamp target log DID exceeds maximum length")

	// ErrStampNilProof indicates a nil AdmissionProof passed to VerifyStamp.
	ErrStampNilProof = errors.New("admission: stamp proof is nil")

	// ErrStampModeMismatch indicates an AdmissionProof whose Mode is
	// not AdmissionModeB. Mode A entries never reach VerifyStamp —
	// the operator's admission layer handles Mode A via write-credit
	// validation before this function is called.
	ErrStampModeMismatch = errors.New("admission: stamp mode is not AdmissionModeB")

	// ErrStampTargetLogMismatch indicates a stamp whose TargetLog does
	// not match the operator's expected log DID. This prevents stamp
	// reuse across logs.
	ErrStampTargetLogMismatch = errors.New("admission: stamp target log does not match operator log")

	// ErrStampDifficultyBelowMin indicates a stamp whose claimed
	// difficulty is below the operator's configured minimum.
	ErrStampDifficultyBelowMin = errors.New("admission: stamp difficulty below operator minimum")

	// ErrStampEpochOutOfWindow indicates a stamp whose epoch is outside
	// the operator's acceptance window around the current epoch.
	ErrStampEpochOutOfWindow = errors.New("admission: stamp epoch outside acceptance window")

	// ErrStampHashBelowTarget indicates a stamp whose recomputed hash
	// does not meet the claimed difficulty's leading-zero-bit target.
	ErrStampHashBelowTarget = errors.New("admission: stamp hash does not meet difficulty target")

	// ErrStampUnknownHashFunc indicates an unrecognized HashFunc value.
	ErrStampUnknownHashFunc = errors.New("admission: unknown hash function")

	// ErrStampNonceExhausted indicates GenerateStamp exhausted the full
	// 64-bit nonce space without finding a valid stamp. In practice this
	// is unreachable for any realistic difficulty; it exists to remove
	// the theoretical infinite loop from the code.
	ErrStampNonceExhausted = errors.New("admission: nonce space exhausted")
)

// -------------------------------------------------------------------------------------------------
// 7) StampParams — the single input struct for generation and verification
// -------------------------------------------------------------------------------------------------

// StampParams bundles every input the stamp hash consumes. Both GenerateStamp
// and the internal hash function operate on this struct. VerifyStamp
// constructs one internally from the AdmissionProof under test.
//
// Fields:
//
//	EntryHash       — canonical hash of the entry the stamp is attached to.
//	                  SHA-256 of the serialized entry, produced by
//	                  envelope.EntryIdentity.
//	LogDID          — the log the stamp is bound to. MUST be non-empty and
//	                  MUST NOT exceed 65535 bytes.
//	Difficulty      — required leading zero bits, in [1, 256].
//	HashFunc        — HashSHA256 or HashArgon2id.
//	Argon2idParams  — parameters for Argon2id. nil uses DefaultArgon2idParams.
//	                  Ignored when HashFunc is HashSHA256.
//	Epoch           — the epoch index this stamp is bound to. See CurrentEpoch.
//	SubmitterCommit — optional 32-byte binding; nil when absent.
type StampParams struct {
	EntryHash       [32]byte
	LogDID          string
	Difficulty      uint32
	HashFunc        HashFunc
	Argon2idParams  *Argon2idParams
	Epoch           uint64
	SubmitterCommit *[32]byte
}

// validate enforces StampParams invariants. Called at the entry point of
// GenerateStamp and (after policy checks) at the entry point of VerifyStamp.
func (p StampParams) validate() error {
	if p.Difficulty < difficultyMin || p.Difficulty > difficultyMax {
		return fmt.Errorf("%w: got %d", ErrStampDifficultyOutOfRange, p.Difficulty)
	}
	if p.LogDID == "" {
		return ErrStampEmptyLogDID
	}
	if len(p.LogDID) > maxDIDLength {
		return fmt.Errorf("%w: length %d", ErrStampLogDIDTooLong, len(p.LogDID))
	}
	switch p.HashFunc {
	case HashSHA256, HashArgon2id:
		// ok
	default:
		return fmt.Errorf("%w: %d", ErrStampUnknownHashFunc, p.HashFunc)
	}
	return nil
}

// -------------------------------------------------------------------------------------------------
// 8) GenerateStamp — submitter side
// -------------------------------------------------------------------------------------------------

// GenerateStamp finds the smallest nonce for which the stamp hash has at
// least p.Difficulty leading zero bits. Returns the nonce on success.
//
// The iteration is strictly sequential from nonce=0 to nonce=MaxUint64.
// Exhausting this space without finding a valid stamp returns
// ErrStampNonceExhausted, which is effectively unreachable for any
// realistic difficulty but removes the theoretical infinite loop.
func GenerateStamp(p StampParams) (uint64, error) {
	if err := p.validate(); err != nil {
		return 0, err
	}

	// Pre-build the immutable portion of the hash input so the nonce loop
	// only overwrites the nonce bytes on each iteration.
	input, nonceOffset, err := buildHashInputBuffer(p)
	if err != nil {
		return 0, err
	}

	for nonce := uint64(0); ; nonce++ {
		binary.BigEndian.PutUint64(input[nonceOffset:nonceOffset+8], nonce)
		h, err := runHash(input, p.HashFunc, p.Argon2idParams)
		if err != nil {
			return 0, err
		}
		if hasLeadingZeros(h[:], p.Difficulty) {
			return nonce, nil
		}
		if nonce == ^uint64(0) {
			return 0, ErrStampNonceExhausted
		}
	}
}

// -------------------------------------------------------------------------------------------------
// 9) VerifyStamp — operator side
// -------------------------------------------------------------------------------------------------

// VerifyStamp validates an AdmissionProof against operator policy and
// confirms the stamp hash meets its claimed difficulty.
//
// Arguments:
//
//	proof            — the admission proof under test. MUST NOT be nil.
//	                   MUST have Mode == AdmissionModeB.
//	entryHash        — canonical hash of the entry the proof is attached
//	                   to. The operator computes this from the received
//	                   wire bytes; it is not trusted from the submitter.
//	expectedLogDID   — the operator's own log DID. Rejects stamps bound
//	                   to any other log.
//	minDifficulty    — the operator's minimum acceptable difficulty.
//	                   Stamps claiming less are rejected.
//	hashFunc         — the operator's configured hash function. The
//	                   proof does not carry this selector; the operator
//	                   publishes it via its difficulty endpoint.
//	argonParams      — parameters for Argon2id. nil uses defaults.
//	                   Ignored when hashFunc is HashSHA256.
//	currentEpoch     — the operator's view of the current epoch index.
//	                   Typically computed at request handling time via
//	                   CurrentEpoch(operator.EpochWindowSeconds).
//	acceptanceWindow — tolerance in epochs around currentEpoch. A value
//	                   of 0 DISABLES the epoch check entirely. A value
//	                   of 1 accepts stamps from [current-1, current+1].
//
// Returns nil on success. On failure, returns a wrapped named error
// identifying the specific policy or cryptographic failure. Callers
// dispatch on errors.Is to map failures to HTTP status codes.
func VerifyStamp(
	proof *types.AdmissionProof,
	entryHash [32]byte,
	expectedLogDID string,
	minDifficulty uint32,
	hashFunc HashFunc,
	argonParams *Argon2idParams,
	currentEpoch uint64,
	acceptanceWindow uint64,
) error {
	if proof == nil {
		return ErrStampNilProof
	}
	if proof.Mode != types.AdmissionModeB {
		return fmt.Errorf("%w: got mode %d", ErrStampModeMismatch, proof.Mode)
	}
	if expectedLogDID == "" {
		return ErrStampEmptyLogDID
	}
	if proof.TargetLog != expectedLogDID {
		return fmt.Errorf("%w: proof targets %q, operator is %q",
			ErrStampTargetLogMismatch, proof.TargetLog, expectedLogDID)
	}
	if proof.Difficulty < minDifficulty {
		return fmt.Errorf("%w: %d < %d",
			ErrStampDifficultyBelowMin, proof.Difficulty, minDifficulty)
	}
	if proof.Difficulty < difficultyMin || proof.Difficulty > difficultyMax {
		return fmt.Errorf("%w: got %d", ErrStampDifficultyOutOfRange, proof.Difficulty)
	}
	if acceptanceWindow > 0 && absDiff(proof.Epoch, currentEpoch) > acceptanceWindow {
		return fmt.Errorf("%w: proof epoch %d vs current %d (window ±%d)",
			ErrStampEpochOutOfWindow, proof.Epoch, currentEpoch, acceptanceWindow)
	}

	params := StampParams{
		EntryHash:       entryHash,
		LogDID:          proof.TargetLog,
		Difficulty:      proof.Difficulty,
		HashFunc:        hashFunc,
		Argon2idParams:  argonParams,
		Epoch:           proof.Epoch,
		SubmitterCommit: proof.SubmitterCommit,
	}
	if err := params.validate(); err != nil {
		return err
	}

	input, nonceOffset, err := buildHashInputBuffer(params)
	if err != nil {
		return err
	}
	binary.BigEndian.PutUint64(input[nonceOffset:nonceOffset+8], proof.Nonce)

	h, err := runHash(input, hashFunc, argonParams)
	if err != nil {
		return err
	}
	if !hasLeadingZeros(h[:], proof.Difficulty) {
		return ErrStampHashBelowTarget
	}
	return nil
}

// -------------------------------------------------------------------------------------------------
// 10) Internal: hash input construction
// -------------------------------------------------------------------------------------------------

// buildHashInputBuffer allocates and populates a hash input buffer according
// to the canonical layout:
//
//	entry_hash(32) || nonce(8) || did_len(2) || did(N) ||
//	epoch(8) || commit_present(1) || commit(32)
//
// The nonce bytes are left zero-filled; the caller overwrites them per
// iteration via binary.BigEndian.PutUint64 at nonceOffset. All other
// bytes are populated and MUST NOT be mutated by the caller.
//
// Returns the buffer and the byte offset of the nonce slot.
func buildHashInputBuffer(p StampParams) (input []byte, nonceOffset int, err error) {
	didBytes := []byte(p.LogDID)
	if len(didBytes) > maxDIDLength {
		return nil, 0, fmt.Errorf("%w: length %d", ErrStampLogDIDTooLong, len(didBytes))
	}

	size := 32 + 8 + 2 + len(didBytes) + 8 + 1 + commitLength
	input = make([]byte, size)

	off := 0
	copy(input[off:off+32], p.EntryHash[:])
	off += 32

	nonceOffset = off
	// Nonce bytes deliberately left zero here; GenerateStamp overwrites
	// them per iteration and VerifyStamp overwrites them once before
	// computing the hash.
	off += 8

	binary.BigEndian.PutUint16(input[off:off+2], uint16(len(didBytes)))
	off += 2
	copy(input[off:off+len(didBytes)], didBytes)
	off += len(didBytes)

	binary.BigEndian.PutUint64(input[off:off+8], p.Epoch)
	off += 8

	if p.SubmitterCommit != nil {
		input[off] = 1
		off++
		copy(input[off:off+commitLength], p.SubmitterCommit[:])
	} else {
		input[off] = 0
		off++
		// Remaining commitLength bytes remain zero-filled.
	}

	return input, nonceOffset, nil
}

// -------------------------------------------------------------------------------------------------
// 11) Internal: hash dispatch
// -------------------------------------------------------------------------------------------------

// runHash dispatches to the configured hash function. Returns exactly 32
// bytes of output regardless of function. Fails loudly and closed for
// unknown HashFunc values.
func runHash(input []byte, hashFunc HashFunc, argonParams *Argon2idParams) ([32]byte, error) {
	switch hashFunc {
	case HashSHA256:
		return sha256.Sum256(input), nil
	case HashArgon2id:
		params := DefaultArgon2idParams()
		if argonParams != nil {
			params = *argonParams
		}
		raw := argon2.IDKey(input, argon2Salt, params.Time, params.Memory, params.Threads, 32)
		var h [32]byte
		copy(h[:], raw)
		return h, nil
	default:
		return [32]byte{}, fmt.Errorf("%w: %d", ErrStampUnknownHashFunc, hashFunc)
	}
}

// -------------------------------------------------------------------------------------------------
// 12) Internal: leading zero bit check
// -------------------------------------------------------------------------------------------------

// hasLeadingZeros returns true when the first n bits of hash are zero.
// n is bounded by the caller's validation (1..256); for defensiveness
// this function handles n > 8*len(hash) by returning false, and n == 0
// by returning true.
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
