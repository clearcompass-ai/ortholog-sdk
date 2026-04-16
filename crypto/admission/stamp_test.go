// FILE PATH:
//     crypto/admission/stamp_test.go
//
// DESCRIPTION:
//     Exhaustive test coverage for the Mode B admission stamp primitive.
//     Covers: round-trip generate-then-verify for both SHA-256 and Argon2id,
//     every named error path, epoch window boundaries, submitter commit
//     presence semantics, DID length validation, and the invariant that
//     the hash input layout is fixed-length (present-zero commit produces
//     a different hash than absent commit).
//
// KEY ARCHITECTURAL DECISIONS:
//     - Tests use difficulty 8 for speed. Real deployments use 16-24 or
//       higher; 8 is computationally trivial but still exercises the
//       leading-zero-bit logic for multi-byte zero runs.
//     - Argon2id tests use Memory=8192 (8 MiB) and Time=1 to keep the
//       test suite fast. Production parameters are stricter.
//     - Every named error has at least one test that confirms
//       errors.Is returns true, which is the contract downstream
//       dispatchers depend on.
//
// OVERVIEW:
//     Test functions are grouped by concern:
//         Round-trip tests: stamp a known entry hash, verify the returned
//             proof, confirm hash-below-target detection on mutation.
//         Input validation: every rejection path in validate().
//         Policy rejection: every rejection path in VerifyStamp before
//             the hash check (mode mismatch, log mismatch, difficulty,
//             epoch window).
//         Hash input uniqueness: absent-commit and present-zero-commit
//             produce different hashes, confirming the presence byte
//             is actually bound into the hash.
//         Epoch helpers: CurrentEpoch semantics around windowSeconds=0,
//             acceptanceWindow=0 disabling the check, epoch deltas at
//             the boundary.
//
// KEY DEPENDENCIES:
//     - testing: Go standard test framework.
//     - errors: errors.Is dispatch verification.
//     - types/admission.go: AdmissionProof construction in test cases.
package admission

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// -------------------------------------------------------------------------------------------------
// 1) Test fixtures
// -------------------------------------------------------------------------------------------------

var (
	fixtureEntryHash = sha256.Sum256([]byte("test-entry"))
	fixtureLogDID    = "did:web:test.example.com"
	fixtureCommit    = [32]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
)

func newTestParams() StampParams {
	return StampParams{
		EntryHash:      fixtureEntryHash,
		LogDID:         fixtureLogDID,
		Difficulty:     8,
		HashFunc:       HashSHA256,
		Epoch:          100,
	}
}

// -------------------------------------------------------------------------------------------------
// 2) Round-trip: SHA-256
// -------------------------------------------------------------------------------------------------

func TestRoundTrip_SHA256_NoCommit(t *testing.T) {
	p := newTestParams()
	nonce, err := GenerateStamp(p)
	if err != nil {
		t.Fatalf("GenerateStamp: %v", err)
	}

	proof := &types.AdmissionProof{
		Mode:       types.AdmissionModeB,
		Nonce:      nonce,
		TargetLog:  p.LogDID,
		Difficulty: p.Difficulty,
		Epoch:      p.Epoch,
	}

	if err := VerifyStamp(proof, p.EntryHash, p.LogDID, p.Difficulty,
		p.HashFunc, nil, p.Epoch, 1); err != nil {
		t.Fatalf("VerifyStamp on fresh stamp: %v", err)
	}
}

func TestRoundTrip_SHA256_WithCommit(t *testing.T) {
	p := newTestParams()
	commit := fixtureCommit
	p.SubmitterCommit = &commit

	nonce, err := GenerateStamp(p)
	if err != nil {
		t.Fatalf("GenerateStamp: %v", err)
	}

	proof := &types.AdmissionProof{
		Mode:            types.AdmissionModeB,
		Nonce:           nonce,
		TargetLog:       p.LogDID,
		Difficulty:      p.Difficulty,
		Epoch:           p.Epoch,
		SubmitterCommit: &commit,
	}

	if err := VerifyStamp(proof, p.EntryHash, p.LogDID, p.Difficulty,
		p.HashFunc, nil, p.Epoch, 1); err != nil {
		t.Fatalf("VerifyStamp on fresh stamp with commit: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 3) Round-trip: Argon2id
// -------------------------------------------------------------------------------------------------

func TestRoundTrip_Argon2id(t *testing.T) {
	p := newTestParams()
	p.HashFunc = HashArgon2id
	// Lower Argon2 parameters for test speed; production uses defaults.
	fast := Argon2idParams{Time: 1, Memory: 8 * 1024, Threads: 1}
	p.Argon2idParams = &fast
	p.Difficulty = 4 // Argon2 is slow; keep difficulty trivial for tests.

	nonce, err := GenerateStamp(p)
	if err != nil {
		t.Fatalf("GenerateStamp: %v", err)
	}

	proof := &types.AdmissionProof{
		Mode:       types.AdmissionModeB,
		Nonce:      nonce,
		TargetLog:  p.LogDID,
		Difficulty: p.Difficulty,
		Epoch:      p.Epoch,
	}

	if err := VerifyStamp(proof, p.EntryHash, p.LogDID, p.Difficulty,
		HashArgon2id, &fast, p.Epoch, 1); err != nil {
		t.Fatalf("VerifyStamp on fresh Argon2id stamp: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 4) Hash-below-target detection
// -------------------------------------------------------------------------------------------------

func TestVerify_DetectsWrongNonce(t *testing.T) {
	p := newTestParams()
	nonce, err := GenerateStamp(p)
	if err != nil {
		t.Fatalf("GenerateStamp: %v", err)
	}

	// Tamper with the nonce. Valid nonce + 1 is almost certainly invalid
	// for difficulty 8.
	proof := &types.AdmissionProof{
		Mode:       types.AdmissionModeB,
		Nonce:      nonce + 1,
		TargetLog:  p.LogDID,
		Difficulty: p.Difficulty,
		Epoch:      p.Epoch,
	}
	err = VerifyStamp(proof, p.EntryHash, p.LogDID, p.Difficulty,
		p.HashFunc, nil, p.Epoch, 1)
	if !errors.Is(err, ErrStampHashBelowTarget) {
		t.Fatalf("expected ErrStampHashBelowTarget for wrong nonce, got: %v", err)
	}
}

func TestVerify_DetectsTamperedEntryHash(t *testing.T) {
	p := newTestParams()
	nonce, err := GenerateStamp(p)
	if err != nil {
		t.Fatalf("GenerateStamp: %v", err)
	}

	proof := &types.AdmissionProof{
		Mode:       types.AdmissionModeB,
		Nonce:      nonce,
		TargetLog:  p.LogDID,
		Difficulty: p.Difficulty,
		Epoch:      p.Epoch,
	}

	// Different entry hash — verification should fail on hash target.
	otherHash := sha256.Sum256([]byte("different-entry"))
	err = VerifyStamp(proof, otherHash, p.LogDID, p.Difficulty,
		p.HashFunc, nil, p.Epoch, 1)
	if !errors.Is(err, ErrStampHashBelowTarget) {
		t.Fatalf("expected ErrStampHashBelowTarget for tampered entry hash, got: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 5) Input validation
// -------------------------------------------------------------------------------------------------

func TestValidate_DifficultyOutOfRange(t *testing.T) {
	cases := []struct {
		name       string
		difficulty uint32
	}{
		{"zero", 0},
		{"above_max", 257},
		{"way_above", 1000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := newTestParams()
			p.Difficulty = tc.difficulty
			_, err := GenerateStamp(p)
			if !errors.Is(err, ErrStampDifficultyOutOfRange) {
				t.Fatalf("expected ErrStampDifficultyOutOfRange, got: %v", err)
			}
		})
	}
}

func TestValidate_EmptyLogDID(t *testing.T) {
	p := newTestParams()
	p.LogDID = ""
	_, err := GenerateStamp(p)
	if !errors.Is(err, ErrStampEmptyLogDID) {
		t.Fatalf("expected ErrStampEmptyLogDID, got: %v", err)
	}
}

func TestValidate_LogDIDTooLong(t *testing.T) {
	p := newTestParams()
	p.LogDID = string(make([]byte, maxDIDLength+1))
	_, err := GenerateStamp(p)
	if !errors.Is(err, ErrStampLogDIDTooLong) {
		t.Fatalf("expected ErrStampLogDIDTooLong, got: %v", err)
	}
}

func TestValidate_UnknownHashFunc(t *testing.T) {
	p := newTestParams()
	p.HashFunc = 99
	_, err := GenerateStamp(p)
	if !errors.Is(err, ErrStampUnknownHashFunc) {
		t.Fatalf("expected ErrStampUnknownHashFunc, got: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 6) Verify policy rejections
// -------------------------------------------------------------------------------------------------

func TestVerify_NilProof(t *testing.T) {
	err := VerifyStamp(nil, fixtureEntryHash, fixtureLogDID, 8,
		HashSHA256, nil, 0, 0)
	if !errors.Is(err, ErrStampNilProof) {
		t.Fatalf("expected ErrStampNilProof, got: %v", err)
	}
}

func TestVerify_ModeMismatch(t *testing.T) {
	proof := &types.AdmissionProof{
		Mode:      types.AdmissionModeA,
		TargetLog: fixtureLogDID,
	}
	err := VerifyStamp(proof, fixtureEntryHash, fixtureLogDID, 8,
		HashSHA256, nil, 0, 0)
	if !errors.Is(err, ErrStampModeMismatch) {
		t.Fatalf("expected ErrStampModeMismatch, got: %v", err)
	}
}

func TestVerify_TargetLogMismatch(t *testing.T) {
	p := newTestParams()
	nonce, err := GenerateStamp(p)
	if err != nil {
		t.Fatalf("GenerateStamp: %v", err)
	}
	proof := &types.AdmissionProof{
		Mode:       types.AdmissionModeB,
		Nonce:      nonce,
		TargetLog:  p.LogDID,
		Difficulty: p.Difficulty,
		Epoch:      p.Epoch,
	}
	err = VerifyStamp(proof, p.EntryHash, "did:web:other.example.com",
		p.Difficulty, p.HashFunc, nil, p.Epoch, 1)
	if !errors.Is(err, ErrStampTargetLogMismatch) {
		t.Fatalf("expected ErrStampTargetLogMismatch, got: %v", err)
	}
}

func TestVerify_DifficultyBelowMin(t *testing.T) {
	p := newTestParams()
	p.Difficulty = 4
	nonce, err := GenerateStamp(p)
	if err != nil {
		t.Fatalf("GenerateStamp: %v", err)
	}
	proof := &types.AdmissionProof{
		Mode:       types.AdmissionModeB,
		Nonce:      nonce,
		TargetLog:  p.LogDID,
		Difficulty: 4,
		Epoch:      p.Epoch,
	}
	// Operator requires difficulty 8; proof claims 4.
	err = VerifyStamp(proof, p.EntryHash, p.LogDID, 8,
		p.HashFunc, nil, p.Epoch, 1)
	if !errors.Is(err, ErrStampDifficultyBelowMin) {
		t.Fatalf("expected ErrStampDifficultyBelowMin, got: %v", err)
	}
}

func TestVerify_EpochOutOfWindow(t *testing.T) {
	p := newTestParams()
	p.Epoch = 100
	nonce, err := GenerateStamp(p)
	if err != nil {
		t.Fatalf("GenerateStamp: %v", err)
	}
	proof := &types.AdmissionProof{
		Mode:       types.AdmissionModeB,
		Nonce:      nonce,
		TargetLog:  p.LogDID,
		Difficulty: p.Difficulty,
		Epoch:      p.Epoch,
	}
	// Current epoch is 105, window is ±1 → 100 is out of window.
	err = VerifyStamp(proof, p.EntryHash, p.LogDID, p.Difficulty,
		p.HashFunc, nil, 105, 1)
	if !errors.Is(err, ErrStampEpochOutOfWindow) {
		t.Fatalf("expected ErrStampEpochOutOfWindow, got: %v", err)
	}
}

func TestVerify_EpochWindowZeroDisablesCheck(t *testing.T) {
	p := newTestParams()
	p.Epoch = 100
	nonce, err := GenerateStamp(p)
	if err != nil {
		t.Fatalf("GenerateStamp: %v", err)
	}
	proof := &types.AdmissionProof{
		Mode:       types.AdmissionModeB,
		Nonce:      nonce,
		TargetLog:  p.LogDID,
		Difficulty: p.Difficulty,
		Epoch:      p.Epoch,
	}
	// acceptanceWindow = 0 means "disabled"; verification should pass
	// despite an epoch 1000 epochs in the past.
	err = VerifyStamp(proof, p.EntryHash, p.LogDID, p.Difficulty,
		p.HashFunc, nil, 1100, 0)
	if err != nil {
		t.Fatalf("expected success with acceptanceWindow=0, got: %v", err)
	}
}

func TestVerify_EpochWithinWindow(t *testing.T) {
	p := newTestParams()
	p.Epoch = 100
	nonce, err := GenerateStamp(p)
	if err != nil {
		t.Fatalf("GenerateStamp: %v", err)
	}
	proof := &types.AdmissionProof{
		Mode:       types.AdmissionModeB,
		Nonce:      nonce,
		TargetLog:  p.LogDID,
		Difficulty: p.Difficulty,
		Epoch:      p.Epoch,
	}
	// Current 101, window ±1 → delta is 1, within window.
	err = VerifyStamp(proof, p.EntryHash, p.LogDID, p.Difficulty,
		p.HashFunc, nil, 101, 1)
	if err != nil {
		t.Fatalf("expected success within window, got: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 7) Hash input layout invariants
// -------------------------------------------------------------------------------------------------

// TestHashInput_AbsentVsZeroCommit confirms that an absent SubmitterCommit
// and a present all-zero SubmitterCommit produce DIFFERENT hash inputs.
// This validates the presence byte is actually bound into the hash and
// prevents a collision class between the two semantic states.
func TestHashInput_AbsentVsZeroCommit(t *testing.T) {
	pAbsent := newTestParams()
	inputAbsent, _, err := buildHashInputBuffer(pAbsent)
	if err != nil {
		t.Fatalf("buildHashInputBuffer absent: %v", err)
	}

	pZero := newTestParams()
	var zeroCommit [32]byte
	pZero.SubmitterCommit = &zeroCommit
	inputZero, _, err := buildHashInputBuffer(pZero)
	if err != nil {
		t.Fatalf("buildHashInputBuffer zero: %v", err)
	}

	if bytes.Equal(inputAbsent, inputZero) {
		t.Fatal("hash input for absent commit equals input for present-zero commit; presence byte not differentiating")
	}

	// Sanity: both buffers are the same length (fixed-length layout).
	if len(inputAbsent) != len(inputZero) {
		t.Fatalf("hash input lengths differ: absent=%d, zero=%d", len(inputAbsent), len(inputZero))
	}
}

// TestHashInput_DIDLengthPrefix confirms that two DIDs of different
// lengths but that concatenate to the same bytes when appended raw
// produce different hash inputs. This is the bug the length prefix
// eliminates.
func TestHashInput_DIDLengthPrefix(t *testing.T) {
	// DID "ab" with fake trailing "cd" vs DID "abcd". Under a
	// non-length-prefixed layout, the next field's bytes would
	// blur the DID boundary. Under length-prefixed, they cannot.
	p1 := newTestParams()
	p1.LogDID = "ab"
	p1.Epoch = 0x6364000000000000 // "cd" as big-endian uint64 high bytes

	p2 := newTestParams()
	p2.LogDID = "abcd"
	p2.Epoch = 0

	in1, _, err := buildHashInputBuffer(p1)
	if err != nil {
		t.Fatalf("buildHashInputBuffer p1: %v", err)
	}
	in2, _, err := buildHashInputBuffer(p2)
	if err != nil {
		t.Fatalf("buildHashInputBuffer p2: %v", err)
	}

	if bytes.Equal(in1, in2) {
		t.Fatal("hash inputs collided across DID boundary; length prefix missing or broken")
	}
}

// -------------------------------------------------------------------------------------------------
// 8) Epoch helpers
// -------------------------------------------------------------------------------------------------

func TestCurrentEpoch_WindowZero(t *testing.T) {
	if got := CurrentEpoch(0); got != 0 {
		t.Fatalf("CurrentEpoch(0) = %d, want 0", got)
	}
}

func TestCurrentEpoch_WindowNonZero(t *testing.T) {
	// We can't assert an exact value (depends on wall clock), but we
	// can assert non-zero and that it's consistent across adjacent calls.
	a := CurrentEpoch(DefaultEpochWindowSeconds)
	b := CurrentEpoch(DefaultEpochWindowSeconds)
	if a == 0 {
		t.Fatal("CurrentEpoch with non-zero window returned 0 (clock pre-1970?)")
	}
	if absDiff(a, b) > 1 {
		t.Fatalf("adjacent CurrentEpoch calls differ by more than 1: %d vs %d", a, b)
	}
}

func TestAbsDiff(t *testing.T) {
	cases := []struct {
		a, b, want uint64
	}{
		{10, 3, 7},
		{3, 10, 7},
		{5, 5, 0},
		{0, 0, 0},
		{^uint64(0), 0, ^uint64(0)},
	}
	for _, tc := range cases {
		if got := absDiff(tc.a, tc.b); got != tc.want {
			t.Fatalf("absDiff(%d, %d) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// -------------------------------------------------------------------------------------------------
// 9) Leading zero bits
// -------------------------------------------------------------------------------------------------

func TestHasLeadingZeros(t *testing.T) {
	cases := []struct {
		name string
		hash []byte
		n    uint32
		want bool
	}{
		{"zero_bits_on_any", []byte{0xFF}, 0, true},
		{"one_bit_on_zero_byte", []byte{0x00}, 1, true},
		{"eight_bits_on_zero_byte", []byte{0x00, 0xFF}, 8, true},
		{"nine_bits_needs_more", []byte{0x00, 0xFF}, 9, false},
		{"sixteen_bits_full_zeros", []byte{0x00, 0x00, 0xFF}, 16, true},
		{"partial_byte_ok", []byte{0x0F}, 4, true},
		{"partial_byte_fail", []byte{0x0F}, 5, false},
		{"beyond_hash_length", []byte{0x00}, 9, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasLeadingZeros(tc.hash, tc.n); got != tc.want {
				t.Fatalf("hasLeadingZeros(%x, %d) = %v, want %v", tc.hash, tc.n, got, tc.want)
			}
		})
	}
}
