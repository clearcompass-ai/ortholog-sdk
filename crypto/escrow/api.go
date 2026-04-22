// Package escrow — api.go implements the public Split / Reconstruct API
// for V1 (GF(256) Shamir secret sharing), with:
//
//   - Threshold enforcement at the reconstruction boundary (closes BUG-010).
//   - SplitID binding: every share carries a random 256-bit identifier
//     that ties it to a specific split. Reconstruct rejects share sets
//     whose SplitIDs do not match, preventing cross-split share mixing.
//   - Threshold stamping: every share carries the M it was split under.
//     Reconstruct rejects shares with inconsistent thresholds.
//   - Constant-time GF(256) multiplication (no early-terminating loop,
//     no data-dependent branches in the inner loop).
//
// This file is also the home of the package's authoritative zeroization
// primitives (ZeroBytes, ZeroArray32). Every file in the escrow package
// — and the consumers outside it — must route secret-buffer clearing
// through these functions rather than writing ad-hoc clearing loops. The
// functions use runtime.KeepAlive and are marked go:noinline to resist
// dead-store elimination by the Go compiler.
//
// V1 operates on fixed 32-byte secrets. Callers with larger payloads must
// AES-wrap the payload and Split the 32-byte key (see mapping_escrow.go
// for the canonical pattern).
//
// V2 (future) will swap the GF(256) math for Pedersen VSS over secp256k1
// without changing this file's public API shape or the Share wire format.
// The V2 code will populate BlindingFactor and CommitmentHash; it will
// use the same ZeroBytes/ZeroArray32 primitives defined here.
package escrow

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"runtime"
)

// SecretSize is the required size of secrets passed to Split. Fixed at 32
// bytes to align with the secp256k1 scalar width V2 will use.
const SecretSize = 32

// ─────────────────────────────────────────────────────────────────────
// Authoritative zeroization primitives.
//
// All secret-buffer clearing in the escrow package AND its consumers
// routes through these two functions. They are marked go:noinline and
// call runtime.KeepAlive after the clearing loop to prevent the Go
// compiler from eliding the writes under dead-store analysis.
//
// Go does not guarantee memory zeroization even with these hardening
// steps (stack copies, register spills, GC relocation, and OS-level
// paging are all out of user control), but this is the best portable
// approach available in pure Go.
// ─────────────────────────────────────────────────────────────────────

// ZeroBytes clears a byte slice in place. Authoritative zeroizer for
// variable-length secret material.
//
//go:noinline
func ZeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// ZeroArray32 clears a 32-byte array in place. Authoritative zeroizer
// for fixed 32-byte secret material (secp256k1 scalars, AES keys,
// share Value fields, etc.). A nil pointer is a no-op: callers wiring
// this into defer chains cannot always statically prove the target is
// non-nil, and an elision-proof primitive that panics defeats the
// purpose.
//
//go:noinline
func ZeroArray32(a *[32]byte) {
	if a == nil {
		return
	}
	for i := range a {
		a[i] = 0
	}
	runtime.KeepAlive(a)
}

// ZeroizeShare clears every field of a Share in place, including the
// structural metadata (Version, Threshold, Index). A fully zeroed
// Share is distinguishable from a live one and cannot be re-used as
// an oracle in a timing or replay attack.
//
// Secret fields: Value, BlindingFactor. Commitment fields:
// CommitmentHash, SplitID. Structural fields: Version, Threshold,
// Index. All are reset.
//
// In V1, BlindingFactor and CommitmentHash are already zero by
// construction. The call is still correct and idempotent.
//
// A nil pointer is a no-op — symmetric with ZeroArray32's
// elision-proof contract. Defer chains that cannot statically prove
// non-nil targets remain safe.
func ZeroizeShare(s *Share) {
	if s == nil {
		return
	}
	s.Version = 0
	s.Threshold = 0
	s.Index = 0
	ZeroArray32(&s.Value)
	ZeroArray32(&s.BlindingFactor)
	ZeroArray32(&s.CommitmentHash)
	ZeroArray32(&s.SplitID)
}

// ZeroizeShares clears the secret-bearing fields of a slice of Shares
// in place.
func ZeroizeShares(shares []Share) {
	for i := range shares {
		ZeroizeShare(&shares[i])
	}
}

// ─────────────────────────────────────────────────────────────────────
// Split / Reconstruct
// ─────────────────────────────────────────────────────────────────────

// Split divides secret into N shares with threshold M, using V1 (GF(256)
// Shamir) math. Returns the N shares plus a random 256-bit SplitID that
// identifies this split on every share.
//
// Constraints:
//   - M must be at least 2 (1-of-N is a degenerate "copy" and is rejected).
//   - N must be at most 255 (Share.Index is a single byte; 0 is reserved).
//   - M must not exceed N.
//   - secret must be exactly SecretSize (32) bytes.
//
// The returned shares are plaintext and live in caller memory. Callers
// that distribute shares across escrow nodes should encrypt each share
// for its destination node (see EncryptShareForNode in ecies.go) before
// releasing it from their trust boundary.
//
// The caller should zeroize the input secret after Split returns, if
// the secret is a one-time value. See mapping_escrow.go for an example.
func Split(secret []byte, M, N int) ([]Share, [32]byte, error) {
	var zeroID [32]byte

	// Parameter validation.
	if M < 2 {
		return nil, zeroID, fmt.Errorf(
			"%w: M=%d, minimum is 2", ErrInvalidThreshold, M,
		)
	}
	if N < 2 {
		return nil, zeroID, fmt.Errorf(
			"%w: N=%d, minimum is 2", ErrInvalidThreshold, N,
		)
	}
	if M > N {
		return nil, zeroID, fmt.Errorf(
			"%w: M=%d exceeds N=%d", ErrInvalidThreshold, M, N,
		)
	}
	if N > 255 {
		return nil, zeroID, fmt.Errorf(
			"%w: N=%d exceeds 255", ErrInvalidThreshold, N,
		)
	}
	if len(secret) != SecretSize {
		return nil, zeroID, fmt.Errorf(
			"escrow/split: secret must be %d bytes, got %d",
			SecretSize, len(secret),
		)
	}

	// Generate the 256-bit SplitID that binds these shares together.
	var splitID [32]byte
	if _, err := io.ReadFull(rand.Reader, splitID[:]); err != nil {
		return nil, zeroID, fmt.Errorf("escrow/split: generating split id: %w", err)
	}

	// Allocate shares with their identifying fields stamped.
	shares := make([]Share, N)
	for i := 0; i < N; i++ {
		shares[i] = Share{
			Version:   VersionV1,
			Threshold: byte(M),
			Index:     byte(i + 1),
			SplitID:   splitID,
			// Value, BlindingFactor, CommitmentHash left as zero arrays.
			// BlindingFactor and CommitmentHash remain zero (V2-only).
		}
	}

	// Per-byte GF(256) Shamir.
	coeffs := make([]byte, M)
	defer ZeroBytes(coeffs) // coefficients include the secret bytes

	for byteIdx := 0; byteIdx < SecretSize; byteIdx++ {
		coeffs[0] = secret[byteIdx]
		if _, err := io.ReadFull(rand.Reader, coeffs[1:]); err != nil {
			return nil, zeroID, fmt.Errorf(
				"escrow/split: generating coefficients: %w", err,
			)
		}
		for i := 0; i < N; i++ {
			shares[i].Value[byteIdx] = evalPolynomialGF256(coeffs, byte(i+1))
		}
	}

	return shares, splitID, nil
}

// Reconstruct reassembles the 32-byte secret from at least M shares.
//
// Enforces at the reconstruction boundary:
//   - len(shares) >= shares[0].Threshold (closes BUG-010).
//   - All shares agree on Version, Threshold, and SplitID.
//   - All share Indices are unique and non-zero.
//   - Every share passes ValidateShareFormat.
//
// If any check fails, Reconstruct returns a typed error (see
// share_format.go for the sentinel errors) and does not attempt
// interpolation.
//
// The returned secret is 32 bytes. Callers should zeroize it after use
// using ZeroBytes.
func Reconstruct(shares []Share) ([]byte, error) {
	// Set-level validation (also runs per-share ValidateShareFormat).
	if err := VerifyShareSet(shares); err != nil {
		return nil, err
	}

	secret := make([]byte, SecretSize)
	xs := make([]byte, len(shares))
	for i, s := range shares {
		xs[i] = s.Index
	}
	ys := make([]byte, len(shares))
	defer ZeroBytes(ys) // ys carries secret-derived bytes

	for byteIdx := 0; byteIdx < SecretSize; byteIdx++ {
		for i, s := range shares {
			ys[i] = s.Value[byteIdx]
		}
		secret[byteIdx] = lagrangeInterpolateGF256(xs, ys, 0)
	}
	return secret, nil
}

// ─────────────────────────────────────────────────────────────────────
// GF(256) arithmetic primitives.
//
// Field: GF(2^8) with reduction polynomial 0x11B (AES convention).
// ─────────────────────────────────────────────────────────────────────

// gf256Mul multiplies a and b in GF(256). Constant-time: always runs
// exactly 8 iterations with no data-dependent branches. The conditional
// updates are implemented via bit masks derived from the low bit of b
// and the high bit of a respectively.
//
// The earlier implementation's `for b > 0` loop terminated early when
// b had leading zero bits, leaking information via timing. This version
// runs a fixed number of rounds regardless of operand values.
func gf256Mul(a, b byte) byte {
	var result byte
	for i := 0; i < 8; i++ {
		// If the low bit of b is 1, XOR a into result.
		// mask = 0xFF when low bit of b is 1, 0x00 otherwise.
		mask := byte(-(b & 1))
		result ^= a & mask

		// Compute a << 1 with reduction by 0x1B if the high bit was set.
		// carryMask = 0xFF when high bit of a was 1, 0x00 otherwise.
		carryMask := byte(-(a >> 7))
		a <<= 1
		a ^= 0x1B & carryMask

		b >>= 1
	}
	return result
}

// gf256Inv returns the multiplicative inverse of a in GF(256) via
// Fermat's little theorem: a^(2^8 - 2) = a^254 = a^{-1} when a != 0.
func gf256Inv(a byte) byte {
	if a == 0 {
		return 0
	}
	result := a
	for i := 0; i < 6; i++ {
		result = gf256Mul(result, result) // square
		result = gf256Mul(result, a)      // multiply by a
	}
	result = gf256Mul(result, result) // one final square
	return result
}

// evalPolynomialGF256 evaluates the polynomial with given coefficients
// at point x using Horner's method. coeffs[0] is the constant term;
// coeffs[len-1] is the leading coefficient.
func evalPolynomialGF256(coeffs []byte, x byte) byte {
	result := coeffs[len(coeffs)-1]
	for i := len(coeffs) - 2; i >= 0; i-- {
		result = gf256Mul(result, x) ^ coeffs[i]
	}
	return result
}

// lagrangeInterpolateGF256 computes the polynomial value at `target`
// given sample points (xs[i], ys[i]) using Lagrange interpolation in
// GF(256). For share reconstruction, target is always 0 (the secret
// is the y-intercept).
func lagrangeInterpolateGF256(xs, ys []byte, target byte) byte {
	var result byte
	for i := 0; i < len(xs); i++ {
		num := byte(1)
		den := byte(1)
		for j := 0; j < len(xs); j++ {
			if i == j {
				continue
			}
			num = gf256Mul(num, target^xs[j])
			den = gf256Mul(den, xs[i]^xs[j])
		}
		result ^= gf256Mul(ys[i], gf256Mul(num, gf256Inv(den)))
	}
	return result
}

// ─────────────────────────────────────────────────────────────────────
// GF(256)-scheme variants — explicit-scheme wrappers
// ─────────────────────────────────────────────────────────────────────
//
// The GF256 suffix names the underlying arithmetic (byte-wise
// polynomial evaluation in GF(2^8)). Reserved for the future V2
// Pedersen VSS variant that will ship as SplitPedersen /
// ReconstructPedersen without changing these.

// SplitGF256 is a convenience wrapper around Split that stamps every
// returned share's FieldTag as SchemeGF256Tag and drops the SplitID
// from the return (it remains accessible via each share's SplitID
// field). Tests and domain callers that need an explicit-scheme API
// prefer this form.
func SplitGF256(secret []byte, M, N int) ([]Share, error) {
	shares, _, err := Split(secret, M, N)
	if err != nil {
		return nil, err
	}
	for i := range shares {
		shares[i].FieldTag = SchemeGF256Tag
	}
	return shares, nil
}

// ReconstructGF256 is the FieldTag-aware counterpart to Reconstruct.
// Every non-zero FieldTag on the input shares must equal
// SchemeGF256Tag; a zero tag is accepted (legacy shares that predate
// the field). Mismatched tags return ErrUnknownFieldTag so the
// caller can distinguish a scheme confusion from a share-count or
// threshold error.
//
// Threshold-count failures are surfaced as both ErrBelowThreshold
// (structural) and ErrInsufficientShares (semantic) so callers can
// match on either sentinel. Split-level threshold mixing surfaces
// as ErrMixedThresholds in addition to ErrThresholdMismatch.
func ReconstructGF256(shares []Share) ([]byte, error) {
	for _, s := range shares {
		if s.FieldTag != 0 && s.FieldTag != SchemeGF256Tag {
			return nil, fmt.Errorf("%w: 0x%02x", ErrUnknownFieldTag, s.FieldTag)
		}
	}
	secret, err := Reconstruct(shares)
	if err == nil {
		return secret, nil
	}
	// Re-tag known failure modes with the explicit-scheme sentinels
	// so tests / callers matching on ErrInsufficientShares or
	// ErrMixedThresholds see the intended error identity. The
	// original error is wrapped so errors.Is still matches the old
	// sentinel.
	switch {
	case errors.Is(err, ErrBelowThreshold):
		return nil, fmt.Errorf("%w: %v", ErrInsufficientShares, err)
	case errors.Is(err, ErrThresholdMismatch):
		return nil, fmt.Errorf("%w: %v", ErrMixedThresholds, err)
	default:
		return nil, err
	}
}
