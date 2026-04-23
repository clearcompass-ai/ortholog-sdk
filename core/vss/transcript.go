// Package vss — transcript.go implements the Fiat-Shamir challenge
// builder for the DLEQ + Pedersen composition used by Umbral PRE
// CFrag verification, per ADR-005 §5.2.
//
// # Why this lives in core/vss and not crypto/artifact
//
// The transcript specification IS the cross-implementation contract.
// A future Rust or TypeScript SDK that re-implements Umbral CFrag
// verification must produce byte-identical challenge hashes to this
// code — otherwise DLEQ proofs from one implementation fail to verify
// under another. Keeping the transcript spec alongside the other
// cryptographic primitives (pedersen.go, h_generator.go) concentrates
// the audit surface: the external reviewer can sign off core/vss in
// isolation, with the transcript rules locked as a first-class
// primitive rather than buried inside Umbral.
//
// crypto/artifact/pre.go consumes DLEQChallenge the same way it
// consumes vss.VerifyPoints: as an opaque primitive that enforces
// a byte-exact contract.
//
// # The DLEQ statement being proved
//
// Umbral CFrag DLEQ proves: there exists rk_i ∈ F_n such that
//
//	VK_i = rk_i · G
//	E'   = rk_i · E
//
// where G is the secp256k1 generator, E is the capsule ephemeral
// point, VK_i is the proxy's verifier key, and E' = rk_i · E is
// the re-encrypted capsule ephemeral. The two base points of the
// DLEQ statement are G and E — not G and H(msg) as in a Schnorr
// signature over a message.
//
// # What the challenge absorbs
//
// The transcript absorbs the Pedersen commitment set C and the
// Pedersen commitment BK_i BEFORE the standard DLEQ inputs (E, E',
// VK_i, index, R, R'). This prevents an adaptive adversary from
// choosing BK_i post-hoc after observing the challenge. See
// ADR-005 §5.1 for the attack without absorption and §5.6 for the
// non-interference sketch with absorption.
package vss

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// TranscriptDST is the 32-byte domain-separation prefix that
// begins every DLEQ challenge transcript. Locked on first
// publication of v7.75; any change requires a protocol version
// bump and invalidates every pre-existing CFrag.
//
// The printable portion is "ORTHOLOG-V7.75-DLEQ-CHALLENGE-v1"
// (29 ASCII bytes); the trailing three bytes are null padding
// that pads the DST to a clean 32-byte length. The DST value in
// its 32-byte binary form is precomputed as a fixed array rather
// than padded at runtime to eliminate any chance of a zero-run
// length mismatch between implementations.
var TranscriptDST = func() [32]byte {
	const printable = "ORTHOLOG-V7.75-DLEQ-CHALLENGE-v1"
	var dst [32]byte
	copy(dst[:], printable)
	// The string is exactly 32 bytes; no null padding is added at
	// runtime. If a future edit changes the printable portion's
	// length, this copy will silently truncate or leave trailing
	// zero bytes — TestTranscript_DSTFrozen catches that.
	return dst
}()

// TranscriptChallengeSize is the size in bytes of the output
// challenge hash. SHA-256 produces 32 bytes.
const TranscriptChallengeSize = 32

// Errors returned by DLEQChallenge. All wrap a sentinel so
// callers can match on failure type.
var (
	ErrTranscriptEmptyCommitments = errors.New("vss/transcript: commitments vector is empty")
	ErrTranscriptNilPoint         = errors.New("vss/transcript: nil point coordinate")
	ErrTranscriptInvalidPoint     = errors.New("vss/transcript: point is not on secp256k1")
	ErrTranscriptBadCommitment    = errors.New("vss/transcript: commitment point is malformed")
)

// DLEQChallenge computes the Fiat-Shamir challenge scalar for the
// combined DLEQ + Pedersen CFrag verification, per ADR-005 §5.2.
//
// Inputs:
//
//	commitments  — the Pedersen commitment vector published on-log.
//	               len(Points) MUST equal the threshold M.
//	bkX, bkY     — the CFrag's Pedersen commitment BK_i = b_i · H.
//	vkX, vkY     — the proxy's verifier key VK_i = rk_i · G.
//	eX, eY       — the capsule ephemeral E.
//	ePrimeX,
//	ePrimeY      — the re-encrypted ephemeral E' = rk_i · E.
//	index        — the share index i (1..255 in Ortholog).
//	rX, rY       — the DLEQ commitment R = k · G.
//	rPrimeX,
//	rPrimeY      — the DLEQ commitment R' = k · E.
//
// Every point is validated on-curve before serialisation. An
// off-curve input is a caller bug and surfaces as
// ErrTranscriptInvalidPoint — this is a defensive belt-and-braces
// check; callers parsing points from wire bytes should IsOnCurve-
// check at ingress, so this path is unreached for well-formed
// input.
//
// Returns the 32-byte SHA-256 digest of the locked transcript
// byte sequence. The caller reduces the digest mod n when using
// it as a scalar in the DLEQ response.
//
// Byte layout (total 209 + 33·M bytes):
//
//	offset 0    : 32-byte DST ("ORTHOLOG-V7.75-DLEQ-CHALLENGE-v1")
//	offset 32   : BE_uint32(M)                                       (4 bytes)
//	offset 36   : C_0, C_1, ..., C_{M-1}  (each 33 bytes compressed)
//	offset 36+33M : BK_i  (33 bytes compressed)
//	offset ...  : VK_i  (33 bytes compressed)
//	offset ...  : E     (33 bytes compressed)
//	offset ...  : E'    (33 bytes compressed)
//	offset ...  : BE_uint64(index)                                    (8 bytes)
//	offset ...  : R     (33 bytes compressed)
//	offset ...  : R'    (33 bytes compressed)
//
// The byte order is exhaustive and unambiguous. No optional
// fields, no conditional encodings. A Rust or TypeScript port
// reproducing this layout byte-for-byte produces identical
// challenges.
func DLEQChallenge(
	commitments Commitments,
	bkX, bkY *big.Int,
	vkX, vkY *big.Int,
	eX, eY *big.Int,
	ePrimeX, ePrimeY *big.Int,
	index uint64,
	rX, rY *big.Int,
	rPrimeX, rPrimeY *big.Int,
) ([TranscriptChallengeSize]byte, error) {
	var out [TranscriptChallengeSize]byte

	if len(commitments.Points) == 0 {
		return out, ErrTranscriptEmptyCommitments
	}

	curve := secp256k1.S256()

	// Prepare commitment-point compressed encodings up front. This
	// surfaces malformed commitments before any hashing work runs.
	commitBytes := make([][]byte, len(commitments.Points))
	for j, raw := range commitments.Points {
		cx, cy, err := unmarshalOnCurve(curve, raw)
		if err != nil {
			return out, fmt.Errorf("%w: commitment %d: %w", ErrTranscriptBadCommitment, j, err)
		}
		commitBytes[j] = compressedPoint(cx, cy)
	}

	// Validate and compress the free point inputs.
	points := []struct {
		name string
		x, y *big.Int
	}{
		{"BK", bkX, bkY},
		{"VK", vkX, vkY},
		{"E", eX, eY},
		{"E'", ePrimeX, ePrimeY},
		{"R", rX, rY},
		{"R'", rPrimeX, rPrimeY},
	}
	pointBytes := make(map[string][]byte, len(points))
	for _, p := range points {
		if p.x == nil || p.y == nil {
			return out, fmt.Errorf("%w: %s", ErrTranscriptNilPoint, p.name)
		}
		if !curve.IsOnCurve(p.x, p.y) {
			return out, fmt.Errorf("%w: %s", ErrTranscriptInvalidPoint, p.name)
		}
		pointBytes[p.name] = compressedPoint(p.x, p.y)
	}

	// Assemble the transcript in-place. Writing into a SHA-256
	// hash as a writer avoids allocating the full 209+33M buffer;
	// a test path that wants the raw bytes can reconstruct them
	// independently (TranscriptBytes is exposed below for that).
	h := sha256.New()
	h.Write(TranscriptDST[:])

	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(commitments.Points)))
	h.Write(lenBuf[:])

	for _, cb := range commitBytes {
		h.Write(cb)
	}
	h.Write(pointBytes["BK"])
	h.Write(pointBytes["VK"])
	h.Write(pointBytes["E"])
	h.Write(pointBytes["E'"])

	var idxBuf [8]byte
	binary.BigEndian.PutUint64(idxBuf[:], index)
	h.Write(idxBuf[:])

	h.Write(pointBytes["R"])
	h.Write(pointBytes["R'"])

	copy(out[:], h.Sum(nil))
	return out, nil
}

// TranscriptBytes returns the full DLEQ transcript byte sequence
// that DLEQChallenge hashes. Exposed for test fixtures and
// cross-implementation interop tooling; the on-wire protocol
// never transmits this buffer — only the 32-byte challenge
// derived from it.
//
// Output length is 209 + 33 · M bytes, where M is the threshold.
// For M = 3 (the common Umbral delegation size), this is 308 bytes.
// For M = 5, this is 374 bytes.
//
// Returns the same errors as DLEQChallenge when inputs are
// malformed; a caller building golden-vector fixtures should
// handle errors the same way.
func TranscriptBytes(
	commitments Commitments,
	bkX, bkY *big.Int,
	vkX, vkY *big.Int,
	eX, eY *big.Int,
	ePrimeX, ePrimeY *big.Int,
	index uint64,
	rX, rY *big.Int,
	rPrimeX, rPrimeY *big.Int,
) ([]byte, error) {
	if len(commitments.Points) == 0 {
		return nil, ErrTranscriptEmptyCommitments
	}

	curve := secp256k1.S256()
	commitBytes := make([][]byte, len(commitments.Points))
	for j, raw := range commitments.Points {
		cx, cy, err := unmarshalOnCurve(curve, raw)
		if err != nil {
			return nil, fmt.Errorf("%w: commitment %d: %w", ErrTranscriptBadCommitment, j, err)
		}
		commitBytes[j] = compressedPoint(cx, cy)
	}

	points := []struct {
		name string
		x, y *big.Int
	}{
		{"BK", bkX, bkY}, {"VK", vkX, vkY},
		{"E", eX, eY}, {"E'", ePrimeX, ePrimeY},
		{"R", rX, rY}, {"R'", rPrimeX, rPrimeY},
	}
	pointBytes := make(map[string][]byte, len(points))
	for _, p := range points {
		if p.x == nil || p.y == nil {
			return nil, fmt.Errorf("%w: %s", ErrTranscriptNilPoint, p.name)
		}
		if !curve.IsOnCurve(p.x, p.y) {
			return nil, fmt.Errorf("%w: %s", ErrTranscriptInvalidPoint, p.name)
		}
		pointBytes[p.name] = compressedPoint(p.x, p.y)
	}

	total := 32 + 4 + 33*len(commitBytes) + 33*4 + 8 + 33*2
	out := make([]byte, 0, total)
	out = append(out, TranscriptDST[:]...)
	var lenBuf [4]byte
	binary.BigEndian.PutUint32(lenBuf[:], uint32(len(commitBytes)))
	out = append(out, lenBuf[:]...)
	for _, cb := range commitBytes {
		out = append(out, cb...)
	}
	out = append(out, pointBytes["BK"]...)
	out = append(out, pointBytes["VK"]...)
	out = append(out, pointBytes["E"]...)
	out = append(out, pointBytes["E'"]...)
	var idxBuf [8]byte
	binary.BigEndian.PutUint64(idxBuf[:], index)
	out = append(out, idxBuf[:]...)
	out = append(out, pointBytes["R"]...)
	out = append(out, pointBytes["R'"]...)
	return out, nil
}

// compressedPoint returns the 33-byte SEC 1 compressed encoding
// of (x, y) on secp256k1. Prefix 0x02 for even y, 0x03 for odd.
// x is big-endian-encoded left-padded to 32 bytes.
//
// Separate from the encoding in pedersen.go (which uses
// elliptic.Marshal uncompressed) because the transcript spec
// requires compressed; mixing the two encodings in one function
// invites confusion about which path produces which bytes.
func compressedPoint(x, y *big.Int) []byte {
	out := make([]byte, 33)
	if y.Bit(0) == 0 {
		out[0] = 0x02
	} else {
		out[0] = 0x03
	}
	xBytes := x.Bytes()
	copy(out[33-len(xBytes):], xBytes)
	return out
}

// unmarshalOnCurve decodes a stored commitment-point byte slice
// (either 33-byte compressed or 65-byte uncompressed SEC 1) and
// returns its (x, y) coordinates after confirming on-curve. The
// Commitments type in pedersen.go currently stores 65-byte
// uncompressed; accepting both forms here lets the transcript
// code be agnostic to that storage choice.
func unmarshalOnCurve(curve *secp256k1.KoblitzCurve, raw []byte) (*big.Int, *big.Int, error) {
	if len(raw) == 0 {
		return nil, nil, fmt.Errorf("empty point")
	}
	var x, y *big.Int
	switch raw[0] {
	case 0x04:
		// Uncompressed: 0x04 || X (32) || Y (32) = 65 bytes.
		if len(raw) != 65 {
			return nil, nil, fmt.Errorf("uncompressed point must be 65 bytes, got %d", len(raw))
		}
		x = new(big.Int).SetBytes(raw[1:33])
		y = new(big.Int).SetBytes(raw[33:65])
	case 0x02, 0x03:
		// Compressed: 0x02/0x03 || X (32) = 33 bytes. Recover y
		// from x via y² = x³ + 7 mod p, selecting the root with
		// parity matching the prefix.
		if len(raw) != 33 {
			return nil, nil, fmt.Errorf("compressed point must be 33 bytes, got %d", len(raw))
		}
		x = new(big.Int).SetBytes(raw[1:33])
		y = decompressY(curve, x, raw[0])
		if y == nil {
			return nil, nil, fmt.Errorf("point decompression failed: x not on curve")
		}
	default:
		return nil, nil, fmt.Errorf("unknown point tag 0x%02x", raw[0])
	}
	if !curve.IsOnCurve(x, y) {
		return nil, nil, fmt.Errorf("point not on curve after decode")
	}
	return x, y, nil
}

// decompressY recovers the y-coordinate for a compressed
// secp256k1 point given x and the parity prefix byte (0x02 for
// even, 0x03 for odd). Returns nil when no valid y exists —
// either x is not an x-coordinate of any curve point, or the
// parity cannot be matched.
func decompressY(curve *secp256k1.KoblitzCurve, x *big.Int, prefix byte) *big.Int {
	p := curve.Params().P
	// y² = x³ + 7 mod p (secp256k1: a = 0, b = 7).
	x3 := new(big.Int).Exp(x, big.NewInt(3), p)
	rhs := new(big.Int).Add(x3, curve.Params().B)
	rhs.Mod(rhs, p)
	y := new(big.Int).ModSqrt(rhs, p)
	if y == nil {
		return nil
	}
	// Match parity.
	wantOdd := prefix == 0x03
	isOdd := y.Bit(0) == 1
	if wantOdd != isOdd {
		y = new(big.Int).Sub(p, y)
	}
	return y
}
