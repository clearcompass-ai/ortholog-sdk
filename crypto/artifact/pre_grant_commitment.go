// Package artifact — pre_grant_commitment.go ships the v7.75
// PREGrantCommitment surface per ADR-005 §4: struct, wire
// (de)serialization, constructor from vss.Commitments, and the
// verifier that binds a commitment entry to its (grantor, recipient,
// artifact) grant context.
//
// Scope. This file is the cryptographic-layer surface. It knows
// nothing about envelope signatures, log membership, or caller
// authorization — those concerns live in the lifecycle layer. The
// four properties verified here and nothing else are (ADR-005 §4):
//
//  1. every commitment point is on-curve secp256k1,
//  2. len(CommitmentSet) == M,
//  3. threshold bounds 2 <= M <= N <= 255,
//  4. SplitID recomputes from (grantorDID, recipientDID, artifactCID).
//
// RAM vs wire. The in-memory vss.Commitments type stores 65-byte
// uncompressed SEC 1 points (elliptic.Marshal with no compression
// prefix). The PREGrantCommitment wire form uses 33-byte compressed
// points (SEC 1 compressed). NewPREGrantCommitmentFromVSS converts
// at the boundary so in-memory computation avoids repeated
// decompression while the wire stays compact.
package artifact

import (
	"crypto/elliptic"
	"errors"
	"fmt"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/clearcompass-ai/ortholog-sdk/core/vss"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
)

// ─────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────

var (
	// ErrCommitmentWireLength is returned by DeserializePREGrantCommitment
	// when the input buffer length does not match the M-derived
	// expected length (34 + 33*M bytes).
	ErrCommitmentWireLength = errors.New("pre: PREGrantCommitment wire length mismatch")

	// ErrCommitmentThresholdBounds is returned by
	// VerifyPREGrantCommitment when (M, N) violate the 2 <= M <= N
	// <= 255 bounds.
	ErrCommitmentThresholdBounds = errors.New("pre: PREGrantCommitment threshold bounds violated")

	// ErrCommitmentSetLength is returned by VerifyPREGrantCommitment
	// when len(CommitmentSet) != M.
	ErrCommitmentSetLength = errors.New("pre: PREGrantCommitment commitment-set length mismatch")

	// ErrCommitmentPointOffCurve is returned by
	// VerifyPREGrantCommitment when any point in CommitmentSet fails
	// the on-curve check.
	ErrCommitmentPointOffCurve = errors.New("pre: PREGrantCommitment contains off-curve point")

	// ErrCommitmentSplitIDMismatch is returned by
	// VerifyPREGrantCommitment when the embedded SplitID does not
	// recompute from (grantorDID, recipientDID, artifactCID). This is
	// the binding between the commitment entry and the grant context
	// it claims to cover.
	ErrCommitmentSplitIDMismatch = errors.New("pre: PREGrantCommitment SplitID does not match (grantor, recipient, artifact)")
)

// ─────────────────────────────────────────────────────────────────────
// Wire constants
// ─────────────────────────────────────────────────────────────────────

// PREGrantCommitmentPointLen is the fixed size of one compressed
// secp256k1 point in the PREGrantCommitment wire form.
const PREGrantCommitmentPointLen = 33

// PREGrantCommitmentHeaderLen is the fixed prefix length (SplitID +
// M + N) before the commitment-set body.
const PREGrantCommitmentHeaderLen = 34

// PREGrantCommitmentMaxWireLen is the maximum wire length, reached
// at M=255: 34 + 33*255 = 8449 bytes. Callers can use this as an
// upper bound on buffer allocations.
const PREGrantCommitmentMaxWireLen = PREGrantCommitmentHeaderLen + PREGrantCommitmentPointLen*255

// PREGrantCommitmentWireLen returns the expected wire length for a
// commitment with threshold M. Exported so callers bound buffer
// allocations precisely rather than assuming the 8449-byte maximum.
func PREGrantCommitmentWireLen(M int) int {
	return PREGrantCommitmentHeaderLen + PREGrantCommitmentPointLen*M
}

// ─────────────────────────────────────────────────────────────────────
// PREGrantCommitment
// ─────────────────────────────────────────────────────────────────────

// PREGrantCommitment is the Pedersen commitment set for a PRE grant,
// wrapped for on-log publication via the pre-grant-commitment-v1
// schema.
//
// SplitID is the deterministic identifier from ComputePREGrantSplitID.
// M and N are the VSS threshold parameters (2 <= M <= N <= 255).
// CommitmentSet carries M compressed-point commitments — one per
// polynomial coefficient — as 33-byte SEC 1 compressed encodings.
//
// A PREGrantCommitment does not carry private material. It is safe
// to log, persist, or transmit once the grant is admitted.
type PREGrantCommitment struct {
	SplitID       [32]byte
	M             byte
	N             byte
	CommitmentSet [][33]byte
}

// NewPREGrantCommitmentFromVSS converts a vss.Commitments (in-memory
// 65-byte uncompressed points) into a PREGrantCommitment (33-byte
// compressed points on the wire) bound to the supplied SplitID and
// (M, N) thresholds.
//
// This is the boundary between RAM and wire representations. The
// in-memory vss.Commitments uses uncompressed points because the
// primitive's arithmetic consumes them without a decompression step;
// the wire form uses compressed points to halve the commitment-entry
// size.
//
// Constraints:
//   - 2 <= M <= N <= 255.
//   - commitments.Threshold() == M.
//   - every commitment point parses as on-curve secp256k1.
func NewPREGrantCommitmentFromVSS(splitID [32]byte, M, N int, commitments vss.Commitments) (*PREGrantCommitment, error) {
	if M < 2 || N < M || N > 255 {
		return nil, fmt.Errorf("%w: M=%d N=%d (require 2<=M<=N<=255)", ErrCommitmentThresholdBounds, M, N)
	}
	if commitments.Threshold() != M {
		return nil, fmt.Errorf(
			"%w: commitments carry %d points, require %d (=M)",
			ErrCommitmentSetLength, commitments.Threshold(), M,
		)
	}
	c := secp256k1.S256()
	set := make([][33]byte, M)
	for i, raw := range commitments.Points {
		x, y := elliptic.Unmarshal(c, raw)
		if x == nil || !c.IsOnCurve(x, y) {
			return nil, fmt.Errorf("%w: point %d", ErrCommitmentPointOffCurve, i)
		}
		copy(set[i][:], compressedPoint(x, y))
	}
	return &PREGrantCommitment{
		SplitID:       splitID,
		M:             byte(M),
		N:             byte(N),
		CommitmentSet: set,
	}, nil
}

// ToVSSCommitments converts the wire-side compressed points back
// into the in-memory vss.Commitments form that VerifyPoints and
// Reconstruct consume. Every point is re-unmarshalled to (x, y),
// verified on-curve, then re-marshalled to the 65-byte uncompressed
// encoding vss.Commitments expects.
//
// Returns ErrCommitmentPointOffCurve if any point fails the on-curve
// check; ErrCommitmentSetLength if the commitment set length does
// not match M.
func (c *PREGrantCommitment) ToVSSCommitments() (vss.Commitments, error) {
	if c == nil {
		return vss.Commitments{}, fmt.Errorf("%w: nil commitment", ErrCommitmentSetLength)
	}
	if len(c.CommitmentSet) != int(c.M) {
		return vss.Commitments{}, fmt.Errorf(
			"%w: CommitmentSet has %d points, M=%d",
			ErrCommitmentSetLength, len(c.CommitmentSet), c.M,
		)
	}
	curve := secp256k1.S256()
	points := make([][]byte, len(c.CommitmentSet))
	for i := range c.CommitmentSet {
		x, y, err := decompressPoint(c.CommitmentSet[i][:])
		if err != nil {
			return vss.Commitments{}, fmt.Errorf("%w: point %d: %v", ErrCommitmentPointOffCurve, i, err)
		}
		if !curve.IsOnCurve(x, y) {
			return vss.Commitments{}, fmt.Errorf("%w: point %d", ErrCommitmentPointOffCurve, i)
		}
		points[i] = elliptic.Marshal(curve, x, y)
	}
	return vss.Commitments{Points: points}, nil
}

// ─────────────────────────────────────────────────────────────────────
// Wire serialization
// ─────────────────────────────────────────────────────────────────────

// SerializePREGrantCommitment encodes a commitment into the v7.75
// wire form: SplitID || M || N || CommitmentSet[0] || ... ||
// CommitmentSet[M-1]. Total bytes = 34 + 33*M.
//
// Returns ErrCommitmentThresholdBounds on invalid (M, N) and
// ErrCommitmentSetLength if len(CommitmentSet) != M.
func SerializePREGrantCommitment(c PREGrantCommitment) ([]byte, error) {
	M, N := int(c.M), int(c.N)
	if M < 2 || N < M || N > 255 {
		return nil, fmt.Errorf("%w: M=%d N=%d", ErrCommitmentThresholdBounds, M, N)
	}
	if len(c.CommitmentSet) != M {
		return nil, fmt.Errorf(
			"%w: CommitmentSet has %d points, M=%d",
			ErrCommitmentSetLength, len(c.CommitmentSet), M,
		)
	}
	out := make([]byte, PREGrantCommitmentWireLen(M))
	copy(out[:32], c.SplitID[:])
	out[32] = c.M
	out[33] = c.N
	offset := PREGrantCommitmentHeaderLen
	for i := 0; i < M; i++ {
		copy(out[offset:offset+PREGrantCommitmentPointLen], c.CommitmentSet[i][:])
		offset += PREGrantCommitmentPointLen
	}
	return out, nil
}

// DeserializePREGrantCommitment decodes a v7.75 wire buffer. Performs
// structural validation at ingress:
//   - minimum length (header bytes for M/N read).
//   - exact length equals 34 + 33*M (derived from the on-wire M byte).
//   - threshold bounds 2 <= M <= N <= 255.
//   - every commitment point on-curve secp256k1.
//
// The returned commitment is structurally valid. Callers MUST call
// VerifyPREGrantCommitment against the expected (grantorDID,
// recipientDID, artifactCID) before trusting the SplitID binding.
func DeserializePREGrantCommitment(data []byte) (*PREGrantCommitment, error) {
	if len(data) < PREGrantCommitmentHeaderLen {
		return nil, fmt.Errorf("%w: buffer length %d < header %d",
			ErrCommitmentWireLength, len(data), PREGrantCommitmentHeaderLen)
	}
	M := int(data[32])
	N := int(data[33])
	if M < 2 || N < M || N > 255 {
		return nil, fmt.Errorf("%w: M=%d N=%d", ErrCommitmentThresholdBounds, M, N)
	}
	expected := PREGrantCommitmentWireLen(M)
	if len(data) != expected {
		return nil, fmt.Errorf(
			"%w: len=%d, want %d (34 + 33*%d)",
			ErrCommitmentWireLength, len(data), expected, M,
		)
	}

	c := secp256k1.S256()
	out := &PREGrantCommitment{
		M:             byte(M),
		N:             byte(N),
		CommitmentSet: make([][33]byte, M),
	}
	copy(out.SplitID[:], data[:32])

	offset := PREGrantCommitmentHeaderLen
	for i := 0; i < M; i++ {
		copy(out.CommitmentSet[i][:], data[offset:offset+PREGrantCommitmentPointLen])
		x, y, err := decompressPoint(out.CommitmentSet[i][:])
		if err != nil {
			return nil, fmt.Errorf("%w: point %d: %v", ErrCommitmentPointOffCurve, i, err)
		}
		if !c.IsOnCurve(x, y) {
			return nil, fmt.Errorf("%w: point %d", ErrCommitmentPointOffCurve, i)
		}
		offset += PREGrantCommitmentPointLen
	}
	return out, nil
}

// ─────────────────────────────────────────────────────────────────────
// Verifier — four properties, four mutation switches
// ─────────────────────────────────────────────────────────────────────

// VerifyPREGrantCommitment verifies the four cryptographic-layer
// properties ADR-005 §4 locks for a PRE grant commitment. Each gate
// is a single-purpose check backed by a named mutation switch:
//
//  1. muEnableCommitmentOnCurveGate    — every point in CommitmentSet is on-curve.
//  2. muEnableCommitmentSetLengthCheck — len(CommitmentSet) == M.
//  3. muEnableThresholdBoundsCheck     — 2 <= M <= N <= 255.
//  4. muEnableSplitIDRecomputation     — SplitID == ComputePREGrantSplitID(grantor, recipient, artifact).
//
// Returns nil iff all four pass. On failure returns one of
// ErrCommitmentPointOffCurve / ErrCommitmentSetLength /
// ErrCommitmentThresholdBounds / ErrCommitmentSplitIDMismatch.
//
// Explicitly does NOT verify envelope signatures, log membership,
// or recipient authorization. Those concerns live at the lifecycle
// layer (see lifecycle/artifact_access.go and the commitment-entry
// admission path).
func VerifyPREGrantCommitment(
	c *PREGrantCommitment,
	grantorDID, recipientDID string,
	artifactCID storage.CID,
) error {
	if c == nil {
		return fmt.Errorf("%w: nil commitment", ErrCommitmentSetLength)
	}

	// Gate 3: threshold bounds. Checked first because M is read from
	// the struct and the on-curve / length gates below depend on a
	// coherent M.
	if muEnableThresholdBoundsCheck {
		M, N := int(c.M), int(c.N)
		if M < 2 || N < M || N > 255 {
			return fmt.Errorf("%w: M=%d N=%d", ErrCommitmentThresholdBounds, M, N)
		}
	}

	// Gate 2: len(CommitmentSet) == M.
	if muEnableCommitmentSetLengthCheck {
		if len(c.CommitmentSet) != int(c.M) {
			return fmt.Errorf(
				"%w: CommitmentSet has %d points, M=%d",
				ErrCommitmentSetLength, len(c.CommitmentSet), c.M,
			)
		}
	}

	// Gate 1: every commitment point on-curve.
	if muEnableCommitmentOnCurveGate {
		curve := secp256k1.S256()
		for i := range c.CommitmentSet {
			x, y, err := decompressPoint(c.CommitmentSet[i][:])
			if err != nil {
				return fmt.Errorf("%w: point %d: %v", ErrCommitmentPointOffCurve, i, err)
			}
			if !curve.IsOnCurve(x, y) {
				return fmt.Errorf("%w: point %d", ErrCommitmentPointOffCurve, i)
			}
		}
	}

	// Gate 4: SplitID recomputes from (grantor, recipient, artifact).
	// Load-bearing: without this check a commitment entry for one
	// grant context can be silently replayed under another.
	if muEnableSplitIDRecomputation {
		expected := ComputePREGrantSplitID(grantorDID, recipientDID, artifactCID)
		if c.SplitID != expected {
			return ErrCommitmentSplitIDMismatch
		}
	}
	return nil
}
