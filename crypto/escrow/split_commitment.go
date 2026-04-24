// Package escrow — split_commitment.go ships the v7.75
// EscrowSplitCommitment surface per ADR-005 §4, parallel to the PRE
// side in crypto/artifact/pre_grant_commitment.go.
//
// The two surfaces are intentionally symmetric: any audit tool,
// governance check, or cross-implementation port that works against
// the PRE commitment surface works identically here with variable
// names swapped. No subsystem-specific asymmetries.
//
// Scope. This file is the cryptographic-layer surface. It knows
// nothing about envelope signatures, log membership, or caller
// authorization — those concerns live in the lifecycle layer. The
// four properties verified here and nothing else are (ADR-005 §4):
//
//  1. every commitment point is on-curve secp256k1,
//  2. len(CommitmentSet) == M,
//  3. threshold bounds 2 <= M <= N <= 255,
//  4. SplitID recomputes from (dealerDID, nonce).
//
// RAM vs wire. The in-memory vss.Commitments type stores 65-byte
// uncompressed SEC 1 points. The EscrowSplitCommitment wire form uses
// 33-byte compressed points. NewEscrowSplitCommitmentFromVSS converts
// at the boundary (see split_commitment_wire.go).
//
// DealerDID on the wire is length-prefixed (BE_uint16). The field is
// variable-length; applying a BE_uint16 prefix uniformly beats ad-hoc
// delimiter reasoning, matching the universal length-prefix discipline
// even though the commitment itself is not a hashed input.
package escrow

import (
	"errors"
	"fmt"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// ─────────────────────────────────────────────────────────────────────
// Mutation switches
// ─────────────────────────────────────────────────────────────────────
//
// Each switch gates exactly one verification check in
// VerifyEscrowSplitCommitment. In production all four are true;
// flipping a switch to false is a mutation-audit probe whose
// corresponding binding test MUST fail when the gate is off and pass
// when it is on. See the gate-test registry at
// crypto/escrow/split_commitment.mutation-audit.yaml.

const (
	// muEnableEscrowCommitmentOnCurveGate gates the on-curve check
	// for every point in CommitmentSet. Off means a malformed or
	// off-curve commitment set passes verification.
	muEnableEscrowCommitmentOnCurveGate = true

	// muEnableEscrowCommitmentSetLengthCheck gates the invariant
	// len(CommitmentSet) == M. Off means a commitment with fewer or
	// more points than its declared threshold passes verification.
	muEnableEscrowCommitmentSetLengthCheck = true

	// muEnableEscrowThresholdBoundsCheck gates 2 <= M <= N <= 255.
	// Off means degenerate (1-of-N copy), inverted (M > N), or
	// oversized (N > 255) thresholds pass verification.
	muEnableEscrowThresholdBoundsCheck = true

	// muEnableEscrowSplitIDRecomputation gates the binding check
	// SplitID == ComputeEscrowSplitID(dealerDID, nonce). Off means
	// a commitment entry for one escrow context can be silently
	// replayed under another.
	muEnableEscrowSplitIDRecomputation = true
)

// ─────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────

var (
	// ErrEscrowCommitmentWireLength is returned by
	// DeserializeEscrowSplitCommitment when the input buffer length
	// does not match the (M, dealerDID)-derived expected length.
	ErrEscrowCommitmentWireLength = errors.New("escrow: EscrowSplitCommitment wire length mismatch")

	// ErrEscrowCommitmentThresholdBounds is returned when (M, N)
	// violate the 2 <= M <= N <= 255 bounds.
	ErrEscrowCommitmentThresholdBounds = errors.New("escrow: EscrowSplitCommitment threshold bounds violated")

	// ErrEscrowCommitmentSetLength is returned when
	// len(CommitmentSet) != M.
	ErrEscrowCommitmentSetLength = errors.New("escrow: EscrowSplitCommitment commitment-set length mismatch")

	// ErrEscrowCommitmentPointOffCurve is returned when any point in
	// CommitmentSet fails decompression or the on-curve check.
	ErrEscrowCommitmentPointOffCurve = errors.New("escrow: EscrowSplitCommitment contains off-curve point")

	// ErrEscrowCommitmentSplitIDMismatch is returned when the
	// embedded SplitID does not recompute from (dealerDID, nonce).
	// This is the binding between the commitment entry and the
	// escrow context it claims to cover.
	ErrEscrowCommitmentSplitIDMismatch = errors.New("escrow: EscrowSplitCommitment SplitID does not match (dealerDID, nonce)")

	// ErrEscrowCommitmentDealerDID is returned when DealerDID is
	// empty or exceeds 65535 bytes.
	ErrEscrowCommitmentDealerDID = errors.New("escrow: EscrowSplitCommitment dealerDID is empty or oversized")
)

// ─────────────────────────────────────────────────────────────────────
// Wire constants
// ─────────────────────────────────────────────────────────────────────

// EscrowSplitCommitmentPointLen is the fixed size of one compressed
// secp256k1 point in the EscrowSplitCommitment wire form.
const EscrowSplitCommitmentPointLen = 33

// EscrowSplitCommitmentHeaderLen is the fixed prefix length: SplitID
// (32) || M (1) || N (1) = 34 bytes. The 2-byte BE-uint16 DealerDID
// length follows, then the DealerDID bytes, then the commitment-set
// body.
const EscrowSplitCommitmentHeaderLen = 34

// EscrowSplitCommitmentDIDLenPrefixLen is the 2-byte BE-uint16 prefix
// carrying len(DealerDID) on the wire.
const EscrowSplitCommitmentDIDLenPrefixLen = 2

// EscrowSplitCommitmentWireLen returns the expected wire length for a
// commitment with threshold M and the given DealerDID. Exported so
// callers can precisely bound buffer allocations.
func EscrowSplitCommitmentWireLen(M int, dealerDID string) int {
	return EscrowSplitCommitmentHeaderLen +
		EscrowSplitCommitmentDIDLenPrefixLen +
		len(dealerDID) +
		EscrowSplitCommitmentPointLen*M
}

// ─────────────────────────────────────────────────────────────────────
// EscrowSplitCommitment
// ─────────────────────────────────────────────────────────────────────

// EscrowSplitCommitment is the Pedersen commitment set for an escrow
// split, wrapped for on-log publication via the
// escrow-split-commitment-v1 schema.
//
// SplitID is the deterministic identifier from ComputeEscrowSplitID.
// M and N are the VSS threshold parameters (2 <= M <= N <= 255).
// DealerDID identifies the dealer and is bound into SplitID via the
// canonical derivation. CommitmentSet carries M compressed-point
// commitments as 33-byte SEC 1 compressed encodings.
//
// An EscrowSplitCommitment does not carry private material. It is
// safe to log, persist, or transmit once the split is admitted.
type EscrowSplitCommitment struct {
	SplitID       [32]byte
	M             byte
	N             byte
	DealerDID     string
	CommitmentSet [][33]byte
}

// ─────────────────────────────────────────────────────────────────────
// Verifier — four properties, four mutation switches
// ─────────────────────────────────────────────────────────────────────

// VerifyEscrowSplitCommitment verifies the four cryptographic-layer
// properties ADR-005 §4 locks for an escrow split commitment. Each
// gate is a single-purpose check backed by a named mutation switch:
//
//  1. muEnableEscrowCommitmentOnCurveGate    — every point in CommitmentSet is on-curve.
//  2. muEnableEscrowCommitmentSetLengthCheck — len(CommitmentSet) == M.
//  3. muEnableEscrowThresholdBoundsCheck     — 2 <= M <= N <= 255.
//  4. muEnableEscrowSplitIDRecomputation     — SplitID == ComputeEscrowSplitID(dealerDID, nonce).
//
// Returns nil iff all four pass. On failure returns one of
// ErrEscrowCommitmentPointOffCurve / ErrEscrowCommitmentSetLength /
// ErrEscrowCommitmentThresholdBounds / ErrEscrowCommitmentSplitIDMismatch.
//
// Explicitly does NOT verify envelope signatures, log membership, or
// caller authorization. Those concerns live at the lifecycle layer.
func VerifyEscrowSplitCommitment(c *EscrowSplitCommitment, nonce [32]byte) error {
	if c == nil {
		return fmt.Errorf("%w: nil commitment", ErrEscrowCommitmentSetLength)
	}

	// Gate 3: threshold bounds. Checked first because M gates the
	// on-curve/length checks below.
	if muEnableEscrowThresholdBoundsCheck {
		M, N := int(c.M), int(c.N)
		if M < 2 || N < M || N > 255 {
			return fmt.Errorf("%w: M=%d N=%d", ErrEscrowCommitmentThresholdBounds, M, N)
		}
	}

	// Gate 2: len(CommitmentSet) == M.
	if muEnableEscrowCommitmentSetLengthCheck {
		if len(c.CommitmentSet) != int(c.M) {
			return fmt.Errorf("%w: CommitmentSet has %d points, M=%d",
				ErrEscrowCommitmentSetLength, len(c.CommitmentSet), c.M)
		}
	}

	// Gate 1: every commitment point on-curve.
	if muEnableEscrowCommitmentOnCurveGate {
		curve := secp256k1.S256()
		for i := range c.CommitmentSet {
			x, y, err := escrowDecompressPoint(c.CommitmentSet[i][:])
			if err != nil {
				return fmt.Errorf("%w: point %d: %v", ErrEscrowCommitmentPointOffCurve, i, err)
			}
			if !curve.IsOnCurve(x, y) {
				return fmt.Errorf("%w: point %d", ErrEscrowCommitmentPointOffCurve, i)
			}
		}
	}

	// Gate 4: SplitID recomputes from (dealerDID, nonce).
	// Load-bearing: without this check a commitment entry for one
	// escrow context can be silently replayed under another.
	if muEnableEscrowSplitIDRecomputation {
		expected := ComputeEscrowSplitID(c.DealerDID, nonce)
		if c.SplitID != expected {
			return ErrEscrowCommitmentSplitIDMismatch
		}
	}
	return nil
}
