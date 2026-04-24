// Package escrow — split_commitment_wire.go carries the wire-level
// (de)serialization, the vss.Commitments constructor, and the point
// encoding helpers for EscrowSplitCommitment. Split out from
// split_commitment.go to keep file size bounded; the file contents
// are the parallel of the PRE wire side in
// crypto/artifact/pre_grant_commitment.go.
package escrow

import (
	"crypto/elliptic"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/clearcompass-ai/ortholog-sdk/core/vss"
)

// ─────────────────────────────────────────────────────────────────────
// RAM ⇄ wire: constructor and inverse
// ─────────────────────────────────────────────────────────────────────

// NewEscrowSplitCommitmentFromVSS converts vss.Commitments (65-byte
// uncompressed points) into an EscrowSplitCommitment (33-byte
// compressed points on the wire) bound to the supplied SplitID,
// thresholds, and dealer DID.
//
// Constraints: 2 <= M <= N <= 255; commitments.Threshold() == M;
// non-empty dealerDID; every commitment point parses as on-curve
// secp256k1.
func NewEscrowSplitCommitmentFromVSS(splitID [32]byte, M, N int, dealerDID string, commitments vss.Commitments) (*EscrowSplitCommitment, error) {
	if M < 2 || N < M || N > 255 {
		return nil, fmt.Errorf("%w: M=%d N=%d (require 2<=M<=N<=255)", ErrEscrowCommitmentThresholdBounds, M, N)
	}
	if dealerDID == "" || len(dealerDID) > 0xFFFF {
		return nil, fmt.Errorf("%w: len=%d", ErrEscrowCommitmentDealerDID, len(dealerDID))
	}
	if commitments.Threshold() != M {
		return nil, fmt.Errorf("%w: commitments carry %d points, require %d (=M)",
			ErrEscrowCommitmentSetLength, commitments.Threshold(), M)
	}
	curve := secp256k1.S256()
	set := make([][33]byte, M)
	for i, raw := range commitments.Points {
		x, y := elliptic.Unmarshal(curve, raw)
		if x == nil || !curve.IsOnCurve(x, y) {
			return nil, fmt.Errorf("%w: point %d", ErrEscrowCommitmentPointOffCurve, i)
		}
		copy(set[i][:], escrowCompressedPoint(x, y))
	}
	return &EscrowSplitCommitment{
		SplitID:       splitID,
		M:             byte(M),
		N:             byte(N),
		DealerDID:     dealerDID,
		CommitmentSet: set,
	}, nil
}

// ToVSSCommitments converts the wire-side compressed points back into
// the in-memory vss.Commitments form that VerifyPoints and Reconstruct
// consume. Every point is re-unmarshalled, on-curve-checked, and
// re-marshalled to the 65-byte uncompressed encoding.
func (c *EscrowSplitCommitment) ToVSSCommitments() (vss.Commitments, error) {
	if c == nil {
		return vss.Commitments{}, fmt.Errorf("%w: nil commitment", ErrEscrowCommitmentSetLength)
	}
	if len(c.CommitmentSet) != int(c.M) {
		return vss.Commitments{}, fmt.Errorf("%w: CommitmentSet has %d points, M=%d",
			ErrEscrowCommitmentSetLength, len(c.CommitmentSet), c.M)
	}
	curve := secp256k1.S256()
	points := make([][]byte, len(c.CommitmentSet))
	for i := range c.CommitmentSet {
		x, y, err := escrowDecompressPoint(c.CommitmentSet[i][:])
		if err != nil {
			return vss.Commitments{}, fmt.Errorf("%w: point %d: %v", ErrEscrowCommitmentPointOffCurve, i, err)
		}
		if !curve.IsOnCurve(x, y) {
			return vss.Commitments{}, fmt.Errorf("%w: point %d", ErrEscrowCommitmentPointOffCurve, i)
		}
		points[i] = elliptic.Marshal(curve, x, y)
	}
	return vss.Commitments{Points: points}, nil
}

// ─────────────────────────────────────────────────────────────────────
// Wire serialization
// ─────────────────────────────────────────────────────────────────────

// SerializeEscrowSplitCommitment encodes a commitment into the v7.75
// wire form: SplitID || M || N || BE_uint16(len(DealerDID)) ||
// DealerDID || CommitmentSet[0] || ... || CommitmentSet[M-1].
//
// Returns ErrEscrowCommitmentThresholdBounds on invalid (M, N),
// ErrEscrowCommitmentSetLength if len(CommitmentSet) != M, and
// ErrEscrowCommitmentDealerDID for empty or oversized DealerDID.
func SerializeEscrowSplitCommitment(c EscrowSplitCommitment) ([]byte, error) {
	M, N := int(c.M), int(c.N)
	if M < 2 || N < M || N > 255 {
		return nil, fmt.Errorf("%w: M=%d N=%d", ErrEscrowCommitmentThresholdBounds, M, N)
	}
	if len(c.CommitmentSet) != M {
		return nil, fmt.Errorf("%w: CommitmentSet has %d points, M=%d",
			ErrEscrowCommitmentSetLength, len(c.CommitmentSet), M)
	}
	if c.DealerDID == "" || len(c.DealerDID) > 0xFFFF {
		return nil, fmt.Errorf("%w: length %d", ErrEscrowCommitmentDealerDID, len(c.DealerDID))
	}
	out := make([]byte, EscrowSplitCommitmentWireLen(M, c.DealerDID))
	copy(out[:32], c.SplitID[:])
	out[32] = c.M
	out[33] = c.N
	binary.BigEndian.PutUint16(out[34:36], uint16(len(c.DealerDID)))
	copy(out[36:36+len(c.DealerDID)], c.DealerDID)
	offset := 36 + len(c.DealerDID)
	for i := 0; i < M; i++ {
		copy(out[offset:offset+EscrowSplitCommitmentPointLen], c.CommitmentSet[i][:])
		offset += EscrowSplitCommitmentPointLen
	}
	return out, nil
}

// DeserializeEscrowSplitCommitment decodes a v7.75 wire buffer.
// Performs structural validation at ingress: minimum header, derived
// expected length, threshold bounds, non-empty DealerDID, and every
// commitment point on-curve secp256k1.
//
// The returned commitment is structurally valid. Callers MUST call
// VerifyEscrowSplitCommitment against the expected nonce before
// trusting the SplitID binding.
func DeserializeEscrowSplitCommitment(data []byte) (*EscrowSplitCommitment, error) {
	minHeader := EscrowSplitCommitmentHeaderLen + EscrowSplitCommitmentDIDLenPrefixLen
	if len(data) < minHeader {
		return nil, fmt.Errorf("%w: buffer length %d < header %d",
			ErrEscrowCommitmentWireLength, len(data), minHeader)
	}
	M := int(data[32])
	N := int(data[33])
	if M < 2 || N < M || N > 255 {
		return nil, fmt.Errorf("%w: M=%d N=%d", ErrEscrowCommitmentThresholdBounds, M, N)
	}
	didLen := int(binary.BigEndian.Uint16(data[34:36]))
	if didLen == 0 {
		return nil, fmt.Errorf("%w: dealerDID length is zero", ErrEscrowCommitmentDealerDID)
	}
	expected := EscrowSplitCommitmentHeaderLen +
		EscrowSplitCommitmentDIDLenPrefixLen +
		didLen +
		EscrowSplitCommitmentPointLen*M
	if len(data) != expected {
		return nil, fmt.Errorf("%w: len=%d, want %d (34+2+%d+33*%d)",
			ErrEscrowCommitmentWireLength, len(data), expected, didLen, M)
	}
	out := &EscrowSplitCommitment{
		M:             byte(M),
		N:             byte(N),
		DealerDID:     string(data[36 : 36+didLen]),
		CommitmentSet: make([][33]byte, M),
	}
	copy(out.SplitID[:], data[:32])
	curve := secp256k1.S256()
	offset := 36 + didLen
	for i := 0; i < M; i++ {
		copy(out.CommitmentSet[i][:], data[offset:offset+EscrowSplitCommitmentPointLen])
		x, y, err := escrowDecompressPoint(out.CommitmentSet[i][:])
		if err != nil {
			return nil, fmt.Errorf("%w: point %d: %v", ErrEscrowCommitmentPointOffCurve, i, err)
		}
		if !curve.IsOnCurve(x, y) {
			return nil, fmt.Errorf("%w: point %d", ErrEscrowCommitmentPointOffCurve, i)
		}
		offset += EscrowSplitCommitmentPointLen
	}
	return out, nil
}

// ─────────────────────────────────────────────────────────────────────
// Point encoding helpers (package-local to avoid cross-package drift)
// ─────────────────────────────────────────────────────────────────────

// escrowCompressedPoint returns the 33-byte SEC 1 compressed encoding
// of (x, y) on secp256k1. Prefix 0x02 for even y, 0x03 for odd.
func escrowCompressedPoint(x, y *big.Int) []byte {
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

// escrowDecompressPoint decodes a 33-byte compressed secp256k1 point
// into (x, y). Validates the prefix, reconstructs y from x via
// y² = x³ + 7 mod p, and checks the y-parity matches the prefix.
func escrowDecompressPoint(raw []byte) (*big.Int, *big.Int, error) {
	if len(raw) != 33 {
		return nil, nil, fmt.Errorf("compressed point must be 33 bytes, got %d", len(raw))
	}
	prefix := raw[0]
	if prefix != 0x02 && prefix != 0x03 {
		return nil, nil, fmt.Errorf("invalid point prefix 0x%02x", prefix)
	}
	p := secp256k1.S256().Params().P
	x := new(big.Int).SetBytes(raw[1:33])
	if x.Cmp(p) >= 0 {
		return nil, nil, errors.New("x coordinate out of field")
	}
	x3 := new(big.Int).Exp(x, big.NewInt(3), p)
	rhs := new(big.Int).Add(x3, big.NewInt(7))
	rhs.Mod(rhs, p)
	exp := new(big.Int).Add(p, big.NewInt(1))
	exp.Rsh(exp, 2)
	y := new(big.Int).Exp(rhs, exp, p)
	yCheck := new(big.Int).Mul(y, y)
	yCheck.Mod(yCheck, p)
	if yCheck.Cmp(rhs) != 0 {
		return nil, nil, errors.New("x coordinate is not on curve")
	}
	wantOdd := prefix == 0x03
	isOdd := y.Bit(0) == 1
	if wantOdd != isOdd {
		y = new(big.Int).Sub(p, y)
	}
	return x, y, nil
}
