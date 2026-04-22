// Package escrow — share_format.go defines the on-the-wire format for a
// single secret share.
//
// The wire format is forward-compatible across schemes:
//
//	V1 (this release) uses GF(256) Shamir Secret Sharing. It populates
//	  Version, Threshold, Index, Value, and SplitID. BlindingFactor and
//	  CommitmentHash are zero-filled.
//
//	V2 (future) uses Pedersen Verifiable Secret Sharing over secp256k1.
//	  It will populate BlindingFactor (Pedersen r_i) and CommitmentHash
//	  (SHA-256 of the published commitment set). Value becomes a
//	  secp256k1 scalar instead of GF(256) y-bytes. The wire format does
//	  not change between V1 and V2 — only the interpretation of Value,
//	  BlindingFactor, and CommitmentHash changes, keyed on Version.
//
// A V1 reader rejects V2 shares until V2 ships. A future V2 reader can
// choose to accept or reject V1 shares; since no V1 shares exist at rest
// (no backward-compatibility requirement), V2 will reject V1 outright.
//
// Wire layout (131 bytes, fixed):
//
//	offset  size  field
//	────────────────────────────────────
//	0       1     Version        (0x01 = V1 GF(256), 0x02 = V2 Pedersen)
//	1       1     Threshold      (M, the quorum required to reconstruct)
//	2       1     Index          (x-coordinate, 1..255)
//	3       32    Value          (V1: GF(256) y-bytes; V2: secp256k1 scalar)
//	35      32    BlindingFactor (V1: zeros; V2: Pedersen r_i)
//	67      32    CommitmentHash (V1: zeros; V2: SHA-256 of commitments)
//	99      32    SplitID        (random 256-bit identifier for this split)
//	────────────────────────────────────
//	Total:  131 bytes
package escrow

import (
	"errors"
	"fmt"
)

// Version constants. The Version byte tags each share with its scheme.
const (
	// VersionV1 is GF(256) Shamir with threshold enforcement and SplitID
	// binding. Cryptographic share verification is not provided (V2's job).
	VersionV1 byte = 0x01

	// VersionV2 is Pedersen Verifiable Secret Sharing over secp256k1.
	// Reserved; V1 readers reject it.
	VersionV2 byte = 0x02
)

// ShareWireLen is the fixed on-wire size of a serialized Share.
const ShareWireLen = 131

// Field offsets within the wire format.
const (
	offsetVersion        = 0
	offsetThreshold      = 1
	offsetIndex          = 2
	offsetValue          = 3
	offsetBlindingFactor = 35
	offsetCommitmentHash = 67
	offsetSplitID        = 99
)

// Share is a single secret share produced by Split and consumed by Reconstruct.
//
// All fields are fixed-size arrays to support explicit zeroization and to
// avoid slice-aliasing surprises when shares are copied.
type Share struct {
	// Version identifies the scheme. V1 readers accept only VersionV1.
	Version byte

	// Threshold is M — the quorum required to reconstruct this split.
	// Every share from a single split carries the same Threshold value.
	// Reconstruct rejects below-threshold share sets.
	Threshold byte

	// Index is the share's x-coordinate on the polynomial, 1..255.
	// Index 0 is reserved (it would equal the secret, for degree-0 polys).
	Index byte

	// Value is the share's y-value. In V1 this is 32 GF(256) bytes (the
	// polynomial evaluated at Index, per-byte). In V2 this will be a
	// secp256k1 scalar.
	Value [32]byte

	// BlindingFactor is the Pedersen blinding scalar r_i (V2 only).
	// V1 leaves this zero-filled. V1 readers require it to be zero.
	BlindingFactor [32]byte

	// CommitmentHash is SHA-256 of the published Pedersen commitment set
	// (V2 only). V1 leaves this zero-filled. V1 readers require it to be
	// zero.
	CommitmentHash [32]byte

	// SplitID is a random 256-bit identifier for the split this share
	// belongs to. Reconstruct rejects share sets whose SplitIDs do not
	// all match. Prevents cross-split share mixing.
	SplitID [32]byte

	// FieldTag discriminates which secret-sharing scheme produced this
	// share. 0x01 = GF(256) Shamir (V1). Future values reserved for
	// Pedersen / VSS variants. Zero is accepted for backward
	// compatibility with shares constructed before the tag existed;
	// any explicit non-zero value MUST match SchemeGF256Tag.
	FieldTag byte
}

// SchemeGF256Tag marks a share as produced by GF(256) Shamir (V1).
// Populated by Split / SplitGF256; verified by Reconstruct and
// ReconstructGF256.
const SchemeGF256Tag byte = 0x01

// SerializeShare encodes a Share into its 131-byte wire form.
//
// Validates the share structurally before serializing; a share that
// fails ValidateShareFormat cannot be serialized. This prevents
// accidentally wiring malformed shares across a network boundary.
func SerializeShare(s Share) ([]byte, error) {
	if err := ValidateShareFormat(s); err != nil {
		return nil, fmt.Errorf("escrow/serialize: %w", err)
	}
	buf := make([]byte, ShareWireLen)
	buf[offsetVersion] = s.Version
	buf[offsetThreshold] = s.Threshold
	buf[offsetIndex] = s.Index
	copy(buf[offsetValue:offsetValue+32], s.Value[:])
	copy(buf[offsetBlindingFactor:offsetBlindingFactor+32], s.BlindingFactor[:])
	copy(buf[offsetCommitmentHash:offsetCommitmentHash+32], s.CommitmentHash[:])
	copy(buf[offsetSplitID:offsetSplitID+32], s.SplitID[:])
	return buf, nil
}

// DeserializeShare decodes a 131-byte wire form into a Share.
//
// Validates structurally after deserializing; a malformed wire payload
// produces an error rather than a malformed Share. Callers do not need
// to call ValidateShareFormat on the result.
func DeserializeShare(data []byte) (Share, error) {
	if len(data) != ShareWireLen {
		return Share{}, fmt.Errorf(
			"escrow/deserialize: expected %d bytes, got %d",
			ShareWireLen, len(data),
		)
	}
	var s Share
	s.Version = data[offsetVersion]
	s.Threshold = data[offsetThreshold]
	s.Index = data[offsetIndex]
	copy(s.Value[:], data[offsetValue:offsetValue+32])
	copy(s.BlindingFactor[:], data[offsetBlindingFactor:offsetBlindingFactor+32])
	copy(s.CommitmentHash[:], data[offsetCommitmentHash:offsetCommitmentHash+32])
	copy(s.SplitID[:], data[offsetSplitID:offsetSplitID+32])
	if err := ValidateShareFormat(s); err != nil {
		return Share{}, fmt.Errorf("escrow/deserialize: %w", err)
	}
	return s, nil
}

// zeroArray32 returns true if all 32 bytes of b are zero.
// Used to enforce that V1 shares leave V2-only fields empty.
func zeroArray32(b [32]byte) bool {
	var acc byte
	for i := 0; i < 32; i++ {
		acc |= b[i]
	}
	return acc == 0
}

// ─────────────────────────────────────────────────────────────────────
// Sentinel errors (public so callers can distinguish failure modes).
// ─────────────────────────────────────────────────────────────────────

var (
	ErrUnsupportedVersion = errors.New("escrow: unsupported share version")
	ErrInvalidThreshold   = errors.New("escrow: invalid threshold")
	ErrInvalidIndex       = errors.New("escrow: invalid share index")
	ErrV1FieldNotEmpty    = errors.New("escrow: V1 share has non-zero V2-only field")
	ErrSplitIDMissing     = errors.New("escrow: share has zero split id")
	ErrBelowThreshold     = errors.New("escrow: share count below threshold")
	ErrThresholdMismatch  = errors.New("escrow: shares disagree on threshold")
	ErrVersionMismatch    = errors.New("escrow: shares disagree on version")
	ErrSplitIDMismatch    = errors.New("escrow: shares belong to different splits")
	ErrDuplicateIndex     = errors.New("escrow: duplicate share index")
	ErrEmptyShareSet      = errors.New("escrow: empty share set")

	// ErrInsufficientShares is returned by ReconstructGF256 when the
	// caller supplies fewer shares than the threshold recorded on
	// those shares. Wraps ErrBelowThreshold so existing callers that
	// match on the older sentinel keep working.
	ErrInsufficientShares = errors.New("escrow: insufficient shares for reconstruction")

	// ErrMixedThresholds is returned when shares from different
	// splits (differing Threshold values) are mixed. Distinct from
	// ErrThresholdMismatch (which flags the same condition under an
	// earlier name) — tests may match on either.
	ErrMixedThresholds = errors.New("escrow: mixed thresholds across shares")

	// ErrUnknownFieldTag is returned when a share's FieldTag is set
	// to a value the current code does not recognise. Guards against
	// confused-deputy attacks where a caller submits a share from a
	// future scheme (V2 Pedersen) into a V1-only reconstructor.
	ErrUnknownFieldTag = errors.New("escrow: unknown share field tag")
)
