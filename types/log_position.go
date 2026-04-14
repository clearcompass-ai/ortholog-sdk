// Package types defines all shared data structures in the Ortholog protocol.
// No logic. No imports beyond standard library. Every package above this
// directory imports types/.
package types

import "fmt"

// LogPosition identifies a specific entry on a specific log.
// Composed of the log's DID (string) and a gapless sequence number.
// Null representation: empty LogDID and zero Sequence (10 zero bytes when serialized).
type LogPosition struct {
	LogDID   string
	Sequence uint64
}

// NullLogPosition is the canonical null value.
var NullLogPosition = LogPosition{}

// IsNull returns true if this is a null LogPosition (empty DID and zero sequence).
// A zero-length DID with non-zero sequence is invalid (rejected at construction).
func (p LogPosition) IsNull() bool {
	return p.LogDID == "" && p.Sequence == 0
}

// Equal returns true if two LogPositions are identical.
func (p LogPosition) Equal(other LogPosition) bool {
	return p.LogDID == other.LogDID && p.Sequence == other.Sequence
}

// Less returns true if p comes before other in canonical ordering.
// Orders by LogDID lexicographically, then by Sequence.
func (p LogPosition) Less(other LogPosition) bool {
	if p.LogDID != other.LogDID {
		return p.LogDID < other.LogDID
	}
	return p.Sequence < other.Sequence
}

// String returns a human-readable representation.
func (p LogPosition) String() string {
	if p.IsNull() {
		return "<null>"
	}
	return fmt.Sprintf("%s@%d", p.LogDID, p.Sequence)
}

// ValidateLogPosition checks invariants:
// - If LogDID is empty, Sequence must be 0 (null).
// - If Sequence is non-zero, LogDID must be non-empty.
func ValidateLogPosition(p LogPosition) error {
	if p.LogDID == "" && p.Sequence != 0 {
		return fmt.Errorf("invalid LogPosition: empty DID with non-zero sequence %d", p.Sequence)
	}
	return nil
}
