// Package types defines all shared data structures in the Ortholog protocol.
// No logic. No imports beyond standard library. Every package above this
// directory imports types/.
package types

import "fmt"

// LogPosition identifies a specific entry on a specific log.
type LogPosition struct {
	LogDID   string
	Sequence uint64
}

var NullLogPosition = LogPosition{}

func (p LogPosition) IsNull() bool {
	return p.LogDID == "" && p.Sequence == 0
}

func (p LogPosition) Equal(other LogPosition) bool {
	return p.LogDID == other.LogDID && p.Sequence == other.Sequence
}

func (p LogPosition) Less(other LogPosition) bool {
	if p.LogDID != other.LogDID {
		return p.LogDID < other.LogDID
	}
	return p.Sequence < other.Sequence
}

func (p LogPosition) String() string {
	if p.IsNull() {
		return "<null>"
	}
	return fmt.Sprintf("%s@%d", p.LogDID, p.Sequence)
}

func ValidateLogPosition(p LogPosition) error {
	if p.LogDID == "" && p.Sequence != 0 {
		return fmt.Errorf("invalid LogPosition: empty DID with non-zero sequence %d", p.Sequence)
	}
	return nil
}
