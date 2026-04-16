/*
Package envelope — version_policy.go is the authoritative lifecycle state
machine for protocol versions.

Every protocol version transitions through states over its lifetime:

  ACTIVE     — Writers emit, readers accept. Current production version.
               Exactly one version is ACTIVE at any time.
  DEPRECATED — Writers rejected (ErrVersionDeprecated), readers accept.
               The previous ACTIVE version after a new version has shipped.
               Grace period for operators to migrate emission paths.
  FROZEN     — Writers rejected (ErrVersionFrozen), readers accept forever.
               Archival state. Entries from frozen versions remain
               verifiable in perpetuity (the judicial/physician credential
               archive invariant).
  REVOKED    — Writers and readers rejected (ErrVersionRevoked).
               Reserved for cryptographically broken versions.

At SDK v5.0 ship, v5 is the genesis version. Only v5 is in the policy table.
Unknown versions (anything other than 5) fail with ErrUnknownVersion.

When v6 ever ships, adding it is four lines:
    versionPolicy = map[uint16]VersionState{
        5: VersionDeprecated,
        6: VersionActive,
    }
When v7 ships, v5 moves to FROZEN, v6 moves to DEPRECATED, v7 becomes ACTIVE.

No migration override tokens. No legacy compatibility shims. Migration across
versions is the natural flow: Deserialize(old) → transform header →
NewEntry(transformed) → Serialize(new). The Entry roundtrip through NewEntry
rewrites the version to ACTIVE.
*/
package envelope

import (
	"errors"
	"fmt"
)

// VersionState is the lifecycle state of a protocol version.
type VersionState uint8

const (
	VersionActive VersionState = iota
	VersionDeprecated
	VersionFrozen
	VersionRevoked
)

// String renders the state for error messages and diagnostics.
func (s VersionState) String() string {
	switch s {
	case VersionActive:
		return "ACTIVE"
	case VersionDeprecated:
		return "DEPRECATED"
	case VersionFrozen:
		return "FROZEN"
	case VersionRevoked:
		return "REVOKED"
	default:
		return fmt.Sprintf("Unknown(%d)", s)
	}
}

// versionPolicy is the authoritative mapping from protocol version to
// lifecycle state. Updated at each SDK release.
//
// SDK v5.0 (this release): v5 is the genesis production version.
// Only v5 appears in the table. Any other version is unknown.
var versionPolicy = map[uint16]VersionState{
	5: VersionActive,
}

// PolicyFor returns the lifecycle state for a protocol version.
// Returns (state, true) if known; (0, false) if the SDK has no record of it.
func PolicyFor(version uint16) (VersionState, bool) {
	state, known := versionPolicy[version]
	return state, known
}

// KnownVersions lists every version in the policy table. Order is not guaranteed.
func KnownVersions() []uint16 {
	out := make([]uint16, 0, len(versionPolicy))
	for v := range versionPolicy {
		out = append(out, v)
	}
	return out
}

// ActiveVersion returns the single version in ACTIVE state.
// Panics at process start if the policy table is malformed — this is a
// programming error in versionPolicy, not a runtime condition.
func ActiveVersion() uint16 {
	var active uint16
	found := 0
	for v, state := range versionPolicy {
		if state == VersionActive {
			active = v
			found++
		}
	}
	if found != 1 {
		panic(fmt.Sprintf("envelope: versionPolicy must contain exactly one ACTIVE version, found %d", found))
	}
	return active
}

// CheckReadAllowed reports whether entries at this version may be deserialized.
// ACTIVE, DEPRECATED, and FROZEN all permit reads (archive invariant).
// REVOKED and unknown versions reject.
func CheckReadAllowed(version uint16) error {
	state, known := versionPolicy[version]
	if !known {
		return fmt.Errorf("%w: protocol version %d", ErrUnknownVersion, version)
	}
	if state == VersionRevoked {
		return fmt.Errorf("%w: protocol version %d", ErrVersionRevoked, version)
	}
	return nil
}

// CheckWriteAllowed reports whether new entries may be emitted at this version.
// Only ACTIVE permits writes. DEPRECATED and FROZEN reject with distinct errors
// so HTTP dispatch can distinguish "recently retired" from "long archived."
func CheckWriteAllowed(version uint16) error {
	state, known := versionPolicy[version]
	if !known {
		return fmt.Errorf("%w: protocol version %d", ErrUnknownVersion, version)
	}
	switch state {
	case VersionActive:
		return nil
	case VersionDeprecated:
		return fmt.Errorf("%w: protocol version %d", ErrVersionDeprecated, version)
	case VersionFrozen:
		return fmt.Errorf("%w: protocol version %d", ErrVersionFrozen, version)
	case VersionRevoked:
		return fmt.Errorf("%w: protocol version %d", ErrVersionRevoked, version)
	default:
		return fmt.Errorf("%w: protocol version %d in unknown state %d",
			ErrUnknownVersion, version, state)
	}
}

// ─────────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────────

var (
	// ErrUnknownVersion — the protocol version is not in this SDK's policy table.
	// HTTP dispatch: 400 Bad Request.
	ErrUnknownVersion = errors.New("envelope: protocol version not in policy table")

	// ErrVersionDeprecated — write attempt at a deprecated version.
	// HTTP dispatch: 400 Bad Request.
	ErrVersionDeprecated = errors.New("envelope: protocol version deprecated; reads accepted, writes rejected")

	// ErrVersionFrozen — write attempt at a frozen archival version.
	// HTTP dispatch: 410 Gone.
	ErrVersionFrozen = errors.New("envelope: protocol version frozen; archival reads only")

	// ErrVersionRevoked — any operation on a cryptographically broken version.
	// HTTP dispatch: 451 Unavailable For Legal Reasons.
	ErrVersionRevoked = errors.New("envelope: protocol version revoked; all operations rejected")
)
