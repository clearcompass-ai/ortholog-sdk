/*
FILE PATH:
    core/envelope/version_policy.go

DESCRIPTION:
    Authoritative lifecycle state machine for protocol versions. Declares
    which versions are active (writable and readable), deprecated (readable
    only), frozen (archival reads only), and revoked (rejected everywhere).

KEY ARCHITECTURAL DECISIONS:
    - Exactly one version is ACTIVE at any time. ActiveVersion() panics
      at process start if the policy table violates this invariant —
      a malformed policy is a programming error, not a runtime condition.
    - v6 is the genesis production version at this SDK release. No v5
      entry appears in the table because the hard-cut migration retired
      v5 before this release shipped (no v5 data exists in production;
      see migration plan). Reading v5 bytes returns ErrUnknownVersion.
    - When v7 eventually ships: v6 moves to DEPRECATED (grace period),
      v7 becomes ACTIVE. When v8 ships: v6 moves to FROZEN (archival),
      v7 moves to DEPRECATED, v8 becomes ACTIVE.
    - No migration override tokens. No legacy compatibility shims. Any
      cross-version transformation runs explicitly through Deserialize
      (at the old version) → caller transformation → NewEntry (at the
      new version). The roundtrip rewrites the version.
    - CheckReadAllowed and CheckWriteAllowed return distinct error types
      per state so HTTP dispatch can emit appropriate status codes (400
      for deprecated writes, 410 for frozen writes, 451 for revoked
      operations).

OVERVIEW:
    Serialize reads currentProtocolVersion and writes it to the entry
    preamble. Deserialize reads the preamble version and calls
    CheckReadAllowed(version). NewEntry calls CheckWriteAllowed(active)
    defensively (the constant and the policy table should agree, but
    the check guards against drift during version-transition PRs).

KEY DEPENDENCIES:
    - api.go: currentProtocolVersion constant
*/
package envelope

import (
	"errors"
	"fmt"
)

// -------------------------------------------------------------------------------------------------
// 1) Lifecycle states
// -------------------------------------------------------------------------------------------------

// VersionState is the lifecycle state of a protocol version.
type VersionState uint8

const (
	// VersionActive — writers emit this version, readers accept it.
	// Exactly one version is ACTIVE at any time.
	VersionActive VersionState = iota

	// VersionDeprecated — writers rejected, readers accept. The previous
	// ACTIVE version after a new version has shipped. Grace period for
	// operators to migrate emission paths.
	VersionDeprecated

	// VersionFrozen — writers rejected, readers accept forever. Archival
	// state. Entries from frozen versions remain verifiable in perpetuity
	// (the judicial/physician credential archive invariant).
	VersionFrozen

	// VersionRevoked — writers and readers rejected. Reserved for
	// cryptographically broken versions.
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

// -------------------------------------------------------------------------------------------------
// 2) Policy table
// -------------------------------------------------------------------------------------------------

// versionPolicy is the authoritative mapping from protocol version to
// lifecycle state. Updated at each SDK release.
//
// SDK v6.0 (this release): v6 is the genesis production version. Only v6
// appears in the table. Any other version (including v5) is unknown and
// CheckReadAllowed/CheckWriteAllowed reject with ErrUnknownVersion.
//
// The hard-cut migration from v5 to v6 assumes no v5 data in production
// at the time of this release. If v5 data exists, it must be rewritten
// via the explicit migration path (Deserialize-v5-SDK → transform →
// NewEntry-v6-SDK) before this release is deployed.
var versionPolicy = map[uint16]VersionState{
	7: VersionActive,
}

// -------------------------------------------------------------------------------------------------
// 3) Policy accessors
// -------------------------------------------------------------------------------------------------

// PolicyFor returns the lifecycle state for a protocol version.
// Returns (state, true) if known; (0, false) if the SDK has no record of it.
func PolicyFor(version uint16) (VersionState, bool) {
	state, known := versionPolicy[version]
	return state, known
}

// KnownVersions lists every version in the policy table. Order is not
// guaranteed (Go map iteration). Callers that need stable ordering must
// sort the result.
func KnownVersions() []uint16 {
	out := make([]uint16, 0, len(versionPolicy))
	for v := range versionPolicy {
		out = append(out, v)
	}
	return out
}

// ActiveVersion returns the single version in ACTIVE state. Panics at
// process start if the policy table is malformed — this is a programming
// error in versionPolicy, not a runtime condition. The panic fires on
// first call; in production Serialize is called on every entry, so a
// malformed table is detected within microseconds of process startup.
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

// -------------------------------------------------------------------------------------------------
// 4) Read/write gates
// -------------------------------------------------------------------------------------------------

// CheckReadAllowed reports whether entries at this version may be
// deserialized. ACTIVE, DEPRECATED, and FROZEN all permit reads (archive
// invariant). REVOKED and unknown versions reject.
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

// CheckWriteAllowed reports whether new entries may be emitted at this
// version. Only ACTIVE permits writes. DEPRECATED and FROZEN reject with
// distinct errors so HTTP dispatch can distinguish "recently retired"
// from "long archived."
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

// -------------------------------------------------------------------------------------------------
// 5) Version lifecycle errors
// -------------------------------------------------------------------------------------------------

var (
	// ErrUnknownVersion — the protocol version is not in this SDK's
	// policy table. HTTP dispatch: 400 Bad Request.
	ErrUnknownVersion = errors.New("envelope: protocol version not in policy table")

	// ErrVersionDeprecated — write attempt at a deprecated version.
	// HTTP dispatch: 400 Bad Request.
	ErrVersionDeprecated = errors.New("envelope: protocol version deprecated; reads accepted, writes rejected")

	// ErrVersionFrozen — write attempt at a frozen archival version.
	// HTTP dispatch: 410 Gone.
	ErrVersionFrozen = errors.New("envelope: protocol version frozen; archival reads only")

	// ErrVersionRevoked — any operation on a cryptographically broken
	// version. HTTP dispatch: 451 Unavailable For Legal Reasons.
	ErrVersionRevoked = errors.New("envelope: protocol version revoked; all operations rejected")
)
