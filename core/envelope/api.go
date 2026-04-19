/*
FILE PATH:
    core/envelope/api.go

DESCRIPTION:
    Protocol version constants and wire-format size caps for the envelope
    package. Single source of truth for the currently-active protocol
    version and for every numeric limit that gates entry construction
    and parsing.

KEY ARCHITECTURAL DECISIONS:
    - currentProtocolVersion is package-private. External callers read
      via CurrentProtocolVersion() or via ActiveVersion() in
      version_policy.go. Keeping the variable private prevents callers
      from pinning an entry to a non-active version through direct
      assignment (NewEntry always overwrites Header.ProtocolVersion
      with the active value).
    - MaxCanonicalBytes is 1 MiB — an SDK-side guard, not a protocol
      constraint. The binding ceiling is c2sp.org/tlog-tiles's 64 KiB
      bundle limit (see tessera_compat.MaxBundleEntrySize). The 1 MiB
      cap catches runaway allocations during deserialization before
      bundle-size validation even runs.
    - v6 is the protocol version shipped by this SDK release. v5 is not
      supported — per the hard-cut migration plan, no v5 data exists in
      production. Reading v5 bytes returns ErrUnknownVersion (see
      version_policy.go).

OVERVIEW:
    Constants declared here are read by:
      - serialize.go NewEntry / Deserialize for size caps
      - control_header.go for MaxDelegationPointers and
        MaxEvidencePointers enforcement
      - version_policy.go for version-transition gates
      - signatures_section.go (indirectly, via MaxSignaturesPerEntry which
        lives there because it's signatures-specific)

KEY DEPENDENCIES:
    - (none — this is a leaf configuration file)
*/
package envelope

// -------------------------------------------------------------------------------------------------
// 1) Protocol version
// -------------------------------------------------------------------------------------------------

const (
	// currentProtocolVersion is the version that NewEntry emits for new
	// entries. At SDK v6.0 (this release): 6. Internal; callers use
	// CurrentProtocolVersion() or ActiveVersion().
	currentProtocolVersion uint16 = 6
)

// CurrentProtocolVersion returns the protocol version that new entries
// are emitted at. Equivalent to ActiveVersion() in version_policy.go but
// reads the constant directly (avoiding the policy-table scan).
func CurrentProtocolVersion() uint16 {
	return currentProtocolVersion
}

// -------------------------------------------------------------------------------------------------
// 2) Size caps
// -------------------------------------------------------------------------------------------------

const (
	// MaxCanonicalBytes caps the total serialized entry size at 1 MiB.
	// Includes preamble + header body + payload + signatures section.
	// Rejects oversized entries during NewEntry and Deserialize before
	// excessive allocation.
	//
	// The operational ceiling is tighter: c2sp.org/tlog-tiles bundles
	// entries with a uint16 length prefix, capping per-entry bundle
	// size at 65535 bytes. Entries exceeding that limit cannot be
	// bundled into a Tessera tile. The 1 MiB cap is a defensive
	// first-pass check before bundle-size validation.
	MaxCanonicalBytes = 1 << 20

	// MaxDelegationPointers caps Path B delegation chain depth at 3.
	// Enforced by validateHeaderForWrite in serialize.go.
	MaxDelegationPointers = 3

	// MaxEvidencePointers caps routine Evidence_Pointers arrays.
	// Authority snapshot entries (Path C with PriorAuthority and
	// AuthoritySet) are exempt — they may carry arbitrarily many
	// cosignature references.
	MaxEvidencePointers = 32

	// MaxAdmissionProofBody caps the length-prefixed admission proof body.
	// Prevents Authority_Skip corruption by bounding the sub-reader
	// region during deserialization.
	MaxAdmissionProofBody = 4096
)
