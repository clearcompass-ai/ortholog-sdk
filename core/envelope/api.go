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
  - MaxCanonicalBytes is pinned to MaxBundleEntrySize (64 KiB — 1). An
    entry larger than c2sp.org/tlog-tiles's uint16 length prefix
    cannot be bundled and would panic inside MarshalBundleEntry if it
    reached the tile writer (ORTHO-BUG-005). Enforcing the bundle
    limit at construction / Validate / Deserialize time produces a
    clean HTTP 400-class rejection at the REST boundary instead of
    crashing the operator backend.
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
	// entries. At SDK v7 (v7.5 bundle): 7. Internal; callers use
	// CurrentProtocolVersion() or ActiveVersion().
	currentProtocolVersion uint16 = 7
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
	// MaxCanonicalBytes caps the total serialized entry size at the
	// c2sp.org/tlog-tiles bundle limit (MaxBundleEntrySize = 65535).
	// Includes preamble + header body + payload + signatures section.
	// Enforced by NewEntry, Entry.Validate, and Deserialize.
	//
	// Pinning this to the bundle limit closes ORTHO-BUG-005: any entry
	// that passes Validate is also guaranteed to fit in a Tessera tile
	// bundle. Previously MaxCanonicalBytes = 1 MiB admitted entries
	// that would panic inside MarshalBundleEntry's uint16 length
	// prefix when the operator later bundled them.
	MaxCanonicalBytes = MaxBundleEntrySize

	// MaxDelegationPointers caps Path B delegation chain depth at 3.
	// Enforced by validateHeaderForWrite in serialize.go.
	MaxDelegationPointers = 3

	// MaxEvidencePointers caps routine Evidence_Pointers arrays.
	// Authority snapshot entries (Path C with PriorAuthority and
	// AuthoritySet) are exempt — they may carry arbitrarily many
	// cosignature references.
	MaxEvidencePointers = 32

	// MaxAdmissionProofBody caps the length-prefixed admission proof
	// body. Bounds the sub-reader region during deserialization so
	// a malformed proof cannot bleed into adjacent fields.
	MaxAdmissionProofBody = 4096
)
