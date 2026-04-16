/*
Package envelope — api.go defines protocol version constants and wire format
limits.

Wire format summary (v5):

	Preamble (6 bytes, bytes 0–5, permanent across all versions):
	  [uint16 Protocol_Version] [uint32 Header_Body_Length]
	Header body (variable, bytes 6 to 6+HBL):
	  Fields in declaration order.
	Payload (variable):
	  [uint32 Payload_Length] [Payload_Bytes]

Domain identity is NOT carried in the Control Header. Per the protocol's
strict domain/protocol separation principle, domain semantics travel via
SchemaRef: every domain-governed entry points to an immutable schema entry
whose Domain Payload is the manifest. The Control Header is locked to
protocol mechanics; domain vocabulary never crosses into it.

Forward compatibility: parsers tolerate unknown trailing bytes within the
HBL region. When v6 ships with a new field, v5 parsers read their known
fields, skip any remaining HBL bytes, and read the payload normally.
*/
package envelope

const (
	// currentProtocolVersion is the version that NewEntry emits for new entries.
	// At SDK v5.0: 5. Internal; use ActiveVersion() or CurrentProtocolVersion().
	currentProtocolVersion uint16 = 5

	// MaxCanonicalBytes caps the total serialized entry size at 1 MiB.
	// Includes preamble + header body + payload. Rejects oversized entries
	// during NewEntry and Deserialize before excessive allocation.
	MaxCanonicalBytes = 1 << 20

	// MaxDelegationPointers caps Path B delegation chain depth at 3.
	MaxDelegationPointers = 3

	// MaxEvidencePointers caps routine Evidence_Pointers arrays.
	// Authority snapshot entries (Path C with PriorAuthority + AuthoritySet)
	// are exempt — they may carry arbitrarily many cosignature references.
	MaxEvidencePointers = 32

	// MaxAdmissionProofBody caps the length-prefixed admission proof body.
	// Prevents Authority_Skip corruption by bounding the sub-reader region
	// during deserialization.
	MaxAdmissionProofBody = 4096
)

// CurrentProtocolVersion returns the protocol version that new entries are
// emitted at. Equivalent to ActiveVersion() but uses the constant directly.
func CurrentProtocolVersion() uint16 {
	return currentProtocolVersion
}
