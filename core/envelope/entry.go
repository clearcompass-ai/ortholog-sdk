package envelope

// Entry is the bifurcated envelope: Control Header + Domain Payload.
// The Control Header is the only part the SMT builder reads.
// The Domain Payload is schema-defined, strictly opaque to all infrastructure.
// Both are included in the canonical hash. The wall between them is absolute.
type Entry struct {
	Header        ControlHeader
	DomainPayload []byte // Opaque. Never read by builder or log operator.
}
