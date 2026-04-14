// Package envelope implements the bifurcated entry envelope:
// Control Header (protocol-defined, read by builder) + Domain Payload (schema-defined, opaque).
package envelope

import "github.com/clearcompass-ai/ortholog-sdk/types"

// AuthorityPath is the authority path enumeration.
type AuthorityPath uint8

const (
	AuthoritySameSigner     AuthorityPath = 1
	AuthorityDelegation     AuthorityPath = 2
	AuthorityScopeAuthority AuthorityPath = 3
)

// KeyGenMode is the key generation mode enumeration.
type KeyGenMode uint8

const (
	KeyGenExchangeManaged KeyGenMode = 1
	KeyGenClientSideBlind KeyGenMode = 2
)

// ControlHeader contains the complete structural vocabulary for state transitions.
// Protocol_Version (uint16, value 3) is in the 6-byte preamble at bytes 0-1.
// Header body fields serialize in declaration order: Signer_DID through Authority_Skip.
type ControlHeader struct {
	// Protocol_Version is in the preamble, not the header body.
	// Always 3 for v1.3 entries.
	ProtocolVersion uint16

	// Signer_DID: who signed this entry. Never empty.
	SignerDID string

	// Subject_Identifier: opaque subject reference.
	SubjectIdentifier []byte

	// Target_Root: root entity being affected. nil = null.
	// SMT always updates this leaf when set.
	TargetRoot *types.LogPosition

	// Target_Intermediate: specific intermediate entry being modified.
	// SMT also updates this leaf when set.
	TargetIntermediate *types.LogPosition

	// Authority_Path: determines which SMT lane is updated. nil = null.
	AuthorityPath *AuthorityPath

	// Delegate_DID: DID being granted authority in delegation entries.
	DelegateDID *string

	// Authority_Set: complete authority DID set for scope entries.
	// Internally a hash map for O(1) lookup; serialized as sorted slice.
	AuthoritySet map[string]struct{}

	// Authority_DID: DID being added/removed in scope amendments.
	AuthorityDID *string

	// Schema_Ref: pointer to governing schema entry (pinned resolution).
	SchemaRef *types.LogPosition

	// Evidence_Pointers: references to cosignatures, attestations, evidence.
	// Max 10 for non-snapshot entries (Decision 51).
	EvidencePointers []types.LogPosition

	// Key_Generation_Mode: exchange_managed or client_side_blind.
	KeyGenerationMode *KeyGenMode

	// Commutative_Operations: operation type IDs declared commutative by schema.
	CommutativeOperations []uint32

	// Delegation_Pointers: delegation chain entries for Path B (max 3).
	DelegationPointers []types.LogPosition

	// Scope_Pointer: scope entity for Path C. Self-amendment when == Target_Root.
	ScopePointer *types.LogPosition

	// Approval_Pointers: approval entries for scope amendments.
	ApprovalPointers []types.LogPosition

	// Prior_Authority: OCC acknowledgment of concurrent enforcement.
	PriorAuthority *types.LogPosition

	// Cosignature_Of: entry being cosigned (for cosignature entries).
	CosignatureOf *types.LogPosition

	// Event_Time: signer-asserted timestamp (Unix microseconds, signed).
	EventTime int64

	// Admission_Proof: Mode A (nil) or Mode B (compute stamp).
	AdmissionProof *types.AdmissionProof

	// Authority_Skip: skip pointer for O(log A) verifier traversal.
	// Builder records but does not use — verifier validates lazily.
	AuthoritySkip *types.LogPosition
}

// AuthoritySetContains returns true if the DID is in the Authority_Set.
func (h *ControlHeader) AuthoritySetContains(did string) bool {
	if h.AuthoritySet == nil {
		return false
	}
	_, ok := h.AuthoritySet[did]
	return ok
}

// AuthoritySetSize returns the number of DIDs in the Authority_Set.
func (h *ControlHeader) AuthoritySetSize() int {
	return len(h.AuthoritySet)
}
