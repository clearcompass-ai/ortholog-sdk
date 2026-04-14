package envelope

import "github.com/clearcompass-ai/ortholog-sdk/types"

type AuthorityPath uint8

const (
	AuthoritySameSigner     AuthorityPath = 1
	AuthorityDelegation     AuthorityPath = 2
	AuthorityScopeAuthority AuthorityPath = 3
)

type KeyGenMode uint8

const (
	KeyGenExchangeManaged KeyGenMode = 1
	KeyGenClientSideBlind KeyGenMode = 2
)

type ControlHeader struct {
	ProtocolVersion       uint16
	// Signer_DID: who signed this entry. Never empty.
	SignerDID string

	// Subject_Identifier: opaque subject reference (spec-defined as bytes).
	// Serialized in header body. Included in canonical hash.
	// Never read by builder or verifier.
	// Carried for discoverability. Domain applications populate
	// via entry builders for credential-bearing entries.
	// nil for self-referential entries (DID profiles, schemas, scopes).
	// Populated for issued credentials (degrees, party bindings,
	//   exam results, coverage credentials).
	// []byte not string — spec defines as bytes (opaque).
	SubjectIdentifier []byte
	TargetRoot            *types.LogPosition
	TargetIntermediate    *types.LogPosition
	AuthorityPath         *AuthorityPath
	DelegateDID           *string
	AuthoritySet          map[string]struct{}
	AuthorityDID          *string
	SchemaRef             *types.LogPosition
	EvidencePointers      []types.LogPosition
	KeyGenerationMode     *KeyGenMode
	CommutativeOperations []uint32
	DelegationPointers    []types.LogPosition
	ScopePointer          *types.LogPosition
	ApprovalPointers      []types.LogPosition
	PriorAuthority        *types.LogPosition
	CosignatureOf         *types.LogPosition
	EventTime             int64
	AdmissionProof        *types.AdmissionProof
	AuthoritySkip         *types.LogPosition
}

func (h *ControlHeader) AuthoritySetContains(did string) bool {
	if h.AuthoritySet == nil {
		return false
	}
	_, ok := h.AuthoritySet[did]
	return ok
}

func (h *ControlHeader) AuthoritySetSize() int {
	return len(h.AuthoritySet)
}
