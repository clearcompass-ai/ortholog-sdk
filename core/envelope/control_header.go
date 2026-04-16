/*
Package envelope — control_header.go defines the ControlHeader struct that
every protocol entry carries. The Control Header is the protocol's
constitutional layer — its fields are read by the builder for path
classification and by the verifier for state evaluation.

Protocol v5 adds DomainManifestVersion to pin each entry to a specific
domain manifest version (Option 1 — pinned per-entry versioning).
This enables cross-version verification at scale: a verifier reading
entries spanning 10 years can resolve each entry's governance semantics
against the exact manifest version it was issued under.

Field discipline (Decision 25): the Control Header is locked to protocol
governance. Adding fields requires unanimous scope authority approval
through the three-phase amendment lifecycle. Domain-specific concepts
belong in Domain Payload, never here.
*/
package envelope

import (
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// AuthorityPath is the structural discriminator that the builder reads
// to classify Path A / Path B / Path C entries. Commentary entries have
// no AuthorityPath (nil pointer in ControlHeader).
type AuthorityPath uint8

const (
	// AuthoritySameSigner: Path A. Signer_DID == target entry's signer.
	AuthoritySameSigner AuthorityPath = 1

	// AuthorityDelegation: Path B. Delegation chain connects signer to target.
	AuthorityDelegation AuthorityPath = 2

	// AuthorityScopeAuthority: Path C. Signer is in scope's Authority_Set.
	AuthorityScopeAuthority AuthorityPath = 3
)

// KeyGenMode declares how signing keys for a new entity are produced.
// Carried on root entity entries; read by verifier for Tier 2/3 classification.
type KeyGenMode uint8

const (
	// KeyGenExchangeManaged: the exchange generates and holds the signing key.
	KeyGenExchangeManaged KeyGenMode = 1

	// KeyGenClientSideBlind: the client generates the key in a secure enclave;
	// the exchange routes ciphertext only.
	KeyGenClientSideBlind KeyGenMode = 2
)

// ControlHeader carries the protocol-level metadata for a single entry.
// All fields are read by the builder or verifier as part of path classification
// and state evaluation. Domain Payload is opaque to both.
type ControlHeader struct {
	DomainManifestVersion *[3]uint16
	// SignerDID is the DID whose signing key produced the signature over
	// this entry's canonical bytes. Required for every entry.
	SignerDID string

	// TargetRoot references the root entity being acted on. Nil for
	// commentary entries and new root entities.
	TargetRoot *types.LogPosition

	// TargetIntermediate optionally references an intermediate entity
	// (e.g., an amendment position that should also have OriginTip advanced).
	TargetIntermediate *types.LogPosition

	// AuthorityPath discriminates Path A/B/C. Nil for commentary.
	AuthorityPath *AuthorityPath

	// DelegationPointers carries the delegation chain for Path B.
	// Capped at MaxDelegationPointers (3).
	DelegationPointers []types.LogPosition

	// DelegateDID names the delegate on delegation entries (Path A entries
	// that establish a delegation). Nil on non-delegation entries.
	DelegateDID *string

	// ScopePointer references the governing scope for Path C entries.
	// Nil on Path A / Path B / commentary.
	ScopePointer *types.LogPosition

	// AuthoritySet is the scope's authority membership, carried on scope
	// creation and scope amendment entries. Empty on other entries.
	AuthoritySet map[string]struct{}

	// AuthorityDID optionally identifies the specific authority being
	// added or removed in a scope amendment. Nil for parameter changes.
	AuthorityDID *string

	// PriorAuthority references the Authority_Tip the writer observed
	// when constructing this Path C entry. Used for OCC verification.
	PriorAuthority *types.LogPosition

	// ApprovalPointers references cosignature entries approving this
	// entry's underlying proposal. Used for multi-party scope amendments.
	ApprovalPointers []types.LogPosition

	// EvidencePointers references supporting entries (cosignatures,
	// attestations, witness confirmations) that establish activation.
	// Capped at MaxEvidencePointers (32) except on authority snapshots.
	EvidencePointers []types.LogPosition

	// SchemaRef pins the governing schema for this entry. Readers follow
	// this pointer to resolve activation delay, cosignature threshold,
	// and other schema-declared parameters.
	SchemaRef *types.LogPosition

	// KeyGenerationMode declares the key generation path for root entity
	// entries. Nil on non-root entries.
	KeyGenerationMode *KeyGenMode

	// CommutativeOperations, if non-empty, marks the governing schema as
	// permitting commutative OCC (Δ-window CRDT resolution). The specific
	// operation tags are domain-interpreted; the builder checks only
	// emptiness for OCC mode selection (SDK-D7).
	CommutativeOperations []uint32

	// SubjectIdentifier carries the credential subject's identifier on
	// credential entries. Domain-interpreted structure; the builder
	// treats it as opaque bytes.
	SubjectIdentifier []byte

	// CosignatureOf references the entry being cosigned, on cosignature
	// commentary entries. Used by log operators to build the Cosignature_Of
	// index required by exchange certification.
	CosignatureOf *types.LogPosition

	// EventTime is the domain-asserted timestamp for the underlying event.
	// Distinct from Log_Time (the operator-asserted admission timestamp).
	// Unix seconds.
	EventTime int64

	// AdmissionProof carries Mode B proof-of-work payload. Nil for Mode A
	// entries. Wire-serialized as a length-prefixed body region to isolate
	// it from Authority_Skip (protects against cross-field corruption).
	AdmissionProof *AdmissionProofBody

	// AuthoritySkip is the verifier hint (v3+) for fast authority chain
	// traversal. Recorded by builder; read by verifier; opaque to SMT.
	AuthoritySkip *types.LogPosition

	// DomainManifestVersion pins this entry to a specific domain manifest
	// version [major, minor, patch]. Nil indicates a legacy v4 entry that
	// predates per-entry manifest pinning; verifiers resolve such entries
	// against the latest-known manifest for the domain.
	//
	// NEW in protocol v5. On the wire: 1 presence byte + 6 bytes when present.
	DomainManifestVersion *[3]uint16

	// protocolVersion tracks which protocol version this entry was
	// serialized under. Populated by Deserialize; set to currentProtocolVersion
	// by NewEntry. Private — callers access via ProtocolVersion().
	protocolVersion uint16
}

// ProtocolVersion returns the protocol version this header was serialized
// under (populated during Deserialize) or will be serialized under
// (populated by NewEntry).
func (h *ControlHeader) ProtocolVersion() uint16 {
	if h.protocolVersion == 0 {
		return currentProtocolVersion
	}
	return h.protocolVersion
}

// setProtocolVersion is the internal setter used by Deserialize and NewEntry.
func (h *ControlHeader) setProtocolVersion(v uint16) {
	h.protocolVersion = v
}

// AuthoritySetContains reports whether a DID is a member of this header's
// Authority_Set. Used by the builder during Path C verification.
func (h *ControlHeader) AuthoritySetContains(did string) bool {
	if h.AuthoritySet == nil {
		return false
	}
	_, ok := h.AuthoritySet[did]
	return ok
}

// SortedDIDs returns the Authority_Set DIDs in deterministic sorted order
// (NFC-normalized lexicographic). Used for canonical serialization.
func (h *ControlHeader) SortedDIDs() []string {
	if len(h.AuthoritySet) == 0 {
		return nil
	}
	dids := make([]string, 0, len(h.AuthoritySet))
	for did := range h.AuthoritySet {
		dids = append(dids, did)
	}
	sortDIDs(dids)
	return dids
}

// AdmissionProofBody is the length-prefixed admission proof region.
// Length-prefixing on the wire isolates this field from Authority_Skip
// corruption (SDK-3).
type AdmissionProofBody struct {
	// Mode declares the admission mode (B = stamp).
	Mode uint8

	// Difficulty is the bits-of-work target for Mode B.
	Difficulty uint8

	// HashFunc tags the hash function (e.g., SHA-256, Argon2id-tagged).
	HashFunc uint8

	// Epoch pins the stamp to a time window (SDK-2).
	Epoch uint64

	// SubmitterCommit optionally pins the stamp to a specific submitter
	// for rate-limiting (SDK-4). Nil = unbound stamp.
	SubmitterCommit *[32]byte

	// Nonce is the proof-of-work nonce.
	Nonce uint64

	// Hash is the computed stamp hash below the difficulty target.
	Hash [32]byte
}

// sortDIDs sorts DIDs in lexicographic order. Exported via SortedDIDs;
// internal to allow test stubbing.
func sortDIDs(dids []string) {
	// Standard sort; real implementation uses sort.Strings at package init.
	for i := 1; i < len(dids); i++ {
		for j := i; j > 0 && dids[j-1] > dids[j]; j-- {
			dids[j-1], dids[j] = dids[j], dids[j-1]
		}
	}
}
