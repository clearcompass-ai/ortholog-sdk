/*
Package envelope — control_header.go defines the ControlHeader struct that
every protocol entry carries. The Control Header is the protocol's
constitutional layer — its fields are read by the builder for path
classification and by the verifier for state evaluation.

Protocol v5 is the current active wire-format version.

Domain identity and versioning do NOT live in the Control Header.
Per the protocol's domain/protocol separation principle, domain
semantics travel via SchemaRef: each domain-governed entry points
to an immutable schema entry whose Domain Payload is the manifest.
The Control Header carries only protocol mechanics.

Field discipline (Decision 25): the Control Header is locked to protocol
governance. Adding fields requires unanimous scope authority approval
through the three-phase amendment lifecycle. Domain-specific concepts
belong in Domain Payload, never here.

Destination binding: the Destination field cryptographically binds every
entry to its intended exchange. This is part of the canonical hash, so
an entry signed for exchange A cannot be verified against exchange B,
preventing cross-exchange replay. See docs on the Destination field.
*/
package envelope

import (
	"sort"

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
//
// Field ordering mirrors wire order. ProtocolVersion is first because it is
// the first field of the canonical preamble (bytes 0–1) and authoritatively
// identifies how every other field is encoded.
type ControlHeader struct {
	// ProtocolVersion is the wire-format version of this entry. Populated by
	// NewEntry (set to currentProtocolVersion) and by Deserialize (read from
	// the canonical preamble). Callers read this field directly; there is no
	// zero-value fallback — a zero here means the header has not been through
	// NewEntry or Deserialize, which is a programming error, not a valid state.
	ProtocolVersion uint16

	// SignerDID is the DID whose signing key produced the signature over
	// this entry's canonical bytes. Required for every entry.
	SignerDID string

	// Destination is the DID of the intended destination exchange. Required
	// for every entry. Part of the canonical hash — an entry signed for
	// exchange A cannot be verified against exchange B, because the hash
	// Alice signed over commits to A and any attempt to verify with B
	// recomputes a different hash.
	//
	// This is the protocol-level defense against cross-exchange replay:
	// an attacker who captures a signed entry cannot submit it to any
	// exchange other than the one it was bound to at signing time.
	//
	// Validated by envelope.ValidateDestination at serialize time (non-empty,
	// non-whitespace-padded, within MaxDestinationDIDLen). The verifier
	// registry checks entry.Destination against its own scope before
	// accepting any entry for verification.
	//
	// Note: Destination is NOT Log_DID. A single log may host entries bound
	// to multiple logical destinations if the protocol evolves to support
	// multiplexed exchanges; Destination is the authoritative binding for
	// the signature, Log_DID is a physical-storage concern.
	Destination string

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

// AuthoritySetSize returns the cardinality of Authority_Set.
func (h *ControlHeader) AuthoritySetSize() int {
	return len(h.AuthoritySet)
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
	sort.Strings(dids)
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
