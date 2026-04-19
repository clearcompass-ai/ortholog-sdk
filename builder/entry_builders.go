/*
Package builder — entry_builders.go provides 18 typed entry construction
functions for the Ortholog protocol.

Every domain application consumes these. No manual header population.
Each builder validates domain-specific constraints, populates ControlHeader
fields correctly for its path, and delegates to envelope.NewEntry for
normalization + protocol-level validation.

The judicial network's 14 interface rules depend on these builders
producing correctly-formed headers. The builder algorithm (algorithm.go)
classifies entries based on header shape — a misformed header silently
falls to Path D.

Destination binding: every *Params struct carries a Destination field (the
DID of the exchange this entry is bound to). Every Build* validates it
with envelope.ValidateDestination and copies it into the ControlHeader,
where serialize.go includes it in the canonical hash. Cross-exchange
replay of a signed entry is cryptographically impossible.
*/
package builder

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────

var (
	ErrEmptySignerDID       = errors.New("builder/entry: Signer_DID must not be empty")
	ErrMissingTargetRoot    = errors.New("builder/entry: Target_Root required")
	ErrMissingDelegateDID   = errors.New("builder/entry: Delegate_DID required for delegation")
	ErrMissingScopePointer  = errors.New("builder/entry: Scope_Pointer required for scope authority")
	ErrEmptyAuthoritySet    = errors.New("builder/entry: Authority_Set must not be empty")
	ErrMissingCosignatureOf = errors.New("builder/entry: Cosignature_Of required for cosignature")
	ErrEmptyDelegationChain = errors.New("builder/entry: Delegation_Pointers must not be empty for Path B")
	ErrMissingSourceLogDID  = errors.New("builder/entry: source log DID required")
)

// validateCommon checks invariants that apply to every builder: signer DID
// presence and destination-binding validity. Returns the first error.
func validateCommon(signerDID, destination string) error {
	if signerDID == "" {
		return ErrEmptySignerDID
	}
	if err := envelope.ValidateDestination(destination); err != nil {
		return fmt.Errorf("builder/entry: %w", err)
	}
	return nil
}

// ═════════════════════════════════════════════════════════════════════
// Origin lane (5 builders)
// ═════════════════════════════════════════════════════════════════════

// ── 1. BuildRootEntity ──────────────────────────────────────────────

// RootEntityParams configures a new root entity entry.
type RootEntityParams struct {
	Destination       string // DID of target exchange. Required.
	SignerDID         string
	Payload           []byte
	SchemaRef         *types.LogPosition
	KeyGenMode        *envelope.KeyGenMode
	SubjectIdentifier []byte
	EventTime         int64
}

// BuildRootEntity creates a new root entity. Becomes an SMT leaf with
// OriginTip=self, AuthorityTip=self. AuthorityPath=SameSigner, no TargetRoot.
func BuildRootEntity(p RootEntityParams) (*envelope.Entry, error) {
	if err := validateCommon(p.SignerDID, p.Destination); err != nil {
		return nil, err
	}
	ap := envelope.AuthoritySameSigner
	return envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:         p.SignerDID,
		Destination:       p.Destination,
		AuthorityPath:     &ap,
		SchemaRef:         p.SchemaRef,
		KeyGenerationMode: p.KeyGenMode,
		SubjectIdentifier: p.SubjectIdentifier,
		EventTime:         p.EventTime,
	}, p.Payload)

}

// ── 2. BuildAmendment ───────────────────────────────────────────────

// AmendmentParams configures a same-signer amendment (Path A).
type AmendmentParams struct {
	Destination        string // DID of target exchange. Required.
	SignerDID          string
	TargetRoot         types.LogPosition
	TargetIntermediate *types.LogPosition
	Payload            []byte
	SchemaRef          *types.LogPosition
	EvidencePointers   []types.LogPosition
	SubjectIdentifier  []byte
	EventTime          int64
}

// BuildAmendment creates a same-signer amendment. Signer must match the
// root entity's signer. Advances OriginTip via Path A.
func BuildAmendment(p AmendmentParams) (*envelope.Entry, error) {
	if err := validateCommon(p.SignerDID, p.Destination); err != nil {
		return nil, err
	}
	if p.TargetRoot.IsNull() {
		return nil, ErrMissingTargetRoot
	}
	ap := envelope.AuthoritySameSigner
	return envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:          p.SignerDID,
		Destination:        p.Destination,
		TargetRoot:         &p.TargetRoot,
		TargetIntermediate: p.TargetIntermediate,
		AuthorityPath:      &ap,
		SchemaRef:          p.SchemaRef,
		EvidencePointers:   p.EvidencePointers,
		SubjectIdentifier:  p.SubjectIdentifier,
		EventTime:          p.EventTime,
	}, p.Payload)

}

// ── 3. BuildDelegation ──────────────────────────────────────────────

// DelegationParams configures a delegation entry.
type DelegationParams struct {
	Destination string // DID of target exchange. Required.
	SignerDID   string // Who is delegating (grantor).
	DelegateDID string // Who receives delegated authority.
	Payload     []byte
	SchemaRef   *types.LogPosition
	ScopeLimit  []byte // Domain-specific scope constraint (opaque, in payload).
	EventTime   int64
}

// BuildDelegation creates a delegation entry. The entry becomes an SMT
// leaf. Live when OriginTip == self (not revoked, not amended).
// ScopeLimit, if provided, is embedded in the Domain Payload by the caller.
func BuildDelegation(p DelegationParams) (*envelope.Entry, error) {
	if err := validateCommon(p.SignerDID, p.Destination); err != nil {
		return nil, err
	}
	if p.DelegateDID == "" {
		return nil, ErrMissingDelegateDID
	}
	ap := envelope.AuthoritySameSigner
	return envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:     p.SignerDID,
		Destination:   p.Destination,
		AuthorityPath: &ap,
		DelegateDID:   &p.DelegateDID,
		SchemaRef:     p.SchemaRef,
		EventTime:     p.EventTime,
	}, p.Payload)

}

// ── 4. BuildSuccession ──────────────────────────────────────────────

// SuccessionParams configures a succession entry.
type SuccessionParams struct {
	Destination  string // DID of target exchange. Required.
	SignerDID    string
	TargetRoot   types.LogPosition // Entity being replaced.
	NewSignerDID string            // Successor's DID (carried in payload).
	Payload      []byte
	SchemaRef    *types.LogPosition
	EventTime    int64
}

// BuildSuccession creates a succession entry. Path A: same signer,
// advances OriginTip. NewSignerDID is domain-level (in payload).
func BuildSuccession(p SuccessionParams) (*envelope.Entry, error) {
	if err := validateCommon(p.SignerDID, p.Destination); err != nil {
		return nil, err
	}
	if p.TargetRoot.IsNull() {
		return nil, ErrMissingTargetRoot
	}
	ap := envelope.AuthoritySameSigner
	return envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:     p.SignerDID,
		Destination:   p.Destination,
		TargetRoot:    &p.TargetRoot,
		AuthorityPath: &ap,
		SchemaRef:     p.SchemaRef,
		EventTime:     p.EventTime,
	}, p.Payload)

}

// ── 5. BuildRevocation ──────────────────────────────────────────────

// RevocationParams configures a revocation entry.
type RevocationParams struct {
	Destination string // DID of target exchange. Required.
	SignerDID   string
	TargetRoot  types.LogPosition
	Payload     []byte
	EventTime   int64
}

// BuildRevocation creates a revocation. Path A: same signer advances
// OriginTip, breaking liveness for delegations (OriginTip != position).
func BuildRevocation(p RevocationParams) (*envelope.Entry, error) {
	if err := validateCommon(p.SignerDID, p.Destination); err != nil {
		return nil, err
	}
	if p.TargetRoot.IsNull() {
		return nil, ErrMissingTargetRoot
	}
	ap := envelope.AuthoritySameSigner
	return envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:     p.SignerDID,
		Destination:   p.Destination,
		TargetRoot:    &p.TargetRoot,
		AuthorityPath: &ap,
		EventTime:     p.EventTime,
	}, p.Payload)

}

// ═════════════════════════════════════════════════════════════════════
// Authority lane (3 builders)
// ═════════════════════════════════════════════════════════════════════

// ── 6. BuildScopeCreation ───────────────────────────────────────────

// ScopeCreationParams configures a scope entity with an authority set.
type ScopeCreationParams struct {
	Destination  string // DID of target exchange. Required.
	SignerDID    string
	AuthoritySet map[string]struct{}
	Payload      []byte
	SchemaRef    *types.LogPosition
	EventTime    int64
}

// BuildScopeCreation creates a scope entity. Constraint: AuthoritySet
// must be non-empty and contain at least SignerDID.
func BuildScopeCreation(p ScopeCreationParams) (*envelope.Entry, error) {
	if err := validateCommon(p.SignerDID, p.Destination); err != nil {
		return nil, err
	}
	if len(p.AuthoritySet) == 0 {
		return nil, ErrEmptyAuthoritySet
	}
	if _, ok := p.AuthoritySet[p.SignerDID]; !ok {
		return nil, fmt.Errorf("%w: must contain Signer_DID", ErrEmptyAuthoritySet)
	}
	ap := envelope.AuthoritySameSigner
	return envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:     p.SignerDID,
		Destination:   p.Destination,
		AuthorityPath: &ap,
		AuthoritySet:  p.AuthoritySet,
		SchemaRef:     p.SchemaRef,
		EventTime:     p.EventTime,
	}, p.Payload)

}

// ── 7. BuildScopeAmendment ──────────────────────────────────────────

// ScopeAmendmentParams configures a scope amendment (Path C).
type ScopeAmendmentParams struct {
	Destination      string // DID of target exchange. Required.
	SignerDID        string
	TargetRoot       types.LogPosition   // Scope position (self-referencing).
	ScopePointer     types.LogPosition   // Same as TargetRoot for amendments.
	NewAuthoritySet  map[string]struct{} // Updated authority set.
	PriorAuthority   *types.LogPosition
	ApprovalPointers []types.LogPosition
	Payload          []byte
	SchemaRef        *types.LogPosition
	EventTime        int64
}

// BuildScopeAmendment creates a scope amendment (Path C). ScopePointer
// equals TargetRoot (self-referencing). AuthoritySet carries the new set.
func BuildScopeAmendment(p ScopeAmendmentParams) (*envelope.Entry, error) {
	if err := validateCommon(p.SignerDID, p.Destination); err != nil {
		return nil, err
	}
	if p.TargetRoot.IsNull() {
		return nil, ErrMissingTargetRoot
	}
	if len(p.NewAuthoritySet) == 0 {
		return nil, ErrEmptyAuthoritySet
	}
	ap := envelope.AuthorityScopeAuthority
	return envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:        p.SignerDID,
		Destination:      p.Destination,
		TargetRoot:       &p.TargetRoot,
		AuthorityPath:    &ap,
		ScopePointer:     &p.ScopePointer,
		AuthoritySet:     p.NewAuthoritySet,
		PriorAuthority:   p.PriorAuthority,
		ApprovalPointers: p.ApprovalPointers,
		SchemaRef:        p.SchemaRef,
		EventTime:        p.EventTime,
	}, p.Payload)

}

// ── 8. BuildScopeRemoval ────────────────────────────────────────────

// ScopeRemovalParams configures a scope removal (Path C, no AuthoritySet).
type ScopeRemovalParams struct {
	Destination    string // DID of target exchange. Required.
	SignerDID      string
	TargetRoot     types.LogPosition
	ScopePointer   types.LogPosition
	PriorAuthority *types.LogPosition
	Payload        []byte
	EventTime      int64
}

// BuildScopeRemoval creates a scope removal (Path C). No AuthoritySet
// field — distinguishes removal from amendment. Updates AuthorityTip.
func BuildScopeRemoval(p ScopeRemovalParams) (*envelope.Entry, error) {
	if err := validateCommon(p.SignerDID, p.Destination); err != nil {
		return nil, err
	}
	if p.ScopePointer.IsNull() {
		return nil, ErrMissingScopePointer
	}
	ap := envelope.AuthorityScopeAuthority
	return envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:      p.SignerDID,
		Destination:    p.Destination,
		TargetRoot:     &p.TargetRoot,
		AuthorityPath:  &ap,
		ScopePointer:   &p.ScopePointer,
		PriorAuthority: p.PriorAuthority,
		EventTime:      p.EventTime,
	}, p.Payload)

}

// ═════════════════════════════════════════════════════════════════════
// Enforcement (1 builder — separate from scope amendment)
// ═════════════════════════════════════════════════════════════════════

// ── 9. BuildEnforcement ─────────────────────────────────────────────

// EnforcementParams configures a scope authority enforcement (Path C).
type EnforcementParams struct {
	Destination      string // DID of target exchange. Required.
	SignerDID        string
	TargetRoot       types.LogPosition
	ScopePointer     types.LogPosition
	PriorAuthority   *types.LogPosition
	EvidencePointers []types.LogPosition
	ApprovalPointers []types.LogPosition
	Payload          []byte
	SchemaRef        *types.LogPosition
	EventTime        int64
}

// BuildEnforcement creates a scope authority enforcement (Path C).
// Signer must be in the scope's AuthoritySet (caller responsibility).
// Updates AuthorityTip, NOT OriginTip.
func BuildEnforcement(p EnforcementParams) (*envelope.Entry, error) {
	if err := validateCommon(p.SignerDID, p.Destination); err != nil {
		return nil, err
	}
	if p.TargetRoot.IsNull() {
		return nil, ErrMissingTargetRoot
	}
	if p.ScopePointer.IsNull() {
		return nil, ErrMissingScopePointer
	}
	ap := envelope.AuthorityScopeAuthority
	return envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:        p.SignerDID,
		Destination:      p.Destination,
		TargetRoot:       &p.TargetRoot,
		AuthorityPath:    &ap,
		ScopePointer:     &p.ScopePointer,
		PriorAuthority:   p.PriorAuthority,
		EvidencePointers: p.EvidencePointers,
		ApprovalPointers: p.ApprovalPointers,
		SchemaRef:        p.SchemaRef,
		EventTime:        p.EventTime,
	}, p.Payload)

}

// ═════════════════════════════════════════════════════════════════════
// Commentary lane (4 builders)
// ═════════════════════════════════════════════════════════════════════

// ── 10. BuildCommentary ─────────────────────────────────────────────

// CommentaryParams configures a zero-SMT-impact commentary entry.
type CommentaryParams struct {
	Destination string // DID of target exchange. Required.
	SignerDID   string
	Payload     []byte
	EventTime   int64
}

// BuildCommentary creates a commentary entry. No TargetRoot, no
// AuthorityPath. Zero SMT impact — no leaf created or modified.
func BuildCommentary(p CommentaryParams) (*envelope.Entry, error) {
	if err := validateCommon(p.SignerDID, p.Destination); err != nil {
		return nil, err
	}
	return envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:   p.SignerDID,
		Destination: p.Destination,
		EventTime:   p.EventTime,
	}, p.Payload)

}

// ── 11. BuildCosignature ────────────────────────────────────────────

// CosignatureParams configures a cosignature commentary entry.
type CosignatureParams struct {
	Destination   string // DID of target exchange. Required.
	SignerDID     string
	CosignatureOf types.LogPosition
	Payload       []byte
	EventTime     int64
}

// BuildCosignature creates a cosignature. CosignatureOf references
// the entry being endorsed. Zero SMT impact.
func BuildCosignature(p CosignatureParams) (*envelope.Entry, error) {
	if err := validateCommon(p.SignerDID, p.Destination); err != nil {
		return nil, err
	}
	if p.CosignatureOf.IsNull() {
		return nil, ErrMissingCosignatureOf
	}
	return envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:     p.SignerDID,
		Destination:   p.Destination,
		CosignatureOf: &p.CosignatureOf,
		EventTime:     p.EventTime,
	}, p.Payload)

}

// ── 12. BuildRecoveryRequest ────────────────────────────────────────

// RecoveryRequestParams configures a recovery request commentary.
type RecoveryRequestParams struct {
	Destination string // DID of target exchange. Required.
	SignerDID   string // New exchange or recovery agent.
	Payload     []byte // Recovery evidence.
	EventTime   int64
}

// BuildRecoveryRequest creates a commentary entry initiating key
// recovery. Escrow nodes cosign via BuildCosignature to authorize.
func BuildRecoveryRequest(p RecoveryRequestParams) (*envelope.Entry, error) {
	if err := validateCommon(p.SignerDID, p.Destination); err != nil {
		return nil, err
	}
	return envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:   p.SignerDID,
		Destination: p.Destination,
		EventTime:   p.EventTime,
	}, p.Payload)

}

// ── 13. BuildAnchorEntry ────────────────────────────────────────────

// AnchorParams configures an anchor commentary entry (Decision 44).
type AnchorParams struct {
	Destination  string // DID of target exchange. Required.
	SignerDID    string // Operator DID.
	SourceLogDID string
	TreeHeadRef  string // Hex-encoded SHA-256 of serialized tree head.
	TreeSize     uint64
	EventTime    int64
}

// BuildAnchorEntry creates a commentary entry containing a tree head
// reference for cross-log anchoring. Decision 44: standard commentary.
// Constructs JSON payload from structured params.
func BuildAnchorEntry(p AnchorParams) (*envelope.Entry, error) {
	if err := validateCommon(p.SignerDID, p.Destination); err != nil {
		return nil, err
	}
	if p.SourceLogDID == "" {
		return nil, ErrMissingSourceLogDID
	}
	payload, err := json.Marshal(map[string]any{
		"anchor_type":    "tree_head_ref",
		"source_log_did": p.SourceLogDID,
		"tree_head_ref":  p.TreeHeadRef,
		"tree_size":      p.TreeSize,
	})
	if err != nil {
		return nil, fmt.Errorf("builder/entry: marshal anchor payload: %w", err)
	}
	return envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:   p.SignerDID,
		Destination: p.Destination,
		EventTime:   p.EventTime,
	}, payload)

}

// ═════════════════════════════════════════════════════════════════════
// Key management (2 builders)
// ═════════════════════════════════════════════════════════════════════

// ── 14. BuildKeyRotation ────────────────────────────────────────────

// KeyRotationParams configures a key rotation entry (Path A).
type KeyRotationParams struct {
	Destination  string // DID of target exchange. Required.
	SignerDID    string
	TargetRoot   types.LogPosition  // DID profile entity.
	NewPublicKey []byte             // New public key bytes (in payload).
	Payload      []byte             // Full payload (overrides NewPublicKey if set).
	SchemaRef    *types.LogPosition // Schema with maturation/activation params.
	EventTime    int64
}

// BuildKeyRotation creates a key rotation (Path A). Targets the DID
// profile entity. Tier classification (2 vs 3) is the verifier's job.
func BuildKeyRotation(p KeyRotationParams) (*envelope.Entry, error) {
	if err := validateCommon(p.SignerDID, p.Destination); err != nil {
		return nil, err
	}
	if p.TargetRoot.IsNull() {
		return nil, ErrMissingTargetRoot
	}
	payload := p.Payload
	if payload == nil && p.NewPublicKey != nil {
		payload, _ = json.Marshal(map[string]any{
			"new_public_key": fmt.Sprintf("%x", p.NewPublicKey),
		})
	}
	ap := envelope.AuthoritySameSigner
	return envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:     p.SignerDID,
		Destination:   p.Destination,
		TargetRoot:    &p.TargetRoot,
		AuthorityPath: &ap,
		SchemaRef:     p.SchemaRef,
		EventTime:     p.EventTime,
	}, payload)

}

// ── 15. BuildKeyPrecommit ───────────────────────────────────────────

// KeyPrecommitParams configures a key pre-commitment entry (Path A).
type KeyPrecommitParams struct {
	Destination string // DID of target exchange. Required.
	SignerDID   string
	TargetRoot  types.LogPosition // DID profile entity.
	NextKeyHash string            // Hex-encoded hash of next public key.
	Payload     []byte            // Full payload (overrides NextKeyHash if set).
	SchemaRef   *types.LogPosition
	EventTime   int64
}

// BuildKeyPrecommit creates a pre-commitment for key rotation. After
// maturation_epoch, the pre-committed key rotates at Tier 2 (immediate).
func BuildKeyPrecommit(p KeyPrecommitParams) (*envelope.Entry, error) {
	if err := validateCommon(p.SignerDID, p.Destination); err != nil {
		return nil, err
	}
	if p.TargetRoot.IsNull() {
		return nil, ErrMissingTargetRoot
	}
	payload := p.Payload
	if payload == nil && p.NextKeyHash != "" {
		payload, _ = json.Marshal(map[string]any{
			"next_key_hash": p.NextKeyHash,
		})
	}
	ap := envelope.AuthoritySameSigner
	return envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:     p.SignerDID,
		Destination:   p.Destination,
		TargetRoot:    &p.TargetRoot,
		AuthorityPath: &ap,
		SchemaRef:     p.SchemaRef,
		EventTime:     p.EventTime,
	}, payload)

}

// ═════════════════════════════════════════════════════════════════════
// Schema (1 builder)
// ═════════════════════════════════════════════════════════════════════

// ── 16. BuildSchemaEntry ────────────────────────────────────────────

// SchemaEntryParams configures a schema definition entry.
// PredecessorSchema lives in Domain Payload JSON — SchemaParameterExtractor
// reads it. This builder does not parse payload.
type SchemaEntryParams struct {
	Destination           string // DID of target exchange. Required.
	SignerDID             string
	Payload               []byte   // JSON with 10 well-known fields (incl predecessor_schema).
	CommutativeOperations []uint32 // Non-empty → commutative OCC mode.
	EventTime             int64
}

// BuildSchemaEntry creates a schema definition. Becomes an SMT leaf.
// Referenced by other entries via Schema_Ref. Payload is not parsed here —
// that's SchemaParameterExtractor's job.
func BuildSchemaEntry(p SchemaEntryParams) (*envelope.Entry, error) {
	if err := validateCommon(p.SignerDID, p.Destination); err != nil {
		return nil, err
	}
	ap := envelope.AuthoritySameSigner
	return envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:             p.SignerDID,
		Destination:           p.Destination,
		AuthorityPath:         &ap,
		CommutativeOperations: p.CommutativeOperations,
		EventTime:             p.EventTime,
	}, p.Payload)

}

// ═════════════════════════════════════════════════════════════════════
// Delegation use (1 builder)
// ═════════════════════════════════════════════════════════════════════

// ── 17. BuildPathBEntry ─────────────────────────────────────────────

// PathBParams configures a delegated authority entry (Path B).
type PathBParams struct {
	Destination        string // DID of target exchange. Required.
	SignerDID          string
	TargetRoot         types.LogPosition
	DelegationPointers []types.LogPosition
	TargetIntermediate *types.LogPosition
	Payload            []byte
	SchemaRef          *types.LogPosition
	EvidencePointers   []types.LogPosition
	SubjectIdentifier  []byte
	EventTime          int64
}

// BuildPathBEntry creates an entry using delegated authority (Path B).
// DelegationPointers must form a chain connecting signer back to the
// target root entity's signer through at most 3 hops.
// Consumed by judicial filing.go after AssemblePathB.
func BuildPathBEntry(p PathBParams) (*envelope.Entry, error) {
	if err := validateCommon(p.SignerDID, p.Destination); err != nil {
		return nil, err
	}
	if p.TargetRoot.IsNull() {
		return nil, ErrMissingTargetRoot
	}
	if len(p.DelegationPointers) == 0 {
		return nil, ErrEmptyDelegationChain
	}
	ap := envelope.AuthorityDelegation
	return envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:          p.SignerDID,
		Destination:        p.Destination,
		TargetRoot:         &p.TargetRoot,
		TargetIntermediate: p.TargetIntermediate,
		AuthorityPath:      &ap,
		DelegationPointers: p.DelegationPointers,
		SchemaRef:          p.SchemaRef,
		EvidencePointers:   p.EvidencePointers,
		SubjectIdentifier:  p.SubjectIdentifier,
		EventTime:          p.EventTime,
	}, p.Payload)

}

// ═════════════════════════════════════════════════════════════════════
// Cross-log mirror (1 builder)
// ═════════════════════════════════════════════════════════════════════

// ── 18. BuildMirrorEntry ────────────────────────────────────────────

// MirrorParams configures a cross-log mirror commentary entry.
type MirrorParams struct {
	Destination    string // DID of target exchange. Required.
	SignerDID      string
	SourcePosition types.LogPosition // Entry being mirrored.
	SourceLogDID   string            // Foreign log DID.
	Payload        []byte            // Full payload (overrides auto-construction if set).
	EventTime      int64
}

// BuildMirrorEntry creates a commentary entry mirroring a foreign log
// entry. Used for cross-jurisdiction relays. Zero SMT impact.
func BuildMirrorEntry(p MirrorParams) (*envelope.Entry, error) {
	if err := validateCommon(p.SignerDID, p.Destination); err != nil {
		return nil, err
	}
	if p.SourceLogDID == "" {
		return nil, ErrMissingSourceLogDID
	}
	payload := p.Payload
	if payload == nil {
		payload, _ = json.Marshal(map[string]any{
			"mirror_type":     "cross_log_relay",
			"source_log_did":  p.SourceLogDID,
			"source_sequence": p.SourcePosition.Sequence,
		})
	}
	return envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:   p.SignerDID,
		Destination: p.Destination,
		EventTime:   p.EventTime,
	}, payload)

}
