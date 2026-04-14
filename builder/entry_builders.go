/*
Package builder — entry_builders.go provides 18 typed entry construction
functions for the Ortholog protocol.

Every domain application consumes these. No manual header population.
Each builder:
  1. Validates domain-specific constraints (e.g., BuildDelegation requires DelegateDID).
  2. Populates ControlHeader fields correctly for its path.
  3. Calls envelope.NewEntry for normalization + protocol-level validation.
  4. Returns *envelope.Entry or error.

The judicial network's 14 interface rules depend on these builders producing
correctly-formed headers. The builder algorithm (algorithm.go) classifies
entries based on header shape — a misformed header silently falls to Path D.

Grouping:
  Origin lane:    BuildRootEntity, BuildAmendment, BuildDelegation,
                  BuildSuccession, BuildRevocation
  Authority lane: BuildEnforcement, BuildScopeCreation, BuildScopeAmendment,
                  BuildScopeRemoval
  Commentary:     BuildCommentary, BuildCosignature, BuildRecoveryRequest,
                  BuildMirrorEntry, BuildAnchorEntry
  Key management: BuildKeyRotation, BuildKeyPrecommit
  Schema:         BuildSchemaEntry
  Delegation use: BuildPathBEntry
*/
package builder

import (
	"errors"
	"fmt"
	"time"

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
	ErrEmptyAuthoritySet    = errors.New("builder/entry: Authority_Set must not be empty for scope creation")
	ErrMissingCosignatureOf = errors.New("builder/entry: Cosignature_Of required for cosignature")
	ErrMissingSchemaRef     = errors.New("builder/entry: Schema_Ref required")
	ErrEmptyDelegationChain = errors.New("builder/entry: Delegation_Pointers must not be empty for Path B")
	ErrMissingSourceLogDID  = errors.New("builder/entry: source log DID required for mirror entry")
)

// ─────────────────────────────────────────────────────────────────────
// 1. BuildRootEntity — creates a new root entity (Path A origin)
// ─────────────────────────────────────────────────────────────────────

// BuildRootEntityParams configures a root entity entry.
type BuildRootEntityParams struct {
	SignerDID         string
	Payload           []byte
	SchemaRef         *types.LogPosition
	SubjectIdentifier []byte
	EventTime         int64
}

// BuildRootEntity creates a new root entity entry. This becomes a new SMT
// leaf with OriginTip=self, AuthorityTip=self. AuthorityPath=SameSigner,
// no TargetRoot (the entry IS the root).
func BuildRootEntity(p BuildRootEntityParams) (*envelope.Entry, error) {
	if p.SignerDID == "" {
		return nil, ErrEmptySignerDID
	}
	ap := envelope.AuthoritySameSigner
	return envelope.NewEntry(envelope.ControlHeader{
		SignerDID:         p.SignerDID,
		AuthorityPath:     &ap,
		SchemaRef:         p.SchemaRef,
		SubjectIdentifier: p.SubjectIdentifier,
		EventTime:         p.EventTime,
	}, p.Payload)
}

// ─────────────────────────────────────────────────────────────────────
// 2. BuildAmendment — same-signer amendment (Path A)
// ─────────────────────────────────────────────────────────────────────

// BuildAmendmentParams configures an amendment entry.
type BuildAmendmentParams struct {
	SignerDID          string
	TargetRoot         types.LogPosition
	TargetIntermediate *types.LogPosition // Path compression (optional).
	Payload            []byte
	SchemaRef          *types.LogPosition
	EvidencePointers   []types.LogPosition
	SubjectIdentifier  []byte
	EventTime          int64
}

// BuildAmendment creates a same-signer amendment (Path A). The signer
// must match the root entity's signer. Advances OriginTip.
func BuildAmendment(p BuildAmendmentParams) (*envelope.Entry, error) {
	if p.SignerDID == "" {
		return nil, ErrEmptySignerDID
	}
	ap := envelope.AuthoritySameSigner
	return envelope.NewEntry(envelope.ControlHeader{
		SignerDID:          p.SignerDID,
		TargetRoot:         &p.TargetRoot,
		TargetIntermediate: p.TargetIntermediate,
		AuthorityPath:      &ap,
		SchemaRef:          p.SchemaRef,
		EvidencePointers:   p.EvidencePointers,
		SubjectIdentifier:  p.SubjectIdentifier,
		EventTime:          p.EventTime,
	}, p.Payload)
}

// ─────────────────────────────────────────────────────────────────────
// 3. BuildDelegation — creates a delegation entry
// ─────────────────────────────────────────────────────────────────────

// BuildDelegationParams configures a delegation entry.
type BuildDelegationParams struct {
	SignerDID   string // Who is delegating (grantor).
	DelegateDID string // Who receives delegated authority.
	Payload     []byte
	SchemaRef   *types.LogPosition
	EventTime   int64
}

// BuildDelegation creates a delegation entry. The entry itself becomes
// an SMT leaf. The delegation is "live" when the leaf's OriginTip
// equals the entry's own position (not revoked, not amended).
func BuildDelegation(p BuildDelegationParams) (*envelope.Entry, error) {
	if p.SignerDID == "" {
		return nil, ErrEmptySignerDID
	}
	if p.DelegateDID == "" {
		return nil, ErrMissingDelegateDID
	}
	ap := envelope.AuthoritySameSigner
	return envelope.NewEntry(envelope.ControlHeader{
		SignerDID:     p.SignerDID,
		AuthorityPath: &ap,
		DelegateDID:   &p.DelegateDID,
		SchemaRef:     p.SchemaRef,
		EventTime:     p.EventTime,
	}, p.Payload)
}

// ─────────────────────────────────────────────────────────────────────
// 4. BuildSuccession — schema succession entry
// ─────────────────────────────────────────────────────────────────────

// BuildSuccessionParams configures a succession entry.
type BuildSuccessionParams struct {
	SignerDID         string
	TargetRoot        types.LogPosition  // The entity being succeeded.
	PredecessorSchema *types.LogPosition // The predecessor schema version.
	SchemaRef         *types.LogPosition // The new schema version.
	Payload           []byte
	SubjectIdentifier []byte
	EventTime         int64
}

// BuildSuccession creates a succession entry linking an entity to a
// new schema version. Path A: same signer, advances OriginTip.
func BuildSuccession(p BuildSuccessionParams) (*envelope.Entry, error) {
	if p.SignerDID == "" {
		return nil, ErrEmptySignerDID
	}
	ap := envelope.AuthoritySameSigner
	return envelope.NewEntry(envelope.ControlHeader{
		SignerDID:         p.SignerDID,
		TargetRoot:        &p.TargetRoot,
		AuthorityPath:     &ap,
		SchemaRef:         p.SchemaRef,
		SubjectIdentifier: p.SubjectIdentifier,
		EventTime:         p.EventTime,
	}, p.Payload)
}

// ─────────────────────────────────────────────────────────────────────
// 5. BuildCommentary — zero-SMT-impact commentary entry
// ─────────────────────────────────────────────────────────────────────

// BuildCommentaryParams configures a commentary entry.
type BuildCommentaryParams struct {
	SignerDID string
	Payload   []byte
	SchemaRef *types.LogPosition
	EventTime int64
}

// BuildCommentary creates a commentary entry. No TargetRoot, no
// AuthorityPath. Zero SMT impact — no leaf created or modified.
// Used for attestations, proposals, evidence grants, relays.
func BuildCommentary(p BuildCommentaryParams) (*envelope.Entry, error) {
	if p.SignerDID == "" {
		return nil, ErrEmptySignerDID
	}
	return envelope.NewEntry(envelope.ControlHeader{
		SignerDID: p.SignerDID,
		SchemaRef: p.SchemaRef,
		EventTime: p.EventTime,
	}, p.Payload)
}

// ─────────────────────────────────────────────────────────────────────
// 6. BuildCosignature — cosignature commentary
// ─────────────────────────────────────────────────────────────────────

// BuildCosignatureParams configures a cosignature entry.
type BuildCosignatureParams struct {
	SignerDID     string
	CosignatureOf types.LogPosition // The entry being cosigned.
	Payload       []byte
	EventTime     int64
}

// BuildCosignature creates a cosignature commentary entry. CosignatureOf
// references the entry being endorsed. Zero SMT impact.
func BuildCosignature(p BuildCosignatureParams) (*envelope.Entry, error) {
	if p.SignerDID == "" {
		return nil, ErrEmptySignerDID
	}
	if p.CosignatureOf.IsNull() {
		return nil, ErrMissingCosignatureOf
	}
	return envelope.NewEntry(envelope.ControlHeader{
		SignerDID:     p.SignerDID,
		CosignatureOf: &p.CosignatureOf,
		EventTime:     p.EventTime,
	}, p.Payload)
}

// ─────────────────────────────────────────────────────────────────────
// 7. BuildRevocation — revokes a delegation or entity (Path A)
// ─────────────────────────────────────────────────────────────────────

// BuildRevocationParams configures a revocation entry.
type BuildRevocationParams struct {
	SignerDID  string
	TargetRoot types.LogPosition // The delegation or entity to revoke.
	Payload    []byte
	SchemaRef  *types.LogPosition
	EventTime  int64
}

// BuildRevocation creates a revocation entry. Path A: same signer
// advances OriginTip, which breaks liveness checks for delegations
// (OriginTip != delegation position → delegation is dead).
func BuildRevocation(p BuildRevocationParams) (*envelope.Entry, error) {
	if p.SignerDID == "" {
		return nil, ErrEmptySignerDID
	}
	ap := envelope.AuthoritySameSigner
	return envelope.NewEntry(envelope.ControlHeader{
		SignerDID:     p.SignerDID,
		TargetRoot:    &p.TargetRoot,
		AuthorityPath: &ap,
		SchemaRef:     p.SchemaRef,
		EventTime:     p.EventTime,
	}, p.Payload)
}

// ─────────────────────────────────────────────────────────────────────
// 8. BuildEnforcement — scope authority enforcement (Path C)
// ─────────────────────────────────────────────────────────────────────

// BuildEnforcementParams configures an enforcement entry.
type BuildEnforcementParams struct {
	SignerDID        string
	TargetRoot       types.LogPosition  // The entity being enforced upon.
	ScopePointer     types.LogPosition  // The scope granting authority.
	PriorAuthority   *types.LogPosition // OCC: must match current AuthorityTip.
	SchemaRef        *types.LogPosition
	ApprovalPointers []types.LogPosition // Multi-party approvals.
	EvidencePointers []types.LogPosition
	Payload          []byte
	EventTime        int64
}

// BuildEnforcement creates a scope authority enforcement entry (Path C).
// The signer must be in the scope's AuthoritySet. Advances AuthorityTip
// on the target entity (not OriginTip).
func BuildEnforcement(p BuildEnforcementParams) (*envelope.Entry, error) {
	if p.SignerDID == "" {
		return nil, ErrEmptySignerDID
	}
	if p.ScopePointer.IsNull() {
		return nil, ErrMissingScopePointer
	}
	ap := envelope.AuthorityScopeAuthority
	return envelope.NewEntry(envelope.ControlHeader{
		SignerDID:        p.SignerDID,
		TargetRoot:       &p.TargetRoot,
		AuthorityPath:    &ap,
		ScopePointer:     &p.ScopePointer,
		PriorAuthority:   p.PriorAuthority,
		SchemaRef:        p.SchemaRef,
		ApprovalPointers: p.ApprovalPointers,
		EvidencePointers: p.EvidencePointers,
		EventTime:        p.EventTime,
	}, p.Payload)
}

// ─────────────────────────────────────────────────────────────────────
// 9. BuildScopeCreation — creates a scope entity with authority set
// ─────────────────────────────────────────────────────────────────────

// BuildScopeCreationParams configures a scope creation entry.
type BuildScopeCreationParams struct {
	SignerDID    string
	AuthoritySet map[string]struct{} // DIDs with authority in this scope.
	Payload      []byte
	SchemaRef    *types.LogPosition
	EventTime    int64
}

// BuildScopeCreation creates a scope entity with an authority set. The
// scope becomes an SMT leaf. Path C entries reference this scope via
// ScopePointer.
func BuildScopeCreation(p BuildScopeCreationParams) (*envelope.Entry, error) {
	if p.SignerDID == "" {
		return nil, ErrEmptySignerDID
	}
	if len(p.AuthoritySet) == 0 {
		return nil, ErrEmptyAuthoritySet
	}
	ap := envelope.AuthoritySameSigner
	return envelope.NewEntry(envelope.ControlHeader{
		SignerDID:     p.SignerDID,
		AuthorityPath: &ap,
		AuthoritySet:  p.AuthoritySet,
		SchemaRef:     p.SchemaRef,
		EventTime:     p.EventTime,
	}, p.Payload)
}

// ─────────────────────────────────────────────────────────────────────
// 10. BuildScopeAmendment — amends a scope's authority set (Path C)
// ─────────────────────────────────────────────────────────────────────

// BuildScopeAmendmentParams configures a scope amendment entry.
type BuildScopeAmendmentParams struct {
	SignerDID       string
	ScopePosition   types.LogPosition   // TargetRoot AND ScopePointer both point here.
	NewAuthoritySet map[string]struct{}  // The updated authority set.
	PriorAuthority  *types.LogPosition
	ApprovalPointers []types.LogPosition
	Payload         []byte
	SchemaRef       *types.LogPosition
	EventTime       int64
}

// BuildScopeAmendment creates a scope amendment entry (Path C). The
// scope pointer equals the target root (self-referencing amendment).
// The AuthoritySet field carries the new set. Updates OriginTip
// (amendment execution) on the scope leaf.
func BuildScopeAmendment(p BuildScopeAmendmentParams) (*envelope.Entry, error) {
	if p.SignerDID == "" {
		return nil, ErrEmptySignerDID
	}
	if len(p.NewAuthoritySet) == 0 {
		return nil, ErrEmptyAuthoritySet
	}
	ap := envelope.AuthorityScopeAuthority
	return envelope.NewEntry(envelope.ControlHeader{
		SignerDID:        p.SignerDID,
		TargetRoot:       &p.ScopePosition,
		AuthorityPath:    &ap,
		ScopePointer:     &p.ScopePosition,
		AuthoritySet:     p.NewAuthoritySet,
		PriorAuthority:   p.PriorAuthority,
		ApprovalPointers: p.ApprovalPointers,
		SchemaRef:        p.SchemaRef,
		EventTime:        p.EventTime,
	}, p.Payload)
}

// ─────────────────────────────────────────────────────────────────────
// 11. BuildScopeRemoval — removes authority from a scope (Path C)
// ─────────────────────────────────────────────────────────────────────

// BuildScopeRemovalParams configures a scope removal entry.
type BuildScopeRemovalParams struct {
	SignerDID      string
	ScopePosition  types.LogPosition  // The scope being modified.
	TargetEntity   types.LogPosition  // The entity affected by removal.
	PriorAuthority *types.LogPosition
	Payload        []byte
	SchemaRef      *types.LogPosition
	EventTime      int64
}

// BuildScopeRemoval creates a scope removal entry (Path C). Updates
// AuthorityTip on the target entity. Does NOT update OriginTip unless
// AuthoritySet is provided (which would make it an amendment).
func BuildScopeRemoval(p BuildScopeRemovalParams) (*envelope.Entry, error) {
	if p.SignerDID == "" {
		return nil, ErrEmptySignerDID
	}
	if p.ScopePosition.IsNull() {
		return nil, ErrMissingScopePointer
	}
	ap := envelope.AuthorityScopeAuthority
	return envelope.NewEntry(envelope.ControlHeader{
		SignerDID:      p.SignerDID,
		TargetRoot:     &p.TargetEntity,
		AuthorityPath:  &ap,
		ScopePointer:   &p.ScopePosition,
		PriorAuthority: p.PriorAuthority,
		SchemaRef:      p.SchemaRef,
		EventTime:      p.EventTime,
	}, p.Payload)
}

// ─────────────────────────────────────────────────────────────────────
// 12. BuildKeyRotation — key rotation entry (Path A)
// ─────────────────────────────────────────────────────────────────────

// BuildKeyRotationParams configures a key rotation entry.
type BuildKeyRotationParams struct {
	SignerDID  string             // Current key holder.
	TargetRoot types.LogPosition  // DID profile entity.
	SchemaRef  *types.LogPosition // Schema with maturation/activation params.
	Payload    []byte             // Contains new_key_hash or new_public_key.
	EventTime  int64
}

// BuildKeyRotation creates a key rotation entry (Path A). The entry
// targets the DID profile entity. Tier classification (2 vs 3) is
// determined by the verifier, not the builder — the builder just
// constructs the entry correctly.
func BuildKeyRotation(p BuildKeyRotationParams) (*envelope.Entry, error) {
	if p.SignerDID == "" {
		return nil, ErrEmptySignerDID
	}
	ap := envelope.AuthoritySameSigner
	return envelope.NewEntry(envelope.ControlHeader{
		SignerDID:     p.SignerDID,
		TargetRoot:    &p.TargetRoot,
		AuthorityPath: &ap,
		SchemaRef:     p.SchemaRef,
		EventTime:     p.EventTime,
	}, p.Payload)
}

// ─────────────────────────────────────────────────────────────────────
// 13. BuildKeyPrecommit — pre-commitment for key rotation (Path A)
// ─────────────────────────────────────────────────────────────────────

// BuildKeyPrecommitParams configures a key pre-commitment entry.
type BuildKeyPrecommitParams struct {
	SignerDID  string
	TargetRoot types.LogPosition // DID profile entity.
	Payload    []byte            // Contains next_key_hash.
	SchemaRef  *types.LogPosition
	EventTime  int64
}

// BuildKeyPrecommit creates a pre-commitment entry for key rotation.
// Path A: same signer amends the DID profile to include next_key_hash.
// After maturation_epoch passes, the pre-committed key can be rotated
// to at Tier 2 (immediate effect, no contest window).
func BuildKeyPrecommit(p BuildKeyPrecommitParams) (*envelope.Entry, error) {
	if p.SignerDID == "" {
		return nil, ErrEmptySignerDID
	}
	ap := envelope.AuthoritySameSigner
	return envelope.NewEntry(envelope.ControlHeader{
		SignerDID:     p.SignerDID,
		TargetRoot:    &p.TargetRoot,
		AuthorityPath: &ap,
		SchemaRef:     p.SchemaRef,
		EventTime:     p.EventTime,
	}, p.Payload)
}

// ─────────────────────────────────────────────────────────────────────
// 14. BuildRecoveryRequest — M-of-N escrow recovery request
// ─────────────────────────────────────────────────────────────────────

// BuildRecoveryRequestParams configures a recovery request entry.
type BuildRecoveryRequestParams struct {
	SignerDID string // The new exchange or recovery agent.
	Payload   []byte // Contains recovery parameters.
	EventTime int64
}

// BuildRecoveryRequest creates a commentary entry initiating key
// recovery. Escrow nodes cosign this entry (via BuildCosignature)
// to authorize reconstruction of the holder's key material.
func BuildRecoveryRequest(p BuildRecoveryRequestParams) (*envelope.Entry, error) {
	if p.SignerDID == "" {
		return nil, ErrEmptySignerDID
	}
	return envelope.NewEntry(envelope.ControlHeader{
		SignerDID: p.SignerDID,
		EventTime: p.EventTime,
	}, p.Payload)
}

// ─────────────────────────────────────────────────────────────────────
// 15. BuildMirrorEntry — cross-log mirror/relay commentary
// ─────────────────────────────────────────────────────────────────────

// BuildMirrorEntryParams configures a mirror entry.
type BuildMirrorEntryParams struct {
	SignerDID    string
	SourceLogDID string // Foreign log DID being mirrored.
	Payload      []byte // Contains source entry reference + proof data.
	EventTime    int64
}

// BuildMirrorEntry creates a commentary entry mirroring or relaying
// a foreign log entry. Used for cross-jurisdiction relays and appellate
// court references. Zero SMT impact.
func BuildMirrorEntry(p BuildMirrorEntryParams) (*envelope.Entry, error) {
	if p.SignerDID == "" {
		return nil, ErrEmptySignerDID
	}
	if p.SourceLogDID == "" {
		return nil, ErrMissingSourceLogDID
	}
	return envelope.NewEntry(envelope.ControlHeader{
		SignerDID: p.SignerDID,
		EventTime: p.EventTime,
	}, p.Payload)
}

// ─────────────────────────────────────────────────────────────────────
// 16. BuildAnchorEntry — periodic anchor commentary (Decision 44)
// ─────────────────────────────────────────────────────────────────────

// BuildAnchorEntryParams configures an anchor entry.
type BuildAnchorEntryParams struct {
	SignerDID string // Operator DID.
	Payload   []byte // Contains tree_head_ref, source_log_did, etc.
	EventTime int64
}

// BuildAnchorEntry creates a commentary entry containing a tree head
// reference for cross-log anchoring. Decision 44: anchors are standard
// entries with no special handling. Zero SMT impact.
func BuildAnchorEntry(p BuildAnchorEntryParams) (*envelope.Entry, error) {
	if p.SignerDID == "" {
		return nil, ErrEmptySignerDID
	}
	return envelope.NewEntry(envelope.ControlHeader{
		SignerDID: p.SignerDID,
		EventTime: p.EventTime,
	}, p.Payload)
}

// ─────────────────────────────────────────────────────────────────────
// 17. BuildSchemaEntry — schema definition entry
// ─────────────────────────────────────────────────────────────────────

// BuildSchemaEntryParams configures a schema entry.
type BuildSchemaEntryParams struct {
	SignerDID             string
	Payload               []byte             // JSON schema parameters.
	CommutativeOperations []uint32           // Non-empty → commutative OCC.
	PredecessorSchema     *types.LogPosition // Predecessor for succession.
	EventTime             int64
}

// BuildSchemaEntry creates a schema definition entry. The entry becomes
// an SMT leaf. Other entries reference it via Schema_Ref. The Domain
// Payload contains the 10 well-known schema parameters (activation_delay,
// cosignature_threshold, etc.) as JSON.
func BuildSchemaEntry(p BuildSchemaEntryParams) (*envelope.Entry, error) {
	if p.SignerDID == "" {
		return nil, ErrEmptySignerDID
	}
	ap := envelope.AuthoritySameSigner
	return envelope.NewEntry(envelope.ControlHeader{
		SignerDID:             p.SignerDID,
		AuthorityPath:         &ap,
		CommutativeOperations: p.CommutativeOperations,
		EventTime:             p.EventTime,
	}, p.Payload)
}

// ─────────────────────────────────────────────────────────────────────
// 18. BuildPathBEntry — entry using delegation chain (Path B)
// ─────────────────────────────────────────────────────────────────────

// BuildPathBEntryParams configures a Path B (delegated authority) entry.
type BuildPathBEntryParams struct {
	SignerDID          string              // The delegate acting on behalf of the root entity signer.
	TargetRoot         types.LogPosition   // The root entity being acted upon.
	TargetIntermediate *types.LogPosition  // Path compression (optional).
	DelegationPointers []types.LogPosition // Chain from delegate back to root signer.
	Payload            []byte
	SchemaRef          *types.LogPosition
	EvidencePointers   []types.LogPosition
	SubjectIdentifier  []byte
	EventTime          int64
}

// BuildPathBEntry creates an entry that uses delegated authority (Path B).
// The DelegationPointers must form a chain connecting the signer back
// to the root entity's signer through at most 3 hops. Each delegation
// in the chain must be "live" (OriginTip == delegation position).
func BuildPathBEntry(p BuildPathBEntryParams) (*envelope.Entry, error) {
	if p.SignerDID == "" {
		return nil, ErrEmptySignerDID
	}
	if len(p.DelegationPointers) == 0 {
		return nil, ErrEmptyDelegationChain
	}
	ap := envelope.AuthorityDelegation
	return envelope.NewEntry(envelope.ControlHeader{
		SignerDID:          p.SignerDID,
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

// ─────────────────────────────────────────────────────────────────────
// Convenience: EventTimeNow returns current UTC microseconds.
// ─────────────────────────────────────────────────────────────────────

// EventTimeNow returns the current time as microseconds since epoch,
// suitable for the EventTime field in entry builders.
func EventTimeNow() int64 {
	return time.Now().UTC().UnixMicro()
}
