/*
Package lifecycle — scope_governance.go implements the three-phase scope
amendment lifecycle from the governance design document.

Three phases:
  Phase 1 — Proposal: any scope authority publishes a commentary entry
  Phase 2 — Approvals: authorities publish cosignature entries
  Phase 3 — Execution: once unanimity (or N-1 for removal) is met,
    any authority publishes the execution entry

Scope operations:
  ProposeAmendment → CollectApprovals → ExecuteAmendment
  ProposeRemoval   → CollectApprovals → ExecuteRemoval (with time-lock)

The time-lock mechanism:
  Default 90 days for N-1 scope removal.
  Reduced to 7 days with objective triggers (proven equivocation,
  missed SLA attestations, builder-rejected unauthorized actions,
  escrow node fire drill non-response within SLA window).

Consumed by:
  - judicial-network/consortium/scope_governance.go
  - Domain governance tooling
  - Consortium management
*/
package lifecycle

import (
	"fmt"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────

const (
	// DefaultRemovalTimeLock is the default time-lock for N-1 scope removal.
	DefaultRemovalTimeLock = 90 * 24 * time.Hour // 90 days.

	// ReducedRemovalTimeLock is the time-lock with objective triggers.
	ReducedRemovalTimeLock = 7 * 24 * time.Hour // 7 days.
)

// ObjectiveTrigger identifies a type of provable misbehavior that
// qualifies for the reduced time-lock.
type ObjectiveTrigger string

const (
	// TriggerEquivocation: two valid cosigned heads, same size, different roots.
	TriggerEquivocation ObjectiveTrigger = "proven_equivocation"

	// TriggerMissedSLA: monitoring attestation of consecutive SLA failures.
	TriggerMissedSLA ObjectiveTrigger = "missed_sla_attestations"

	// TriggerUnauthorizedAction: documented Path D rejections.
	TriggerUnauthorizedAction ObjectiveTrigger = "builder_rejected_unauthorized"

	// TriggerEscrowLiveness: escrow node fire drill non-response within SLA
	// window (applies when recovery.go is in use).
	TriggerEscrowLiveness ObjectiveTrigger = "escrow_node_liveness_failure"
)

// ─────────────────────────────────────────────────────────────────────
// ProposalType — typed enum (Wave 2)
// ─────────────────────────────────────────────────────────────────────
//
// ProposalType classifies a scope amendment proposal for the SDK's
// unanimity-vs-N-1 routing. The SDK recognizes only protocol-level
// proposal types; domain-specific proposal types (e.g., "add_access_tier"
// in the judicial network) are encoded in the Domain Payload and do not
// change SDK routing.
//
// Before Wave 2, ProposalType was a free-form string with a documented
// set of allowed values and a branch (`!= "remove_authority"`) that
// silently routed typos and domain-specific strings to unanimity. The
// typed enum makes the routing exhaustive: every value is a declared
// constant, and domain-specific types route explicitly via
// ProposalDomainExtension.
//
// Same typed-enum pattern as ObjectiveTrigger (above), MigrationPolicyType,
// and GrantAuthorizationMode.

type ProposalType uint8

const (
	// ProposalAddAuthority adds a DID to the scope's Authority_Set.
	// Requires unanimity of existing authorities.
	ProposalAddAuthority ProposalType = 1

	// ProposalRemoveAuthority removes a DID from Authority_Set.
	// Requires N-1 approvals (the target cannot block its own removal).
	ProposalRemoveAuthority ProposalType = 2

	// ProposalChangeParameters modifies scope parameters without
	// membership change. Requires unanimity.
	ProposalChangeParameters ProposalType = 3

	// ProposalDomainExtension is a catch-all for domain-specific
	// proposal types that require unanimity but carry their specific
	// semantics in Domain Payload. The SDK treats this as unanimity
	// but does not otherwise interpret the proposal.
	//
	// Judicial network proposal types like "add_access_tier" route
	// through this value — the tier name is recorded in ProposalPayload
	// or Description, and the SDK's unanimity routing applies.
	ProposalDomainExtension ProposalType = 4
)

// String returns the canonical snake_case label for a ProposalType.
// Used when serializing the proposal commentary's Domain Payload so the
// wire format remains string-based (readable by monitoring tools and
// non-Go consumers) even though the in-memory type is enum-based.
func (pt ProposalType) String() string {
	switch pt {
	case ProposalAddAuthority:
		return "add_authority"
	case ProposalRemoveAuthority:
		return "remove_authority"
	case ProposalChangeParameters:
		return "change_parameters"
	case ProposalDomainExtension:
		return "domain_extension"
	default:
		return "unknown"
	}
}

// ─────────────────────────────────────────────────────────────────────
// Phase 1: Proposal
// ─────────────────────────────────────────────────────────────────────

// AmendmentProposalParams configures a scope amendment proposal.
type AmendmentProposalParams struct {
	// ProposerDID is the scope authority proposing the change.
	ProposerDID string

	// ProposalType classifies the change for unanimity-vs-N-1 routing.
	// Use ProposalDomainExtension for domain-specific proposal types;
	// encode the domain-specific label in Description or ProposalPayload.
	ProposalType ProposalType

	// Description is a human-readable description of the proposed change.
	Description string

	// NewAuthoritySet is the proposed Authority_Set (for add/remove).
	// Nil for parameter-only changes.
	NewAuthoritySet map[string]struct{}

	// TargetDID is the DID being added or removed (for add/remove).
	// Empty for parameter changes.
	TargetDID string

	// ProposalPayload is additional domain-specific proposal data.
	ProposalPayload []byte

	EventTime int64
}

// AmendmentProposal holds the proposal entry and metadata.
type AmendmentProposal struct {
	// Entry is the commentary entry to submit to the operator.
	Entry *envelope.Entry

	// ProposalType is the enum classifier for this proposal.
	ProposalType ProposalType

	// RequiresUnanimity is true for add_authority, change_parameters,
	// and domain_extension. False only for remove_authority (N-1).
	RequiresUnanimity bool
}

// ProposeAmendment creates a Phase 1 proposal commentary entry.
// The proposal does not update the SMT (Target_Root is null, no
// Authority_Path). It's a commentary entry announcing intent.
func ProposeAmendment(p AmendmentProposalParams) (*AmendmentProposal, error) {
	if p.ProposerDID == "" {
		return nil, fmt.Errorf("lifecycle/scope: empty proposer DID")
	}

	eventTime := p.EventTime
	if eventTime == 0 {
		eventTime = time.Now().UTC().UnixMicro()
	}

	// The proposal_type string on the wire is the enum's canonical label.
	// Monitoring tools and non-Go consumers continue to see human-readable
	// strings; only the typed enum is the in-memory representation.
	payload := map[string]any{
		"proposal_type": p.ProposalType.String(),
		"description":   p.Description,
	}
	if p.TargetDID != "" {
		payload["target_did"] = p.TargetDID
	}
	if p.NewAuthoritySet != nil {
		dids := make([]string, 0, len(p.NewAuthoritySet))
		for did := range p.NewAuthoritySet {
			dids = append(dids, did)
		}
		payload["proposed_authority_set"] = dids
	}

	finalPayload := p.ProposalPayload
	if finalPayload == nil {
		finalPayload = mustMarshalJSON(payload)
	}

	entry, err := builder.BuildCommentary(builder.CommentaryParams{
		SignerDID: p.ProposerDID,
		Payload:   finalPayload,
		EventTime: eventTime,
	})
	if err != nil {
		return nil, fmt.Errorf("lifecycle/scope: build proposal: %w", err)
	}

	// Only ProposalRemoveAuthority uses the N-1 rule. Everything else —
	// add, change_parameters, domain_extension, and any unrecognized
	// future constant — requires unanimity. The conservative default
	// matches the pre-Wave-2 branch `!= "remove_authority"` exactly.
	requiresUnanimity := p.ProposalType != ProposalRemoveAuthority

	return &AmendmentProposal{
		Entry:             entry,
		ProposalType:      p.ProposalType,
		RequiresUnanimity: requiresUnanimity,
	}, nil
}

// ─────────────────────────────────────────────────────────────────────
// Phase 2: Approvals
// ─────────────────────────────────────────────────────────────────────

// CosignatureQuerier discovers cosignatures by the entry they reference.
// Satisfied by log.OperatorQueryAPI.QueryByCosignatureOf (structural typing).
type CosignatureQuerier interface {
	QueryByCosignatureOf(pos types.LogPosition) ([]types.EntryWithMetadata, error)
}

// ApprovalStatus holds the current state of approval collection.
type ApprovalStatus struct {
	// ProposalPos is the position of the proposal entry.
	ProposalPos types.LogPosition

	// TotalAuthorities is the size of the current Authority_Set.
	TotalAuthorities int

	// ApprovalCount is the number of unique valid cosignatures.
	ApprovalCount int

	// ApproverDIDs lists the DIDs that have approved.
	ApproverDIDs []string

	// RequiredCount is the number of approvals needed:
	// Unanimity (all) for amendments, N-1 for removals.
	RequiredCount int

	// Sufficient is true when ApprovalCount >= RequiredCount.
	Sufficient bool

	// ApprovalPositions are the log positions of the cosignature entries.
	// Used as Approval_Pointers in the execution entry.
	ApprovalPositions []types.LogPosition
}

// CollectApprovalsParams configures approval collection.
type CollectApprovalsParams struct {
	// ProposalPos is the position of the proposal entry.
	ProposalPos types.LogPosition

	// CurrentAuthoritySet is the scope's current Authority_Set.
	// The caller reads this from the scope entity via the fetcher.
	CurrentAuthoritySet map[string]struct{}

	// Querier discovers cosignature entries.
	Querier CosignatureQuerier

	// RequiresUnanimity is true for add/change, false for removal.
	RequiresUnanimity bool

	// ProposerDID is excluded from the required approvers
	// (the proposer's intent is implicit in the proposal).
	ProposerDID string
}

// CollectApprovals queries for cosignature entries and determines
// whether the approval threshold is met.
//
// The caller provides the current Authority_Set. For unanimity, every
// authority except the proposer must cosign. For N-1 removal, all
// authorities except the target must cosign.
func CollectApprovals(p CollectApprovalsParams) (*ApprovalStatus, error) {
	if p.Querier == nil {
		return nil, fmt.Errorf("lifecycle/scope: nil cosignature querier")
	}

	cosigs, err := p.Querier.QueryByCosignatureOf(p.ProposalPos)
	if err != nil {
		return nil, fmt.Errorf("lifecycle/scope: query cosignatures: %w", err)
	}

	totalAuth := len(p.CurrentAuthoritySet)
	status := &ApprovalStatus{
		ProposalPos:      p.ProposalPos,
		TotalAuthorities: totalAuth,
	}

	// Count required approvals.
	if p.RequiresUnanimity {
		// All authorities must approve (proposer's intent is implicit).
		status.RequiredCount = totalAuth - 1 // Exclude proposer.
	} else {
		// N-1 for removal: all except the target.
		status.RequiredCount = totalAuth - 1
	}
	if status.RequiredCount < 1 {
		status.RequiredCount = 1
	}

	// Count valid approvals.
	seen := make(map[string]bool)
	// Proposer's intent counts as implicit approval.
	if p.ProposerDID != "" {
		seen[p.ProposerDID] = true
	}

	for _, meta := range cosigs {
		entry, desErr := envelope.Deserialize(meta.CanonicalBytes)
		if desErr != nil {
			continue
		}
		signerDID := entry.Header.SignerDID

		// Must be a current authority.
		if _, inSet := p.CurrentAuthoritySet[signerDID]; !inSet {
			continue
		}

		// Skip duplicates.
		if seen[signerDID] {
			continue
		}
		seen[signerDID] = true

		status.ApproverDIDs = append(status.ApproverDIDs, signerDID)
		status.ApprovalPositions = append(status.ApprovalPositions, meta.Position)
		status.ApprovalCount++
	}

	status.Sufficient = status.ApprovalCount >= status.RequiredCount
	return status, nil
}

// ─────────────────────────────────────────────────────────────────────
// Phase 3: Execution — Amendment
// ─────────────────────────────────────────────────────────────────────

// ExecuteAmendmentParams configures the amendment execution entry.
type ExecuteAmendmentParams struct {
	// ExecutorDID is any authority executing the amendment.
	ExecutorDID string

	// ScopePos is the position of the scope entity (self-referencing).
	ScopePos types.LogPosition

	// NewAuthoritySet is the updated Authority_Set.
	NewAuthoritySet map[string]struct{}

	// ApprovalPositions are the Approval_Pointers from CollectApprovals.
	ApprovalPositions []types.LogPosition

	// PriorAuthority is the current Authority_Tip for OCC.
	// Nil if this is the first amendment (Authority_Tip == self).
	PriorAuthority *types.LogPosition

	// SchemaRef is the governing schema for this scope.
	SchemaRef *types.LogPosition

	// Payload is additional Domain Payload for the amendment.
	Payload []byte

	EventTime int64
}

// ExecuteAmendment creates a Phase 3 execution entry for a scope amendment.
// The entry has Target_Root = Scope_Pointer = ScopePos (self-referencing),
// Authority_Set carries the new set, and Approval_Pointers reference all
// cosignature entries.
//
// The builder processes this as Path C with the lane selection rule:
// ScopePointer == TargetRoot AND AuthoritySet present → OriginTip update
// (membership change, not enforcement).
func ExecuteAmendment(p ExecuteAmendmentParams) (*envelope.Entry, error) {
	if p.ExecutorDID == "" {
		return nil, fmt.Errorf("lifecycle/scope: empty executor DID")
	}
	if p.ScopePos.IsNull() {
		return nil, fmt.Errorf("lifecycle/scope: null scope position")
	}
	if len(p.NewAuthoritySet) == 0 {
		return nil, fmt.Errorf("lifecycle/scope: empty new authority set")
	}

	eventTime := p.EventTime
	if eventTime == 0 {
		eventTime = time.Now().UTC().UnixMicro()
	}

	return builder.BuildScopeAmendment(builder.ScopeAmendmentParams{
		SignerDID:        p.ExecutorDID,
		TargetRoot:       p.ScopePos,
		ScopePointer:     p.ScopePos,
		NewAuthoritySet:  p.NewAuthoritySet,
		PriorAuthority:   p.PriorAuthority,
		ApprovalPointers: p.ApprovalPositions,
		Payload:          p.Payload,
		SchemaRef:        p.SchemaRef,
		EventTime:        eventTime,
	})
}

// ─────────────────────────────────────────────────────────────────────
// Phase 3: Execution — Removal (with time-lock)
// ─────────────────────────────────────────────────────────────────────

// RemovalParams configures an N-1 scope removal execution.
type RemovalParams struct {
	// ExecutorDID is any authority (other than the target) executing removal.
	ExecutorDID string

	// ScopePos is the scope entity position.
	ScopePos types.LogPosition

	// TargetDID is the authority being removed.
	TargetDID string

	// ApprovalPositions from CollectApprovals.
	ApprovalPositions []types.LogPosition

	// PriorAuthority for OCC.
	PriorAuthority *types.LogPosition

	// ObjectiveTriggers are positions of on-log evidence proving misbehavior.
	// If present and valid, the time-lock reduces from 90 to 7 days.
	ObjectiveTriggers []types.LogPosition

	// TriggerType identifies the type of objective trigger.
	TriggerType ObjectiveTrigger

	EventTime int64
}

// RemovalExecution holds the removal entry and time-lock metadata.
type RemovalExecution struct {
	// RemovalEntry is the scope removal entry (Path C, no AuthoritySet).
	// The builder processes this as Path C enforcement → AuthorityTip update.
	RemovalEntry *envelope.Entry

	// TimeLock is the mandatory waiting period before activation.
	TimeLock time.Duration

	// ActivationAt is the earliest time the removal can activate.
	// The caller must not publish the activation entry before this time.
	ActivationAt time.Time

	// HasObjectiveTrigger is true when valid triggers reduced the time-lock.
	HasObjectiveTrigger bool
}

// ExecuteRemoval creates a scope removal entry with time-lock calculation.
// N-1 removal: all authorities except the target must have approved.
//
// The removal entry is published immediately but enters a pending state.
// The activation entry cannot be published before TimeLock elapses.
// During the time-lock window, the targeted authority:
//  - Remains in the active Authority_Set
//  - Can sign Path C actions
//  - Can publish contest entries
func ExecuteRemoval(p RemovalParams) (*RemovalExecution, error) {
	if p.ExecutorDID == "" {
		return nil, fmt.Errorf("lifecycle/scope: empty executor DID")
	}
	if p.ScopePos.IsNull() {
		return nil, fmt.Errorf("lifecycle/scope: null scope position")
	}

	eventTime := p.EventTime
	if eventTime == 0 {
		eventTime = time.Now().UTC().UnixMicro()
	}

	// Build scope removal entry (Path C, no AuthoritySet → AuthorityTip update).
	payload := map[string]any{
		"removal_type": "scope_authority_removal",
		"target_did":   p.TargetDID,
	}
	if p.TriggerType != "" {
		payload["objective_trigger"] = string(p.TriggerType)
	}

	removalEntry, err := builder.BuildScopeRemoval(builder.ScopeRemovalParams{
		SignerDID:      p.ExecutorDID,
		TargetRoot:     p.ScopePos,
		ScopePointer:   p.ScopePos,
		PriorAuthority: p.PriorAuthority,
		Payload:        mustMarshalJSON(payload),
		EventTime:      eventTime,
	})
	if err != nil {
		return nil, fmt.Errorf("lifecycle/scope: build removal: %w", err)
	}

	// Calculate time-lock.
	timeLock := DefaultRemovalTimeLock
	hasObjective := false
	if len(p.ObjectiveTriggers) > 0 && p.TriggerType != "" {
		timeLock = ReducedRemovalTimeLock
		hasObjective = true
	}

	activationAt := time.UnixMicro(eventTime).Add(timeLock)

	return &RemovalExecution{
		RemovalEntry:        removalEntry,
		TimeLock:            timeLock,
		ActivationAt:        activationAt,
		HasObjectiveTrigger: hasObjective,
	}, nil
}

// ─────────────────────────────────────────────────────────────────────
// Removal Activation (after time-lock elapses)
// ─────────────────────────────────────────────────────────────────────

// ActivateRemovalParams configures the activation entry for a removal.
type ActivateRemovalParams struct {
	// ExecutorDID is the authority publishing the activation.
	ExecutorDID string

	// ScopePos is the scope entity position.
	ScopePos types.LogPosition

	// NewAuthoritySet is the Authority_Set with the target removed.
	NewAuthoritySet map[string]struct{}

	// RemovalEntryPos is the position of the removal entry.
	RemovalEntryPos types.LogPosition

	// EvidencePointers references the removal entry, all approval
	// cosignatures, and any objective trigger evidence.
	EvidencePointers []types.LogPosition

	// PriorAuthority for OCC.
	PriorAuthority *types.LogPosition

	EventTime int64
}

// ActivateRemoval creates the activation entry that finalizes a scope
// removal after the time-lock has elapsed.
//
// The caller MUST verify:
//  1. The time-lock has elapsed (compare now against RemovalExecution.ActivationAt)
//  2. No unresolved contest exists (check via verifier.EvaluateContest)
//  3. All Evidence_Pointers are valid
//
// The builder processes this as Path C with AuthoritySet present →
// OriginTip update (the removal activation changes membership).
func ActivateRemoval(p ActivateRemovalParams) (*envelope.Entry, error) {
	if p.ExecutorDID == "" {
		return nil, fmt.Errorf("lifecycle/scope: empty executor DID")
	}

	eventTime := p.EventTime
	if eventTime == 0 {
		eventTime = time.Now().UTC().UnixMicro()
	}

	return builder.BuildScopeAmendment(builder.ScopeAmendmentParams{
		SignerDID:        p.ExecutorDID,
		TargetRoot:       p.ScopePos,
		ScopePointer:     p.ScopePos,
		NewAuthoritySet:  p.NewAuthoritySet,
		PriorAuthority:   p.PriorAuthority,
		ApprovalPointers: p.EvidencePointers,
		Payload: mustMarshalJSON(map[string]any{
			"activation_type": "removal_activation",
			"removal_entry":   p.RemovalEntryPos.String(),
		}),
		EventTime: eventTime,
	})
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

// BuildApprovalCosignature creates a cosignature entry for a proposal.
// Convenience wrapper around builder.BuildCosignature.
func BuildApprovalCosignature(signerDID string, proposalPos types.LogPosition, eventTime int64) (*envelope.Entry, error) {
	if eventTime == 0 {
		eventTime = time.Now().UTC().UnixMicro()
	}
	return builder.BuildCosignature(builder.CosignatureParams{
		SignerDID:     signerDID,
		CosignatureOf: proposalPos,
		EventTime:     eventTime,
	})
}

// ComputeRemovedSet removes a DID from an Authority_Set.
// Returns the new set. Does not modify the input.
func ComputeRemovedSet(currentSet map[string]struct{}, targetDID string) map[string]struct{} {
	newSet := make(map[string]struct{}, len(currentSet)-1)
	for did := range currentSet {
		if did != targetDID {
			newSet[did] = struct{}{}
		}
	}
	return newSet
}

// ComputeAddedSet adds a DID to an Authority_Set.
// Returns the new set. Does not modify the input.
func ComputeAddedSet(currentSet map[string]struct{}, newDID string) map[string]struct{} {
	newSet := make(map[string]struct{}, len(currentSet)+1)
	for did := range currentSet {
		newSet[did] = struct{}{}
	}
	newSet[newDID] = struct{}{}
	return newSet
}
