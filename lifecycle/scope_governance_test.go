// Package lifecycle — scope_governance_test.go tests the three-phase
// scope amendment lifecycle: proposal routing, approval math
// (including N-1 removal semantics), execution validation, and
// helper purity.
//
// Removal-path coverage is particularly load-bearing: the N-1 math
// must reach Sufficient=true under honest cosignatures (target
// abstains, non-target authorities approve), must credit the
// proposer's implicit approval, and must ignore adversarial
// target-self-cosigns.
package lifecycle

import (
	"testing"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// -------------------------------------------------------------------------------------------------
// Shared fixtures
// -------------------------------------------------------------------------------------------------

// proposalPos returns a non-null test LogPosition for use as
// ProposalPos. Tests that need multiple distinct positions bump the
// sequence number.
func proposalPos(sequence uint64) types.LogPosition {
	return types.LogPosition{
		LogDID:   "did:web:test-log",
		Sequence: sequence,
	}
}

// cosigQuerierWithDIDs returns a stub CosignatureQuerier that serves
// cosignature entries signed by the given DIDs, each referencing
// proposalPos as their cosignature target.
func cosigQuerierWithDIDs(t *testing.T, signerDIDs []string, target types.LogPosition) CosignatureQuerier {
	t.Helper()
	entries := make([]types.EntryWithMetadata, 0, len(signerDIDs))
	for _, did := range signerDIDs {
		entries = append(entries, buildCosigMeta(t, did, &target))
	}
	return &stubCosignatureQuerier{entries: entries}
}

// -------------------------------------------------------------------------------------------------
// ProposalType enum
// -------------------------------------------------------------------------------------------------

func TestProposalType_StringValues(t *testing.T) {
	cases := []struct {
		pt   ProposalType
		want string
	}{
		{ProposalAddAuthority, "add_authority"},
		{ProposalRemoveAuthority, "remove_authority"},
		{ProposalChangeParameters, "change_parameters"},
		{ProposalDomainExtension, "domain_extension"},
		{ProposalType(99), "unknown"},
	}
	for _, c := range cases {
		if got := c.pt.String(); got != c.want {
			t.Errorf("ProposalType(%d).String() = %q, want %q", c.pt, got, c.want)
		}
	}
}

func TestProposalType_DistinctNumericValues(t *testing.T) {
	pts := []ProposalType{
		ProposalAddAuthority,
		ProposalRemoveAuthority,
		ProposalChangeParameters,
		ProposalDomainExtension,
	}
	seen := map[ProposalType]bool{}
	for _, p := range pts {
		if seen[p] {
			t.Fatalf("ProposalType %d is duplicated in the constant set", p)
		}
		seen[p] = true
	}
}

// -------------------------------------------------------------------------------------------------
// Constants
// -------------------------------------------------------------------------------------------------

func TestRemovalTimeLock_Constants(t *testing.T) {
	if DefaultRemovalTimeLock != 90*24*time.Hour {
		t.Errorf("DefaultRemovalTimeLock = %v, want 90 days", DefaultRemovalTimeLock)
	}
	if ReducedRemovalTimeLock != 7*24*time.Hour {
		t.Errorf("ReducedRemovalTimeLock = %v, want 7 days", ReducedRemovalTimeLock)
	}
	if ReducedRemovalTimeLock >= DefaultRemovalTimeLock {
		t.Error("ReducedRemovalTimeLock must be shorter than DefaultRemovalTimeLock")
	}
}

func TestObjectiveTrigger_Values(t *testing.T) {
	if string(TriggerEquivocation) != "proven_equivocation" {
		t.Errorf("TriggerEquivocation = %q, want proven_equivocation", TriggerEquivocation)
	}
	if string(TriggerMissedSLA) != "missed_sla_attestations" {
		t.Errorf("TriggerMissedSLA = %q, want missed_sla_attestations", TriggerMissedSLA)
	}
	if string(TriggerUnauthorizedAction) != "builder_rejected_unauthorized" {
		t.Errorf("TriggerUnauthorizedAction = %q, want builder_rejected_unauthorized", TriggerUnauthorizedAction)
	}
	if string(TriggerEscrowLiveness) != "escrow_node_liveness_failure" {
		t.Errorf("TriggerEscrowLiveness = %q, want escrow_node_liveness_failure", TriggerEscrowLiveness)
	}
}

// -------------------------------------------------------------------------------------------------
// ProposeAmendment — validation and unanimity routing
// -------------------------------------------------------------------------------------------------

func TestProposeAmendment_RejectsEmptyDestination(t *testing.T) {
	_, err := ProposeAmendment(AmendmentProposalParams{
		ProposerDID:  "did:web:proposer.test",
		ProposalType: ProposalAddAuthority,
	})
	if err == nil {
		t.Fatal("expected error for empty Destination, got nil")
	}
}

func TestProposeAmendment_RejectsEmptyProposerDID(t *testing.T) {
	_, err := ProposeAmendment(AmendmentProposalParams{
		Destination:  testDestination,
		ProposalType: ProposalAddAuthority,
	})
	if err == nil {
		t.Fatal("expected error for empty ProposerDID, got nil")
	}
}

func TestProposeAmendment_AddAuthorityRequiresUnanimity(t *testing.T) {
	prop, err := ProposeAmendment(AmendmentProposalParams{
		Destination:  testDestination,
		ProposerDID:  "did:web:proposer.test",
		ProposalType: ProposalAddAuthority,
		TargetDID:    "did:web:newbie.test",
	})
	if err != nil {
		t.Fatalf("ProposeAmendment: %v", err)
	}
	if !prop.RequiresUnanimity {
		t.Error("ProposalAddAuthority must require unanimity")
	}
	if prop.Entry == nil {
		t.Error("Entry is nil")
	}
	if prop.ProposalType != ProposalAddAuthority {
		t.Errorf("ProposalType = %d, want ProposalAddAuthority", prop.ProposalType)
	}
}

func TestProposeAmendment_RemoveAuthorityUsesNMinusOne(t *testing.T) {
	prop, err := ProposeAmendment(AmendmentProposalParams{
		Destination:  testDestination,
		ProposerDID:  "did:web:proposer.test",
		ProposalType: ProposalRemoveAuthority,
		TargetDID:    "did:web:target.test",
	})
	if err != nil {
		t.Fatalf("ProposeAmendment: %v", err)
	}
	if prop.RequiresUnanimity {
		t.Error("ProposalRemoveAuthority must NOT require unanimity (N-1 rule)")
	}
}

func TestProposeAmendment_ChangeParametersRequiresUnanimity(t *testing.T) {
	prop, err := ProposeAmendment(AmendmentProposalParams{
		Destination:  testDestination,
		ProposerDID:  "did:web:proposer.test",
		ProposalType: ProposalChangeParameters,
	})
	if err != nil {
		t.Fatalf("ProposeAmendment: %v", err)
	}
	if !prop.RequiresUnanimity {
		t.Error("ProposalChangeParameters must require unanimity")
	}
}

func TestProposeAmendment_DomainExtensionRequiresUnanimity(t *testing.T) {
	prop, err := ProposeAmendment(AmendmentProposalParams{
		Destination:  testDestination,
		ProposerDID:  "did:web:proposer.test",
		ProposalType: ProposalDomainExtension,
	})
	if err != nil {
		t.Fatalf("ProposeAmendment: %v", err)
	}
	if !prop.RequiresUnanimity {
		t.Error("ProposalDomainExtension must require unanimity (conservative default)")
	}
}

func TestProposeAmendment_UnknownTypeDefaultsToUnanimity(t *testing.T) {
	prop, err := ProposeAmendment(AmendmentProposalParams{
		Destination:  testDestination,
		ProposerDID:  "did:web:proposer.test",
		ProposalType: ProposalType(99),
	})
	if err != nil {
		t.Fatalf("ProposeAmendment: %v", err)
	}
	if !prop.RequiresUnanimity {
		t.Error("unknown ProposalType must default to requiring unanimity")
	}
}

// -------------------------------------------------------------------------------------------------
// ComputeAddedSet / ComputeRemovedSet — helper purity
// -------------------------------------------------------------------------------------------------

func TestComputeAddedSet_AddsNewDID(t *testing.T) {
	current := map[string]struct{}{
		"did:web:a.test": {},
		"did:web:b.test": {},
	}
	newSet := ComputeAddedSet(current, "did:web:c.test")
	if len(newSet) != 3 {
		t.Fatalf("len = %d, want 3", len(newSet))
	}
	if _, ok := newSet["did:web:c.test"]; !ok {
		t.Error("new DID not in result")
	}
}

func TestComputeAddedSet_DoesNotMutateInput(t *testing.T) {
	current := map[string]struct{}{
		"did:web:a.test": {},
	}
	_ = ComputeAddedSet(current, "did:web:b.test")
	if len(current) != 1 {
		t.Fatalf("input mutated: len = %d, want 1", len(current))
	}
}

func TestComputeRemovedSet_RemovesTarget(t *testing.T) {
	current := map[string]struct{}{
		"did:web:a.test": {},
		"did:web:b.test": {},
		"did:web:c.test": {},
	}
	newSet := ComputeRemovedSet(current, "did:web:b.test")
	if len(newSet) != 2 {
		t.Fatalf("len = %d, want 2", len(newSet))
	}
	if _, ok := newSet["did:web:b.test"]; ok {
		t.Error("target DID still in result")
	}
}

func TestComputeRemovedSet_DoesNotMutateInput(t *testing.T) {
	current := map[string]struct{}{
		"did:web:a.test": {},
		"did:web:b.test": {},
	}
	_ = ComputeRemovedSet(current, "did:web:a.test")
	if _, ok := current["did:web:a.test"]; !ok {
		t.Error("input mutated: target DID removed from original")
	}
}

func TestComputeRemovedSet_TargetAbsentIsNoOp(t *testing.T) {
	current := map[string]struct{}{
		"did:web:a.test": {},
	}
	newSet := ComputeRemovedSet(current, "did:web:nonexistent.test")
	if len(newSet) != 1 {
		t.Fatalf("len = %d, want 1 (no-op when target absent)", len(newSet))
	}
}

// -------------------------------------------------------------------------------------------------
// CollectApprovals — input validation
// -------------------------------------------------------------------------------------------------

func TestCollectApprovals_RejectsNilQuerier(t *testing.T) {
	_, err := CollectApprovals(CollectApprovalsParams{
		ProposalPos:         proposalPos(1),
		CurrentAuthoritySet: map[string]struct{}{"did:web:a.test": {}},
		Querier:             nil,
	})
	if err == nil {
		t.Fatal("expected error for nil Querier, got nil")
	}
}

// Removal requires TargetDID — omitting it is a caller bug that
// must surface explicitly, not silently produce an unreachable
// approval threshold.
func TestCollectApprovals_RejectsRemovalWithoutTargetDID(t *testing.T) {
	querier := &stubCosignatureQuerier{entries: nil}
	_, err := CollectApprovals(CollectApprovalsParams{
		ProposalPos:         proposalPos(1),
		CurrentAuthoritySet: map[string]struct{}{"did:web:a.test": {}, "did:web:b.test": {}},
		Querier:             querier,
		RequiresUnanimity:   false, // removal
		ProposerDID:         "did:web:a.test",
		// TargetDID omitted
	})
	if err == nil {
		t.Fatal("expected error for removal without TargetDID, got nil")
	}
}

// Self-removal attempt: a proposer cannot propose their own removal.
func TestCollectApprovals_RejectsSelfRemoval(t *testing.T) {
	querier := &stubCosignatureQuerier{entries: nil}
	_, err := CollectApprovals(CollectApprovalsParams{
		ProposalPos:         proposalPos(1),
		CurrentAuthoritySet: map[string]struct{}{"did:web:a.test": {}, "did:web:b.test": {}},
		Querier:             querier,
		RequiresUnanimity:   false,
		ProposerDID:         "did:web:a.test",
		TargetDID:           "did:web:a.test", // same as proposer
	})
	if err == nil {
		t.Fatal("expected error for proposer==target, got nil")
	}
}

// -------------------------------------------------------------------------------------------------
// CollectApprovals — unanimity math
// -------------------------------------------------------------------------------------------------

// Unanimity: RequiredCount=N-1 (excluding proposer), ApprovalCount
// counts only non-proposer cosigs. With no cosigs, ApprovalCount=0,
// NOT sufficient.
func TestCollectApprovals_UnanimityNoCosigsIsInsufficient(t *testing.T) {
	querier := &stubCosignatureQuerier{entries: nil}
	authority := map[string]struct{}{
		"did:web:a.test": {},
		"did:web:b.test": {},
		"did:web:c.test": {},
	}
	status, err := CollectApprovals(CollectApprovalsParams{
		ProposalPos:         proposalPos(1),
		CurrentAuthoritySet: authority,
		Querier:             querier,
		RequiresUnanimity:   true,
		ProposerDID:         "did:web:a.test",
	})
	if err != nil {
		t.Fatalf("CollectApprovals: %v", err)
	}
	if status.RequiredCount != 2 {
		t.Errorf("RequiredCount = %d, want 2 (N-1 excluding proposer)", status.RequiredCount)
	}
	if status.ApprovalCount != 0 {
		t.Errorf("ApprovalCount = %d, want 0 (proposer not counted for unanimity)", status.ApprovalCount)
	}
	if status.Sufficient {
		t.Error("Sufficient = true with 0 cosigs, want false")
	}
	if status.TotalAuthorities != 3 {
		t.Errorf("TotalAuthorities = %d, want 3", status.TotalAuthorities)
	}
}

// Unanimity: with non-proposer cosigs meeting N-1, reaches sufficiency.
func TestCollectApprovals_UnanimityReachesSufficiencyWithAllCosigs(t *testing.T) {
	proposal := proposalPos(10)
	authority := map[string]struct{}{
		"did:web:a.test": {},
		"did:web:b.test": {},
		"did:web:c.test": {},
	}
	// Cosigs from B and C (not proposer A).
	querier := cosigQuerierWithDIDs(t, []string{"did:web:b.test", "did:web:c.test"}, proposal)

	status, err := CollectApprovals(CollectApprovalsParams{
		ProposalPos:         proposal,
		CurrentAuthoritySet: authority,
		Querier:             querier,
		RequiresUnanimity:   true,
		ProposerDID:         "did:web:a.test",
	})
	if err != nil {
		t.Fatalf("CollectApprovals: %v", err)
	}
	if status.ApprovalCount != 2 {
		t.Errorf("ApprovalCount = %d, want 2 (B + C)", status.ApprovalCount)
	}
	if status.RequiredCount != 2 {
		t.Errorf("RequiredCount = %d, want 2", status.RequiredCount)
	}
	if !status.Sufficient {
		t.Error("Sufficient = false with full non-proposer quorum")
	}
}

// -------------------------------------------------------------------------------------------------
// CollectApprovals — removal math (bug-catcher)
// -------------------------------------------------------------------------------------------------

// The critical bug-catcher: removal MUST reach sufficiency under
// honest cosigs (target abstains, proposer and non-target non-proposer
// authorities approve). Previously the proposer's implicit approval
// was not counted, making removal unreachable.
func TestCollectApprovals_RemovalReachesSufficiencyWithHonestCosigs(t *testing.T) {
	proposal := proposalPos(20)
	authority := map[string]struct{}{
		"did:web:a.test": {}, // proposer
		"did:web:b.test": {},
		"did:web:c.test": {},
		"did:web:d.test": {}, // target
	}
	// Honest cosigs: B and C (not D, not A).
	querier := cosigQuerierWithDIDs(t, []string{"did:web:b.test", "did:web:c.test"}, proposal)

	status, err := CollectApprovals(CollectApprovalsParams{
		ProposalPos:         proposal,
		CurrentAuthoritySet: authority,
		Querier:             querier,
		RequiresUnanimity:   false,
		ProposerDID:         "did:web:a.test",
		TargetDID:           "did:web:d.test",
	})
	if err != nil {
		t.Fatalf("CollectApprovals: %v", err)
	}
	// Expected: proposer A implicit + B explicit + C explicit = 3.
	if status.ApprovalCount != 3 {
		t.Errorf("ApprovalCount = %d, want 3 (A implicit + B + C)", status.ApprovalCount)
	}
	if status.RequiredCount != 3 {
		t.Errorf("RequiredCount = %d, want 3 (N-1)", status.RequiredCount)
	}
	if !status.Sufficient {
		t.Fatal("Sufficient = false with honest N-1 cosigs — removal pathway is broken")
	}
	// Proposer's implicit approval should appear first in ApproverDIDs.
	if len(status.ApproverDIDs) == 0 || status.ApproverDIDs[0] != "did:web:a.test" {
		t.Errorf("ApproverDIDs[0] = %v, want proposer first", status.ApproverDIDs)
	}
	// First ApprovalPosition for removal should be the proposal itself.
	if len(status.ApprovalPositions) == 0 || status.ApprovalPositions[0] != proposal {
		t.Errorf("ApprovalPositions[0] = %v, want ProposalPos", status.ApprovalPositions[0])
	}
}

// Adversarial case: target cosigns their own removal. The target's
// cosignature must be ignored — they cannot approve their own removal.
func TestCollectApprovals_RemovalIgnoresTargetCosig(t *testing.T) {
	proposal := proposalPos(21)
	authority := map[string]struct{}{
		"did:web:a.test": {},
		"did:web:b.test": {},
		"did:web:c.test": {},
		"did:web:d.test": {}, // target
	}
	// Including target's cosig in the mix.
	querier := cosigQuerierWithDIDs(t,
		[]string{"did:web:b.test", "did:web:c.test", "did:web:d.test"},
		proposal)

	status, err := CollectApprovals(CollectApprovalsParams{
		ProposalPos:         proposal,
		CurrentAuthoritySet: authority,
		Querier:             querier,
		RequiresUnanimity:   false,
		ProposerDID:         "did:web:a.test",
		TargetDID:           "did:web:d.test",
	})
	if err != nil {
		t.Fatalf("CollectApprovals: %v", err)
	}
	// Proposer A implicit + B + C = 3. Target D's cosig must NOT inflate count.
	if status.ApprovalCount != 3 {
		t.Errorf("ApprovalCount = %d, want 3 (target cosig must be ignored)", status.ApprovalCount)
	}
	for _, did := range status.ApproverDIDs {
		if did == "did:web:d.test" {
			t.Error("target DID appears in ApproverDIDs — independence violated")
		}
	}
}

// Removal: when proposer is NOT in the current authority set (edge
// case: stale proposer state), their implicit approval is not credited.
// ApprovalCount counts only explicit cosigs.
func TestCollectApprovals_RemovalProposerNotInSetIsNotCredited(t *testing.T) {
	proposal := proposalPos(22)
	authority := map[string]struct{}{
		"did:web:b.test": {},
		"did:web:c.test": {},
		"did:web:d.test": {}, // target
	}
	querier := cosigQuerierWithDIDs(t, []string{"did:web:b.test", "did:web:c.test"}, proposal)

	status, err := CollectApprovals(CollectApprovalsParams{
		ProposalPos:         proposal,
		CurrentAuthoritySet: authority,
		Querier:             querier,
		RequiresUnanimity:   false,
		ProposerDID:         "did:web:a.test", // not in authority
		TargetDID:           "did:web:d.test",
	})
	if err != nil {
		t.Fatalf("CollectApprovals: %v", err)
	}
	// Proposer not in set → not credited. ApprovalCount = 2 (B + C only).
	if status.ApprovalCount != 2 {
		t.Errorf("ApprovalCount = %d, want 2 (no proposer credit when out of set)", status.ApprovalCount)
	}
}

// Removal: partial cosigs (only 1 of 2 non-target non-proposer
// authorities cosigns) → insufficient.
func TestCollectApprovals_RemovalInsufficientWithPartialCosigs(t *testing.T) {
	proposal := proposalPos(23)
	authority := map[string]struct{}{
		"did:web:a.test": {},
		"did:web:b.test": {},
		"did:web:c.test": {},
		"did:web:d.test": {}, // target
	}
	// Only B cosigns (C abstains).
	querier := cosigQuerierWithDIDs(t, []string{"did:web:b.test"}, proposal)

	status, err := CollectApprovals(CollectApprovalsParams{
		ProposalPos:         proposal,
		CurrentAuthoritySet: authority,
		Querier:             querier,
		RequiresUnanimity:   false,
		ProposerDID:         "did:web:a.test",
		TargetDID:           "did:web:d.test",
	})
	if err != nil {
		t.Fatalf("CollectApprovals: %v", err)
	}
	// A implicit + B = 2. Required = 3.
	if status.ApprovalCount != 2 {
		t.Errorf("ApprovalCount = %d, want 2", status.ApprovalCount)
	}
	if status.RequiredCount != 3 {
		t.Errorf("RequiredCount = %d, want 3", status.RequiredCount)
	}
	if status.Sufficient {
		t.Error("Sufficient = true with 2 of 3 approvals, want false")
	}
}

// Edge case: minimum RequiredCount is 1 (single-authority scope).
func TestCollectApprovals_MinimumRequiredIsOne(t *testing.T) {
	querier := &stubCosignatureQuerier{entries: nil}
	status, err := CollectApprovals(CollectApprovalsParams{
		ProposalPos:         proposalPos(30),
		CurrentAuthoritySet: map[string]struct{}{"did:web:only.test": {}},
		Querier:             querier,
		RequiresUnanimity:   true,
		ProposerDID:         "did:web:only.test",
	})
	if err != nil {
		t.Fatalf("CollectApprovals: %v", err)
	}
	if status.RequiredCount < 1 {
		t.Errorf("RequiredCount = %d, want >= 1 (floor)", status.RequiredCount)
	}
}

// -------------------------------------------------------------------------------------------------
// ExecuteAmendment — input validation
// -------------------------------------------------------------------------------------------------

func TestExecuteAmendment_RejectsEmptyDestination(t *testing.T) {
	_, err := ExecuteAmendment(ExecuteAmendmentParams{
		ExecutorDID:     "did:web:executor.test",
		ScopePos:        proposalPos(40),
		NewAuthoritySet: map[string]struct{}{"did:web:a.test": {}},
	})
	if err == nil {
		t.Fatal("expected error for empty Destination, got nil")
	}
}

func TestExecuteAmendment_RejectsEmptyExecutorDID(t *testing.T) {
	_, err := ExecuteAmendment(ExecuteAmendmentParams{
		Destination:     testDestination,
		ScopePos:        proposalPos(41),
		NewAuthoritySet: map[string]struct{}{"did:web:a.test": {}},
	})
	if err == nil {
		t.Fatal("expected error for empty ExecutorDID, got nil")
	}
}

func TestExecuteAmendment_RejectsNullScopePosition(t *testing.T) {
	_, err := ExecuteAmendment(ExecuteAmendmentParams{
		Destination:     testDestination,
		ExecutorDID:     "did:web:executor.test",
		ScopePos:        types.LogPosition{}, // null
		NewAuthoritySet: map[string]struct{}{"did:web:a.test": {}},
	})
	if err == nil {
		t.Fatal("expected error for null ScopePos, got nil")
	}
}

func TestExecuteAmendment_RejectsEmptyAuthoritySet(t *testing.T) {
	_, err := ExecuteAmendment(ExecuteAmendmentParams{
		Destination:     testDestination,
		ExecutorDID:     "did:web:executor.test",
		ScopePos:        proposalPos(42),
		NewAuthoritySet: map[string]struct{}{},
	})
	if err == nil {
		t.Fatal("expected error for empty NewAuthoritySet, got nil")
	}
}

// -------------------------------------------------------------------------------------------------
// ExecuteRemoval — input validation and time-lock math
// -------------------------------------------------------------------------------------------------

func TestExecuteRemoval_RejectsEmptyDestination(t *testing.T) {
	_, err := ExecuteRemoval(RemovalParams{
		ExecutorDID: "did:web:executor.test",
		ScopePos:    proposalPos(50),
	})
	if err == nil {
		t.Fatal("expected error for empty Destination, got nil")
	}
}

func TestExecuteRemoval_RejectsEmptyExecutorDID(t *testing.T) {
	_, err := ExecuteRemoval(RemovalParams{
		Destination: testDestination,
		ScopePos:    proposalPos(51),
	})
	if err == nil {
		t.Fatal("expected error for empty ExecutorDID, got nil")
	}
}

func TestExecuteRemoval_RejectsNullScopePosition(t *testing.T) {
	_, err := ExecuteRemoval(RemovalParams{
		Destination: testDestination,
		ExecutorDID: "did:web:executor.test",
		ScopePos:    types.LogPosition{},
	})
	if err == nil {
		t.Fatal("expected error for null ScopePos, got nil")
	}
}

func TestExecuteRemoval_DefaultTimeLockWithoutTriggers(t *testing.T) {
	exec, err := ExecuteRemoval(RemovalParams{
		Destination: testDestination,
		ExecutorDID: "did:web:executor.test",
		ScopePos:    proposalPos(52),
		TargetDID:   "did:web:target.test",
		EventTime:   time.Now().UTC().UnixMicro(),
	})
	if err != nil {
		t.Fatalf("ExecuteRemoval: %v", err)
	}
	if exec.TimeLock != DefaultRemovalTimeLock {
		t.Errorf("TimeLock = %v, want %v (default, no triggers)", exec.TimeLock, DefaultRemovalTimeLock)
	}
	if exec.HasObjectiveTrigger {
		t.Error("HasObjectiveTrigger = true, want false (no triggers supplied)")
	}
	if exec.RemovalEntry == nil {
		t.Error("RemovalEntry is nil")
	}
}

func TestExecuteRemoval_ReducedTimeLockWithTriggers(t *testing.T) {
	// Multiple trigger positions plus non-empty TriggerType → reduced.
	triggers := []types.LogPosition{
		{LogDID: "did:web:evidence-log", Sequence: 100},
		{LogDID: "did:web:evidence-log", Sequence: 101},
	}
	exec, err := ExecuteRemoval(RemovalParams{
		Destination:       testDestination,
		ExecutorDID:       "did:web:executor.test",
		ScopePos:          proposalPos(53),
		TargetDID:         "did:web:target.test",
		ObjectiveTriggers: triggers,
		TriggerType:       TriggerEquivocation,
		EventTime:         time.Now().UTC().UnixMicro(),
	})
	if err != nil {
		t.Fatalf("ExecuteRemoval: %v", err)
	}
	if exec.TimeLock != ReducedRemovalTimeLock {
		t.Errorf("TimeLock = %v, want %v (reduced with triggers)", exec.TimeLock, ReducedRemovalTimeLock)
	}
	if !exec.HasObjectiveTrigger {
		t.Error("HasObjectiveTrigger = false, want true")
	}
}

// -------------------------------------------------------------------------------------------------
// BuildApprovalCosignature — destination validation
// -------------------------------------------------------------------------------------------------

func TestBuildApprovalCosignature_RejectsEmptyDestination(t *testing.T) {
	_, err := BuildApprovalCosignature(
		"did:web:signer.test",
		"",
		proposalPos(60),
		0,
	)
	if err == nil {
		t.Fatal("expected error for empty destination, got nil")
	}
}

// -------------------------------------------------------------------------------------------------
// ActivateRemoval — input validation
// -------------------------------------------------------------------------------------------------

func TestActivateRemoval_RejectsEmptyDestination(t *testing.T) {
	_, err := ActivateRemoval(ActivateRemovalParams{
		ExecutorDID: "did:web:executor.test",
	})
	if err == nil {
		t.Fatal("expected error for empty Destination, got nil")
	}
}

func TestActivateRemoval_RejectsEmptyExecutorDID(t *testing.T) {
	_, err := ActivateRemoval(ActivateRemovalParams{
		Destination: testDestination,
	})
	if err == nil {
		t.Fatal("expected error for empty ExecutorDID, got nil")
	}
}
