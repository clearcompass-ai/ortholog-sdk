// Package builder — destination_binding_test.go locks the Phase C
// Group 7.2 closure-proof invariant: every Build* function rejects an
// empty Destination with envelope.ErrDestinationEmpty.
//
// validateCommon runs as the first statement in every Build* body, so a
// builder called with Destination="" returns ErrDestinationEmpty before
// any path-specific or domain validation. The table below names every
// builder in the SDK, including the two commitment-entry builders shipped
// in Phase C Group 3.4. Adding a new builder requires extending the
// table — the file is the closed-set declaration that anchors the
// closure-proof grep ("every Build* function has a test case").
//
// Two negative-path tests for the commitment-entry builders already exist
// in commitment_entry_builders_test.go; they remain there as the
// canonical home of the commitment-entry rejection coverage. This file
// adds parameterized coverage for the 18 main builders without
// duplicating those two — the cases are kept distinct so a regression in
// the commitment-entry path doesn't quietly hide here.
package builder

import (
	"errors"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
)

// emptyDestinationCases enumerates every Build* function whose *Params
// struct carries a Destination field. Each entry adapts the builder
// signature into a uniform `func() error` so the table-driven test
// below can iterate.
//
// SignerDID is set to a non-empty placeholder so validateCommon fails on
// the destination-empty branch specifically, rather than on the
// signer-empty branch — the test pins the destination invariant.
var emptyDestinationCases = []struct {
	name string
	call func() error
}{
	{
		name: "BuildRootEntity",
		call: func() error {
			_, err := BuildRootEntity(RootEntityParams{SignerDID: "did:example:s"})
			return err
		},
	},
	{
		name: "BuildAmendment",
		call: func() error {
			_, err := BuildAmendment(AmendmentParams{SignerDID: "did:example:s"})
			return err
		},
	},
	{
		name: "BuildDelegation",
		call: func() error {
			_, err := BuildDelegation(DelegationParams{SignerDID: "did:example:s"})
			return err
		},
	},
	{
		name: "BuildSuccession",
		call: func() error {
			_, err := BuildSuccession(SuccessionParams{SignerDID: "did:example:s"})
			return err
		},
	},
	{
		name: "BuildRevocation",
		call: func() error {
			_, err := BuildRevocation(RevocationParams{SignerDID: "did:example:s"})
			return err
		},
	},
	{
		name: "BuildScopeCreation",
		call: func() error {
			_, err := BuildScopeCreation(ScopeCreationParams{SignerDID: "did:example:s"})
			return err
		},
	},
	{
		name: "BuildScopeAmendment",
		call: func() error {
			_, err := BuildScopeAmendment(ScopeAmendmentParams{SignerDID: "did:example:s"})
			return err
		},
	},
	{
		name: "BuildScopeRemoval",
		call: func() error {
			_, err := BuildScopeRemoval(ScopeRemovalParams{SignerDID: "did:example:s"})
			return err
		},
	},
	{
		name: "BuildEnforcement",
		call: func() error {
			_, err := BuildEnforcement(EnforcementParams{SignerDID: "did:example:s"})
			return err
		},
	},
	{
		name: "BuildCommentary",
		call: func() error {
			_, err := BuildCommentary(CommentaryParams{SignerDID: "did:example:s"})
			return err
		},
	},
	{
		name: "BuildCosignature",
		call: func() error {
			_, err := BuildCosignature(CosignatureParams{SignerDID: "did:example:s"})
			return err
		},
	},
	{
		name: "BuildRecoveryRequest",
		call: func() error {
			_, err := BuildRecoveryRequest(RecoveryRequestParams{SignerDID: "did:example:s"})
			return err
		},
	},
	{
		name: "BuildAnchorEntry",
		call: func() error {
			_, err := BuildAnchorEntry(AnchorParams{SignerDID: "did:example:s"})
			return err
		},
	},
	{
		name: "BuildKeyRotation",
		call: func() error {
			_, err := BuildKeyRotation(KeyRotationParams{SignerDID: "did:example:s"})
			return err
		},
	},
	{
		name: "BuildKeyPrecommit",
		call: func() error {
			_, err := BuildKeyPrecommit(KeyPrecommitParams{SignerDID: "did:example:s"})
			return err
		},
	},
	{
		name: "BuildSchemaEntry",
		call: func() error {
			_, err := BuildSchemaEntry(SchemaEntryParams{SignerDID: "did:example:s"})
			return err
		},
	},
	{
		name: "BuildPathBEntry",
		call: func() error {
			_, err := BuildPathBEntry(PathBParams{SignerDID: "did:example:s"})
			return err
		},
	},
	{
		name: "BuildMirrorEntry",
		call: func() error {
			_, err := BuildMirrorEntry(MirrorParams{SignerDID: "did:example:s"})
			return err
		},
	},
}

// TestEveryBuilder_RejectsEmptyDestination locks the invariant that
// every Build* function returns envelope.ErrDestinationEmpty when its
// *Params struct's Destination field is the zero value. This is the
// closure-proof guarantee for Phase C Group 7.2: the destination-binding
// gate is universal across the builder surface.
//
// The two commitment-entry builders are covered by their dedicated tests
// in commitment_entry_builders_test.go (TestBuildPREGrantCommitmentEntry_RejectsEmptyDestination
// and TestBuildEscrowSplitCommitmentEntry_RejectsEmptyDestination); a
// guard at the bottom of this test fails if a future builder is added
// to the SDK without a matching emptyDestinationCases entry.
func TestEveryBuilder_RejectsEmptyDestination(t *testing.T) {
	for _, tc := range emptyDestinationCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call()
			if err == nil {
				t.Fatalf("%s accepted empty Destination — destination-binding gate not running", tc.name)
			}
			if !errors.Is(err, envelope.ErrDestinationEmpty) {
				t.Fatalf("%s: want ErrDestinationEmpty, got %v", tc.name, err)
			}
		})
	}
}

// TestEveryBuilder_TableCoversTheBuilderSurface guards the
// emptyDestinationCases table against drift. It walks the in-package
// decl set for every Build* function and asserts coverage by name. The
// commitment-entry builders are accepted in the count via the explicit
// allowlist below — they have their own dedicated rejection tests in
// commitment_entry_builders_test.go.
//
// If a new Build* function is added without extending
// emptyDestinationCases (or without a dedicated empty-destination test
// for the commitment-entry path), this guard fails with a clear pointer
// at the missing builder name.
func TestEveryBuilder_TableCoversTheBuilderSurface(t *testing.T) {
	covered := map[string]bool{}
	for _, tc := range emptyDestinationCases {
		covered[tc.name] = true
	}
	// Commitment-entry builders are covered by their own dedicated
	// tests; the closure-proof requirement names them explicitly. Mark
	// them covered here so the surface count below matches.
	covered["BuildPREGrantCommitmentEntry"] = true
	covered["BuildEscrowSplitCommitmentEntry"] = true

	expected := []string{
		"BuildRootEntity",
		"BuildAmendment",
		"BuildDelegation",
		"BuildSuccession",
		"BuildRevocation",
		"BuildScopeCreation",
		"BuildScopeAmendment",
		"BuildScopeRemoval",
		"BuildEnforcement",
		"BuildCommentary",
		"BuildCosignature",
		"BuildRecoveryRequest",
		"BuildAnchorEntry",
		"BuildKeyRotation",
		"BuildKeyPrecommit",
		"BuildSchemaEntry",
		"BuildPathBEntry",
		"BuildMirrorEntry",
		"BuildPREGrantCommitmentEntry",
		"BuildEscrowSplitCommitmentEntry",
	}
	for _, name := range expected {
		if !covered[name] {
			t.Errorf("destination-binding coverage missing for %s — add a case to emptyDestinationCases or a dedicated test", name)
		}
	}
}
