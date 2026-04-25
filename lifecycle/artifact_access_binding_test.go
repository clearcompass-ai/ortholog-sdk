// Package lifecycle — artifact_access_binding_test.go holds the
// binding tests for the lifecycle-layer mutation-audit switches
// declared in artifact_access_mutation_switches.go that don't
// already have a pre-existing test bound to them.
//
// Cross-registered existing tests cover the rest:
//
//   muEnableArtifactCommitmentRequired →
//     TestVerifyAndDecryptArtifact_PRE_MissingCommitments
//     (artifact_access_test.go)
//
//   muEnableWitnessPositionBinding →
//     TestEvaluateArbitration_RejectsUnboundWitnessCosignature
//     (recovery_test.go)
//
//   muEnableWitnessIndependence →
//     TestEvaluateArbitration_RejectsEscrowNodeAsWitness
//     (recovery_test.go)
//
// See lifecycle/artifact_access.mutation-audit.yaml for the
// full registry.
package lifecycle

import (
	"errors"
	"strings"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/escrow"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// Binding: muEnableGrantAuthorizationCheck
// ─────────────────────────────────────────────────────────────────────

// TestGrantArtifactAccess_AuthCheck_Binding pins that
// GrantArtifactAccess invokes CheckGrantAuthorization when the
// schema declares a non-open authorization mode and the granter
// fails the authorization check. The granter DID is empty (which
// CheckGrantAuthorization rejects with a clear error inside the
// scope-membership lookup), so the function returns a
// "grant denied" or "grant authorization" wrapped error.
//
// With the gate on, Phase 1 fires CheckGrantAuthorization and
// rejects. With the gate off, Phase 1 is bypassed entirely; the
// function proceeds to Phase 2 key-material production where it
// produces a different error (or, depending on grant context,
// silently succeeds with an unauthorized recipient). The error
// classification swap is the load-bearing signal.
func TestGrantArtifactAccess_AuthCheck_Binding(t *testing.T) {
	params := GrantArtifactAccessParams{
		Destination:     "did:web:example.com:exchange",
		ArtifactCID:     storage.CID{Algorithm: storage.AlgoSHA256, Digest: make([]byte, 32)},
		RecipientPubKey: make([]byte, 65),
		SchemaParams: &types.SchemaParameters{
			ArtifactEncryption:     types.EncryptionAESGCM,
			GrantAuthorizationMode: types.GrantAuthRestricted,
		},
		// GranterDID empty → CheckGrantAuthorization rejects in
		// the restricted-mode scope-membership lookup.
		GranterDID:   "",
		RecipientDID: "did:web:example.com:recipient",
	}
	_, err := GrantArtifactAccess(params)
	if err == nil {
		t.Fatal("GrantArtifactAccess accepted empty granter on restricted mode (muEnableGrantAuthorizationCheck not load-bearing?)")
	}
	// With the gate on, the rejection comes from Phase 1 and the
	// error message contains "grant authorization" or
	// "grant denied". With the gate off, Phase 1 is skipped and
	// Phase 2 fails for a different reason (key store / recipient
	// key parse). Asserting the gate-on substring keeps the
	// binding load-bearing.
	if !strings.Contains(err.Error(), "grant authorization") &&
		!strings.Contains(err.Error(), "grant denied") {
		t.Fatalf("want grant-authorization rejection, got %q", err.Error())
	}
}

// ─────────────────────────────────────────────────────────────────────
// Binding: muEnableWitnessDeserialize
// ─────────────────────────────────────────────────────────────────────

// TestEvaluateArbitration_WitnessDeserialize_Binding pins the
// gate-specific error message produced when the witness
// cosignature envelope fails to deserialize. The pre-existing
// TestEvaluateArbitration_RejectsDeserializeFailure asserts only
// OverrideAuthorized=false; with the gate off, the defensive
// nil-witnessEntry guard still rejects but with a different
// reason string ("witness cosignature is malformed"), so a
// substring assertion on "deserialize failed" is what makes the
// gate observably load-bearing.
func TestEvaluateArbitration_WitnessDeserialize_Binding(t *testing.T) {
	fx := newArbitrationFixture(t)

	garbage := &types.EntryWithMetadata{
		CanonicalBytes: []byte("not-a-valid-envelope-entry"),
	}

	result, err := EvaluateArbitration(ArbitrationParams{
		RecoveryRequestPos: fx.recoveryPos,
		EscrowApprovals:    fx.escrowApprovals,
		TotalEscrowNodes:   fx.totalEscrowNodes,
		EscrowNodeSet:      fx.escrowNodeSet,
		WitnessCosignature: garbage,
		SchemaParams:       fx.schemaParams,
	})
	if err != nil {
		t.Fatalf("EvaluateArbitration: %v", err)
	}
	if result.OverrideAuthorized {
		t.Fatal("OverrideAuthorized = true despite witness deserialize failure")
	}
	if !strings.Contains(result.Reason, "deserialize failed") {
		t.Fatalf("want gate-specific 'deserialize failed' reason, got %q (muEnableWitnessDeserialize not load-bearing?)", result.Reason)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Binding: muEnableReconstructSizeCheck
// ─────────────────────────────────────────────────────────────────────

// TestReconstructSizeCheck_Binding pins the
// muEnableReconstructSizeCheck invariant: assertReconstructSize
// MUST return ErrReconstructedSizeMismatch on a wrong-size input.
// The production happy path never produces such an input
// (escrow.Reconstruct honours its 32-byte contract), so the
// helper is the only observable boundary for the gate.
//
// With the gate on, the assertion fires on a synthetic short
// slice. With the gate off, the helper short-circuits to nil and
// the test fails — the load-bearing signal that the gate is
// active.
func TestReconstructSizeCheck_Binding(t *testing.T) {
	short := make([]byte, escrow.SecretSize-1)
	if err := assertReconstructSize(short); !errors.Is(err, ErrReconstructedSizeMismatch) {
		t.Fatalf("short slice: want ErrReconstructedSizeMismatch, got %v", err)
	}

	long := make([]byte, escrow.SecretSize+1)
	if err := assertReconstructSize(long); !errors.Is(err, ErrReconstructedSizeMismatch) {
		t.Fatalf("long slice: want ErrReconstructedSizeMismatch, got %v", err)
	}

	// Sanity: the happy path returns nil with the gate on.
	exact := make([]byte, escrow.SecretSize)
	if err := assertReconstructSize(exact); err != nil {
		t.Fatalf("exact-size slice: want nil, got %v", err)
	}
}
