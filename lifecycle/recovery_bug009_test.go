/*
FILE PATH:

	lifecycle/recovery_bug009_test.go

DESCRIPTION:

	Tests for the three BUG-009 fixes in EvaluateArbitration. Each
	independent hole gets its own dedicated test so a regression
	surfaces precisely.

	If a recovery_test.go already exists, merge these into it and
	delete this file.

	Tests:

	  TestEvaluateArbitration_RejectsDeserializeFailure
	    Fix 1: malformed witness cosignature bytes block authorization.

	  TestEvaluateArbitration_RejectsUnboundWitnessCosignature
	    Fix 2: witness cosignature not bound to recovery request is rejected.

	  TestEvaluateArbitration_RejectsEscrowNodeAsWitness
	    Fix 3: witness signer in escrow node set is rejected (not independent).

	  TestEvaluateArbitration_RequiresEscrowNodeSet
	    Configuration guard: OverrideRequiresIndependentWitness=true
	    with nil/empty EscrowNodeSet must fail fast rather than silently
	    skip the independence check.

	  TestEvaluateArbitration_AcceptsValidIndependentBoundCosignature
	    Positive control: all three conditions hold → OverrideAuthorized.

MUTATION PROBES
───────────────

 1. Comment out `if err != nil { ... return ... }` in witness block.
    TestEvaluateArbitration_RejectsDeserializeFailure must FAIL.

 2. Replace `!verifier.IsCosignatureOf(...)` with `witnessEntry.Header.CosignatureOf == nil`.
    TestEvaluateArbitration_RejectsUnboundWitnessCosignature must FAIL.

 3. Comment out `if p.EscrowNodeSet[...]` check.
    TestEvaluateArbitration_RejectsEscrowNodeAsWitness must FAIL.

 4. Comment out `if requiresWitness && len(p.EscrowNodeSet) == 0`.
    TestEvaluateArbitration_RequiresEscrowNodeSet must FAIL.

Restore all. Full test suite green.
*/
package lifecycle

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ═══════════════════════════════════════════════════════════════════
// Test helpers (shared within this file)
// ═══════════════════════════════════════════════════════════════════

// signTestEntryBug009 completes a signed envelope.Entry.
func signTestEntryBug009(t *testing.T, entry *envelope.Entry, priv *ecdsa.PrivateKey) {
	t.Helper()
	hash := sha256.Sum256(envelope.SigningPayload(entry))
	sig, err := signatures.SignEntry(hash, priv)
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}
	entry.Signatures = []envelope.Signature{{
		SignerDID: entry.Header.SignerDID,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     sig,
	}}
	if err := entry.Validate(); err != nil {
		t.Fatalf("entry.Validate: %v", err)
	}
}

// buildCosigMetaBug009 produces a cosignature EntryWithMetadata.
func buildCosigMetaBug009(t *testing.T, signerDID string, cosigOf *types.LogPosition) types.EntryWithMetadata {
	t.Helper()

	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	unsigned, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:     signerDID,
		Destination:   "did:web:target",
		CosignatureOf: cosigOf,
		EventTime:     1_700_000_000,
	}, []byte("arb-cosig-payload"))
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}

	signTestEntryBug009(t, unsigned, priv)

	return types.EntryWithMetadata{
		CanonicalBytes: envelope.Serialize(unsigned),
	}
}

// arbitrationFixture holds the common inputs for EvaluateArbitration
// tests. Callers customize individual fields per test.
type arbitrationFixture struct {
	recoveryPos      types.LogPosition
	totalEscrowNodes int
	escrowNodeSet    map[string]bool
	escrowApprovals  []types.EntryWithMetadata
	schemaParams     *types.SchemaParameters
}

func newArbitrationFixture(t *testing.T) *arbitrationFixture {
	t.Helper()
	recoveryPos := types.LogPosition{LogDID: "did:web:source-log", Sequence: 50}

	escrowSet := map[string]bool{
		"did:web:escrow-1": true,
		"did:web:escrow-2": true,
		"did:web:escrow-3": true,
	}

	// 3 escrow approvals correctly bound to recoveryPos — meets 2/3 threshold of 3 nodes.
	approvals := []types.EntryWithMetadata{}
	for did := range escrowSet {
		approvals = append(approvals, buildCosigMetaBug009(t, did, &recoveryPos))
	}

	sp := &types.SchemaParameters{
		OverrideThreshold:                  types.ThresholdTwoThirdsMajority,
		OverrideRequiresIndependentWitness: true,
	}

	return &arbitrationFixture{
		recoveryPos:      recoveryPos,
		totalEscrowNodes: 3,
		escrowNodeSet:    escrowSet,
		escrowApprovals:  approvals,
		schemaParams:     sp,
	}
}

// ═══════════════════════════════════════════════════════════════════
// BUG-009 fix 1: Deserialize error blocks authorization
// ═══════════════════════════════════════════════════════════════════

// TestEvaluateArbitration_RejectsDeserializeFailure exercises fix 1.
// A malformed WitnessCosignature must block OverrideAuthorized.
func TestEvaluateArbitration_RejectsDeserializeFailure(t *testing.T) {
	fx := newArbitrationFixture(t)

	// Non-deserializable bytes.
	garbageWitness := &types.EntryWithMetadata{
		CanonicalBytes: []byte("not-a-valid-envelope-entry"),
	}

	result, err := EvaluateArbitration(ArbitrationParams{
		RecoveryRequestPos: fx.recoveryPos,
		EscrowApprovals:    fx.escrowApprovals,
		TotalEscrowNodes:   fx.totalEscrowNodes,
		EscrowNodeSet:      fx.escrowNodeSet,
		WitnessCosignature: garbageWitness,
		SchemaParams:       fx.schemaParams,
	})

	if err != nil {
		t.Fatalf("unexpected error from EvaluateArbitration: %v", err)
	}
	if result.OverrideAuthorized {
		t.Fatal("BUG-009 fix 1 REGRESSION: OverrideAuthorized = true " +
			"despite witness cosignature deserialize failure. The " +
			"deserialize-error guard is missing or broken.")
	}
}

// ═══════════════════════════════════════════════════════════════════
// BUG-009 fix 2: Witness cosignature must bind to recovery request
// ═══════════════════════════════════════════════════════════════════

// TestEvaluateArbitration_RejectsUnboundWitnessCosignature exercises
// fix 2. A witness cosignature pointing at a different position than
// the recovery request must be rejected.
func TestEvaluateArbitration_RejectsUnboundWitnessCosignature(t *testing.T) {
	fx := newArbitrationFixture(t)

	unrelatedPos := types.LogPosition{LogDID: "did:web:source-log", Sequence: 999}
	witnessMeta := buildCosigMetaBug009(t, "did:web:independent-witness", &unrelatedPos)

	result, err := EvaluateArbitration(ArbitrationParams{
		RecoveryRequestPos: fx.recoveryPos,
		EscrowApprovals:    fx.escrowApprovals,
		TotalEscrowNodes:   fx.totalEscrowNodes,
		EscrowNodeSet:      fx.escrowNodeSet,
		WitnessCosignature: &witnessMeta,
		SchemaParams:       fx.schemaParams,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.OverrideAuthorized {
		t.Fatalf("BUG-009 fix 2 REGRESSION: OverrideAuthorized = true "+
			"for witness cosignature bound to position %v (expected %v). "+
			"The IsCosignatureOf binding is missing or broken.",
			unrelatedPos, fx.recoveryPos)
	}
}

// ═══════════════════════════════════════════════════════════════════
// BUG-009 fix 3: Witness must be independent of escrow
// ═══════════════════════════════════════════════════════════════════

// TestEvaluateArbitration_RejectsEscrowNodeAsWitness exercises fix 3.
// A witness cosignature correctly bound but signed by an escrow node
// must be rejected as non-independent.
//
// This is the most consequential of the three holes: without this
// check, a compromised escrow operator could sign their own "witness
// attestation" and satisfy the independence requirement unilaterally.
func TestEvaluateArbitration_RejectsEscrowNodeAsWitness(t *testing.T) {
	fx := newArbitrationFixture(t)

	// Witness correctly bound, but signed by an escrow node.
	witnessMeta := buildCosigMetaBug009(t, "did:web:escrow-1", &fx.recoveryPos)

	result, err := EvaluateArbitration(ArbitrationParams{
		RecoveryRequestPos: fx.recoveryPos,
		EscrowApprovals:    fx.escrowApprovals,
		TotalEscrowNodes:   fx.totalEscrowNodes,
		EscrowNodeSet:      fx.escrowNodeSet,
		WitnessCosignature: &witnessMeta,
		SchemaParams:       fx.schemaParams,
	})

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.OverrideAuthorized {
		t.Fatal("BUG-009 fix 3 REGRESSION: OverrideAuthorized = true " +
			"for witness cosignature signed by an escrow node. " +
			"The independence check is missing or broken.")
	}
}

// ═══════════════════════════════════════════════════════════════════
// Configuration guard: EscrowNodeSet required when witness required
// ═══════════════════════════════════════════════════════════════════

// TestEvaluateArbitration_RequiresEscrowNodeSet confirms fail-fast
// behavior when OverrideRequiresIndependentWitness=true but
// EscrowNodeSet is nil/empty. Silently skipping the independence
// check in this configuration would turn fix 3 into a no-op.
func TestEvaluateArbitration_RequiresEscrowNodeSet(t *testing.T) {
	fx := newArbitrationFixture(t)

	witnessMeta := buildCosigMetaBug009(t, "did:web:independent-witness", &fx.recoveryPos)

	// Nil EscrowNodeSet with requiresWitness=true — misconfiguration.
	_, err := EvaluateArbitration(ArbitrationParams{
		RecoveryRequestPos: fx.recoveryPos,
		EscrowApprovals:    fx.escrowApprovals,
		TotalEscrowNodes:   fx.totalEscrowNodes,
		EscrowNodeSet:      nil, // deliberate
		WitnessCosignature: &witnessMeta,
		SchemaParams:       fx.schemaParams,
	})

	if err == nil {
		t.Fatal("expected EvaluateArbitration to fail when EscrowNodeSet " +
			"is nil but OverrideRequiresIndependentWitness is true. " +
			"This configuration silently disables the independence check " +
			"and must be flagged loudly.")
	}
	if !errors.Is(err, ErrMissingEscrowNodeSet) {
		t.Errorf("expected ErrMissingEscrowNodeSet, got: %v", err)
	}
}

// ═══════════════════════════════════════════════════════════════════
// Positive control: all three conditions hold
// ═══════════════════════════════════════════════════════════════════

// TestEvaluateArbitration_AcceptsValidIndependentBoundCosignature is
// the positive control. A witness cosignature that is (1) deserializable,
// (2) bound to the recovery request, and (3) signed by a non-escrow
// identity must be accepted.
func TestEvaluateArbitration_AcceptsValidIndependentBoundCosignature(t *testing.T) {
	fx := newArbitrationFixture(t)

	// Valid witness: correctly bound, non-escrow signer.
	witnessMeta := buildCosigMetaBug009(t, "did:web:independent-witness", &fx.recoveryPos)

	result, err := EvaluateArbitration(ArbitrationParams{
		RecoveryRequestPos: fx.recoveryPos,
		EscrowApprovals:    fx.escrowApprovals,
		TotalEscrowNodes:   fx.totalEscrowNodes,
		EscrowNodeSet:      fx.escrowNodeSet,
		WitnessCosignature: &witnessMeta,
		SchemaParams:       fx.schemaParams,
	})

	if err != nil {
		t.Fatalf("unexpected error on valid fixture: %v", err)
	}
	if !result.OverrideAuthorized {
		t.Fatalf("positive control failed: OverrideAuthorized = false "+
			"for a valid independent bound witness cosignature. "+
			"Reason given: %q. The fix is over-restrictive.",
			result.Reason)
	}
	if !result.HasWitnessCosig {
		t.Error("HasWitnessCosig = false despite valid witness")
	}
}
