// Package lifecycle — recovery_test.go tests the full three-phase
// identity recovery pipeline plus arbitration evaluation.
//
// This file ABSORBS the former recovery_bug009_test.go (which tested
// the three EvaluateArbitration witness-binding fixes). Delete that
// file after installing this one.
//
// Coverage:
//   - InitiateRecovery: destination validation, payload fields
//   - CollectShares: threshold validation (BUG-010), share validation,
//     duplicate detection, sufficiency math
//   - ExecuteRecovery: reconstruction, MasterKey invariants, Zeroize,
//     optional Succession Entry, failure paths
//   - RecoveryResult.Zeroize: idempotent, nil-safe
//   - EvaluateArbitration: threshold math, three witness-binding
//     gates, configuration guard, positive control
package lifecycle

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/escrow"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// -------------------------------------------------------------------------------------------------
// Test helpers (shared across this file)
// -------------------------------------------------------------------------------------------------

// signTestEntry completes a signed envelope.Entry. Used for building
// cosignature fixtures for EvaluateArbitration tests.
func signTestEntry(t *testing.T, entry *envelope.Entry, priv *ecdsa.PrivateKey) {
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

// buildCosigMeta produces a cosignature EntryWithMetadata for tests.
func buildCosigMeta(t *testing.T, signerDID string, cosigOf *types.LogPosition) types.EntryWithMetadata {
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
	}, []byte("cosig-payload"))
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}

	signTestEntry(t, unsigned, priv)

	return types.EntryWithMetadata{
		CanonicalBytes: envelope.Serialize(unsigned),
	}
}

// -------------------------------------------------------------------------------------------------
// InitiateRecovery
// -------------------------------------------------------------------------------------------------

func TestInitiateRecovery_HappyPath(t *testing.T) {
	result, err := InitiateRecovery(InitiateRecoveryParams{
		Destination:      testDestination,
		NewExchangeDID:   "did:web:new-exchange.test",
		HolderDID:        "did:web:holder.test",
		Reason:           "lost hardware token",
		EscrowPackageCID: storage.Compute([]byte("escrow-package-bytes")),
	})
	if err != nil {
		t.Fatalf("InitiateRecovery: %v", err)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
	if result.RequestEntry == nil {
		t.Error("RequestEntry is nil")
	}
	if result.RequestPayload == nil {
		t.Fatal("RequestPayload is nil")
	}
	if result.RequestPayload["recovery_type"] != "escrow_key_recovery" {
		t.Errorf("recovery_type = %v, want escrow_key_recovery", result.RequestPayload["recovery_type"])
	}
	if result.RequestPayload["holder_did"] != "did:web:holder.test" {
		t.Errorf("holder_did = %v, want did:web:holder.test", result.RequestPayload["holder_did"])
	}
	if result.RequestPayload["reason"] != "lost hardware token" {
		t.Errorf("reason mismatch: got %v", result.RequestPayload["reason"])
	}
}

func TestInitiateRecovery_RejectsEmptyDestination(t *testing.T) {
	_, err := InitiateRecovery(InitiateRecoveryParams{
		NewExchangeDID: "did:web:new-exchange.test",
		HolderDID:      "did:web:holder.test",
	})
	if err == nil {
		t.Fatal("expected error for empty Destination, got nil")
	}
}

func TestInitiateRecovery_RejectsEmptyNewExchangeDID(t *testing.T) {
	_, err := InitiateRecovery(InitiateRecoveryParams{
		Destination: testDestination,
		HolderDID:   "did:web:holder.test",
	})
	if err == nil {
		t.Fatal("expected error for empty NewExchangeDID, got nil")
	}
}

func TestInitiateRecovery_RejectsEmptyHolderDID(t *testing.T) {
	_, err := InitiateRecovery(InitiateRecoveryParams{
		Destination:    testDestination,
		NewExchangeDID: "did:web:new-exchange.test",
	})
	if err == nil {
		t.Fatal("expected error for empty HolderDID, got nil")
	}
}

// -------------------------------------------------------------------------------------------------
// CollectShares — threshold validation (guards vacuous-sufficiency bug)
// -------------------------------------------------------------------------------------------------

// TestCollectShares_RejectsZeroThreshold guards against the vacuous
// sufficiency bug. With RequiredThreshold=0, len(ValidShares) >= 0 is
// always true, so SufficientForRecovery would falsely report "yes" for
// any share set (including empty). The function must reject this input.
func TestCollectShares_RejectsZeroThreshold(t *testing.T) {
	_, err := CollectShares(CollectSharesParams{
		RequiredThreshold: 0,
	})
	if err == nil {
		t.Fatal("expected error for RequiredThreshold=0, got nil")
	}
}

// TestCollectShares_RejectsThresholdOne guards against the degenerate
// case: a single share trivially reconstructs the secret, defeating
// M-of-N. Matches the M >= 2 constraint in escrow.Split.
func TestCollectShares_RejectsThresholdOne(t *testing.T) {
	_, err := CollectShares(CollectSharesParams{
		RequiredThreshold: 1,
	})
	if err == nil {
		t.Fatal("expected error for RequiredThreshold=1, got nil")
	}
}

// TestCollectShares_RejectsNegativeThreshold guards against integer
// underflow / caller misuse of the signed int field.
func TestCollectShares_RejectsNegativeThreshold(t *testing.T) {
	_, err := CollectShares(CollectSharesParams{
		RequiredThreshold: -1,
	})
	if err == nil {
		t.Fatal("expected error for RequiredThreshold=-1, got nil")
	}
}

// -------------------------------------------------------------------------------------------------
// CollectShares — happy paths
// -------------------------------------------------------------------------------------------------

func TestCollectShares_EmptyInputYieldsEmptyResult(t *testing.T) {
	result, err := CollectShares(CollectSharesParams{
		RequiredThreshold: 3,
		DecryptedShares:   nil,
	})
	if err != nil {
		t.Fatalf("CollectShares: %v", err)
	}
	if len(result.ValidShares) != 0 {
		t.Errorf("ValidShares = %d, want 0", len(result.ValidShares))
	}
	if result.InvalidCount != 0 {
		t.Errorf("InvalidCount = %d, want 0", result.InvalidCount)
	}
	if result.SufficientForRecovery {
		t.Error("SufficientForRecovery = true on empty input, want false")
	}
	if result.Threshold != 3 {
		t.Errorf("Threshold = %d, want 3", result.Threshold)
	}
}

func TestCollectShares_AllValidSharesMeetingThreshold(t *testing.T) {
	secret := make([]byte, escrow.SecretSize)
	for i := range secret {
		secret[i] = byte(i)
	}
	shares, _, err := escrow.Split(secret, 3, 5)
	if err != nil {
		t.Fatalf("escrow.Split: %v", err)
	}
	result, err := CollectShares(CollectSharesParams{
		RequiredThreshold: 3,
		DecryptedShares:   shares,
	})
	if err != nil {
		t.Fatalf("CollectShares: %v", err)
	}
	if len(result.ValidShares) != 5 {
		t.Errorf("ValidShares = %d, want 5", len(result.ValidShares))
	}
	if result.InvalidCount != 0 {
		t.Errorf("InvalidCount = %d, want 0", result.InvalidCount)
	}
	if !result.SufficientForRecovery {
		t.Error("SufficientForRecovery = false with 5 valid shares / threshold 3")
	}
}

func TestCollectShares_BelowThresholdNotSufficient(t *testing.T) {
	secret := make([]byte, escrow.SecretSize)
	shares, _, _ := escrow.Split(secret, 3, 5)
	result, err := CollectShares(CollectSharesParams{
		RequiredThreshold: 3,
		DecryptedShares:   shares[:2], // only 2 valid, threshold 3
	})
	if err != nil {
		t.Fatalf("CollectShares: %v", err)
	}
	if len(result.ValidShares) != 2 {
		t.Errorf("ValidShares = %d, want 2", len(result.ValidShares))
	}
	if result.SufficientForRecovery {
		t.Error("SufficientForRecovery = true with 2 of 3 shares")
	}
}

func TestCollectShares_InvalidSharesSurfaceInReasons(t *testing.T) {
	secret := make([]byte, escrow.SecretSize)
	shares, _, _ := escrow.Split(secret, 3, 5)
	// Corrupt share[1] — set Index to 0 which is reserved.
	shares[1].Index = 0
	result, err := CollectShares(CollectSharesParams{
		RequiredThreshold: 3,
		DecryptedShares:   shares,
	})
	if err != nil {
		t.Fatalf("CollectShares: %v", err)
	}
	if result.InvalidCount != 1 {
		t.Errorf("InvalidCount = %d, want 1", result.InvalidCount)
	}
	if _, ok := result.InvalidReasons[1]; !ok {
		t.Error("InvalidReasons[1] missing — expected reason for corrupted share")
	}
}

func TestCollectShares_DuplicateIndexRejected(t *testing.T) {
	secret := make([]byte, escrow.SecretSize)
	shares, _, _ := escrow.Split(secret, 3, 5)
	// Force duplicate: copy share[0] into share[2].
	shares[2] = shares[0]
	result, err := CollectShares(CollectSharesParams{
		RequiredThreshold: 3,
		DecryptedShares:   shares,
	})
	if err != nil {
		t.Fatalf("CollectShares: %v", err)
	}
	if result.InvalidCount != 1 {
		t.Errorf("InvalidCount = %d, want 1", result.InvalidCount)
	}
}

// -------------------------------------------------------------------------------------------------
// ExecuteRecovery — happy paths
// -------------------------------------------------------------------------------------------------

func TestExecuteRecovery_ReconstructsMasterKey(t *testing.T) {
	secret := make([]byte, escrow.SecretSize)
	for i := range secret {
		secret[i] = byte(i + 1) // non-zero pattern
	}
	shares, _, err := escrow.Split(secret, 3, 5)
	if err != nil {
		t.Fatalf("escrow.Split: %v", err)
	}

	result, err := ExecuteRecovery(ExecuteRecoveryParams{
		Destination: testDestination,
		Shares:      shares[:3],
	})
	if err != nil {
		t.Fatalf("ExecuteRecovery: %v", err)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
	if !bytes.Equal(result.MasterKey[:], secret) {
		t.Fatal("MasterKey does not match the original secret")
	}
	if result.SuccessionEntry != nil {
		t.Error("SuccessionEntry should be nil when not requested")
	}
	if result.SuccessionError != nil {
		t.Errorf("SuccessionError = %v, want nil", result.SuccessionError)
	}
}

func TestExecuteRecovery_RoundTripThroughZeroize(t *testing.T) {
	secret := make([]byte, escrow.SecretSize)
	for i := range secret {
		secret[i] = 0xAA
	}
	shares, _, _ := escrow.Split(secret, 3, 5)

	result, err := ExecuteRecovery(ExecuteRecoveryParams{
		Destination: testDestination,
		Shares:      shares[:3],
	})
	if err != nil {
		t.Fatalf("ExecuteRecovery: %v", err)
	}

	// Assert non-zero before zeroize.
	allZero := true
	for _, b := range result.MasterKey {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("MasterKey is all zeros before Zeroize — test is broken")
	}

	result.Zeroize()

	for i, b := range result.MasterKey {
		if b != 0 {
			t.Fatalf("MasterKey[%d] = 0x%02x after Zeroize, want 0", i, b)
		}
	}
}

// -------------------------------------------------------------------------------------------------
// ExecuteRecovery — fail-fast conditions
// -------------------------------------------------------------------------------------------------

func TestExecuteRecovery_RejectsEmptyShares(t *testing.T) {
	_, err := ExecuteRecovery(ExecuteRecoveryParams{
		Destination: testDestination,
		Shares:      nil,
	})
	if !errors.Is(err, ErrInsufficientShares) {
		t.Fatalf("got %v, want ErrInsufficientShares", err)
	}
}

func TestExecuteRecovery_RejectsEmptyDestination(t *testing.T) {
	secret := make([]byte, escrow.SecretSize)
	shares, _, _ := escrow.Split(secret, 3, 5)
	_, err := ExecuteRecovery(ExecuteRecoveryParams{
		Destination: "",
		Shares:      shares[:3],
	})
	if err == nil {
		t.Fatal("expected error for empty Destination, got nil")
	}
}

func TestExecuteRecovery_RejectsBelowThreshold(t *testing.T) {
	secret := make([]byte, escrow.SecretSize)
	shares, _, _ := escrow.Split(secret, 3, 5)
	_, err := ExecuteRecovery(ExecuteRecoveryParams{
		Destination: testDestination,
		Shares:      shares[:2], // 2 shares, threshold 3
	})
	if !errors.Is(err, ErrReconstructionFailed) {
		t.Fatalf("got %v, want ErrReconstructionFailed", err)
	}
}

// -------------------------------------------------------------------------------------------------
// RecoveryResult.Zeroize
// -------------------------------------------------------------------------------------------------

func TestRecoveryResult_ZeroizeNilReceiver(t *testing.T) {
	var r *RecoveryResult
	r.Zeroize() // must not panic
}

func TestRecoveryResult_ZeroizeIsIdempotent(t *testing.T) {
	secret := make([]byte, escrow.SecretSize)
	for i := range secret {
		secret[i] = 0xAA
	}
	shares, _, _ := escrow.Split(secret, 3, 5)

	result, _ := ExecuteRecovery(ExecuteRecoveryParams{
		Destination: testDestination,
		Shares:      shares[:3],
	})

	result.Zeroize()
	result.Zeroize() // second call must not panic

	for i, b := range result.MasterKey {
		if b != 0 {
			t.Fatalf("MasterKey[%d] = 0x%02x after idempotent Zeroize, want 0", i, b)
		}
	}
}

// -------------------------------------------------------------------------------------------------
// EvaluateArbitration — threshold math
// -------------------------------------------------------------------------------------------------

func TestEvaluateArbitration_RejectsZeroTotalNodes(t *testing.T) {
	_, err := EvaluateArbitration(ArbitrationParams{TotalEscrowNodes: 0})
	if !errors.Is(err, ErrInvalidEscrowNodeCount) {
		t.Fatalf("got %v, want ErrInvalidEscrowNodeCount", err)
	}
}

func TestEvaluateArbitration_RejectsNegativeTotalNodes(t *testing.T) {
	_, err := EvaluateArbitration(ArbitrationParams{TotalEscrowNodes: -1})
	if !errors.Is(err, ErrInvalidEscrowNodeCount) {
		t.Fatalf("got %v, want ErrInvalidEscrowNodeCount", err)
	}
}

func TestEvaluateArbitration_ReportsInsufficientWhenBelowThreshold(t *testing.T) {
	result, err := EvaluateArbitration(ArbitrationParams{
		TotalEscrowNodes: 5,
		EscrowApprovals:  nil,
	})
	if err != nil {
		t.Fatalf("EvaluateArbitration: %v", err)
	}
	if result.OverrideAuthorized {
		t.Error("OverrideAuthorized = true with 0 approvals")
	}
	if result.ApprovalCount != 0 {
		t.Errorf("ApprovalCount = %d, want 0", result.ApprovalCount)
	}
	if result.RequiredCount < 1 {
		t.Errorf("RequiredCount = %d, want >= 1", result.RequiredCount)
	}
	if result.Reason == "" {
		t.Error("Reason is empty when override not authorized")
	}
}

// -------------------------------------------------------------------------------------------------
// EvaluateArbitration — witness-binding gates
//
// Each independent gate gets its own test so a regression surfaces
// precisely. Mutation probes against recovery.go:
//
//	Probe 1: Comment out the deserialize-error guard.
//	         TestEvaluateArbitration_RejectsDeserializeFailure must FAIL.
//	Probe 2: Replace `!verifier.IsCosignatureOf(...)` with a weaker check.
//	         TestEvaluateArbitration_RejectsUnboundWitnessCosignature must FAIL.
//	Probe 3: Comment out the EscrowNodeSet membership check.
//	         TestEvaluateArbitration_RejectsEscrowNodeAsWitness must FAIL.
//	Probe 4: Comment out the requiresWitness && empty-set guard.
//	         TestEvaluateArbitration_RequiresEscrowNodeSet must FAIL.
//
// Restore all probes → full suite green.
// -------------------------------------------------------------------------------------------------

// arbitrationFixture holds common inputs for EvaluateArbitration tests.
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

	// 3 escrow approvals correctly bound to recoveryPos — meets 2/3 of 3 nodes.
	approvals := []types.EntryWithMetadata{}
	for did := range escrowSet {
		approvals = append(approvals, buildCosigMeta(t, did, &recoveryPos))
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

// Gate 1: malformed witness cosignature bytes block authorization.
func TestEvaluateArbitration_RejectsDeserializeFailure(t *testing.T) {
	fx := newArbitrationFixture(t)

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
		t.Fatalf("unexpected error: %v", err)
	}
	if result.OverrideAuthorized {
		t.Fatal("OverrideAuthorized = true despite witness deserialize failure. " +
			"The deserialize-error guard is missing or broken.")
	}
}

// Gate 2: witness cosignature must bind to recovery request position.
func TestEvaluateArbitration_RejectsUnboundWitnessCosignature(t *testing.T) {
	fx := newArbitrationFixture(t)

	unrelatedPos := types.LogPosition{LogDID: "did:web:source-log", Sequence: 999}
	witnessMeta := buildCosigMeta(t, "did:web:independent-witness", &unrelatedPos)

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
		t.Fatalf("OverrideAuthorized = true for witness cosignature bound to "+
			"position %v (expected %v). The IsCosignatureOf binding is "+
			"missing or broken.", unrelatedPos, fx.recoveryPos)
	}
}

// Gate 3: witness must be independent of escrow (most consequential).
// Without this check, a compromised escrow operator could sign their
// own "witness attestation" and satisfy the independence requirement
// unilaterally.
func TestEvaluateArbitration_RejectsEscrowNodeAsWitness(t *testing.T) {
	fx := newArbitrationFixture(t)

	// Witness correctly bound, but signed by an escrow node.
	witnessMeta := buildCosigMeta(t, "did:web:escrow-1", &fx.recoveryPos)

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
		t.Fatal("OverrideAuthorized = true for witness cosignature signed by " +
			"an escrow node. The independence check is missing or broken.")
	}
}

// Configuration guard: EscrowNodeSet required when witness required.
// Silently skipping the independence check in this configuration
// would turn gate 3 into a no-op.
func TestEvaluateArbitration_RequiresEscrowNodeSet(t *testing.T) {
	fx := newArbitrationFixture(t)

	witnessMeta := buildCosigMeta(t, "did:web:independent-witness", &fx.recoveryPos)

	_, err := EvaluateArbitration(ArbitrationParams{
		RecoveryRequestPos: fx.recoveryPos,
		EscrowApprovals:    fx.escrowApprovals,
		TotalEscrowNodes:   fx.totalEscrowNodes,
		EscrowNodeSet:      nil, // deliberate
		WitnessCosignature: &witnessMeta,
		SchemaParams:       fx.schemaParams,
	})

	if err == nil {
		t.Fatal("expected error when EscrowNodeSet is nil but " +
			"OverrideRequiresIndependentWitness is true. Silent skip would " +
			"disable the independence check.")
	}
	if !errors.Is(err, ErrMissingEscrowNodeSet) {
		t.Errorf("expected ErrMissingEscrowNodeSet, got: %v", err)
	}
}

// Positive control: all gates pass.
func TestEvaluateArbitration_AcceptsValidIndependentBoundCosignature(t *testing.T) {
	fx := newArbitrationFixture(t)

	witnessMeta := buildCosigMeta(t, "did:web:independent-witness", &fx.recoveryPos)

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
			"for a valid independent bound witness. Reason: %q",
			result.Reason)
	}
	if !result.HasWitnessCosig {
		t.Error("HasWitnessCosig = false despite valid witness")
	}
}
