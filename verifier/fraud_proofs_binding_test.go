// Package verifier — fraud_proofs_binding_test.go holds the
// binding test for muEnableFraudProofValidation. See
// verifier/fraud_proofs.mutation-audit.yaml for the registry.
package verifier

import "testing"

// TestFraudProofValidation_Binding seeds a corrupt commitment
// (NewOriginTip mutated post-replay) and asserts
// VerifyDerivationCommitment surfaces Valid:false plus at least
// one fraud proof. With muEnableFraudProofValidation on, the
// per-leaf comparison detects the corruption. With the gate off,
// the function short-circuits to Valid:true and this test fails —
// the signal that the gate is load-bearing.
//
// Mirrors the input shape of TestFraud_SingleCorruptMutation but
// asserts only the binding-relevant property (Valid:false) so
// the test stays self-contained when the audit runner targets it.
func TestFraudProofValidation_Binding(t *testing.T) {
	commitment, fetcher, priorState := buildGenesisCommitmentFixture(t, 3)
	if len(commitment.Mutations) == 0 {
		t.Fatal("fixture produced no mutations; binding test cannot exercise the gate")
	}
	// Corrupt the first mutation's claimed new tip. Replay will
	// produce a different value; the gate detects the divergence.
	commitment.Mutations[0].NewOriginTip = p5bPos(9999)

	result, err := VerifyDerivationCommitment(commitment, priorState, fetcher, nil, p5bTestLogDID)
	if err != nil {
		t.Fatalf("VerifyDerivationCommitment: %v", err)
	}
	if result.Valid {
		t.Fatal("corrupt commitment accepted as valid (muEnableFraudProofValidation not load-bearing?)")
	}
	if len(result.Proofs) == 0 {
		t.Fatal("no fraud proofs surfaced for corrupt commitment")
	}
}
