// Package verifier — fraud_proofs_mutation_switches.go holds the
// ADR-005 §6 mutation-audit switch for verifier/fraud_proofs.go.
// Declared in its own file so the audit-v775 runner's line-local
// rewrite can target exactly one declaration.
//
//	┌─────────────────────────────────────────────────────────────┐
//	│  STOP. READ THIS BEFORE MODIFYING muEnableFraudProofValidation. │
//	├─────────────────────────────────────────────────────────────┤
//	│  This constant gates the per-leaf comparison and post-root  │
//	│  divergence detection inside VerifyDerivationCommitment —   │
//	│  the function that distinguishes honest operators from      │
//	│  malicious SMT operators publishing fraudulent commitments. │
//	│  Setting it to false permanently makes every commitment     │
//	│  unconditionally Valid, which is exactly the failure mode   │
//	│  fraud-proof verification exists to prevent. The switch     │
//	│  exists so the audit runner can flip it and observe that    │
//	│  the binding test fires; any other use is wrong.            │
//	│                                                             │
//	│  Binding test:                                              │
//	│    TestFraudProofValidation_Binding                         │
//	└─────────────────────────────────────────────────────────────┘
package verifier

// muEnableFraudProofValidation gates the per-leaf mutation
// comparison and the post-root divergence check inside
// VerifyDerivationCommitment. When true (production), the function
// compares each committed mutation against the replayed mutation
// and asserts the post-replay root matches the committed PostSMTRoot.
// When false, both checks are bypassed and the function returns
// {Valid: true} regardless of input — readmitting silent
// acceptance of fraudulent commitments.
const muEnableFraudProofValidation = true
