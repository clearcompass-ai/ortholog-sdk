// Package signatures — bls_verifier_mutation_switches.go holds the
// ADR-005 §6 mutation-audit switches for the BLS verification path
// (bls_verifier.go and the closely-related ParseBLSPubKey in
// bls_signer.go). Declared in their own file so the audit-v775
// runner's line-local rewrite can target exactly one declaration
// per constant.
//
//	┌─────────────────────────────────────────────────────────────┐
//	│  STOP. READ THIS BEFORE MODIFYING ANY muEnable* CONSTANT.   │
//	├─────────────────────────────────────────────────────────────┤
//	│  These constants gate the BLS12-381 verification surface —  │
//	│  cosignature aggregation, Proof-of-Possession verification, │
//	│  DST separation, and subgroup-membership classification.    │
//	│  Setting any to false permanently is a security regression  │
//	│  that admits forged BLS signatures, rogue-key attacks, or   │
//	│  cross-protocol replay (cosignature reused as PoP).         │
//	│                                                             │
//	│  Binding tests (crypto/signatures/bls_verifier.mutation-audit.yaml):
//	│    muEnableBLSSubgroupCheck   → TestParseBLSPubKey_NotInSubgroup
//	│    muEnableBLSPoPVerify       → TestVerifyBLSPoP_RejectsTamperedPoP
//	│                                  TestVerifyBLSPoP_RejectsWrongKey │
//	│    muEnableBLSDSTSeparation   → TestDomainSeparation_DSTsAreDistinct
//	│                                  TestDomainSeparation_CosignatureNotUsableAsPoP
//	│    muEnableBLSAggregateVerify → TestBLSAggregateVerify_RejectsTamperedSig_Binding
//	└─────────────────────────────────────────────────────────────┘
package signatures

// muEnableBLSSubgroupCheck gates the subgroup-error classification
// inside ParseBLSPubKey. When true, a non-subgroup G2 point (even if
// otherwise on-curve) is rejected with ErrBLSPubKeyNotInSubgroup;
// when false, the typed-error narrowing is bypassed and every parse
// failure is mapped to ErrBLSPubKeyNotOnCurve — losing the security-
// critical distinction between "malformed bytes" and "rogue point
// outside the prime-order subgroup".
const muEnableBLSSubgroupCheck = true

// muEnableBLSPoPVerify gates the PairingCheck inside VerifyBLSPoP —
// the cryptographic step that proves the prover knows the secret
// scalar matching the public key. When off, any well-formed PoP
// shape returns nil; rogue-key attacks succeed because PoP no
// longer attests to scalar knowledge.
const muEnableBLSPoPVerify = true

// muEnableBLSDSTSeparation is a documentation-only constant that
// the audit runner flips ALONGSIDE the string-mutation that swaps
// BLSPoPDomainTag with BLSDomainTag. The string mutation is the
// load-bearing probe; this constant exists so the registry has a
// bool-shaped audit row that pairs with the string mutation in
// the docs/audit/mutation-audit-log.md table.
const muEnableBLSDSTSeparation = true

// muEnableBLSAggregateVerify gates the optimistic aggregation
// PairingCheck inside VerifyAggregate. When off, the aggregation
// check is bypassed and all parsed signatures are marked valid
// regardless of the actual signature relationships — silent
// forgery acceptance for BLS cosignatures.
const muEnableBLSAggregateVerify = true
