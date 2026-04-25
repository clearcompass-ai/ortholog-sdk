# Mutation-audit log

Every row records one gate's mutation result from a run of
`cmd/audit-v775 mutation`.

- **PASS** — gate was flipped, listed binding tests failed as expected,
  gate was restored, listed binding tests passed again.
- **FAIL** — discipline broken. Either the mutation did not cause the
  binding tests to fail (the switch is not load-bearing) or the
  restored source did not bring the tests back green (the test suite
  is unstable).
- **SKIP** — gate was filtered out by `--only` or the runner
  could not locate the source file (registry drift).

The file is append-only. Entries are committed to the repo.

## 2026-04-25T00:58:27Z — audit-v775 mutation

| Registry | Gate | Result | Note |
| --- | --- | --- | --- |
| core/envelope/serialize.mutation-audit.yaml | muEnableCanonicalOrdering | PASS | — |
| core/envelope/serialize.mutation-audit.yaml | muEnableSizeCap | PASS | — |
| core/envelope/serialize.mutation-audit.yaml | muEnableVersionReject | PASS | — |
| core/envelope/serialize.mutation-audit.yaml | muEnableDestinationBound | PASS | — |
| core/smt/verify.mutation-audit.yaml | muEnableRootMatch | PASS | — |
| core/smt/verify.mutation-audit.yaml | muEnableProofDepthBounds | PASS | — |
| core/smt/verify.mutation-audit.yaml | muEnableEmptyLeafDistinction | PASS | — |
| core/vss/h_generator.mutation-audit.yaml | muEnableHGeneratorLiftX | PASS | — |
| core/vss/h_generator.mutation-audit.yaml | HGeneratorSeedFlip | PASS | — |
| core/vss/pedersen.mutation-audit.yaml | muEnablePedersenIndexBounds | PASS | — |
| core/vss/pedersen.mutation-audit.yaml | muEnablePedersenOnCurveCheck | PASS | — |
| core/vss/transcript.mutation-audit.yaml | TranscriptDSTFlip | PASS | — |
| crypto/artifact/pre.mutation-audit.yaml | muEnableCommitmentsGate | PASS | — |
| crypto/artifact/pre.mutation-audit.yaml | muEnableOnCurveGate | PASS | — |
| crypto/artifact/pre.mutation-audit.yaml | muEnableDLEQCheck | PASS | — |
| crypto/artifact/pre.mutation-audit.yaml | muEnablePedersenCheck | PASS | — |
| crypto/artifact/pre.mutation-audit.yaml | muEnableSufficientCFragsGate | PASS | — |
| crypto/artifact/pre.mutation-audit.yaml | muEnableVerifyBeforeCombine | PASS | — |
| crypto/artifact/pre.mutation-audit.yaml | muEnableKFragReservedCheck | PASS | — |
| crypto/artifact/pre.mutation-audit.yaml | muEnableCommitmentOnCurveGate | PASS | — |
| crypto/artifact/pre.mutation-audit.yaml | muEnableCommitmentSetLengthCheck | PASS | — |
| crypto/artifact/pre.mutation-audit.yaml | muEnableThresholdBoundsCheck | PASS | — |
| crypto/artifact/pre.mutation-audit.yaml | muEnableSplitIDRecomputation | PASS | — |
| crypto/escrow/split_commitment.mutation-audit.yaml | muEnableEscrowCommitmentOnCurveGate | PASS | — |
| crypto/escrow/split_commitment.mutation-audit.yaml | muEnableEscrowCommitmentSetLengthCheck | PASS | — |
| crypto/escrow/split_commitment.mutation-audit.yaml | muEnableEscrowThresholdBoundsCheck | PASS | — |
| crypto/escrow/split_commitment.mutation-audit.yaml | muEnableEscrowSplitIDRecomputation | PASS | — |
| crypto/escrow/verify_share.mutation-audit.yaml | muEnableV1FieldEmptyCheck | PASS | — |
| crypto/escrow/verify_share.mutation-audit.yaml | muEnableV2FieldPopulatedCheck | PASS | — |
| crypto/escrow/verify_share.mutation-audit.yaml | muEnableShareIndexNonZero | PASS | — |
| crypto/escrow/verify_share.mutation-audit.yaml | muEnableSplitIDPresent | PASS | — |
| crypto/escrow/verify_share.mutation-audit.yaml | muEnableFieldTagDiscrimination | PASS | — |
| crypto/escrow/vss_v2.mutation-audit.yaml | muEnableEscrowSecretSizeCheck | PASS | — |
| crypto/escrow/vss_v2.mutation-audit.yaml | muEnableEscrowDealerDIDNonEmpty | PASS | — |
| crypto/escrow/vss_v2.mutation-audit.yaml | muEnableEscrowThresholdBounds | PASS | — |
| crypto/escrow/vss_v2.mutation-audit.yaml | muEnableReconstructVersionCheck | PASS | — |
| crypto/escrow/vss_v2.mutation-audit.yaml | muEnableReconstructShareVerification | PASS | — |
| crypto/signatures/bls_verifier.mutation-audit.yaml | muEnableBLSSubgroupCheck | PASS | — |
| crypto/signatures/bls_verifier.mutation-audit.yaml | muEnableBLSPoPVerify | PASS | — |
| crypto/signatures/bls_verifier.mutation-audit.yaml | BLSPoPDomainTagFlip | PASS | — |
| crypto/signatures/bls_verifier.mutation-audit.yaml | muEnableBLSAggregateVerify | PASS | — |
| crypto/signatures/entry_verify.mutation-audit.yaml | muEnableEntrySignatureVerify | PASS | — |
| crypto/signatures/entry_verify.mutation-audit.yaml | muEnablePubKeyOnCurve | PASS | — |
| crypto/signatures/entry_verify.mutation-audit.yaml | muEnableSignatureLength | PASS | — |
| exchange/identity/mapping_escrow_v2.mutation-audit.yaml | muEnableCommitmentEmissionAtomicV2 | PASS | — |
| lifecycle/artifact_access.mutation-audit.yaml | muEnableArtifactCommitmentRequired | PASS | — |
| lifecycle/artifact_access.mutation-audit.yaml | muEnableGrantAuthorizationCheck | PASS | — |
| lifecycle/artifact_access.mutation-audit.yaml | muEnableWitnessDeserialize | PASS | — |
| lifecycle/artifact_access.mutation-audit.yaml | muEnableWitnessPositionBinding | PASS | — |
| lifecycle/artifact_access.mutation-audit.yaml | muEnableWitnessIndependence | PASS | — |
| lifecycle/artifact_access.mutation-audit.yaml | muEnableReconstructSizeCheck | PASS | — |
| lifecycle/commitment_atomic.mutation-audit.yaml | muEnableCommitmentEmissionAtomic | PASS | — |
| verifier/cosignature.mutation-audit.yaml | muEnableCosignatureBinding | PASS | — |
| verifier/fraud_proofs.mutation-audit.yaml | muEnableFraudProofValidation | PASS | — |
| witness/verify.mutation-audit.yaml | muEnableWitnessQuorumCount | PASS | — |
| witness/verify.mutation-audit.yaml | muEnableEquivocationDetection | PASS | — |

## 2026-04-25T01:19:36Z — audit-v775 mutation

| Registry | Gate | Result | Note |
| --- | --- | --- | --- |
| crypto/escrow/vss_v2.mutation-audit.yaml | muEnableReconstructVersionCheck | PASS | — |
| crypto/escrow/vss_v2.mutation-audit.yaml | muEnableReconstructShareVerification | PASS | — |
| exchange/identity/mapping_escrow_v2.mutation-audit.yaml | muEnableCommitmentEmissionAtomicV2 | PASS | — |
| lifecycle/artifact_access.mutation-audit.yaml | muEnableArtifactCommitmentRequired | PASS | — |
| lifecycle/artifact_access.mutation-audit.yaml | muEnableGrantAuthorizationCheck | PASS | — |
| lifecycle/artifact_access.mutation-audit.yaml | muEnableWitnessDeserialize | PASS | — |
| lifecycle/artifact_access.mutation-audit.yaml | muEnableWitnessPositionBinding | PASS | — |
| lifecycle/artifact_access.mutation-audit.yaml | muEnableWitnessIndependence | PASS | — |
| lifecycle/artifact_access.mutation-audit.yaml | muEnableReconstructSizeCheck | PASS | — |
| lifecycle/commitment_atomic.mutation-audit.yaml | muEnableCommitmentEmissionAtomic | PASS | — |
| verifier/cosignature.mutation-audit.yaml | muEnableCosignatureBinding | PASS | — |
| verifier/fraud_proofs.mutation-audit.yaml | muEnableFraudProofValidation | PASS | — |
| witness/verify.mutation-audit.yaml | muEnableWitnessQuorumCount | PASS | — |
| witness/verify.mutation-audit.yaml | muEnableEquivocationDetection | PASS | — |

## 2026-04-25T01:23:32Z — audit-v775 mutation

| Registry | Gate | Result | Note |
| --- | --- | --- | --- |
| core/envelope/serialize.mutation-audit.yaml | muEnableCanonicalOrdering | PASS | — |
| core/envelope/serialize.mutation-audit.yaml | muEnableSizeCap | PASS | — |
| core/envelope/serialize.mutation-audit.yaml | muEnableVersionReject | PASS | — |
| core/envelope/serialize.mutation-audit.yaml | muEnableDestinationBound | PASS | — |
| core/smt/verify.mutation-audit.yaml | muEnableRootMatch | PASS | — |
| core/smt/verify.mutation-audit.yaml | muEnableProofDepthBounds | PASS | — |
| core/smt/verify.mutation-audit.yaml | muEnableEmptyLeafDistinction | PASS | — |
| core/vss/h_generator.mutation-audit.yaml | muEnableHGeneratorLiftX | PASS | — |
| core/vss/h_generator.mutation-audit.yaml | HGeneratorSeedFlip | PASS | — |
| core/vss/pedersen.mutation-audit.yaml | muEnablePedersenIndexBounds | PASS | — |
| core/vss/pedersen.mutation-audit.yaml | muEnablePedersenOnCurveCheck | PASS | — |
| core/vss/transcript.mutation-audit.yaml | TranscriptDSTFlip | PASS | — |
| crypto/artifact/pre.mutation-audit.yaml | muEnableCommitmentsGate | PASS | — |
| crypto/artifact/pre.mutation-audit.yaml | muEnableOnCurveGate | PASS | — |
| crypto/artifact/pre.mutation-audit.yaml | muEnableDLEQCheck | PASS | — |
| crypto/artifact/pre.mutation-audit.yaml | muEnablePedersenCheck | PASS | — |
| crypto/artifact/pre.mutation-audit.yaml | muEnableSufficientCFragsGate | PASS | — |
| crypto/artifact/pre.mutation-audit.yaml | muEnableVerifyBeforeCombine | PASS | — |
| crypto/artifact/pre.mutation-audit.yaml | muEnableKFragReservedCheck | PASS | — |
| crypto/artifact/pre.mutation-audit.yaml | muEnableCommitmentOnCurveGate | PASS | — |
| crypto/artifact/pre.mutation-audit.yaml | muEnableCommitmentSetLengthCheck | PASS | — |
| crypto/artifact/pre.mutation-audit.yaml | muEnableThresholdBoundsCheck | PASS | — |
| crypto/artifact/pre.mutation-audit.yaml | muEnableSplitIDRecomputation | PASS | — |
| crypto/escrow/split_commitment.mutation-audit.yaml | muEnableEscrowCommitmentOnCurveGate | PASS | — |
| crypto/escrow/split_commitment.mutation-audit.yaml | muEnableEscrowCommitmentSetLengthCheck | PASS | — |
| crypto/escrow/split_commitment.mutation-audit.yaml | muEnableEscrowThresholdBoundsCheck | PASS | — |
| crypto/escrow/split_commitment.mutation-audit.yaml | muEnableEscrowSplitIDRecomputation | PASS | — |
| crypto/escrow/verify_share.mutation-audit.yaml | muEnableV1FieldEmptyCheck | PASS | — |
| crypto/escrow/verify_share.mutation-audit.yaml | muEnableV2FieldPopulatedCheck | PASS | — |
| crypto/escrow/verify_share.mutation-audit.yaml | muEnableShareIndexNonZero | PASS | — |
| crypto/escrow/verify_share.mutation-audit.yaml | muEnableSplitIDPresent | PASS | — |
| crypto/escrow/verify_share.mutation-audit.yaml | muEnableFieldTagDiscrimination | PASS | — |
| crypto/escrow/vss_v2.mutation-audit.yaml | muEnableEscrowSecretSizeCheck | PASS | — |
| crypto/escrow/vss_v2.mutation-audit.yaml | muEnableEscrowDealerDIDNonEmpty | PASS | — |
| crypto/escrow/vss_v2.mutation-audit.yaml | muEnableEscrowThresholdBounds | PASS | — |
| crypto/escrow/vss_v2.mutation-audit.yaml | muEnableReconstructVersionCheck | PASS | — |
| crypto/escrow/vss_v2.mutation-audit.yaml | muEnableReconstructShareVerification | PASS | — |
| crypto/signatures/bls_verifier.mutation-audit.yaml | muEnableBLSSubgroupCheck | PASS | — |
| crypto/signatures/bls_verifier.mutation-audit.yaml | muEnableBLSPoPVerify | PASS | — |
| crypto/signatures/bls_verifier.mutation-audit.yaml | BLSPoPDomainTagFlip | PASS | — |
| crypto/signatures/bls_verifier.mutation-audit.yaml | muEnableBLSAggregateVerify | PASS | — |
| crypto/signatures/entry_verify.mutation-audit.yaml | muEnableEntrySignatureVerify | PASS | — |
| crypto/signatures/entry_verify.mutation-audit.yaml | muEnablePubKeyOnCurve | PASS | — |
| crypto/signatures/entry_verify.mutation-audit.yaml | muEnableSignatureLength | PASS | — |
| exchange/identity/mapping_escrow_v2.mutation-audit.yaml | muEnableCommitmentEmissionAtomicV2 | PASS | — |
| lifecycle/artifact_access.mutation-audit.yaml | muEnableArtifactCommitmentRequired | PASS | — |
| lifecycle/artifact_access.mutation-audit.yaml | muEnableGrantAuthorizationCheck | PASS | — |
| lifecycle/artifact_access.mutation-audit.yaml | muEnableWitnessDeserialize | PASS | — |
| lifecycle/artifact_access.mutation-audit.yaml | muEnableWitnessPositionBinding | PASS | — |
| lifecycle/artifact_access.mutation-audit.yaml | muEnableWitnessIndependence | PASS | — |
| lifecycle/artifact_access.mutation-audit.yaml | muEnableReconstructSizeCheck | PASS | — |
| lifecycle/commitment_atomic.mutation-audit.yaml | muEnableCommitmentEmissionAtomic | PASS | — |
| verifier/cosignature.mutation-audit.yaml | muEnableCosignatureBinding | PASS | — |
| verifier/fraud_proofs.mutation-audit.yaml | muEnableFraudProofValidation | PASS | — |
| witness/verify.mutation-audit.yaml | muEnableWitnessQuorumCount | PASS | — |
| witness/verify.mutation-audit.yaml | muEnableEquivocationDetection | PASS | — |

## 2026-04-25T01:59:05Z — audit-v775 mutation (Group 6.3 scope)

Phase C Group 6.3 extends mutation-audit discipline one layer deeper:
VerifyAndDecryptArtifact's commitment-required invariant (existing),
CheckGrantAuthorization's two internal membership checks (new),
EvaluateArbitration's IsCosignatureOf binding and EscrowNodeSet
independence (existing). The two new switches
(muEnableGrantAuthoritySetMembership,
muEnableAuthorizedRecipientMembership) ship with dedicated binding
tests; the three cross-referenced existing switches pass via their
Group 6.2 binding tests.

| Registry | Gate | Result | Note |
| --- | --- | --- | --- |
| lifecycle/artifact_access.mutation-audit.yaml | muEnableArtifactCommitmentRequired | PASS | Group 6.3 cross-ref (existing 6.2 gate) |
| lifecycle/artifact_access.mutation-audit.yaml | muEnableWitnessPositionBinding | PASS | Group 6.3 cross-ref (existing 6.2 gate) |
| lifecycle/artifact_access.mutation-audit.yaml | muEnableWitnessIndependence | PASS | Group 6.3 cross-ref (existing 6.2 gate) |
| lifecycle/artifact_access.mutation-audit.yaml | muEnableGrantAuthoritySetMembership | PASS | Group 6.3 new gate |
| lifecycle/artifact_access.mutation-audit.yaml | muEnableAuthorizedRecipientMembership | PASS | Group 6.3 new gate |

