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

## 2026-04-24T22:38:46Z — audit-v775 mutation

| Registry | Gate | Result | Note |
| --- | --- | --- | --- |
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
| lifecycle/commitment_atomic.mutation-audit.yaml | muEnableCommitmentEmissionAtomic | PASS | — |

