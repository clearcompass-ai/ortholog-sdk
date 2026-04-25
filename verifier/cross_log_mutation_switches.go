// Package verifier — cross_log_mutation_switches.go holds the
// Group 8.2 mutation-audit switches for the nine-step cross-log
// proof verification in cross_log.go, plus the extractor-required
// fail-fast guard. Declared in their own file so the audit-v775
// runner's line-local rewrite can target exactly one declaration
// per gate.
//
//	┌─────────────────────────────────────────────────────────────┐
//	│  STOP. READ THIS BEFORE MODIFYING ANY muEnable* CONSTANT.   │
//	├─────────────────────────────────────────────────────────────┤
//	│  These constants gate the ten verification checks inside    │
//	│  VerifyCrossLogProof. Setting any to false permanently      │
//	│  re-opens one row of the ORTHO-BUG-001 attack matrix:       │
//	│                                                             │
//	│    muEnableExtractorRequired        — A9 nil-extractor      │
//	│    muEnableSourceEntryNonZero       — degenerate zero hash  │
//	│    muEnableSourceInclusionBinding   — A1 source entry swap  │
//	│    muEnableSourceInclusionVerify    — A2 inclusion forge    │
//	│    muEnableSourceHeadCosigVerify    — A3 fake source head   │
//	│    muEnableLocalInclusionBinding    — A6 local incl. swap   │
//	│    muEnableLocalInclusionVerify     — A2 local incl. forge  │
//	│    muEnableAnchorBytesHashBinding   — A7 substituted bytes  │
//	│    muEnableAnchorPayloadExtraction  — A8 tampered payload   │
//	│    muEnableAnchorContentBinding     — A4 forged anchor      │
//	│                                                             │
//	│  Binding tests live in cross_log_test.go (ORTHO-BUG-001     │
//	│  attack-matrix suite); the registry cross-references each   │
//	│  gate to the test that asserts its specific attack vector.  │
//	└─────────────────────────────────────────────────────────────┘
package verifier

// muEnableExtractorRequired gates the fail-fast guard that rejects
// VerifyCrossLogProof calls with a nil AnchorPayloadExtractor. On,
// the guard returns ErrExtractorRequired before any verification
// runs. Off, the call proceeds and the content-binding check (step 9)
// becomes reachable only via nil-deref panic — a degenerate failure
// mode that re-opens the Forged Anchor Attack. Binding test:
// TestVerifyCrossLogProof_RejectsNilExtractor.
const muEnableExtractorRequired = true

// muEnableSourceEntryNonZero gates the zero-hash check at step 1.
// On, a CrossLogProof with SourceEntryHash == [32]byte{} is rejected
// before any Merkle arithmetic runs. Off, the walk proceeds and the
// downstream inclusion-binding check (step 2) catches the same
// degenerate input — but the error classification is less specific
// and the shape of the attack is harder to recognize. Binding test:
// TestVerifyCrossLogProof_RejectsZeroSourceEntryHash.
const muEnableSourceEntryNonZero = true

// muEnableSourceInclusionBinding gates the
// SourceInclusion.LeafHash == SourceEntryHash check at step 2. On, a
// proof whose inclusion proof references a different leaf than the
// claimed source entry hash is rejected. Off, the downstream Merkle
// verification succeeds on whatever leaf the proof carries and the
// claimed source entry is trusted without cryptographic binding —
// ORTHO-BUG-001 A1 source-entry-swap. Binding test:
// TestVerifyCrossLogProof_RejectsForgedSourceEntryHash.
const muEnableSourceInclusionBinding = true

// muEnableSourceInclusionVerify gates the
// smt.VerifyMerkleInclusion call at step 3. On, the inclusion proof
// is verified against SourceTreeHead.RootHash. Off, a forged proof
// passes through and the source tree head is trusted without
// cryptographic evidence of inclusion — ORTHO-BUG-001 A2. Binding
// test: TestVerifyCrossLogProof_RejectsCorruptedSourceInclusion.
const muEnableSourceInclusionVerify = true

// muEnableSourceHeadCosigVerify gates the witness.VerifyTreeHead
// call at step 4. On, the source tree head is required to carry
// K-of-N valid witness cosignatures. Off, an attacker-controlled
// tree head passes through and cross-log proofs can be manufactured
// against it — ORTHO-BUG-001 A3. Binding test lives at the witness
// package level; cross-registered integration coverage is in
// tests/cross_log_test.go.
const muEnableSourceHeadCosigVerify = true

// muEnableLocalInclusionBinding gates the
// LocalInclusion.LeafHash == AnchorEntryHash check at step 5. On, a
// proof whose local inclusion proof references a different leaf than
// the claimed anchor hash is rejected. Off, the local tree head is
// trusted without binding — ORTHO-BUG-001 A6. Binding test:
// TestVerifyCrossLogProof_RejectsForgedAnchorEntryHash.
const muEnableLocalInclusionBinding = true

// muEnableLocalInclusionVerify gates the smt.VerifyMerkleInclusion
// call at step 6. On, the local inclusion proof is verified against
// LocalTreeHead.RootHash. Off, a forged proof passes through and
// the local tree head is trusted without evidence of anchor
// inclusion — parallel to A2 on the local side. Binding test:
// TestVerifyCrossLogProof_RejectsCorruptedLocalInclusion.
const muEnableLocalInclusionVerify = true

// muEnableAnchorBytesHashBinding gates the step-7 check that the
// CanonicalBytes carried in the proof actually hash to
// AnchorEntryHash. On, byte substitution is detected. Off, the
// verifier deserializes attacker-supplied bytes whose hash was never
// proven into any Merkle tree — ORTHO-BUG-001 A7. Binding test:
// TestVerifyCrossLogProof_RejectsSubstitutedAnchorBytes.
const muEnableAnchorBytesHashBinding = true

// muEnableAnchorPayloadExtraction gates the extractor error-
// propagation path at step 8-9. On, an extractor error bubbles up
// and the proof is rejected. Off, extractor errors are silenced and
// the content-binding check at step 10 runs against a zero-valued
// ref — the payload-tamper defense collapses. Binding test:
// TestVerifyCrossLogProof_PropagatesExtractorError.
const muEnableAnchorPayloadExtraction = true

// muEnableAnchorContentBinding gates the final step-10 check that
// the tree-head-ref embedded in the anchor's DomainPayload matches
// TreeHeadHash(SourceTreeHead). On, the payload commits explicitly
// to the source head. Off, an anchor entry committing to a different
// tree head is accepted and every cross-log proof becomes
// unverifiable — ORTHO-BUG-001 A4 Forged Anchor. Binding test:
// TestVerifyCrossLogProof_RejectsMismatchedExtractorResult (covers
// the ref-mismatch path specifically).
const muEnableAnchorContentBinding = true
