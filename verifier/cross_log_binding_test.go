// Package verifier — cross_log_binding_test.go holds the Group 8.2
// binding tests for the four cross_log.go gates whose ORTHO-BUG-001
// matrix counterpart passes with the gate off because a downstream
// check (usually the next step in the nine-step flow) catches the
// same bad input via a more general error type.
//
// These tests assert the gate-SPECIFIC error by error type or
// message substring, so the mutation-audit runner observes the
// switch flip as a test failure:
//
//   muEnableExtractorRequired   → TestCrossLog_ExtractorRequired_Binding
//   muEnableSourceEntryNonZero  → TestCrossLog_SourceEntryNonZero_Binding
//   muEnableSourceHeadCosigVerify → TestCrossLog_SourceHeadCosigVerify_Binding
//   muEnableLocalInclusionVerify → TestCrossLog_LocalInclusionVerify_Binding
//
// The other six gates are bound by existing ORTHO-BUG-001 tests that
// assert specific error sentinels and are already load-bearing; those
// are cross-registered in cross_log.mutation-audit.yaml.
package verifier

import (
	"errors"
	"strings"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// muEnableExtractorRequired
// ─────────────────────────────────────────────────────────────────────

// TestCrossLog_ExtractorRequired_Binding asserts the specific
// ErrExtractorRequired sentinel surfaces when extractAnchor is nil.
// The existing TestVerifyCrossLogProof_RejectsNilExtractor only
// asserts err != nil, which passes with the gate off (because the
// function falls through to step 10 and returns ErrAnchorMismatch
// from the zero-valued embeddedRef check). Asserting the specific
// sentinel makes the gate load-bearing.
func TestCrossLog_ExtractorRequired_Binding(t *testing.T) {
	proof, _, _, witnessKeys := buildWellFormedProof(t)

	err := VerifyCrossLogProof(*proof, witnessKeys, 1, nil, nil)
	if err == nil {
		t.Fatal("VerifyCrossLogProof accepted nil extractor")
	}
	if !errors.Is(err, ErrExtractorRequired) {
		t.Fatalf("want ErrExtractorRequired, got %v (muEnableExtractorRequired not load-bearing?)", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// muEnableSourceEntryNonZero
// ─────────────────────────────────────────────────────────────────────

// TestCrossLog_SourceEntryNonZero_Binding asserts the
// "zero source entry hash" error specifically. With the gate on, step
// 1 rejects before step 2 runs. With the gate off, step 2's inclusion-
// binding check catches the same bad input but produces a generic
// "inclusion leaf hash %x does not match" message — the error sentinel
// is still ErrSourceInclusionFailed. Distinguishing the two checks
// requires asserting the message substring.
func TestCrossLog_SourceEntryNonZero_Binding(t *testing.T) {
	proof, _, _, witnessKeys := buildWellFormedProof(t)
	proof.SourceEntryHash = [32]byte{}
	// With the gate on, step 1 fires on the zero check and never
	// reaches step 2. Also zero the inclusion proof's LeafHash so
	// step 2 would accept it when step 1 is skipped — removing this
	// line would make step 2 catch the zero input via the mismatch
	// path, which is the current "gate off" behavior.
	proof.SourceInclusion.LeafHash = [32]byte{}

	err := defaultArgs(witnessKeys).call(*proof)
	if err == nil {
		t.Fatal("verifier accepted zero SourceEntryHash with matching zero LeafHash")
	}
	if !strings.Contains(err.Error(), "zero source entry hash") {
		t.Fatalf("want 'zero source entry hash' error, got %v (muEnableSourceEntryNonZero not load-bearing?)", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// muEnableSourceHeadCosigVerify
// ─────────────────────────────────────────────────────────────────────

// TestCrossLog_SourceHeadCosigVerify_Binding asserts the source tree
// head cosignature-verification path fires on an under-quorum head.
// We pass quorumK = len(witnessKeys) + 1 so witness.VerifyTreeHead's
// quorum pre-check triggers; with the gate on, VerifyCrossLogProof
// wraps that failure in ErrSourceHeadInvalid. With the gate off,
// step 4 is skipped and step 5 fires instead with a completely
// different error (LeafHash mismatch if we tamper, or nil-pass
// through). Asserting ErrSourceHeadInvalid makes the gate load-bearing.
func TestCrossLog_SourceHeadCosigVerify_Binding(t *testing.T) {
	proof, _, _, witnessKeys := buildWellFormedProof(t)

	args := defaultArgs(witnessKeys)
	// Demand more signatures than the witness set size so
	// witness.VerifyTreeHead's `len(witnessKeys) < quorumK`
	// pre-check fires and returns an error.
	args.quorumK = len(witnessKeys) + 1

	err := args.call(*proof)
	if err == nil {
		t.Fatal("verifier accepted proof with over-threshold quorum requirement")
	}
	if !errors.Is(err, ErrSourceHeadInvalid) {
		t.Fatalf("want ErrSourceHeadInvalid, got %v (muEnableSourceHeadCosigVerify not load-bearing?)", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// muEnableLocalInclusionVerify
// ─────────────────────────────────────────────────────────────────────

// TestCrossLog_LocalInclusionVerify_Binding asserts the local
// inclusion Merkle verification path fires on a corrupted local path.
// The proof keeps LocalInclusion.LeafHash equal to AnchorEntryHash
// (step 5 passes) but the Merkle path itself is corrupted (step 6
// fails). With the gate on, ErrLocalInclusionFailed surfaces. With
// the gate off, step 6 is skipped entirely and the function proceeds
// to the anchor-payload binding checks — either succeeding on a well-
// formed payload (which is the default fixture) or failing with a
// different error type.
func TestCrossLog_LocalInclusionVerify_Binding(t *testing.T) {
	proof, _, _, witnessKeys := buildWellFormedProof(t)

	// Corrupt the local Merkle path while leaving LeafHash intact.
	// The path length is preserved so VerifyMerkleInclusion doesn't
	// reject on shape; only the hash values are clobbered so the
	// root-recomputation fails.
	for i := range proof.LocalInclusion.Siblings {
		proof.LocalInclusion.Siblings[i] = [32]byte{0xFF, 0xFF}
	}
	// Sanity: assert we didn't accidentally change LeafHash.
	if proof.LocalInclusion.LeafHash != proof.AnchorEntryHash {
		t.Fatal("fixture drift: tampered LocalInclusion.LeafHash; test needs update")
	}
	// Sanity: the path must be non-empty for the corruption to mean
	// anything. If the fixture produced a zero-length path this test
	// would pass vacuously.
	if len(proof.LocalInclusion.Siblings) == 0 {
		t.Skip("fixture yielded empty LocalInclusion path; gate cannot be exercised against it")
	}

	err := defaultArgs(witnessKeys).call(*proof)
	if err == nil {
		t.Fatal("verifier accepted proof with corrupted LocalInclusion path")
	}
	if !errors.Is(err, ErrLocalInclusionFailed) {
		t.Fatalf("want ErrLocalInclusionFailed, got %v (muEnableLocalInclusionVerify not load-bearing?)", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Unused-import guard
// ─────────────────────────────────────────────────────────────────────

var _ = types.LogPosition{}
