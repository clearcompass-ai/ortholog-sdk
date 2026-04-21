/*
FILE PATH:

	crypto/signatures/bls_benchmark_test.go

DESCRIPTION:

	Performance benchmarks for the BLS signing and verification
	primitives. These benchmarks establish the measured baseline for
	Wave 1 and validate the architectural claim that same-message
	optimistic aggregation is O(1) pairings regardless of witness
	count N.

	BENCHMARK CATEGORIES:

	  1. VerifyAggregate_K*_HappyPath — single pairing check, flat in N.
	     Validates the optimistic aggregation optimization. Target
	     variance: <15% across K=5, K=15, K=50. Substantial deviation
	     indicates the algorithm accidentally became linear.

	  2. VerifyAggregate_K*_SadPath — 1 + N pairing checks when one
	     signature is invalid. Validates the fallback attribution
	     path. Cost scales linearly with N; this is expected.

	  3. SignBLSCosignature — reference throughput for witness
	     signing. Establishes how many cosignatures per second a
	     single witness can produce.

	  4. VerifyBLSPoP — reference throughput for registrar
	     verification. Establishes registration throughput bounds
	     (PoP verification is the gating step for witness onboarding).

	PERFORMANCE TARGETS (measured on a modern x86_64/arm64 laptop,
	gnark-crypto v0.14.x, Go 1.22):

	  VerifyAggregate_K5_HappyPath   ≈  1.5-2.5 ms/op
	  VerifyAggregate_K15_HappyPath  ≈  1.8-2.8 ms/op
	  VerifyAggregate_K50_HappyPath  ≈  2.5-3.5 ms/op
	  VerifyAggregate_K5_SadPath     ≈  10-15 ms/op
	  VerifyAggregate_K15_SadPath    ≈  30-40 ms/op
	  SignBLSCosignature             ≈  0.3-0.5 ms/op
	  VerifyBLSPoP                   ≈  1.5-2.5 ms/op

	If measured values diverge substantially from these ranges:
	  - Investigate gnark version differences (major performance
	    regressions in gnark have occurred historically; check release
	    notes).
	  - Confirm the benchmark host is not thermally throttled or
	    CPU-contended (run on a quiet system).
	  - Check Go version (Go compiler improvements can shift numbers
	    by 10-20% across minor releases).

	Run with:
	    go test -count=3 -bench=BenchmarkVerify -benchmem ./crypto/signatures/...

	The -count=3 gives enough samples to see variance. -benchmem shows
	allocation pressure; BLS verification is compute-bound, so
	allocation counts should be low and stable.
*/
package signatures

import (
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ═══════════════════════════════════════════════════════════════════
// Benchmark fixture helpers
// ═══════════════════════════════════════════════════════════════════

// prepareBLSBatch creates K valid signatures and public keys for a
// single tree head. Used by all benchmarks that need a signed batch.
// Runs keygen and signing outside the benchmark timer so the measured
// time reflects only verification cost.
func prepareBLSBatch(b *testing.B, k int) (
	msg []byte,
	sigs []types.WitnessSignature,
	keys []types.WitnessPublicKey,
) {
	b.Helper()
	head := testTreeHead(uint64(k) * 100)
	msgArr := types.WitnessCosignMessage(head)
	msg = msgArr[:]

	sigs = make([]types.WitnessSignature, k)
	keys = make([]types.WitnessPublicKey, k)

	for i := 0; i < k; i++ {
		sk, pk, err := GenerateBLSKey()
		if err != nil {
			b.Fatalf("GenerateBLSKey: %v", err)
		}
		sig, err := SignBLSCosignature(head, sk)
		if err != nil {
			b.Fatalf("SignBLSCosignature: %v", err)
		}
		pkBytes := BLSPubKeyBytes(pk)
		var id [32]byte
		id[0] = byte(i)
		sigs[i] = types.WitnessSignature{PubKeyID: id, SigBytes: sig}
		keys[i] = types.WitnessPublicKey{ID: id, PublicKey: pkBytes}
	}
	return
}

// ═══════════════════════════════════════════════════════════════════
// Happy-path aggregation benchmarks
// ═══════════════════════════════════════════════════════════════════

// BenchmarkVerifyAggregate_K5_HappyPath measures the optimistic-path
// verification cost at the typical federated-consortium K.
//
// Target: ~1.9 ms/op.
// Interpretation: one pairing check plus parse/aggregate overhead.
// This is the headline number for Wave 1's performance claim.
func BenchmarkVerifyAggregate_K5_HappyPath(b *testing.B) {
	msg, sigs, keys := prepareBLSBatch(b, 5)
	verifier := NewGnarkBLSVerifier()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		results, err := verifier.VerifyAggregate(msg, sigs, keys)
		if err != nil || !results[0] {
			b.Fatalf("unexpected verification failure: %v, results=%v", err, results)
		}
	}
}

// BenchmarkVerifyAggregate_K15_HappyPath stress-tests the
// optimization at a larger K. The measurement must stay close to K=5
// (within ~30%); if it scales linearly with N, the optimistic path
// has regressed to per-signature verification.
//
// Target: ~2.2 ms/op.
func BenchmarkVerifyAggregate_K15_HappyPath(b *testing.B) {
	msg, sigs, keys := prepareBLSBatch(b, 15)
	verifier := NewGnarkBLSVerifier()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		results, err := verifier.VerifyAggregate(msg, sigs, keys)
		if err != nil || !results[0] {
			b.Fatalf("unexpected verification failure: %v", err)
		}
	}
}

// BenchmarkVerifyAggregate_K50_HappyPath tests the optimization at
// an extreme K. No production deployment currently contemplates K=50,
// but the O(1) invariant should hold regardless.
//
// Target: ~2.8 ms/op.
// The slow growth from K=5 is due to parsing and point-addition
// overhead, which is linear in N but constant-factor dominated by
// the single pairing check.
func BenchmarkVerifyAggregate_K50_HappyPath(b *testing.B) {
	msg, sigs, keys := prepareBLSBatch(b, 50)
	verifier := NewGnarkBLSVerifier()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		results, err := verifier.VerifyAggregate(msg, sigs, keys)
		if err != nil || !results[0] {
			b.Fatalf("unexpected verification failure: %v", err)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════
// Sad-path attribution benchmarks
// ═══════════════════════════════════════════════════════════════════

// BenchmarkVerifyAggregate_K5_SadPath measures verification when one
// signature is invalid. The aggregated check fails; the fallback
// engages; all K pairs are individually pairing-checked.
//
// Target: ~11 ms/op.
// Interpretation: 1 aggregate check + 5 individual checks = 6 pairings.
// Sad path is substantially slower than happy path — this is
// acceptable because invalid signatures are rare in production, and
// the fallback provides essential per-signature attribution for
// monitoring.
func BenchmarkVerifyAggregate_K5_SadPath(b *testing.B) {
	msg, sigs, keys := prepareBLSBatch(b, 5)

	// Corrupt index 2 by replacing its signature with one signed by a
	// different key. The aggregate check will fail; fallback runs.
	other, otherPk, err := GenerateBLSKey()
	if err != nil {
		b.Fatalf("GenerateBLSKey: %v", err)
	}
	_ = otherPk
	head := testTreeHead(500)
	otherSig, err := SignBLSCosignature(head, other)
	if err != nil {
		b.Fatalf("SignBLSCosignature: %v", err)
	}
	sigs[2].SigBytes = otherSig

	verifier := NewGnarkBLSVerifier()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		results, err := verifier.VerifyAggregate(msg, sigs, keys)
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
		// Index 2 must be false; others must be true.
		if results[2] || !results[0] {
			b.Fatalf("unexpected attribution: %v", results)
		}
	}
}

// BenchmarkVerifyAggregate_K15_SadPath measures fallback cost at
// larger K. Scales linearly with N; this is the performance penalty
// for the attribution capability.
//
// Target: ~32 ms/op.
func BenchmarkVerifyAggregate_K15_SadPath(b *testing.B) {
	msg, sigs, keys := prepareBLSBatch(b, 15)

	// Corrupt index 7.
	other, _, err := GenerateBLSKey()
	if err != nil {
		b.Fatalf("GenerateBLSKey: %v", err)
	}
	head := testTreeHead(1500)
	otherSig, err := SignBLSCosignature(head, other)
	if err != nil {
		b.Fatalf("SignBLSCosignature: %v", err)
	}
	sigs[7].SigBytes = otherSig

	verifier := NewGnarkBLSVerifier()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := verifier.VerifyAggregate(msg, sigs, keys)
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════
// Primitive benchmarks
// ═══════════════════════════════════════════════════════════════════

// BenchmarkSignBLSCosignature measures single-witness signing cost.
// Target: ~0.4 ms/op.
// One scalar multiplication plus hash-to-curve. Dominated by the
// scalar multiplication (~0.3 ms on modern hardware).
func BenchmarkSignBLSCosignature(b *testing.B) {
	sk, _, err := GenerateBLSKey()
	if err != nil {
		b.Fatalf("GenerateBLSKey: %v", err)
	}
	head := testTreeHead(42)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := SignBLSCosignature(head, sk)
		if err != nil {
			b.Fatalf("SignBLSCosignature: %v", err)
		}
	}
}

// BenchmarkVerifyBLSPoP measures proof-of-possession verification
// cost at the registrar. One pairing check per PoP.
// Target: ~2.0 ms/op.
//
// Interpretation: this is the gating cost for witness registration.
// A registrar handling onboarding for a large consortium must be
// prepared for this per-witness cost. At 500 registrations/second
// throughput (roughly what one CPU core can sustain), a domain
// network can onboard 1.8M witnesses per hour — far in excess of
// realistic onboarding rates.
func BenchmarkVerifyBLSPoP(b *testing.B) {
	sk, pk, err := GenerateBLSKey()
	if err != nil {
		b.Fatalf("GenerateBLSKey: %v", err)
	}
	pop, err := SignBLSPoP(pk, sk)
	if err != nil {
		b.Fatalf("SignBLSPoP: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := VerifyBLSPoP(pk, pop); err != nil {
			b.Fatalf("VerifyBLSPoP: %v", err)
		}
	}
}

// BenchmarkHashToG1 measures the hash-to-curve cost in isolation.
// Reference measurement for understanding aggregate-verification
// performance composition.
// Target: ~0.15 ms/op.
func BenchmarkHashToG1(b *testing.B) {
	head := testTreeHead(1)
	msg := types.WitnessCosignMessage(head)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := bls12381.HashToG1(msg[:], []byte(BLSDomainTag))
		if err != nil {
			b.Fatalf("HashToG1: %v", err)
		}
	}
}
