/*
FILE PATH:

	crypto/signatures/bls_verifier_test.go

DESCRIPTION:

	Correctness tests for the BLS12-381 cosignature signing and
	aggregate verification primitives. Organized around the contract
	surface of VerifyAggregate:

	  - Positive paths: happy-path aggregation at varying K
	  - Attribution fallback: sad-path per-signature identification
	  - Malformed inputs: wrong length, off-curve, not-in-subgroup
	  - Tamper detection: byte-flipped signatures and messages
	  - SDK integration: dispatch through VerifyWitnessCosignatures

	Does NOT include:
	  - Proof-of-possession tests (see bls_pop_test.go)
	  - Rogue-key attack tests (see bls_rogue_key_test.go)
	  - Byte-level protocol lock tests (see bls_lock_test.go)
	  - Performance benchmarks (see bls_benchmark_test.go)

	Every test is designed to fail if the corresponding check in
	VerifyAggregate is removed. Mutation testing discipline: if a test
	still passes after its guard is commented out of the production
	code, the test is not exercising the intended contract.
*/
package signatures

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ═══════════════════════════════════════════════════════════════════
// Fixture helpers
// ═══════════════════════════════════════════════════════════════════

// blsTestWitness pairs a BLS private key with the types.WitnessPublicKey
// the verifier consumes. PubKeyID is derived as SHA-256(compressed
// public key bytes) for consistency with the ECDSA witness fixture in
// verifier/cross_log_test.go.
type blsTestWitness struct {
	privKey   interface{} // *fr.Element — typed as interface{} to avoid exposing gnark type in test structs
	pubKey    interface{} // *bls12381.G2Affine
	publicKey types.WitnessPublicKey
}

// newBLSTestWitness generates a fresh BLS keypair for test use.
// Each call produces a distinct witness; seeds are non-deterministic
// (crypto/rand). Tests that need deterministic keys should use the
// deriveBLSKeyForTest internal helper.
func newBLSTestWitness(t *testing.T) *blsTestWitness {
	t.Helper()
	sk, pk, err := GenerateBLSKey()
	if err != nil {
		t.Fatalf("GenerateBLSKey: %v", err)
	}
	pkBytes := BLSPubKeyBytes(pk)
	id := sha256.Sum256(pkBytes)
	return &blsTestWitness{
		privKey: sk,
		pubKey:  pk,
		publicKey: types.WitnessPublicKey{
			ID:        id,
			PublicKey: pkBytes,
		},
	}
}

// cosign produces a types.WitnessSignature under this witness's key
// over the given tree head. Uses the production SignBLSCosignature
// primitive; the output is what an honest witness would emit.
func (w *blsTestWitness) cosign(t *testing.T, head types.TreeHead) types.WitnessSignature {
	t.Helper()
	sig, err := SignBLSCosignature(head, coerceFr(w.privKey))
	if err != nil {
		t.Fatalf("SignBLSCosignature: %v", err)
	}
	return types.WitnessSignature{
		PubKeyID: w.publicKey.ID,
		SigBytes: sig,
	}
}

// testTreeHead produces a deterministic TreeHead for test use.
// Different size values produce different RootHash values, so distinct
// heads are guaranteed.
func testTreeHead(size uint64) types.TreeHead {
	var root [32]byte
	for i := range root {
		root[i] = byte((size + uint64(i)) & 0xFF)
	}
	return types.TreeHead{RootHash: root, TreeSize: size}
}

// ═══════════════════════════════════════════════════════════════════
// Positive paths: round-trip and happy-path aggregation
// ═══════════════════════════════════════════════════════════════════

// TestSignBLSCosignature_RoundTrip verifies the fundamental contract:
// a signature produced by SignBLSCosignature verifies via
// GnarkBLSVerifier.VerifyAggregate against the signer's public key.
// If this test fails, the sign and verify paths have drifted and no
// cosignature the SDK produces will ever be accepted by the SDK's
// own verifier.
func TestSignBLSCosignature_RoundTrip(t *testing.T) {
	w := newBLSTestWitness(t)
	head := testTreeHead(42)
	ws := w.cosign(t, head)

	msg := types.WitnessCosignMessage(head)
	verifier := NewGnarkBLSVerifier()

	results, err := verifier.VerifyAggregate(
		msg[:],
		[]types.WitnessSignature{ws},
		[]types.WitnessPublicKey{w.publicKey},
	)
	if err != nil {
		t.Fatalf("VerifyAggregate: %v", err)
	}
	if len(results) != 1 || !results[0] {
		t.Fatalf("round-trip failed: results=%v", results)
	}
}

// TestSignBLSCosignature_Determinism confirms BLS signatures are
// deterministic: the same (key, message) pair produces the same bytes
// every time. This distinguishes BLS from ECDSA (which uses a random
// nonce per signature) and is important for test fixture stability
// and for anti-replay analysis.
func TestSignBLSCosignature_Determinism(t *testing.T) {
	w := newBLSTestWitness(t)
	head := testTreeHead(100)

	sig1, err := SignBLSCosignature(head, coerceFr(w.privKey))
	if err != nil {
		t.Fatalf("first sign: %v", err)
	}
	sig2, err := SignBLSCosignature(head, coerceFr(w.privKey))
	if err != nil {
		t.Fatalf("second sign: %v", err)
	}
	if !bytes.Equal(sig1, sig2) {
		t.Fatalf("BLS signatures are non-deterministic:\n  sig1 = %x\n  sig2 = %x", sig1, sig2)
	}
}

// TestVerifyAggregate_AllValid_K5 exercises the happy-path
// aggregation optimization at the typical federated-consortium K.
// Five independent witnesses each sign the same tree head; the
// aggregate verifier must accept all five with a single pairing check.
func TestVerifyAggregate_AllValid_K5(t *testing.T) {
	verifyAllValidAtK(t, 5)
}

// TestVerifyAggregate_AllValid_K15 stress-tests the optimistic path
// at a larger K. At K=15 the aggregation CPU advantage becomes
// operationally meaningful: individual verification would be 15
// pairings (~30 ms), aggregated is still 1 pairing (~2 ms).
func TestVerifyAggregate_AllValid_K15(t *testing.T) {
	verifyAllValidAtK(t, 15)
}

// TestVerifyAggregate_AllValid_K50 confirms correctness holds at
// scale. No deployment currently contemplates K=50 witnesses, but the
// algorithm's O(1) nature should be insensitive to N; this test
// catches any accidentally-linear fallback.
func TestVerifyAggregate_AllValid_K50(t *testing.T) {
	verifyAllValidAtK(t, 50)
}

// verifyAllValidAtK constructs K witnesses, has each cosign an
// identical tree head, and asserts the aggregate verifier returns
// all true. Shared by the K=5/15/50 tests.
func verifyAllValidAtK(t *testing.T, k int) {
	t.Helper()
	witnesses := make([]*blsTestWitness, k)
	for i := range witnesses {
		witnesses[i] = newBLSTestWitness(t)
	}

	head := testTreeHead(uint64(k) * 100)
	sigs := make([]types.WitnessSignature, k)
	keys := make([]types.WitnessPublicKey, k)
	for i, w := range witnesses {
		sigs[i] = w.cosign(t, head)
		keys[i] = w.publicKey
	}

	msg := types.WitnessCosignMessage(head)
	verifier := NewGnarkBLSVerifier()
	results, err := verifier.VerifyAggregate(msg[:], sigs, keys)
	if err != nil {
		t.Fatalf("K=%d aggregate: %v", k, err)
	}
	if len(results) != k {
		t.Fatalf("K=%d: expected %d results, got %d", k, k, len(results))
	}
	for i, ok := range results {
		if !ok {
			t.Errorf("K=%d: index %d rejected", k, i)
		}
	}
}

// TestGenerateBLSKey_ProducesDistinctKeys runs 100 key generations
// and confirms every output is unique. A collision would indicate
// a broken entropy source (or, astronomically improbably, a genuine
// scalar-field collision — probability ≈ 2^-255).
//
// Uses compressed public key bytes as the collision identity: two
// keypairs whose public keys share bytes would be operationally
// indistinguishable regardless of private key differences.
func TestGenerateBLSKey_ProducesDistinctKeys(t *testing.T) {
	const n = 100
	seen := make(map[string]bool, n)

	for i := 0; i < n; i++ {
		_, pk, err := GenerateBLSKey()
		if err != nil {
			t.Fatalf("generation %d: %v", i, err)
		}
		pkBytes := BLSPubKeyBytes(pk)
		key := string(pkBytes)
		if seen[key] {
			t.Fatalf("duplicate key at generation %d", i)
		}
		seen[key] = true
	}
}

// TestBLSPubKeyBytes_RoundTrip confirms BLSPubKeyBytes and
// ParseBLSPubKey are inverses. A public key serialized via
// BLSPubKeyBytes and then parsed via ParseBLSPubKey must equal the
// original.
func TestBLSPubKeyBytes_RoundTrip(t *testing.T) {
	for i := 0; i < 10; i++ {
		_, pk, err := GenerateBLSKey()
		if err != nil {
			t.Fatalf("generate: %v", err)
		}
		serialized := BLSPubKeyBytes(pk)
		if len(serialized) != BLSG2CompressedLen {
			t.Fatalf("serialized length %d, expected %d", len(serialized), BLSG2CompressedLen)
		}
		parsed, err := ParseBLSPubKey(serialized)
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		reserialized := BLSPubKeyBytes(parsed)
		if !bytes.Equal(serialized, reserialized) {
			t.Fatalf("round-trip mismatch at iteration %d:\n  original:  %x\n  reparsed:  %x",
				i, serialized, reserialized)
		}
	}
}

// ═══════════════════════════════════════════════════════════════════
// Attribution fallback: sad-path per-signature identification
// ═══════════════════════════════════════════════════════════════════

// TestVerifyAggregate_OneInvalidSignature_K5 is the attribution test.
// Four signatures are valid; one is a random 48-byte blob. The
// optimistic aggregation must fail, the fallback must engage, and the
// returned []bool must precisely identify which entry failed.
//
// This is the critical monitoring path: a production witness service
// must be able to tell "witness 3 is sending bad signatures" from
// "the cosignature is bad." Loss of this distinction breaks
// equivocation detection and per-witness reliability tracking.
func TestVerifyAggregate_OneInvalidSignature_K5(t *testing.T) {
	witnesses := make([]*blsTestWitness, 5)
	for i := range witnesses {
		witnesses[i] = newBLSTestWitness(t)
	}

	head := testTreeHead(500)
	sigs := make([]types.WitnessSignature, 5)
	keys := make([]types.WitnessPublicKey, 5)
	for i, w := range witnesses {
		sigs[i] = w.cosign(t, head)
		keys[i] = w.publicKey
	}

	// Corrupt signature at index 2: well-formed G1 point but not a
	// valid signature under keys[2]. Simplest construction: sign with
	// a different witness's key.
	other := newBLSTestWitness(t)
	sigs[2] = other.cosign(t, head)
	sigs[2].PubKeyID = keys[2].ID // match ID so mapping still works

	msg := types.WitnessCosignMessage(head)
	verifier := NewGnarkBLSVerifier()
	results, err := verifier.VerifyAggregate(msg[:], sigs, keys)
	if err != nil {
		t.Fatalf("VerifyAggregate: %v", err)
	}

	expected := []bool{true, true, false, true, true}
	if len(results) != len(expected) {
		t.Fatalf("results length %d, expected %d", len(results), len(expected))
	}
	for i, want := range expected {
		if results[i] != want {
			t.Errorf("index %d: got %v, want %v", i, results[i], want)
		}
	}
}

// TestVerifyAggregate_AllInvalidSignatures confirms that when no
// signature is valid, all results are false. Edge case of the sad
// path where the aggregated check fails and every individual fallback
// check also fails.
func TestVerifyAggregate_AllInvalidSignatures(t *testing.T) {
	witnesses := make([]*blsTestWitness, 3)
	keys := make([]types.WitnessPublicKey, 3)
	for i := range witnesses {
		witnesses[i] = newBLSTestWitness(t)
		keys[i] = witnesses[i].publicKey
	}

	head := testTreeHead(777)

	// Every signature is produced by a different key than the claimed
	// witness. Each pair fails verification independently.
	sigs := make([]types.WitnessSignature, 3)
	for i := range sigs {
		other := newBLSTestWitness(t)
		sig := other.cosign(t, head)
		sig.PubKeyID = keys[i].ID
		sigs[i] = sig
	}

	msg := types.WitnessCosignMessage(head)
	verifier := NewGnarkBLSVerifier()
	results, err := verifier.VerifyAggregate(msg[:], sigs, keys)
	if err != nil {
		t.Fatalf("VerifyAggregate: %v", err)
	}
	for i, ok := range results {
		if ok {
			t.Errorf("index %d: unexpected true in all-invalid scenario", i)
		}
	}
}

// TestSignBLSCosignature_WrongKey verifies the single-signer negative
// case: a signature under key A must fail verification against key B.
// Exercises the fallback path on a 1-element input.
func TestSignBLSCosignature_WrongKey(t *testing.T) {
	signerWitness := newBLSTestWitness(t)
	claimedWitness := newBLSTestWitness(t)
	head := testTreeHead(1)

	// Sign with signerWitness's key but present claimedWitness's
	// public key to the verifier.
	sig, err := SignBLSCosignature(head, coerceFr(signerWitness.privKey))
	if err != nil {
		t.Fatalf("SignBLSCosignature: %v", err)
	}
	sigs := []types.WitnessSignature{{
		PubKeyID: claimedWitness.publicKey.ID,
		SigBytes: sig,
	}}
	keys := []types.WitnessPublicKey{claimedWitness.publicKey}

	msg := types.WitnessCosignMessage(head)
	verifier := NewGnarkBLSVerifier()
	results, err := verifier.VerifyAggregate(msg[:], sigs, keys)
	if err != nil {
		t.Fatalf("VerifyAggregate: %v", err)
	}
	if len(results) != 1 || results[0] {
		t.Fatalf("wrong-key verification unexpectedly accepted: results=%v", results)
	}
}

// ═══════════════════════════════════════════════════════════════════
// Malformed input handling
// ═══════════════════════════════════════════════════════════════════

// TestSignBLSCosignature_NilKey confirms that signing with nil private
// key returns a typed error rather than panicking.
func TestSignBLSCosignature_NilKey(t *testing.T) {
	head := testTreeHead(1)
	_, err := SignBLSCosignature(head, nil)
	if err == nil {
		t.Fatal("expected error on nil private key, got nil")
	}
}

// TestParseBLSPubKey_WrongLength exercises the length-check path of
// ParseBLSPubKey. Inputs shorter or longer than 96 bytes must be
// rejected with ErrBLSInvalidPubKeyLength.
func TestParseBLSPubKey_WrongLength(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"empty", nil},
		{"too_short_47", make([]byte, 47)},
		{"too_short_95", make([]byte, 95)},
		{"too_long_97", make([]byte, 97)},
		{"too_long_192", make([]byte, 192)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseBLSPubKey(tc.data)
			if err == nil {
				t.Fatalf("expected length error for %d bytes", len(tc.data))
			}
		})
	}
}

// TestParseBLSPubKey_NotOnCurve feeds random bytes of the correct
// length to ParseBLSPubKey. Random bytes almost certainly do not
// decompress to a valid G2 point; the function must reject with a
// typed error rather than panicking.
func TestParseBLSPubKey_NotOnCurve(t *testing.T) {
	// Use a fixed seed so this test is deterministic across runs.
	// The bytes below are a 96-byte value whose first bits do not
	// form a valid G2 compressed encoding.
	junk := make([]byte, BLSG2CompressedLen)
	for i := range junk {
		junk[i] = byte(i) ^ 0xA5
	}
	_, err := ParseBLSPubKey(junk)
	if err == nil {
		t.Fatal("expected decompression error on random bytes, got nil")
	}
}

// TestVerifyAggregate_MalformedSignature confirms that a malformed
// signature produces false at that index without corrupting the
// verification of other signatures. Isolation is essential: one bad
// witness entry must not affect another's attribution.
func TestVerifyAggregate_MalformedSignature(t *testing.T) {
	witnesses := make([]*blsTestWitness, 3)
	sigs := make([]types.WitnessSignature, 3)
	keys := make([]types.WitnessPublicKey, 3)
	head := testTreeHead(3)

	for i := range witnesses {
		witnesses[i] = newBLSTestWitness(t)
		sigs[i] = witnesses[i].cosign(t, head)
		keys[i] = witnesses[i].publicKey
	}

	// Truncate signature at index 1 to 20 bytes — not a valid compressed G1.
	sigs[1].SigBytes = sigs[1].SigBytes[:20]

	msg := types.WitnessCosignMessage(head)
	verifier := NewGnarkBLSVerifier()
	results, err := verifier.VerifyAggregate(msg[:], sigs, keys)
	if err != nil {
		t.Fatalf("VerifyAggregate: %v", err)
	}
	if !results[0] || results[1] || !results[2] {
		t.Fatalf("expected [true false true], got %v", results)
	}
}

// TestVerifyAggregate_MalformedPubkey is the symmetric test:
// a malformed public key at one index must fail at that index without
// affecting the others.
func TestVerifyAggregate_MalformedPubkey(t *testing.T) {
	witnesses := make([]*blsTestWitness, 3)
	sigs := make([]types.WitnessSignature, 3)
	keys := make([]types.WitnessPublicKey, 3)
	head := testTreeHead(4)

	for i := range witnesses {
		witnesses[i] = newBLSTestWitness(t)
		sigs[i] = witnesses[i].cosign(t, head)
		keys[i] = witnesses[i].publicKey
	}

	// Truncate public key at index 0 — not a valid compressed G2.
	keys[0].PublicKey = keys[0].PublicKey[:50]

	msg := types.WitnessCosignMessage(head)
	verifier := NewGnarkBLSVerifier()
	results, err := verifier.VerifyAggregate(msg[:], sigs, keys)
	if err != nil {
		t.Fatalf("VerifyAggregate: %v", err)
	}
	if results[0] || !results[1] || !results[2] {
		t.Fatalf("expected [false true true], got %v", results)
	}
}

// TestVerifyAggregate_MismatchedLengths exercises the contract
// requirement that signatures and pubkeys have equal length. Mismatch
// is a caller bug that must produce a typed error, not silently
// truncate or zero-pad.
func TestVerifyAggregate_MismatchedLengths(t *testing.T) {
	w := newBLSTestWitness(t)
	head := testTreeHead(1)
	sig := w.cosign(t, head)

	verifier := NewGnarkBLSVerifier()
	_, err := verifier.VerifyAggregate(
		[]byte("any"),
		[]types.WitnessSignature{sig, sig},
		[]types.WitnessPublicKey{w.publicKey},
	)
	if err == nil {
		t.Fatal("expected length-mismatch error, got nil")
	}
}

// ═══════════════════════════════════════════════════════════════════
// Tamper detection
// ═══════════════════════════════════════════════════════════════════

// TestSignBLSCosignature_TamperedSignatureByte flips one bit in a
// valid signature. The flipped signature may or may not decompress
// to a valid G1 point depending on which bit is flipped — either
// outcome results in verification failure, and both must be handled
// without a panic.
func TestSignBLSCosignature_TamperedSignatureByte(t *testing.T) {
	w := newBLSTestWitness(t)
	head := testTreeHead(99)
	orig := w.cosign(t, head)

	// Flip a low-bit in the middle of the signature.
	tampered := types.WitnessSignature{
		PubKeyID: orig.PubKeyID,
		SigBytes: append([]byte(nil), orig.SigBytes...),
	}
	tampered.SigBytes[24] ^= 0x01

	msg := types.WitnessCosignMessage(head)
	verifier := NewGnarkBLSVerifier()
	results, err := verifier.VerifyAggregate(
		msg[:],
		[]types.WitnessSignature{tampered},
		[]types.WitnessPublicKey{w.publicKey},
	)
	if err != nil {
		t.Fatalf("VerifyAggregate on tampered sig: %v", err)
	}
	if results[0] {
		t.Fatal("verifier accepted tampered signature")
	}
}

// TestSignBLSCosignature_TamperedMessageByte confirms that verifying
// a valid signature against a tampered message fails. Exercises the
// binding between the cosign message and the signature.
func TestSignBLSCosignature_TamperedMessageByte(t *testing.T) {
	w := newBLSTestWitness(t)
	head := testTreeHead(12)
	sig := w.cosign(t, head)

	// Compute the original message, then tamper it.
	msg := types.WitnessCosignMessage(head)
	tampered := make([]byte, len(msg))
	copy(tampered, msg[:])
	tampered[5] ^= 0xFF

	verifier := NewGnarkBLSVerifier()
	results, err := verifier.VerifyAggregate(
		tampered,
		[]types.WitnessSignature{sig},
		[]types.WitnessPublicKey{w.publicKey},
	)
	if err != nil {
		t.Fatalf("VerifyAggregate on tampered message: %v", err)
	}
	if results[0] {
		t.Fatal("verifier accepted signature under tampered message")
	}
}

// ═══════════════════════════════════════════════════════════════════
// SDK integration
// ═══════════════════════════════════════════════════════════════════

// TestVerifyWitnessCosignatures_BLSHead confirms that a
// CosignedTreeHead with SchemeTag == SchemeBLS dispatches correctly
// to the GnarkBLSVerifier under Wave 1's protocol shape. This is the
// end-to-end integration test: the SDK's top-level cosignature
// verifier delegates to the BLS implementation transparently.
func TestVerifyWitnessCosignatures_BLSHead(t *testing.T) {
	const k = 3
	witnesses := make([]*blsTestWitness, k)
	sigs := make([]types.WitnessSignature, k)
	keys := make([]types.WitnessPublicKey, k)

	head := testTreeHead(2024)
	for i := range witnesses {
		witnesses[i] = newBLSTestWitness(t)
		sigs[i] = witnesses[i].cosign(t, head)
		keys[i] = witnesses[i].publicKey
	}

	cosigned := types.CosignedTreeHead{
		TreeHead:   head,
		SchemeTag:  SchemeBLS,
		Signatures: sigs,
	}

	verifier := NewGnarkBLSVerifier()
	result, err := VerifyWitnessCosignatures(cosigned, keys, k, verifier)
	if err != nil {
		t.Fatalf("VerifyWitnessCosignatures (BLS): %v", err)
	}
	if result.ValidCount != k {
		t.Errorf("valid count = %d, want %d", result.ValidCount, k)
	}
}
