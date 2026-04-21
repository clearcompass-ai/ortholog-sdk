/*
FILE PATH:

	crypto/signatures/bls_pop_test.go

DESCRIPTION:

	Correctness tests for the BLS proof-of-possession primitives.
	Organized around two security properties:

	  1. PoP verification accepts signatures made by the claimed key's
	     private key and rejects everything else (wrong key, tampered
	     bytes, malformed inputs).
	  2. Domain separation between BLSDomainTag (cosignature signing)
	     and BLSPoPDomainTag (proof-of-possession) prevents cross-
	     protocol signature reuse: a cosignature is not a valid PoP
	     and a PoP is not a valid cosignature, even for identical input
	     bytes.

	The second property is the cryptographic barrier that prevents an
	attacker from induction-attacking honest witnesses: "sign this
	tree head for me" cannot be exploited to produce a PoP for a
	different key, because the two signing paths produce hashes at
	different G1 points.

	This file does NOT include the rogue-key attack reconstruction —
	that lives in bls_rogue_key_test.go, which exercises the complete
	attack end-to-end and demonstrates PoP blocks it at registration.
*/
package signatures

import (
	"bytes"
	"math/big"
	"testing"

	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
)

// ═══════════════════════════════════════════════════════════════════
// Positive path: round-trip
// ═══════════════════════════════════════════════════════════════════

// TestSignBLSPoP_RoundTrip verifies the fundamental PoP contract:
// a PoP produced by SignBLSPoP(pk, sk) verifies via VerifyBLSPoP(pk,
// pop) when the (pk, sk) pair is consistent. If this test fails, the
// PoP primitives have drifted and no witness will ever be admissible
// to a BLS-enabled witness set.
func TestSignBLSPoP_RoundTrip(t *testing.T) {
	sk, pk, err := GenerateBLSKey()
	if err != nil {
		t.Fatalf("GenerateBLSKey: %v", err)
	}

	pop, err := SignBLSPoP(pk, sk)
	if err != nil {
		t.Fatalf("SignBLSPoP: %v", err)
	}

	if len(pop) != BLSG1CompressedLen {
		t.Errorf("PoP length = %d, want %d", len(pop), BLSG1CompressedLen)
	}

	if err := VerifyBLSPoP(pk, pop); err != nil {
		t.Fatalf("VerifyBLSPoP: %v", err)
	}
}

// TestSignBLSPoP_Determinism confirms PoP signatures are deterministic
// over the same (pk, sk) pair. A PoP for a given key should be
// reproducible by any witness operator who re-runs the signing process;
// non-determinism would break cross-implementation verification.
func TestSignBLSPoP_Determinism(t *testing.T) {
	sk, pk, err := GenerateBLSKey()
	if err != nil {
		t.Fatalf("GenerateBLSKey: %v", err)
	}

	pop1, err := SignBLSPoP(pk, sk)
	if err != nil {
		t.Fatalf("first sign: %v", err)
	}
	pop2, err := SignBLSPoP(pk, sk)
	if err != nil {
		t.Fatalf("second sign: %v", err)
	}

	if !bytes.Equal(pop1, pop2) {
		t.Fatalf("PoP non-deterministic:\n  pop1 = %x\n  pop2 = %x", pop1, pop2)
	}
}

// ═══════════════════════════════════════════════════════════════════
// Negative paths: wrong key, tampered bytes
// ═══════════════════════════════════════════════════════════════════

// TestVerifyBLSPoP_RejectsWrongKey confirms a PoP under key A does
// not verify against key B. If this test fails, the PoP binding to
// the specific public key is broken, and rogue-key attacks become
// possible.
func TestVerifyBLSPoP_RejectsWrongKey(t *testing.T) {
	skA, pkA, err := GenerateBLSKey()
	if err != nil {
		t.Fatalf("generate A: %v", err)
	}
	_, pkB, err := GenerateBLSKey()
	if err != nil {
		t.Fatalf("generate B: %v", err)
	}

	popA, err := SignBLSPoP(pkA, skA)
	if err != nil {
		t.Fatalf("SignBLSPoP: %v", err)
	}

	// PoP signed for pkA must not verify against pkB.
	if err := VerifyBLSPoP(pkB, popA); err == nil {
		t.Fatal("BUG: PoP for key A accepted under key B (rogue-key defense broken)")
	}
}

// TestVerifyBLSPoP_RejectsTamperedPoP flips bits in a valid PoP and
// confirms verification fails. Exercises the binding between the PoP
// signature bytes and the claimed key.
func TestVerifyBLSPoP_RejectsTamperedPoP(t *testing.T) {
	sk, pk, err := GenerateBLSKey()
	if err != nil {
		t.Fatalf("GenerateBLSKey: %v", err)
	}
	pop, err := SignBLSPoP(pk, sk)
	if err != nil {
		t.Fatalf("SignBLSPoP: %v", err)
	}

	// Tamper at several offsets to cover both "flips to invalid
	// decompression" and "flips to valid point that fails pairing".
	for _, offset := range []int{0, 12, 23, 47} {
		tampered := append([]byte(nil), pop...)
		tampered[offset] ^= 0x01

		if err := VerifyBLSPoP(pk, tampered); err == nil {
			t.Errorf("tampered PoP accepted (flip at offset %d)", offset)
		}
	}
}

// TestVerifyBLSPoP_RejectsMalformedPoP exercises PoP length and
// decompression validation.
func TestVerifyBLSPoP_RejectsMalformedPoP(t *testing.T) {
	_, pk, err := GenerateBLSKey()
	if err != nil {
		t.Fatalf("GenerateBLSKey: %v", err)
	}

	cases := []struct {
		name string
		pop  []byte
	}{
		{"empty", nil},
		{"too_short_47", make([]byte, 47)},
		{"too_long_49", make([]byte, 49)},
		{"too_long_96", make([]byte, 96)},
		{"random_bytes", func() []byte {
			b := make([]byte, BLSG1CompressedLen)
			for i := range b {
				b[i] = byte(i) ^ 0xA5
			}
			return b
		}()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := VerifyBLSPoP(pk, tc.pop); err == nil {
				t.Fatalf("VerifyBLSPoP accepted malformed input of length %d", len(tc.pop))
			}
		})
	}
}

// TestVerifyBLSPoP_RejectsMalformedPubkey confirms VerifyBLSPoP
// handles nil public keys with a typed error rather than panicking.
func TestVerifyBLSPoP_RejectsMalformedPubkey(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("VerifyBLSPoP panicked on nil pubkey: %v", r)
		}
	}()
	pop := make([]byte, BLSG1CompressedLen)
	if err := VerifyBLSPoP(nil, pop); err == nil {
		t.Fatal("expected nil-pubkey error, got nil")
	}
}

// TestSignBLSPoP_RejectsNilInputs confirms SignBLSPoP fails cleanly
// on nil inputs rather than panicking.
func TestSignBLSPoP_RejectsNilInputs(t *testing.T) {
	sk, pk, err := GenerateBLSKey()
	if err != nil {
		t.Fatalf("GenerateBLSKey: %v", err)
	}

	// nil private key.
	if _, err := SignBLSPoP(pk, nil); err == nil {
		t.Error("expected error on nil privKey")
	}

	// nil public key.
	if _, err := SignBLSPoP(nil, sk); err == nil {
		t.Error("expected error on nil pub")
	}
}

// ═══════════════════════════════════════════════════════════════════
// Domain separation: the security-critical property
// ═══════════════════════════════════════════════════════════════════

// TestDomainSeparation_CosignatureNotUsableAsPoP confirms that a
// signature produced by SignBLSCosignature (using BLSDomainTag) does
// NOT function as a valid PoP (which requires BLSPoPDomainTag).
//
// Why this matters: if the two signing paths shared a DST, an attacker
// could induce an honest witness to sign arbitrary 40-byte messages
// via the cosignature path and replay those signatures as PoPs for
// attacker-constructed rogue keys. The distinct DSTs make such
// cross-protocol reuse impossible: H(m, BLSDomainTag) and H(m,
// BLSPoPDomainTag) are different G1 points, so a signature valid
// under one is not a signature under the other.
//
// Specifically: we construct a scenario where the cosignature's
// message payload is chosen to collide byte-wise with the compressed
// public key bytes. Even in this worst case, the cosignature does not
// verify as a PoP because the DSTs differ.
//
// This test is a cryptographic regression guard. If it fails, either
// the DSTs were unified or the underlying hash-to-curve lost domain
// separation — both are protocol-breaking.
func TestDomainSeparation_CosignatureNotUsableAsPoP(t *testing.T) {
	sk, pk, err := GenerateBLSKey()
	if err != nil {
		t.Fatalf("GenerateBLSKey: %v", err)
	}

	// Get the public key's compressed bytes — this is the input to the
	// PoP hash. A cosignature signed over these same bytes (if they
	// were a valid WitnessCosignMessage) would be the worst-case
	// cross-protocol reuse target.
	pkBytes := BLSPubKeyBytes(pk)

	// Construct a signature where the signed message is the public
	// key bytes, using the cosignature signing path (BLSDomainTag).
	// We do this at the primitive level: hash under BLSDomainTag,
	// then sign. This simulates what a naive attacker might attempt.
	hashUnderCosigDST, err := bls12381.HashToG1(pkBytes, []byte(BLSDomainTag))
	if err != nil {
		t.Fatalf("HashToG1 (cosig DST): %v", err)
	}
	var crossProtocolSig bls12381.G1Affine
	skBig := coerceFr(sk).BigInt(new(big.Int))
	crossProtocolSig.ScalarMultiplication(&hashUnderCosigDST, skBig)
	sigBytes := crossProtocolSig.Bytes()

	// Attempt to verify this cosignature-under-pk-bytes as a PoP.
	// VerifyBLSPoP hashes under BLSPoPDomainTag — a different DST —
	// so the hash targets differ and the pairing check must fail.
	if err := VerifyBLSPoP(pk, sigBytes[:]); err == nil {
		t.Fatal("CRITICAL: cosignature accepted as PoP — DST separation failed")
	}
}

// TestDomainSeparation_PoPNotUsableAsCosignature is the symmetric
// check to TestDomainSeparation_CosignatureNotUsableAsPoP: a PoP must
// not verify as a cosignature, even at the primitive pairing level.
//
// # WHY THIS TEST AVOIDS VerifyAggregate
//
// A previous version of this test called VerifyAggregate with the
// compressed-pubkey bytes as the "message" payload. That path had a
// defect: VerifyAggregate could return an error (length validation,
// parse failure, etc.) before reaching the pairing check, and the
// test's early-return-on-any-error clause would accept any such
// error as "success." The test could pass for reasons entirely
// unrelated to DST separation.
//
// This version does the verification at the primitive level instead.
// We compute the hash-to-curve outputs under BOTH DSTs, pair-check
// the PoP against each, and assert that the PoP-DST check passes
// (sanity) while the cosignature-DST check fails (the actual
// assertion). This exercises the DST separation directly at the
// pairing layer, independent of any length validation or parsing
// behavior in VerifyAggregate.
//
// # WHAT THIS TEST LOCKS
//
// Given a valid PoP for some public key pk:
//
//	e(pop, G2_gen) == e(HashToG1(Compress(pk), BLSPoPDomainTag), pk)  [must pass]
//	e(pop, G2_gen) == e(HashToG1(Compress(pk), BLSDomainTag),    pk)  [must fail]
//
// If the second equation passes, the two DSTs produce identical
// hash targets for the same input bytes — domain separation has
// collapsed, and a PoP could be replayed as a cosignature over
// those same bytes. Catastrophic cryptographic failure; the SDK's
// rogue-key defense falls apart.
//
// # ADDITIONAL GUARD
//
// We also assert the two HashToG1 outputs are themselves distinct.
// If they happen to be equal, DST separation has collapsed one
// layer earlier — at the hash-to-curve primitive rather than the
// pairing check. That failure mode is caught explicitly so the
// diagnostic is precise.
func TestDomainSeparation_PoPNotUsableAsCosignature(t *testing.T) {
	// ─────────────────────────────────────────────────────────────
	// Setup: generate a key and produce a valid PoP.
	// ─────────────────────────────────────────────────────────────
	sk, pk, err := GenerateBLSKey()
	if err != nil {
		t.Fatalf("GenerateBLSKey: %v", err)
	}
	popBytes, err := SignBLSPoP(pk, sk)
	if err != nil {
		t.Fatalf("SignBLSPoP: %v", err)
	}

	// Decompress the PoP into a G1 point for use in pairing checks.
	// This also confirms SignBLSPoP produced well-formed bytes — if
	// decompression fails, the bug is in SignBLSPoP, not domain
	// separation, and we surface that clearly.
	var pop bls12381.G1Affine
	if _, err := pop.SetBytes(popBytes); err != nil {
		t.Fatalf("decompress PoP bytes (SignBLSPoP output malformed?): %v", err)
	}

	// The compressed-pubkey bytes are the input to both hash targets.
	// This is what SignBLSPoP hashed under BLSPoPDomainTag; we now
	// also hash the same bytes under BLSDomainTag for the cross-
	// protocol check.
	pkBytes := BLSPubKeyBytes(pk)

	// ─────────────────────────────────────────────────────────────
	// Hash under BOTH DSTs.
	// ─────────────────────────────────────────────────────────────
	hashUnderPoPDST, err := bls12381.HashToG1(pkBytes, []byte(BLSPoPDomainTag))
	if err != nil {
		t.Fatalf("HashToG1 (PoP DST): %v", err)
	}
	hashUnderCosigDST, err := bls12381.HashToG1(pkBytes, []byte(BLSDomainTag))
	if err != nil {
		t.Fatalf("HashToG1 (cosig DST): %v", err)
	}

	// Guard: the two hash outputs must be distinct. If they're equal,
	// domain separation has collapsed at the hash-to-curve layer —
	// every downstream check in this test would be meaningless.
	if hashUnderPoPDST.Equal(&hashUnderCosigDST) {
		t.Fatal("CRITICAL: HashToG1 produced identical outputs under " +
			"BLSPoPDomainTag and BLSDomainTag for the same input bytes. " +
			"Domain separation has collapsed at the hash-to-curve layer. " +
			"This is a more severe failure than the pairing-level check " +
			"below would catch. Investigate BLSDomainTag, BLSPoPDomainTag, " +
			"and the gnark HashToG1 implementation immediately.")
	}

	// ─────────────────────────────────────────────────────────────
	// Prepare pairing-check operands.
	// ─────────────────────────────────────────────────────────────
	// PairingCheck returns true iff the product of pairings equals
	// the identity. For an equality check e(A, B) == e(C, D), we
	// rearrange to e(A, -B) · e(C, D) == 1 and pass that form.
	_, _, _, g2Gen := bls12381.Generators()
	var negG2Gen bls12381.G2Affine
	negG2Gen.Neg(&g2Gen)

	// ─────────────────────────────────────────────────────────────
	// Check 1: PoP against PoP-DST hash. MUST PASS.
	// ─────────────────────────────────────────────────────────────
	// This is the normal VerifyBLSPoP path, done at the primitive
	// level. A failure here means SignBLSPoP/VerifyBLSPoP are
	// themselves broken, and this test cannot assess DST separation
	// until that's fixed. Surface that clearly.
	popDSTCheckPasses, err := bls12381.PairingCheck(
		[]bls12381.G1Affine{pop, hashUnderPoPDST},
		[]bls12381.G2Affine{negG2Gen, *pk},
	)
	if err != nil {
		t.Fatalf("PoP-DST pairing check errored: %v", err)
	}
	if !popDSTCheckPasses {
		t.Fatal("PoP-DST pairing check FAILED for a freshly-generated " +
			"PoP. This indicates a bug in SignBLSPoP or in the PoP " +
			"verification equation, not in DST separation. Fix the " +
			"PoP primitive before this test can validly assess DST " +
			"behavior.")
	}

	// ─────────────────────────────────────────────────────────────
	// Check 2: PoP against COSIG-DST hash. MUST FAIL.
	// ─────────────────────────────────────────────────────────────
	// This is the cross-protocol attack scenario. If this check
	// passes, a valid PoP has successfully verified as a cosignature
	// over the compressed-pubkey bytes. Domain separation has
	// collapsed; the rogue-key defense fails.
	cosigDSTCheckPasses, err := bls12381.PairingCheck(
		[]bls12381.G1Affine{pop, hashUnderCosigDST},
		[]bls12381.G2Affine{negG2Gen, *pk},
	)
	if err != nil {
		// A library-level pairing-check error is NOT a
		// domain-separation pass. It's infrastructure failure.
		// Fail the test loudly so it isn't misread as a security
		// success.
		t.Fatalf("cosig-DST pairing check errored (this is an unexpected "+
			"library failure, NOT a domain-separation pass): %v", err)
	}
	if cosigDSTCheckPasses {
		t.Fatal("CRITICAL SECURITY FAILURE: a valid PoP verified as a " +
			"cosignature over the compressed-pubkey bytes. Domain " +
			"separation between BLSDomainTag and BLSPoPDomainTag has " +
			"collapsed at the pairing check layer. PoPs can now be " +
			"replayed as cosignatures, enabling the rogue-key attack " +
			"class this DST separation was specifically designed to " +
			"prevent.\n\n" +
			"Investigate the DST constants and the HashToG1 " +
			"implementation. Do NOT merge Wave 1 with this test failing.")
	}
}
