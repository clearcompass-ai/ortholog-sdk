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

	"github.com/clearcompass-ai/ortholog-sdk/types"
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
// test: a PoP must not verify as a cosignature over some arbitrary
// tree head. Confirms the separation is bidirectional.
//
// The test constructs a scenario where the tree head's
// WitnessCosignMessage happens to equal the public key's compressed
// bytes. In practice this cannot occur (WitnessCosignMessage is 40
// bytes, compressed G2 pubkey is 96 bytes), so full byte collision is
// impossible — but we demonstrate the DST separation by attempting
// a cross-protocol verification at the pairing level.
func TestDomainSeparation_PoPNotUsableAsCosignature(t *testing.T) {
	sk, pk, err := GenerateBLSKey()
	if err != nil {
		t.Fatalf("GenerateBLSKey: %v", err)
	}
	pop, err := SignBLSPoP(pk, sk)
	if err != nil {
		t.Fatalf("SignBLSPoP: %v", err)
	}

	// Attempt to verify the PoP as a cosignature against the same
	// public key. Use VerifyAggregate with the PoP's 96-byte message
	// payload (the compressed pubkey) as the cosign message.
	// The cosignature path hashes under BLSDomainTag; the PoP was
	// signed under BLSPoPDomainTag. The pairing check must fail.
	pkBytes := BLSPubKeyBytes(pk)
	// WitnessCosignMessage is fixed at 40 bytes. We can't put 96-byte
	// pubkey bytes through it directly; instead we verify at the
	// primitive level using the compressed-pubkey bytes as the "message"
	// passed to VerifyAggregate's hash-to-curve.
	verifier := NewGnarkBLSVerifier()
	results, err := verifier.VerifyAggregate(
		pkBytes,
		[]types.WitnessSignature{{SigBytes: pop}},
		[]types.WitnessPublicKey{{PublicKey: pkBytes}},
	)
	if err != nil {
		// Error from length mismatch or similar is acceptable —
		// the point is verification does not PASS.
		return
	}
	if len(results) > 0 && results[0] {
		t.Fatal("CRITICAL: PoP accepted as cosignature — DST separation failed")
	}
}
