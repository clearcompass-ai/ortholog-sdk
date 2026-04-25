// Package signatures — bls_verifier_binding_test.go holds the
// binding test for muEnableBLSAggregateVerify. The other three
// BLS gates bind to pre-existing tests cross-registered in
// crypto/signatures/bls_verifier.mutation-audit.yaml:
//
//   muEnableBLSSubgroupCheck   → TestParseBLSPubKey_NotInSubgroup
//   muEnableBLSPoPVerify       → TestVerifyBLSPoP_RejectsTamperedPoP
//                                 TestVerifyBLSPoP_RejectsWrongKey
//   muEnableBLSDSTSeparation   → TestDomainSeparation_DSTsAreDistinct
//                                 TestDomainSeparation_CosignatureNotUsableAsPoP
package signatures

import (
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// TestBLSAggregateVerify_RejectsTamperedSig_Binding constructs a
// 3-witness BLS cosignature set, tampers signature[0], and asserts
// VerifyAggregate marks results[0] = false.
//
// With muEnableBLSAggregateVerify on:
//   - the optimistic-aggregation PairingCheck fails (the tampered
//     sig disrupts the aggregate equation),
//   - the per-signature fallback runs and identifies pair[0] as
//     invalid,
//   - results[0] = false, results[1..] = true.
//
// With the gate off:
//   - aggregatedOK is forced to true,
//   - every parsed pair is marked valid without per-pair check,
//   - results[0] = true (silent forgery acceptance).
//
// The assertion `results[0] == false` is the load-bearing signal.
func TestBLSAggregateVerify_RejectsTamperedSig_Binding(t *testing.T) {
	const n = 3

	pks := make([]types.WitnessPublicKey, n)
	sigs := make([]types.WitnessSignature, n)
	head := types.TreeHead{TreeSize: 42}
	wrongHead := types.TreeHead{TreeSize: 999} // for the tampered sig

	for i := 0; i < n; i++ {
		sk, pubAffine, err := GenerateBLSKey()
		if err != nil {
			t.Fatalf("GenerateBLSKey[%d]: %v", i, err)
		}
		pkBytes := BLSPubKeyBytes(pubAffine)
		var id [32]byte
		copy(id[:], pkBytes[:32])
		pks[i] = types.WitnessPublicKey{ID: id, PublicKey: pkBytes}

		// For witness 0, sign the WRONG head: the signature is a
		// valid G1 point (parses and passes subgroup) but does not
		// verify against the public key for the actual message.
		// For witnesses 1 and 2, sign the correct head.
		signFor := head
		if i == 0 {
			signFor = wrongHead
		}
		sigBytes, err := SignBLSCosignature(signFor, sk)
		if err != nil {
			t.Fatalf("SignBLSCosignature[%d]: %v", i, err)
		}
		sigs[i] = types.WitnessSignature{
			PubKeyID:  id,
			SchemeTag: SchemeBLS,
			SigBytes:  sigBytes,
		}
	}

	v := NewGnarkBLSVerifier()
	msg := types.WitnessCosignMessage(head)
	results, err := v.VerifyAggregate(msg[:], sigs, pks)
	if err != nil {
		t.Fatalf("VerifyAggregate: %v", err)
	}
	if len(results) != n {
		t.Fatalf("results len=%d, want %d", len(results), n)
	}
	if results[0] {
		t.Fatal("VerifyAggregate marked wrong-message signature 0 as valid (muEnableBLSAggregateVerify not load-bearing?)")
	}
	// Witnesses 1 and 2 signed the correct head — they must still verify.
	if !results[1] || !results[2] {
		t.Fatalf("VerifyAggregate rejected untampered signatures: %v", results)
	}
}
