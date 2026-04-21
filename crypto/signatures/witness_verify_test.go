package signatures

import (
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// TestSignWitnessCosignature_RoundTrip proves that any signature
// produced by SignWitnessCosignature is accepted by
// VerifyWitnessCosignatures using the matching public key. This
// symmetry is load-bearing: drift between the signing and
// verification hash conventions would be a protocol-level bug that
// silently prevents any witness cosignature from ever verifying.
//
// If this test fails, either:
//   - SignWitnessCosignature's digest construction has drifted from
//     verifyECDSACosignatures', OR
//   - SignEntry / VerifyEntry are no longer round-trip compatible
//     (a deeper SDK bug).
func TestSignWitnessCosignature_RoundTrip(t *testing.T) {
	// Generate a witness keypair.
	priv, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubBytes := PubKeyBytes(&priv.PublicKey)

	// Construct a representative tree head.
	head := types.TreeHead{
		TreeSize: 42,
	}
	copy(head.RootHash[:], []byte("0123456789abcdef0123456789abcdef"))

	// Sign.
	sig, err := SignWitnessCosignature(head, priv)
	if err != nil {
		t.Fatalf("SignWitnessCosignature: %v", err)
	}
	if len(sig) != 64 {
		t.Fatalf("signature length = %d, want 64", len(sig))
	}

	// Construct a CosignedTreeHead carrying the signature and verify
	// via the full VerifyWitnessCosignatures path.
	var pubKeyID [32]byte
	copy(pubKeyID[:], pubBytes[:32]) // arbitrary deterministic ID for this test

	cosigned := types.CosignedTreeHead{
		TreeHead:  head,
		SchemeTag: SchemeECDSA,
		Signatures: []types.WitnessSignature{
			{PubKeyID: pubKeyID, SigBytes: sig},
		},
	}
	witnessKeys := []types.WitnessPublicKey{
		{ID: pubKeyID, PublicKey: pubBytes},
	}

	result, err := VerifyWitnessCosignatures(cosigned, witnessKeys, 1, nil)
	if err != nil {
		t.Fatalf("VerifyWitnessCosignatures: %v (results: %+v)", err, result)
	}
	if result.ValidCount != 1 {
		t.Errorf("ValidCount = %d, want 1", result.ValidCount)
	}
	if len(result.Results) != 1 || !result.Results[0].Valid {
		t.Errorf("signature did not verify as valid: %+v", result.Results)
	}
}

// TestSignWitnessCosignature_NilKey confirms the nil-check error.
func TestSignWitnessCosignature_NilKey(t *testing.T) {
	head := types.TreeHead{TreeSize: 1}
	_, err := SignWitnessCosignature(head, nil)
	if err == nil {
		t.Fatal("expected error for nil private key, got nil")
	}
}

// TestSignWitnessCosignature_Determinism confirms the function is
// deterministic in its preimage construction. Note: ECDSA signatures
// themselves contain randomness (nonce k), so we can't assert
// byte-identical outputs. We assert that two signatures over the
// same head BOTH verify against the same public key.
func TestSignWitnessCosignature_TwoSignaturesBothVerify(t *testing.T) {
	priv, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pubBytes := PubKeyBytes(&priv.PublicKey)

	head := types.TreeHead{TreeSize: 99}
	copy(head.RootHash[:], []byte("deterministic preimage test data"))

	sig1, err := SignWitnessCosignature(head, priv)
	if err != nil {
		t.Fatal(err)
	}
	sig2, err := SignWitnessCosignature(head, priv)
	if err != nil {
		t.Fatal(err)
	}

	// Both signatures should verify individually via the full path.
	for i, sig := range [][]byte{sig1, sig2} {
		var pubKeyID [32]byte
		copy(pubKeyID[:], pubBytes[:32])

		cosigned := types.CosignedTreeHead{
			TreeHead:  head,
			SchemeTag: SchemeECDSA,
			Signatures: []types.WitnessSignature{
				{PubKeyID: pubKeyID, SigBytes: sig},
			},
		}
		witnessKeys := []types.WitnessPublicKey{
			{ID: pubKeyID, PublicKey: pubBytes},
		}

		if _, err := VerifyWitnessCosignatures(cosigned, witnessKeys, 1, nil); err != nil {
			t.Errorf("signature %d did not verify: %v", i+1, err)
		}
	}
}
