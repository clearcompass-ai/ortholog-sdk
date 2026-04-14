package tests

import (
	"crypto/sha256"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// Test 18: ECDSA K=3/N=5 witness cosignature — 3 valid passes, 2 valid fails threshold.
func TestWitnessVerify_ECDSA_K3N5(t *testing.T) {
	head := types.TreeHead{TreeSize: 1000}
	head.RootHash = sha256.Sum256([]byte("test-root"))
	msg := types.WitnessCosignMessage(head)
	msgHash := sha256.Sum256(msg[:])

	// Generate 5 witness keys and sign.
	keys := make([]*struct{ priv, pub interface{} }, 5)
	witnessKeys := make([]types.WitnessPublicKey, 5)
	sigs := make([]types.WitnessSignature, 5)

	for i := 0; i < 5; i++ {
		key, err := signatures.GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		pubBytes := signatures.PubKeyBytes(&key.PublicKey)
		id := sha256.Sum256(pubBytes)
		witnessKeys[i] = types.WitnessPublicKey{ID: id, PublicKey: pubBytes}
		sigBytes, err := signatures.SignEntry(msgHash, key)
		if err != nil {
			t.Fatal(err)
		}
		sigs[i] = types.WitnessSignature{PubKeyID: id, SigBytes: sigBytes}
		_ = keys
	}

	cosigned := types.CosignedTreeHead{
		TreeHead:   head,
		SchemeTag:  signatures.SchemeECDSA,
		Signatures: sigs[:3], // Only 3 of 5.
	}

	result, err := signatures.VerifyWitnessCosignatures(cosigned, witnessKeys, 3, nil)
	if err != nil {
		t.Fatalf("K=3/N=5 should pass with 3 valid: %v", err)
	}
	if result.ValidCount != 3 {
		t.Fatalf("valid count: got %d, want 3", result.ValidCount)
	}

	// K=4 should fail with only 3 signatures.
	_, err = signatures.VerifyWitnessCosignatures(cosigned, witnessKeys, 4, nil)
	if err == nil {
		t.Fatal("K=4 should fail with only 3 valid signatures")
	}
}

// Test 19: BLS verification via mock interface.
func TestWitnessVerify_BLSMock(t *testing.T) {
	head := types.TreeHead{TreeSize: 500}
	head.RootHash = sha256.Sum256([]byte("bls-root"))

	cosigned := types.CosignedTreeHead{
		TreeHead:   head,
		SchemeTag:  signatures.SchemeBLS,
		Signatures: []types.WitnessSignature{{SigBytes: []byte("agg-sig")}},
	}

	// No BLS verifier -> error.
	_, err := signatures.VerifyWitnessCosignatures(cosigned, nil, 1, nil)
	if err == nil {
		t.Fatal("BLS without verifier should error")
	}

	// With mock verifier that returns all valid.
	mock := &mockBLSVerifier{results: []bool{true, true, true}}
	cosigned.Signatures = make([]types.WitnessSignature, 3)
	result, err := signatures.VerifyWitnessCosignatures(cosigned, nil, 3, mock)
	if err != nil {
		t.Fatalf("mock BLS should pass: %v", err)
	}
	if result.ValidCount != 3 {
		t.Fatalf("valid: got %d, want 3", result.ValidCount)
	}
}

type mockBLSVerifier struct {
	results []bool
}

func (m *mockBLSVerifier) VerifyAggregate(msg []byte, sigs []types.WitnessSignature, keys []types.WitnessPublicKey) ([]bool, error) {
	return m.results, nil
}
