package tests

import (
	"crypto/sha256"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/types"
	"testing"
)

func TestWitnessVerify_ECDSA_K3N5(t *testing.T) {
	head := types.TreeHead{TreeSize: 1000}
	head.RootHash = sha256.Sum256([]byte("test-root"))
	msg := types.WitnessCosignMessage(head)
	msgHash := sha256.Sum256(msg[:])
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
	}
	cosigned := types.CosignedTreeHead{TreeHead: head, SchemeTag: signatures.SchemeECDSA, Signatures: sigs[:3]}
	result, err := signatures.VerifyWitnessCosignatures(cosigned, witnessKeys, 3, nil)
	if err != nil {
		t.Fatalf("K=3/N=5 should pass: %v", err)
	}
	if result.ValidCount != 3 {
		t.Fatalf("valid count: got %d, want 3", result.ValidCount)
	}
	_, err = signatures.VerifyWitnessCosignatures(cosigned, witnessKeys, 4, nil)
	if err == nil {
		t.Fatal("K=4 should fail with only 3 signatures")
	}
}

func TestWitnessVerify_BLSMock(t *testing.T) {
	head := types.TreeHead{TreeSize: 500}
	head.RootHash = sha256.Sum256([]byte("bls-root"))
	cosigned := types.CosignedTreeHead{TreeHead: head, SchemeTag: signatures.SchemeBLS, Signatures: []types.WitnessSignature{{SigBytes: []byte("agg-sig")}}}
	_, err := signatures.VerifyWitnessCosignatures(cosigned, nil, 1, nil)
	if err == nil {
		t.Fatal("BLS without verifier should error")
	}
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

type mockBLSVerifier struct{ results []bool }

func (m *mockBLSVerifier) VerifyAggregate(msg []byte, sigs []types.WitnessSignature, keys []types.WitnessPublicKey) ([]bool, error) {
	return m.results, nil
}
