package tests

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/witness"
)

// ─────────────────────────────────────────────────────────────────────
// Helpers: build signed heads with real ECDSA keys
// ─────────────────────────────────────────────────────────────────────

// buildSignedHead generates totalKeys fresh ECDSA keys, signs a tree head
// with the first sigCount of them, and returns the cosigned head + key set.
func buildSignedHead(t *testing.T, treeSize uint64, sigCount, totalKeys int) (types.CosignedTreeHead, []types.WitnessPublicKey) {
	t.Helper()
	head := types.TreeHead{
		TreeSize: treeSize,
		RootHash: sha256.Sum256([]byte("root-for-buildSignedHead")),
	}
	msg := types.WitnessCosignMessage(head)
	msgHash := sha256.Sum256(msg[:])

	keys := make([]types.WitnessPublicKey, totalKeys)
	sigs := make([]types.WitnessSignature, sigCount)

	for i := 0; i < totalKeys; i++ {
		priv, err := signatures.GenerateKey()
		if err != nil {
			t.Fatalf("generate key %d: %v", i, err)
		}
		pubBytes := signatures.PubKeyBytes(&priv.PublicKey)
		id := sha256.Sum256(pubBytes)
		keys[i] = types.WitnessPublicKey{ID: id, PublicKey: pubBytes}

		if i < sigCount {
			sigBytes, err := signatures.SignEntry(msgHash, priv)
			if err != nil {
				t.Fatalf("sign %d: %v", i, err)
			}
			sigs[i] = types.WitnessSignature{PubKeyID: id, SigBytes: sigBytes}
		}
	}

	return types.CosignedTreeHead{
		TreeHead:   head,
		SchemeTag:  signatures.SchemeECDSA,
		Signatures: sigs,
	}, keys
}

// ─────────────────────────────────────────────────────────────────────
// Tests: VerifyTreeHead
// ─────────────────────────────────────────────────────────────────────

func TestWitnessCosig_ECDSA_K3N5_Pass(t *testing.T) {
	cosigned, keys := buildSignedHead(t, 1000, 3, 5)
	result, err := witness.VerifyTreeHead(cosigned, keys, 3, nil)
	if err != nil {
		t.Fatalf("K=3/N=5 should pass: %v", err)
	}
	if result.ValidCount != 3 {
		t.Fatalf("valid: got %d, want 3", result.ValidCount)
	}
	if result.QuorumK != 3 {
		t.Fatalf("quorumK: got %d, want 3", result.QuorumK)
	}
}

func TestWitnessCosig_ECDSA_K5N5_Pass(t *testing.T) {
	cosigned, keys := buildSignedHead(t, 2000, 5, 5)
	result, err := witness.VerifyTreeHead(cosigned, keys, 5, nil)
	if err != nil {
		t.Fatalf("K=5/N=5 should pass: %v", err)
	}
	if result.ValidCount != 5 {
		t.Fatalf("valid: got %d", result.ValidCount)
	}
}

func TestWitnessCosig_ECDSA_K1N1_Pass(t *testing.T) {
	cosigned, keys := buildSignedHead(t, 100, 1, 1)
	result, err := witness.VerifyTreeHead(cosigned, keys, 1, nil)
	if err != nil {
		t.Fatalf("K=1/N=1 should pass: %v", err)
	}
	if result.ValidCount != 1 {
		t.Fatalf("valid: got %d", result.ValidCount)
	}
}

func TestWitnessCosig_ECDSA_K4N3Sigs_InsufficientSigs(t *testing.T) {
	cosigned, keys := buildSignedHead(t, 3000, 3, 5)
	_, err := witness.VerifyTreeHead(cosigned, keys, 4, nil)
	if err == nil {
		t.Fatal("K=4 with only 3 sigs should fail")
	}
	if !errors.Is(err, witness.ErrInsufficientWitnesses) {
		t.Fatalf("expected ErrInsufficientWitnesses, got: %v", err)
	}
}

func TestWitnessCosig_ZeroQuorum_Error(t *testing.T) {
	cosigned, keys := buildSignedHead(t, 100, 1, 1)
	_, err := witness.VerifyTreeHead(cosigned, keys, 0, nil)
	if err == nil {
		t.Fatal("K=0 should error")
	}
}

func TestWitnessCosig_NegativeQuorum_Error(t *testing.T) {
	cosigned, keys := buildSignedHead(t, 100, 1, 1)
	_, err := witness.VerifyTreeHead(cosigned, keys, -1, nil)
	if err == nil {
		t.Fatal("K=-1 should error")
	}
}

func TestWitnessCosig_EmptyWitnessSet_Error(t *testing.T) {
	cosigned, _ := buildSignedHead(t, 100, 1, 1)
	_, err := witness.VerifyTreeHead(cosigned, nil, 1, nil)
	if !errors.Is(err, witness.ErrEmptyWitnessSet) {
		t.Fatalf("expected ErrEmptyWitnessSet, got: %v", err)
	}
}

func TestWitnessCosig_NoSignatures_Error(t *testing.T) {
	keys := make([]types.WitnessPublicKey, 3)
	head := types.CosignedTreeHead{
		TreeHead:   types.TreeHead{TreeSize: 100},
		SchemeTag:  signatures.SchemeECDSA,
		Signatures: nil,
	}
	_, err := witness.VerifyTreeHead(head, keys, 1, nil)
	if !errors.Is(err, witness.ErrNoSignatures) {
		t.Fatalf("expected ErrNoSignatures, got: %v", err)
	}
}

func TestWitnessCosig_WitnessSetSmallerThanK_Error(t *testing.T) {
	cosigned, keys := buildSignedHead(t, 100, 2, 2)
	_, err := witness.VerifyTreeHead(cosigned, keys, 3, nil)
	if err == nil {
		t.Fatal("K=3 with only 2 keys should error")
	}
}

func TestWitnessCosig_ResultDetails(t *testing.T) {
	cosigned, keys := buildSignedHead(t, 500, 3, 5)
	result, err := witness.VerifyTreeHead(cosigned, keys, 3, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Details) != 3 {
		t.Fatalf("details: got %d, want 3", len(result.Details))
	}
	validCount := 0
	for _, d := range result.Details {
		if d.Valid {
			validCount++
		}
	}
	if validCount != 3 {
		t.Fatalf("valid in details: %d, want 3", validCount)
	}
}

func TestWitnessCosig_BLS_NoVerifier_Error(t *testing.T) {
	head := types.CosignedTreeHead{
		TreeHead:   types.TreeHead{TreeSize: 100},
		SchemeTag:  signatures.SchemeBLS,
		Signatures: []types.WitnessSignature{{SigBytes: []byte("agg")}},
	}
	keys := make([]types.WitnessPublicKey, 3)
	for i := range keys {
		keys[i] = types.WitnessPublicKey{PublicKey: []byte("key")}
	}
	_, err := witness.VerifyTreeHead(head, keys, 1, nil)
	if err == nil {
		t.Fatal("BLS without verifier should fail")
	}
}

func TestWitnessCosig_BLS_MockVerifier_Pass(t *testing.T) {
	head := types.CosignedTreeHead{
		TreeHead:   types.TreeHead{TreeSize: 100},
		SchemeTag:  signatures.SchemeBLS,
		Signatures: make([]types.WitnessSignature, 3),
	}
	keys := make([]types.WitnessPublicKey, 3)
	mock := &mockBLSVerifierP4{results: []bool{true, true, true}}
	result, err := witness.VerifyTreeHead(head, keys, 3, mock)
	if err != nil {
		t.Fatalf("mock BLS: %v", err)
	}
	if result.ValidCount != 3 {
		t.Fatalf("valid: %d", result.ValidCount)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Tests: VerifyTreeHeadWithResolution
// ─────────────────────────────────────────────────────────────────────

func TestWitnessCosig_WithResolution_Pass(t *testing.T) {
	cosigned, keys := buildSignedHead(t, 800, 3, 5)
	resolver := &mockEndpointResolver{keys: keys, quorumK: 3}
	result, err := witness.VerifyTreeHeadWithResolution(cosigned, "did:ortholog:test", resolver, nil)
	if err != nil {
		t.Fatalf("resolution should pass: %v", err)
	}
	if result.ValidCount != 3 {
		t.Fatalf("valid: %d", result.ValidCount)
	}
}

func TestWitnessCosig_WithResolution_NilResolver_Error(t *testing.T) {
	cosigned, _ := buildSignedHead(t, 100, 1, 1)
	_, err := witness.VerifyTreeHeadWithResolution(cosigned, "did:test", nil, nil)
	if err == nil {
		t.Fatal("nil resolver should error")
	}
}

func TestWitnessCosig_WithResolution_ResolveFails_Error(t *testing.T) {
	cosigned, _ := buildSignedHead(t, 100, 1, 1)
	resolver := &mockEndpointResolver{resolveErr: errors.New("DID not found")}
	_, err := witness.VerifyTreeHeadWithResolution(cosigned, "did:unknown", resolver, nil)
	if err == nil {
		t.Fatal("failed resolution should error")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Mocks
// ─────────────────────────────────────────────────────────────────────

type mockBLSVerifierP4 struct {
	results []bool
}

func (m *mockBLSVerifierP4) VerifyAggregate(msg []byte, sigs []types.WitnessSignature, keys []types.WitnessPublicKey) ([]bool, error) {
	return m.results, nil
}

type mockEndpointResolver struct {
	keys       []types.WitnessPublicKey
	quorumK    int
	resolveErr error
}

func (m *mockEndpointResolver) ResolveWitnessKeys(logDID string) ([]types.WitnessPublicKey, int, error) {
	if m.resolveErr != nil {
		return nil, 0, m.resolveErr
	}
	return m.keys, m.quorumK, nil
}

// Suppress unused import warning.
var _ *ecdsa.PrivateKey
