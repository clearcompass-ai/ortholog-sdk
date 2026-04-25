/*
FILE PATH:

	tests/witness_cosig_test.go

DESCRIPTION:

	Tests for witness.VerifyTreeHead (and its resolution variant).
	Covers the K-of-N quorum logic, error paths, BLS mock dispatch,
	and DID-based key resolution.

WAVE 2 CHANGE:

	Pre-Wave-2 each CosignedTreeHead carried a head-level SchemeTag
	and every WitnessSignature in Signatures implicitly inherited
	that scheme. Post-Wave-2, each WitnessSignature carries its own
	SchemeTag; the head no longer has one.

	This file updates every literal to the new shape:
	  - Every WitnessSignature now declares SchemeTag explicitly
	  - Every CosignedTreeHead no longer carries SchemeTag
	  - BLS-intent literals declare SchemeTag: signatures.SchemeBLS
	  - All other literals declare SchemeTag: signatures.SchemeECDSA

	The test semantics are preserved: ECDSA tests still verify ECDSA
	signatures through the dispatcher's ECDSA path, BLS tests still
	exercise the BLS mock verifier, and error-path tests still
	exercise the same error conditions.
*/
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
//
// Wave 2: per-signature SchemeTag populated on every WitnessSignature.
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
			sigs[i] = types.WitnessSignature{
				PubKeyID:  id,
				SchemeTag: signatures.SchemeECDSA, // Wave 2: per-signature scheme
				SigBytes:  sigBytes,
			}
		}
	}

	return types.CosignedTreeHead{
		TreeHead:   head,
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
	// Wave 2: head no longer carries SchemeTag. This test exercises the
	// "no signatures present" error path, which triggers before any
	// per-signature scheme dispatch happens.
	head := types.CosignedTreeHead{
		TreeHead:   types.TreeHead{TreeSize: 100},
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
	// Wave 2: the head no longer carries SchemeTag, but the single
	// signature declares SchemeBLS per-signature. The dispatcher
	// recognizes BLS intent and rejects because blsVerifier is nil.
	head := types.CosignedTreeHead{
		TreeHead: types.TreeHead{TreeSize: 100},
		Signatures: []types.WitnessSignature{
			{SchemeTag: signatures.SchemeBLS, SigBytes: []byte("agg")},
		},
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
	// Wave 2: construct three explicit BLS-tagged WitnessSignatures
	// rather than using `make([]WitnessSignature, 3)` which would
	// produce zero-tag signatures that the dispatcher rejects.
	//
	// Group 8.3: each signature carries a distinct PubKeyID so the
	// post-verify uniqueness check (muEnableUniqueSigners) counts
	// three independent signers rather than collapsing them into
	// one. Pre-Group-8.3 the dedup pass did not exist, so identical
	// PubKeyIDs across rows worked by accident.
	//
	// The mock BLSVerifier returns all-true regardless of input
	// bytes; we just need valid scheme-tag dispatch to reach it.
	sigs := []types.WitnessSignature{
		{SchemeTag: signatures.SchemeBLS, PubKeyID: [32]byte{0x01}},
		{SchemeTag: signatures.SchemeBLS, PubKeyID: [32]byte{0x02}},
		{SchemeTag: signatures.SchemeBLS, PubKeyID: [32]byte{0x03}},
	}
	head := types.CosignedTreeHead{
		TreeHead:   types.TreeHead{TreeSize: 100},
		Signatures: sigs,
	}
	// Populate matching keys so the dispatcher can map sig → key.
	// The mock verifier doesn't care about key contents; the
	// dispatcher only needs a PubKeyID match.
	keys := []types.WitnessPublicKey{
		{ID: [32]byte{0x01}, PublicKey: []byte("key")},
		{ID: [32]byte{0x02}, PublicKey: []byte("key")},
		{ID: [32]byte{0x03}, PublicKey: []byte("key")},
	}

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
