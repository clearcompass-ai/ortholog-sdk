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
// Helpers: build rotation messages with valid ECDSA signatures
// ─────────────────────────────────────────────────────────────────────

// generateFreshKeysWithPriv returns both public witness keys and private keys.
func generateFreshKeysWithPriv(t *testing.T, n int) ([]types.WitnessPublicKey, []*ecdsa.PrivateKey) {
	t.Helper()
	keys := make([]types.WitnessPublicKey, n)
	privs := make([]*ecdsa.PrivateKey, n)
	for i := 0; i < n; i++ {
		priv, err := signatures.GenerateKey()
		if err != nil {
			t.Fatalf("generate key %d: %v", i, err)
		}
		pubBytes := signatures.PubKeyBytes(&priv.PublicKey)
		id := sha256.Sum256(pubBytes)
		keys[i] = types.WitnessPublicKey{ID: id, PublicKey: pubBytes}
		privs[i] = priv
	}
	return keys, privs
}

func generateFreshKeys(t *testing.T, n int) []types.WitnessPublicKey {
	t.Helper()
	keys, _ := generateFreshKeysWithPriv(t, n)
	return keys
}

// buildValidRotation creates a rotation from current set to a new set,
// with valid ECDSA signatures from the first sigCount current set members.
func buildValidRotation(t *testing.T, setSize, sigCount, newSetSize int) (
	currentKeys []types.WitnessPublicKey,
	newKeys []types.WitnessPublicKey,
	rotation types.WitnessRotation,
) {
	t.Helper()
	currentKeys, currentPrivs := generateFreshKeysWithPriv(t, setSize)
	newKeys = generateFreshKeys(t, newSetSize)

	setHash := witness.ComputeSetHash(currentKeys)
	newSetHash := witness.ComputeSetHash(newKeys)
	msg := types.WitnessCosignMessage(types.TreeHead{RootHash: newSetHash, TreeSize: 0})
	msgHash := sha256.Sum256(msg[:])

	sigs := make([]types.WitnessSignature, sigCount)
	for i := 0; i < sigCount; i++ {
		sigBytes, err := signatures.SignEntry(msgHash, currentPrivs[i])
		if err != nil {
			t.Fatalf("sign rotation %d: %v", i, err)
		}
		sigs[i] = types.WitnessSignature{
			PubKeyID: currentKeys[i].ID,
			SigBytes: sigBytes,
		}
	}

	rotation = types.WitnessRotation{
		CurrentSetHash:    setHash,
		NewSet:            newKeys,
		SchemeTagOld:      signatures.SchemeECDSA,
		CurrentSignatures: sigs,
	}
	return
}

// buildValidDualSignRotation creates a dual-sign rotation (scheme transition).
func buildValidDualSignRotation(t *testing.T, setSize, sigCount int) (
	currentKeys []types.WitnessPublicKey,
	newKeys []types.WitnessPublicKey,
	rotation types.WitnessRotation,
) {
	t.Helper()
	currentKeys, newKeys, rotation = buildValidRotation(t, setSize, sigCount, setSize)

	// Generate new-scheme keys and sign with them too.
	newKeysWithPriv, newPrivs := generateFreshKeysWithPriv(t, setSize)
	rotation.NewSet = newKeysWithPriv
	rotation.SchemeTagNew = signatures.SchemeECDSA // Using ECDSA for both in test.

	newSetHash := witness.ComputeSetHash(newKeysWithPriv)
	msg := types.WitnessCosignMessage(types.TreeHead{RootHash: newSetHash, TreeSize: 0})
	msgHash := sha256.Sum256(msg[:])

	// Re-sign current sigs against the updated new set hash.
	currentKeysNew, currentPrivsNew := generateFreshKeysWithPriv(t, setSize)
	rotation.CurrentSetHash = witness.ComputeSetHash(currentKeysNew)
	currentSigs := make([]types.WitnessSignature, sigCount)
	for i := 0; i < sigCount; i++ {
		sigBytes, _ := signatures.SignEntry(msgHash, currentPrivsNew[i])
		currentSigs[i] = types.WitnessSignature{PubKeyID: currentKeysNew[i].ID, SigBytes: sigBytes}
	}
	rotation.CurrentSignatures = currentSigs
	currentKeys = currentKeysNew

	// New-scheme sigs from the new set.
	newSigs := make([]types.WitnessSignature, sigCount)
	for i := 0; i < sigCount; i++ {
		sigBytes, _ := signatures.SignEntry(msgHash, newPrivs[i])
		newSigs[i] = types.WitnessSignature{PubKeyID: newKeysWithPriv[i].ID, SigBytes: sigBytes}
	}
	rotation.NewSignatures = newSigs

	return
}

// ─────────────────────────────────────────────────────────────────────
// Tests: VerifyRotation
// ─────────────────────────────────────────────────────────────────────

func TestRotation_SingleValid(t *testing.T) {
	currentKeys, newKeys, rotation := buildValidRotation(t, 5, 3, 5)
	result, err := witness.VerifyRotation(rotation, currentKeys, 3, nil)
	if err != nil {
		t.Fatalf("valid rotation should pass: %v", err)
	}
	if len(result) != len(newKeys) {
		t.Fatalf("new set: got %d, want %d", len(result), len(newKeys))
	}
}

func TestRotation_K1N1(t *testing.T) {
	currentKeys, _, rotation := buildValidRotation(t, 1, 1, 3)
	result, err := witness.VerifyRotation(rotation, currentKeys, 1, nil)
	if err != nil {
		t.Fatalf("K=1/N=1 rotation should pass: %v", err)
	}
	if len(result) != 3 {
		t.Fatalf("new set: got %d, want 3", len(result))
	}
}

func TestRotation_EmptyNewSet_Error(t *testing.T) {
	rotation := types.WitnessRotation{
		NewSet:            nil,
		CurrentSignatures: []types.WitnessSignature{{SigBytes: []byte("sig")}},
	}
	_, err := witness.VerifyRotation(rotation, make([]types.WitnessPublicKey, 3), 2, nil)
	if !errors.Is(err, witness.ErrEmptyNewSet) {
		t.Fatalf("expected ErrEmptyNewSet, got: %v", err)
	}
}

func TestRotation_EmptyCurrentSigs_Error(t *testing.T) {
	rotation := types.WitnessRotation{
		NewSet:            make([]types.WitnessPublicKey, 3),
		CurrentSignatures: nil,
	}
	_, err := witness.VerifyRotation(rotation, make([]types.WitnessPublicKey, 3), 2, nil)
	if !errors.Is(err, witness.ErrEmptyRotationSigs) {
		t.Fatalf("expected ErrEmptyRotationSigs, got: %v", err)
	}
}

func TestRotation_EmptyCurrentSet_Error(t *testing.T) {
	rotation := types.WitnessRotation{
		NewSet:            make([]types.WitnessPublicKey, 3),
		CurrentSignatures: []types.WitnessSignature{{SigBytes: []byte("sig")}},
	}
	_, err := witness.VerifyRotation(rotation, nil, 2, nil)
	if !errors.Is(err, witness.ErrEmptyWitnessSet) {
		t.Fatalf("expected ErrEmptyWitnessSet, got: %v", err)
	}
}

func TestRotation_ZeroQuorum_Error(t *testing.T) {
	rotation := types.WitnessRotation{
		NewSet:            make([]types.WitnessPublicKey, 3),
		CurrentSignatures: []types.WitnessSignature{{SigBytes: []byte("sig")}},
	}
	_, err := witness.VerifyRotation(rotation, make([]types.WitnessPublicKey, 3), 0, nil)
	if err == nil {
		t.Fatal("K=0 should error")
	}
}

func TestRotation_SetHashMismatch_Error(t *testing.T) {
	currentKeys, _, rotation := buildValidRotation(t, 5, 3, 5)
	// Corrupt the set hash.
	rotation.CurrentSetHash = [32]byte{0xFF}
	_, err := witness.VerifyRotation(rotation, currentKeys, 3, nil)
	if err == nil {
		t.Fatal("set hash mismatch should error")
	}
}

func TestRotation_InvalidSigs_Error(t *testing.T) {
	currentKeys := generateFreshKeys(t, 5)
	newKeys := generateFreshKeys(t, 5)
	setHash := witness.ComputeSetHash(currentKeys)
	rotation := types.WitnessRotation{
		CurrentSetHash:    setHash,
		NewSet:            newKeys,
		SchemeTagOld:      signatures.SchemeECDSA,
		CurrentSignatures: []types.WitnessSignature{{SigBytes: make([]byte, 64)}, {SigBytes: make([]byte, 64)}, {SigBytes: make([]byte, 64)}},
	}
	_, err := witness.VerifyRotation(rotation, currentKeys, 3, nil)
	if err == nil {
		t.Fatal("invalid sigs should error")
	}
}

func TestRotation_DualSign_SchemeTransition(t *testing.T) {
	currentKeys, _, rotation := buildValidDualSignRotation(t, 5, 3)
	result, err := witness.VerifyRotation(rotation, currentKeys, 3, nil)
	if err != nil {
		t.Fatalf("dual-sign should pass: %v", err)
	}
	if len(result) == 0 {
		t.Fatal("should return new set")
	}
}

func TestRotation_DualSign_MissingNewSigs_Error(t *testing.T) {
	currentKeys, _, rotation := buildValidDualSignRotation(t, 5, 3)
	rotation.NewSignatures = nil // Remove new-scheme sigs.
	_, err := witness.VerifyRotation(rotation, currentKeys, 3, nil)
	if !errors.Is(err, witness.ErrDualSignMissingNewSigs) {
		t.Fatalf("expected ErrDualSignMissingNewSigs, got: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Tests: VerifyRotationChain
// ─────────────────────────────────────────────────────────────────────

func TestRotationChain_SingleStep(t *testing.T) {
	genesisKeys, _, rotation := buildValidRotation(t, 5, 3, 5)
	newSet, err := witness.VerifyRotationChain(genesisKeys, []types.WitnessRotation{rotation}, 3, nil)
	if err != nil {
		t.Fatalf("single-step chain: %v", err)
	}
	if len(newSet) != 5 {
		t.Fatalf("new set: %d", len(newSet))
	}
}

func TestRotationChain_EmptyGenesis_Error(t *testing.T) {
	_, err := witness.VerifyRotationChain(nil, nil, 3, nil)
	if !errors.Is(err, witness.ErrEmptyWitnessSet) {
		t.Fatalf("expected ErrEmptyWitnessSet, got: %v", err)
	}
}

func TestRotationChain_EmptyRotations_ReturnsGenesis(t *testing.T) {
	genesis := generateFreshKeys(t, 5)
	result, err := witness.VerifyRotationChain(genesis, nil, 3, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 5 {
		t.Fatalf("expected 5, got %d", len(result))
	}
}

func TestRotationChain_BrokenStep_Error(t *testing.T) {
	genesis := generateFreshKeys(t, 5)
	// Rotation with invalid sigs.
	badRotation := types.WitnessRotation{
		CurrentSetHash:    witness.ComputeSetHash(genesis),
		NewSet:            generateFreshKeys(t, 5),
		SchemeTagOld:      signatures.SchemeECDSA,
		CurrentSignatures: []types.WitnessSignature{{SigBytes: make([]byte, 64)}},
	}
	_, err := witness.VerifyRotationChain(genesis, []types.WitnessRotation{badRotation}, 1, nil)
	if err == nil {
		t.Fatal("broken chain should error")
	}
	if !errors.Is(err, witness.ErrRotationChainBroken) {
		t.Fatalf("expected ErrRotationChainBroken, got: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Tests: ComputeSetHash
// ─────────────────────────────────────────────────────────────────────

func TestComputeSetHash_Deterministic(t *testing.T) {
	keys := generateFreshKeys(t, 5)
	h1 := witness.ComputeSetHash(keys)
	h2 := witness.ComputeSetHash(keys)
	if h1 != h2 {
		t.Fatal("same keys should produce same hash")
	}
}

func TestComputeSetHash_DifferentSets(t *testing.T) {
	a := generateFreshKeys(t, 5)
	b := generateFreshKeys(t, 5)
	if witness.ComputeSetHash(a) == witness.ComputeSetHash(b) {
		t.Fatal("different sets should produce different hashes")
	}
}

func TestComputeSetHash_OrderMatters(t *testing.T) {
	keys := generateFreshKeys(t, 3)
	h1 := witness.ComputeSetHash(keys)
	reversed := []types.WitnessPublicKey{keys[2], keys[1], keys[0]}
	h2 := witness.ComputeSetHash(reversed)
	if h1 == h2 {
		t.Fatal("different order should produce different hash")
	}
}

func TestComputeSetHash_EmptySet(t *testing.T) {
	// Should not panic.
	_ = witness.ComputeSetHash(nil)
}

// Suppress unused import warning.
var _ *ecdsa.PrivateKey
