/*
FILE PATH:

	tests/witness_rotation_test.go

DESCRIPTION:

	Tests for witness.VerifyRotation and witness.VerifyRotationChain —
	the functions that validate rotation messages against a current
	witness set and walk a sequence of rotations from genesis to the
	current authority.

	Covers:
	  - Valid single-step rotations (various K-of-N configurations)
	  - Error paths (empty new set, empty sigs, hash mismatch, invalid
	    sigs, zero quorum)
	  - Dual-sign scheme transitions (Decision 41: ECDSA → BLS)
	  - Rotation chain walking with and without breaks

WAVE 2 CHANGE:

	Pre-Wave-2, each CosignedTreeHead carried a head-level SchemeTag
	and every WitnessSignature in the rotation inherited that scheme
	implicitly. Post-Wave-2, each WitnessSignature carries its own
	SchemeTag; the production code in witness/rotation.go enforces
	that CurrentSignatures[i].SchemeTag == SchemeTagOld and
	NewSignatures[i].SchemeTag == SchemeTagNew for every i.

	This file updates every WitnessSignature literal to declare its
	scheme explicitly. Two classes of site:

	  1. Helper-built literals: buildValidRotation and
	     buildValidDualSignRotation construct real ECDSA/BLS
	     signatures. The scheme tag declared must match the rotation's
	     SchemeTagOld (for CurrentSignatures) or SchemeTagNew (for
	     NewSignatures). Thread-through is mechanical.

	  2. Test-fixture literals: error-path tests construct rotations
	     with placeholder signatures ("sig", make([]byte, 64)) to
	     exercise specific error branches. These must still declare a
	     SchemeTag to pass Wave 2's strict enforcement, even though
	     the test short-circuits before cryptographic verification in
	     most cases. Declaring the tag defensively makes the test
	     robust against future reordering of checks in VerifyRotation.

	DUAL-SIGN NOTE (line ~115 in the original, preserved here):

	  The dual-sign helper (buildValidDualSignRotation) constructs a
	  rotation transitioning from ECDSA to BLS. The "new-scheme" signatures
	  are signed with signatures.SignEntry (ECDSA primitive) and placed
	  in NewSignatures with SchemeTag: SchemeBLS — these are NOT
	  cryptographically valid BLS signatures. The dual-sign test works
	  because it injects mockBLSVerifierP4, which returns all-true
	  regardless of input bytes. The test exercises dispatch routing,
	  not cryptographic correctness of the new-scheme path.
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
// Helpers: build rotation messages with valid ECDSA signatures
// ─────────────────────────────────────────────────────────────────────

// generateFreshKeysWithPriv returns both public witness keys and
// private keys. Used by helpers that need to sign rotation messages.
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

// generateFreshKeys is a convenience wrapper for tests that don't
// need the private keys.
func generateFreshKeys(t *testing.T, n int) []types.WitnessPublicKey {
	t.Helper()
	keys, _ := generateFreshKeysWithPriv(t, n)
	return keys
}

// buildValidRotation creates a rotation from current set to a new set,
// with valid ECDSA signatures from the first sigCount current-set
// members.
//
// Wave 2: each WitnessSignature in CurrentSignatures declares
// SchemeTag: signatures.SchemeECDSA to match the rotation's
// SchemeTagOld. If these match is missing, witness/rotation.go's
// strict enforcement (ErrRotationSchemeMismatch) rejects the
// rotation before cryptographic verification.
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
			PubKeyID:  currentKeys[i].ID,
			SchemeTag: signatures.SchemeECDSA, // Wave 2: must match SchemeTagOld below
			SigBytes:  sigBytes,
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

// buildValidDualSignRotation creates a rotation that transitions the
// signing scheme from ECDSA to BLS (Decision 41 dual-sign).
//
// SchemeTagOld = ECDSA (0x01), SchemeTagNew = BLS (0x02).
//
// Wave 2: CurrentSignatures declare SchemeECDSA (matching SchemeTagOld);
// NewSignatures declare SchemeBLS (matching SchemeTagNew). Both
// populations are required by the strict enforcement in
// witness/rotation.go.
//
// Cryptographic caveat: NewSignatures are produced by signatures.SignEntry
// (ECDSA primitive) but tagged as SchemeBLS. These bytes are NOT valid
// BLS signatures. Tests using this helper must inject a mock BLSVerifier
// (mockBLSVerifierP4) that returns all-true regardless of input — the
// helper exercises dispatch routing, not cryptographic correctness of
// the new-scheme path.
func buildValidDualSignRotation(t *testing.T, setSize, sigCount int) (
	currentKeys []types.WitnessPublicKey,
	newKeysWithPriv []types.WitnessPublicKey,
	rotation types.WitnessRotation,
) {
	t.Helper()

	// Build a base ECDSA→ECDSA rotation, then upgrade it to a
	// dual-sign rotation by overriding SchemeTagNew and adding
	// new-scheme signatures.
	currentKeys, _, rotation = buildValidRotation(t, setSize, sigCount, setSize)
	rotation.SchemeTagNew = signatures.SchemeBLS // FIX: must differ from SchemeTagOld (ECDSA).

	// Generate a fresh "new set" with private keys so we can sign
	// the rotation message under the new-scheme authority.
	var newPrivs []*ecdsa.PrivateKey
	newKeysWithPriv, newPrivs = generateFreshKeysWithPriv(t, setSize)
	rotation.NewSet = newKeysWithPriv

	// Recompute message against the updated new set hash.
	newSetHash := witness.ComputeSetHash(newKeysWithPriv)
	msg := types.WitnessCosignMessage(types.TreeHead{RootHash: newSetHash, TreeSize: 0})
	msgHash := sha256.Sum256(msg[:])

	// Re-sign current sigs against the updated new set hash.
	// The current-set signatures must still declare SchemeECDSA.
	currentKeysNew, currentPrivsNew := generateFreshKeysWithPriv(t, setSize)
	rotation.CurrentSetHash = witness.ComputeSetHash(currentKeysNew)
	currentSigs := make([]types.WitnessSignature, sigCount)
	for i := 0; i < sigCount; i++ {
		sigBytes, _ := signatures.SignEntry(msgHash, currentPrivsNew[i])
		currentSigs[i] = types.WitnessSignature{
			PubKeyID:  currentKeysNew[i].ID,
			SchemeTag: signatures.SchemeECDSA, // Wave 2: matches SchemeTagOld
			SigBytes:  sigBytes,
		}
	}
	rotation.CurrentSignatures = currentSigs
	currentKeys = currentKeysNew

	// New-scheme sigs from the new set.
	// These are placeholder bytes (ECDSA-format, BLS-tagged) — verified
	// via mockBLSVerifierP4 in tests which bypasses real BLS math.
	// What matters structurally is that they carry SchemeTag: SchemeBLS
	// so the Wave 2 dispatcher routes them to the BLS verifier path.
	newSigs := make([]types.WitnessSignature, sigCount)
	for i := 0; i < sigCount; i++ {
		sigBytes, _ := signatures.SignEntry(msgHash, newPrivs[i])
		newSigs[i] = types.WitnessSignature{
			PubKeyID:  newKeysWithPriv[i].ID,
			SchemeTag: signatures.SchemeBLS, // Wave 2: matches SchemeTagNew
			SigBytes:  sigBytes,
		}
	}
	rotation.NewSignatures = newSigs

	return
}

// ─────────────────────────────────────────────────────────────────────
// Tests: VerifyRotation
// ─────────────────────────────────────────────────────────────────────

func TestRotation_SingleValid(t *testing.T) {
	currentKeys, _, rotation := buildValidRotation(t, 5, 3, 5)
	newSet, err := witness.VerifyRotation(rotation, currentKeys, 3, nil)
	if err != nil {
		t.Fatalf("valid rotation should pass: %v", err)
	}
	if len(newSet) != 5 {
		t.Fatalf("new set: got %d, want 5", len(newSet))
	}
}

func TestRotation_K1N1(t *testing.T) {
	currentKeys, _, rotation := buildValidRotation(t, 1, 1, 3)
	newSet, err := witness.VerifyRotation(rotation, currentKeys, 1, nil)
	if err != nil {
		t.Fatalf("K=1/N=1 rotation should pass: %v", err)
	}
	if len(newSet) != 3 {
		t.Fatalf("new set: got %d, want 3", len(newSet))
	}
}

func TestRotation_EmptyNewSet_Error(t *testing.T) {
	// Test short-circuits on empty NewSet before reaching scheme check;
	// SchemeTag on the placeholder sig is immaterial but declared for
	// consistency and robustness against check reordering.
	rotation := types.WitnessRotation{
		NewSet: nil,
		CurrentSignatures: []types.WitnessSignature{
			{SchemeTag: signatures.SchemeECDSA, SigBytes: []byte("sig")},
		},
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
	// Short-circuits on empty currentSet before scheme check.
	rotation := types.WitnessRotation{
		NewSet: make([]types.WitnessPublicKey, 3),
		CurrentSignatures: []types.WitnessSignature{
			{SchemeTag: signatures.SchemeECDSA, SigBytes: []byte("sig")},
		},
	}
	_, err := witness.VerifyRotation(rotation, nil, 2, nil)
	if !errors.Is(err, witness.ErrEmptyWitnessSet) {
		t.Fatalf("expected ErrEmptyWitnessSet, got: %v", err)
	}
}

func TestRotation_ZeroQuorum_Error(t *testing.T) {
	// Short-circuits on K=0 before scheme check.
	rotation := types.WitnessRotation{
		NewSet: make([]types.WitnessPublicKey, 3),
		CurrentSignatures: []types.WitnessSignature{
			{SchemeTag: signatures.SchemeECDSA, SigBytes: []byte("sig")},
		},
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
	// Tests that invalid signature BYTES (not scheme mismatch) cause
	// rejection. The SchemeTag must be declared so the test exercises
	// the cryptographic-verification failure path, not the Wave 2
	// scheme-mismatch path.
	currentKeys := generateFreshKeys(t, 5)
	newKeys := generateFreshKeys(t, 5)
	setHash := witness.ComputeSetHash(currentKeys)
	rotation := types.WitnessRotation{
		CurrentSetHash: setHash,
		NewSet:         newKeys,
		SchemeTagOld:   signatures.SchemeECDSA,
		CurrentSignatures: []types.WitnessSignature{
			{SchemeTag: signatures.SchemeECDSA, SigBytes: make([]byte, 64)},
			{SchemeTag: signatures.SchemeECDSA, SigBytes: make([]byte, 64)},
			{SchemeTag: signatures.SchemeECDSA, SigBytes: make([]byte, 64)},
		},
	}
	_, err := witness.VerifyRotation(rotation, currentKeys, 3, nil)
	if err == nil {
		t.Fatal("invalid sigs should error")
	}
}

func TestRotation_DualSign_SchemeTransition(t *testing.T) {
	currentKeys, _, rotation := buildValidDualSignRotation(t, 5, 3)
	// Mock BLS verifier: new-scheme sigs are verified via mock since we
	// don't produce real BLS signatures in the helper.
	mock := &mockBLSVerifierP4{results: []bool{true, true, true}}
	newSet, err := witness.VerifyRotation(rotation, currentKeys, 3, mock)
	if err != nil {
		t.Fatalf("dual-sign should pass: %v", err)
	}
	if len(newSet) != 5 {
		t.Fatalf("new set: got %d, want 5", len(newSet))
	}
}

func TestRotation_DualSign_MissingNewSigs_Error(t *testing.T) {
	currentKeys, _, rotation := buildValidDualSignRotation(t, 5, 3)
	// Strip the new-scheme signatures.
	rotation.NewSignatures = nil
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
		t.Fatalf("new set: got %d, want 5", len(newSet))
	}
}

func TestRotationChain_EmptyChain_ReturnsGenesis(t *testing.T) {
	genesisKeys := generateFreshKeys(t, 5)
	newSet, err := witness.VerifyRotationChain(genesisKeys, nil, 3, nil)
	if err != nil {
		t.Fatalf("empty chain should return genesis: %v", err)
	}
	if len(newSet) != 5 {
		t.Fatalf("should return genesis unchanged: got %d keys", len(newSet))
	}
}

func TestRotationChain_EmptyGenesis_Error(t *testing.T) {
	_, err := witness.VerifyRotationChain(nil, nil, 3, nil)
	if !errors.Is(err, witness.ErrEmptyWitnessSet) {
		t.Fatalf("expected ErrEmptyWitnessSet, got: %v", err)
	}
}

func TestRotationChain_BrokenStep_Error(t *testing.T) {
	// Tests that a chain with an invalid rotation surfaces
	// ErrRotationChainBroken. The single CurrentSignature has correctly
	// declared SchemeTag (matching SchemeTagOld) but invalid bytes; the
	// chain break is from cryptographic verification failure.
	genesis := generateFreshKeys(t, 5)
	badRotation := types.WitnessRotation{
		CurrentSetHash: witness.ComputeSetHash(genesis),
		NewSet:         generateFreshKeys(t, 5),
		SchemeTagOld:   signatures.SchemeECDSA,
		CurrentSignatures: []types.WitnessSignature{
			{SchemeTag: signatures.SchemeECDSA, SigBytes: make([]byte, 64)},
		},
	}
	_, err := witness.VerifyRotationChain(genesis, []types.WitnessRotation{badRotation}, 1, nil)
	if err == nil {
		t.Fatal("broken chain should error")
	}
	if !errors.Is(err, witness.ErrRotationChainBroken) {
		t.Fatalf("expected ErrRotationChainBroken, got: %v", err)
	}
}
