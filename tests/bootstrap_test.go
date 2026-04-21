package tests

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/verifier"
	"github.com/clearcompass-ai/ortholog-sdk/witness"
)

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────
// buildTestHead generates len(keys) fresh ECDSA keys, signs the tree
// head with every one of them, and populates the keys slice with the
// matching public-key material.
//
// Wave 2: per-signature SchemeTag populated on every WitnessSignature;
// the CosignedTreeHead no longer carries a head-level SchemeTag.
//
// Note on the helper's contract: callers pass in a keys slice of the
// desired length. The helper overwrites its contents with freshly
// generated keys. This in-place mutation matches the pattern used by
// the other test helpers in this package.
func buildTestHead(t *testing.T, treeSize uint64, keys []types.WitnessPublicKey, privKeys interface{}) types.CosignedTreeHead {
	t.Helper()
	root := sha256.Sum256([]byte("root"))
	head := types.TreeHead{RootHash: root, TreeSize: treeSize}
	msg := types.WitnessCosignMessage(head)
	msgHash := sha256.Sum256(msg[:])

	sigs := make([]types.WitnessSignature, len(keys))
	for i := range keys {
		// Generate matching key + sig.
		priv, _ := signatures.GenerateKey()
		pubBytes := signatures.PubKeyBytes(&priv.PublicKey)
		id := sha256.Sum256(pubBytes)
		keys[i] = types.WitnessPublicKey{ID: id, PublicKey: pubBytes}
		sigBytes, _ := signatures.SignEntry(msgHash, priv)
		sigs[i] = types.WitnessSignature{
			PubKeyID:  id,
			SchemeTag: signatures.SchemeECDSA, // Wave 2: per-signature scheme
			SigBytes:  sigBytes,
		}
	}

	return types.CosignedTreeHead{
		TreeHead:   head,
		Signatures: sigs,
	}
}

// ─────────────────────────────────────────────────────────────────────
// Tests: HardcodedGenesis
// ─────────────────────────────────────────────────────────────────────

func TestBootstrap_HardcodedGenesis_NoRotations(t *testing.T) {
	keys := make([]types.WitnessPublicKey, 3)
	head := buildTestHead(t, 1000, keys, nil)

	result, err := verifier.HardcodedGenesis(keys, nil, 3, head, nil)
	if err != nil {
		t.Fatalf("genesis: %v", err)
	}
	if result.Method != verifier.MethodHardcodedGenesis {
		t.Fatal("wrong method")
	}
	if len(result.WitnessKeys) != 3 {
		t.Fatalf("keys: %d", len(result.WitnessKeys))
	}
	if result.QuorumK != 3 {
		t.Fatalf("quorumK: %d", result.QuorumK)
	}
	if result.VerifiedHead.TreeSize != 1000 {
		t.Fatalf("tree size: %d", result.VerifiedHead.TreeSize)
	}
	if result.TrustAnchorHash == [32]byte{} {
		t.Fatal("trust anchor hash should not be zero")
	}
}

func TestBootstrap_HardcodedGenesis_EmptyGenesis_Error(t *testing.T) {
	head := types.CosignedTreeHead{TreeHead: types.TreeHead{TreeSize: 100}}
	_, err := verifier.HardcodedGenesis(nil, nil, 1, head, nil)
	if !errors.Is(err, verifier.ErrBootstrapFailed) {
		t.Fatalf("expected ErrBootstrapFailed, got: %v", err)
	}
}

func TestBootstrap_HardcodedGenesis_BadHead_Error(t *testing.T) {
	keys := make([]types.WitnessPublicKey, 3)
	// Build a valid head for different keys.
	_ = buildTestHead(t, 1000, keys, nil)

	// Use a head with no sigs — verification will fail.
	badHead := types.CosignedTreeHead{
		TreeHead:   types.TreeHead{TreeSize: 500, RootHash: sha256.Sum256([]byte("bad"))},
		Signatures: nil,
	}
	_, err := verifier.HardcodedGenesis(keys, nil, 3, badHead, nil)
	if err == nil {
		t.Fatal("bad head should error")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Tests: AnchorLogSync
// ─────────────────────────────────────────────────────────────────────

func TestBootstrap_AnchorLogSync_NilClient_Error(t *testing.T) {
	keys := make([]types.WitnessPublicKey, 3)
	_, err := verifier.AnchorLogSync("did:web:anchor", nil, keys, 3, nil)
	if !errors.Is(err, verifier.ErrBootstrapFailed) {
		t.Fatalf("expected ErrBootstrapFailed, got: %v", err)
	}
}

func TestBootstrap_AnchorLogSync_EmptyKeys_Error(t *testing.T) {
	endpoints := &witness.StaticEndpoints{
		Operators: map[string]string{"did:web:anchor": "http://localhost"},
	}
	client := witness.NewTreeHeadClient(endpoints, witness.DefaultTreeHeadClientConfig())
	_, err := verifier.AnchorLogSync("did:web:anchor", client, nil, 3, nil)
	if !errors.Is(err, verifier.ErrBootstrapFailed) {
		t.Fatalf("expected ErrBootstrapFailed, got: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Tests: TrustOnFirstUse
// ─────────────────────────────────────────────────────────────────────

func TestBootstrap_TOFU_Valid(t *testing.T) {
	head := types.CosignedTreeHead{
		TreeHead: types.TreeHead{
			TreeSize: 500,
			RootHash: sha256.Sum256([]byte("tofu")),
		},
	}
	now := time.Now().UTC()
	result, err := verifier.TrustOnFirstUse(head, now)
	if err != nil {
		t.Fatalf("tofu: %v", err)
	}
	if result.Method != verifier.MethodTrustOnFirstUse {
		t.Fatal("wrong method")
	}
	if result.WitnessKeys != nil {
		t.Fatal("TOFU should have nil witness keys")
	}
	if result.QuorumK != 0 {
		t.Fatal("TOFU quorum should be 0")
	}
	if result.VerifiedHead.TreeSize != 500 {
		t.Fatalf("tree size: %d", result.VerifiedHead.TreeSize)
	}
	if result.EstablishedAt != now {
		t.Fatal("established time mismatch")
	}
}

func TestBootstrap_TOFU_EmptyHead_Error(t *testing.T) {
	_, err := verifier.TrustOnFirstUse(types.CosignedTreeHead{}, time.Now())
	if !errors.Is(err, verifier.ErrEmptyHead) {
		t.Fatalf("expected ErrEmptyHead, got: %v", err)
	}
}

func TestBootstrap_TOFU_ZeroSizeNonZeroRoot_Valid(t *testing.T) {
	head := types.CosignedTreeHead{
		TreeHead: types.TreeHead{
			TreeSize: 0,
			RootHash: sha256.Sum256([]byte("empty-tree")), // Non-zero root.
		},
	}
	_, err := verifier.TrustOnFirstUse(head, time.Now())
	if err != nil {
		t.Fatalf("zero size with non-zero root should be valid: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Tests: TreeHeadHash
// ─────────────────────────────────────────────────────────────────────

func TestTreeHeadHash_Deterministic(t *testing.T) {
	head := types.TreeHead{TreeSize: 1000, RootHash: sha256.Sum256([]byte("root"))}
	h1 := verifier.TreeHeadHash(head)
	h2 := verifier.TreeHeadHash(head)
	if h1 != h2 {
		t.Fatal("should be deterministic")
	}
}

func TestTreeHeadHash_DifferentHeads(t *testing.T) {
	a := types.TreeHead{TreeSize: 100, RootHash: sha256.Sum256([]byte("a"))}
	b := types.TreeHead{TreeSize: 200, RootHash: sha256.Sum256([]byte("b"))}
	if verifier.TreeHeadHash(a) == verifier.TreeHeadHash(b) {
		t.Fatal("different heads should produce different hashes")
	}
}

func TestTreeHeadHash_SizeMatters(t *testing.T) {
	root := sha256.Sum256([]byte("same"))
	a := types.TreeHead{TreeSize: 100, RootHash: root}
	b := types.TreeHead{TreeSize: 101, RootHash: root}
	if verifier.TreeHeadHash(a) == verifier.TreeHeadHash(b) {
		t.Fatal("different sizes should produce different hashes")
	}
}
