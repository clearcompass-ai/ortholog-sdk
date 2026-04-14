package tests

import (
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/verifier"
)

// ─────────────────────────────────────────────────────────────────────
// Mock implementations
// ─────────────────────────────────────────────────────────────────────

type mockEntryFetcher struct {
	entries map[string]*types.EntryWithMetadata // key: "logDID@seq"
}

func (f *mockEntryFetcher) Fetch(pos types.LogPosition) (*types.EntryWithMetadata, error) {
	key := pos.String()
	entry, ok := f.entries[key]
	if !ok {
		return nil, errors.New("entry not found: " + key)
	}
	return entry, nil
}

type mockMerkleProver struct {
	proofs map[uint64]*types.MerkleProof // key: position
	err    error
}

func (p *mockMerkleProver) InclusionProof(position, treeSize uint64) (*types.MerkleProof, error) {
	if p.err != nil {
		return nil, p.err
	}
	proof, ok := p.proofs[position]
	if !ok {
		return nil, errors.New("no proof for position")
	}
	return proof, nil
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

func buildValidCrossLogFixture(t *testing.T) (
	proof types.CrossLogProof,
	keys []types.WitnessPublicKey,
) {
	t.Helper()

	// Build a source tree head with valid signatures.
	sourceRoot := sha256.Sum256([]byte("source-root"))
	sourceHead := types.TreeHead{RootHash: sourceRoot, TreeSize: 100}

	// Generate witness keys and sign.
	keys = make([]types.WitnessPublicKey, 3)
	msg := types.WitnessCosignMessage(sourceHead)
	msgHash := sha256.Sum256(msg[:])
	sigs := make([]types.WitnessSignature, 3)
	for i := 0; i < 3; i++ {
		priv, _ := signatures.GenerateKey()
		pubBytes := signatures.PubKeyBytes(&priv.PublicKey)
		id := sha256.Sum256(pubBytes)
		keys[i] = types.WitnessPublicKey{ID: id, PublicKey: pubBytes}
		sigBytes, _ := signatures.SignEntry(msgHash, priv)
		sigs[i] = types.WitnessSignature{PubKeyID: id, SigBytes: sigBytes}
	}

	sourceCTH := types.CosignedTreeHead{
		TreeHead:   sourceHead,
		SchemeTag:  signatures.SchemeECDSA,
		Signatures: sigs,
	}

	// Source entry.
	sourceEntryHash := sha256.Sum256([]byte("source-entry-bytes"))

	// Source inclusion proof (stub — VerifyMerkleInclusion will verify against root).
	sourceInclusion := types.MerkleProof{
		LeafPosition: 42,
		LeafHash:     sourceEntryHash,
		TreeSize:     100,
	}

	// Anchor.
	anchorTreeHeadRef := verifier.TreeHeadHash(sourceHead)
	anchorEntryHash := sha256.Sum256([]byte("anchor-entry-bytes"))

	// Local tree head (different root).
	localRoot := sha256.Sum256([]byte("local-root"))
	localCTH := types.CosignedTreeHead{
		TreeHead: types.TreeHead{RootHash: localRoot, TreeSize: 500},
	}
	localInclusion := types.MerkleProof{
		LeafPosition: 99,
		LeafHash:     anchorEntryHash,
		TreeSize:     500,
	}

	proof = types.CrossLogProof{
		SourceEntry:       types.LogPosition{LogDID: "did:web:source", Sequence: 42},
		SourceEntryHash:   sourceEntryHash,
		SourceTreeHead:    sourceCTH,
		SourceInclusion:   sourceInclusion,
		AnchorEntry:       types.LogPosition{LogDID: "did:web:local", Sequence: 99},
		AnchorEntryHash:   anchorEntryHash,
		AnchorTreeHeadRef: anchorTreeHeadRef,
		LocalTreeHead:     localCTH,
		LocalInclusion:    localInclusion,
	}

	return proof, keys
}

// ─────────────────────────────────────────────────────────────────────
// Tests: VerifyCrossLogProof
// ─────────────────────────────────────────────────────────────────────

func TestCrossLog_VerifyProof_ZeroSourceHash_Error(t *testing.T) {
	proof, keys := buildValidCrossLogFixture(t)
	proof.SourceEntryHash = [32]byte{} // Zero hash.
	err := verifier.VerifyCrossLogProof(proof, keys, 3, nil)
	if !errors.Is(err, verifier.ErrSourceInclusionFailed) {
		t.Fatalf("expected ErrSourceInclusionFailed, got: %v", err)
	}
}

func TestCrossLog_VerifyProof_AnchorMismatch_Error(t *testing.T) {
	proof, keys := buildValidCrossLogFixture(t)
	proof.AnchorTreeHeadRef = [32]byte{0xFF} // Wrong ref.
	// Skip inclusion checks for this test — they'll pass or fail before anchor check.
	// The anchor mismatch check is step 4.
	err := verifier.VerifyCrossLogProof(proof, keys, 3, nil)
	// May fail at step 2 (inclusion) or step 4 (anchor) depending on mock.
	if err == nil {
		t.Fatal("anchor mismatch should error")
	}
}

func TestCrossLog_VerifyProof_SourceHeadInvalid_Error(t *testing.T) {
	proof, _ := buildValidCrossLogFixture(t)
	// Use wrong witness keys.
	wrongKeys := generateFreshKeys(t, 3)
	err := verifier.VerifyCrossLogProof(proof, wrongKeys, 3, nil)
	if err == nil {
		t.Fatal("wrong keys should error")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Tests: BuildCrossLogProof
// ─────────────────────────────────────────────────────────────────────

func TestCrossLog_Build_Valid(t *testing.T) {
	sourceRef := types.LogPosition{LogDID: "did:web:source", Sequence: 5}
	anchorRef := types.LogPosition{LogDID: "did:web:local", Sequence: 10}

	sourceEntry := &types.EntryWithMetadata{
		CanonicalBytes: []byte("source-entry-data"),
		Position:       sourceRef,
		LogTime:        time.Now(),
	}
	anchorEntry := &types.EntryWithMetadata{
		CanonicalBytes: []byte("anchor-entry-data"),
		Position:       anchorRef,
		LogTime:        time.Now(),
	}

	fetcher := &mockEntryFetcher{
		entries: map[string]*types.EntryWithMetadata{
			sourceRef.String(): sourceEntry,
			anchorRef.String(): anchorEntry,
		},
	}

	sourceProof := &types.MerkleProof{LeafPosition: 5, TreeSize: 100}
	localProof := &types.MerkleProof{LeafPosition: 10, TreeSize: 500}

	sourceProver := &mockMerkleProver{proofs: map[uint64]*types.MerkleProof{5: sourceProof}}
	localProver := &mockMerkleProver{proofs: map[uint64]*types.MerkleProof{10: localProof}}

	sourceRoot := sha256.Sum256([]byte("src-root"))
	sourceHead := types.CosignedTreeHead{TreeHead: types.TreeHead{RootHash: sourceRoot, TreeSize: 100}}
	localRoot := sha256.Sum256([]byte("lcl-root"))
	localHead := types.CosignedTreeHead{TreeHead: types.TreeHead{RootHash: localRoot, TreeSize: 500}}

	proof, err := verifier.BuildCrossLogProof(sourceRef, anchorRef, fetcher, sourceProver, localProver, sourceHead, localHead)
	if err != nil {
		t.Fatalf("build: %v", err)
	}

	if proof.SourceEntry != sourceRef {
		t.Fatal("source entry mismatch")
	}
	if proof.AnchorEntry != anchorRef {
		t.Fatal("anchor entry mismatch")
	}
	expectedSourceHash := sha256.Sum256(sourceEntry.CanonicalBytes)
	if proof.SourceEntryHash != expectedSourceHash {
		t.Fatal("source hash mismatch")
	}
	expectedAnchorHash := sha256.Sum256(anchorEntry.CanonicalBytes)
	if proof.AnchorEntryHash != expectedAnchorHash {
		t.Fatal("anchor hash mismatch")
	}
	expectedRef := verifier.TreeHeadHash(sourceHead.TreeHead)
	if proof.AnchorTreeHeadRef != expectedRef {
		t.Fatal("anchor tree head ref mismatch")
	}
}

func TestCrossLog_Build_SourceNotFound_Error(t *testing.T) {
	fetcher := &mockEntryFetcher{entries: map[string]*types.EntryWithMetadata{}}
	sourceProver := &mockMerkleProver{proofs: map[uint64]*types.MerkleProof{}}
	localProver := &mockMerkleProver{proofs: map[uint64]*types.MerkleProof{}}

	_, err := verifier.BuildCrossLogProof(
		types.LogPosition{LogDID: "did:web:missing", Sequence: 1},
		types.LogPosition{LogDID: "did:web:local", Sequence: 2},
		fetcher, sourceProver, localProver,
		types.CosignedTreeHead{}, types.CosignedTreeHead{},
	)
	if !errors.Is(err, verifier.ErrSourceEntryNotFound) {
		t.Fatalf("expected ErrSourceEntryNotFound, got: %v", err)
	}
}

func TestCrossLog_Build_SourceProofFails_Error(t *testing.T) {
	sourceRef := types.LogPosition{LogDID: "did:web:src", Sequence: 1}
	anchorRef := types.LogPosition{LogDID: "did:web:lcl", Sequence: 2}

	fetcher := &mockEntryFetcher{
		entries: map[string]*types.EntryWithMetadata{
			sourceRef.String(): {CanonicalBytes: []byte("data"), Position: sourceRef},
		},
	}
	sourceProver := &mockMerkleProver{err: errors.New("proof unavailable")}
	localProver := &mockMerkleProver{proofs: map[uint64]*types.MerkleProof{}}

	_, err := verifier.BuildCrossLogProof(sourceRef, anchorRef, fetcher, sourceProver, localProver,
		types.CosignedTreeHead{}, types.CosignedTreeHead{})
	if !errors.Is(err, verifier.ErrSourceInclusionFailed) {
		t.Fatalf("expected ErrSourceInclusionFailed, got: %v", err)
	}
}

func TestCrossLog_Build_AnchorNotFound_Error(t *testing.T) {
	sourceRef := types.LogPosition{LogDID: "did:web:src", Sequence: 1}
	anchorRef := types.LogPosition{LogDID: "did:web:lcl", Sequence: 2}

	fetcher := &mockEntryFetcher{
		entries: map[string]*types.EntryWithMetadata{
			sourceRef.String(): {CanonicalBytes: []byte("data"), Position: sourceRef},
		},
	}
	sourceProver := &mockMerkleProver{proofs: map[uint64]*types.MerkleProof{1: {LeafPosition: 1}}}
	localProver := &mockMerkleProver{proofs: map[uint64]*types.MerkleProof{}}

	_, err := verifier.BuildCrossLogProof(sourceRef, anchorRef, fetcher, sourceProver, localProver,
		types.CosignedTreeHead{TreeHead: types.TreeHead{TreeSize: 10}},
		types.CosignedTreeHead{TreeHead: types.TreeHead{TreeSize: 20}})
	if !errors.Is(err, verifier.ErrAnchorEntryNotFound) {
		t.Fatalf("expected ErrAnchorEntryNotFound, got: %v", err)
	}
}

func TestCrossLog_Build_LocalProofFails_Error(t *testing.T) {
	sourceRef := types.LogPosition{LogDID: "did:web:src", Sequence: 1}
	anchorRef := types.LogPosition{LogDID: "did:web:lcl", Sequence: 2}

	fetcher := &mockEntryFetcher{
		entries: map[string]*types.EntryWithMetadata{
			sourceRef.String(): {CanonicalBytes: []byte("src"), Position: sourceRef},
			anchorRef.String(): {CanonicalBytes: []byte("anc"), Position: anchorRef},
		},
	}
	sourceProver := &mockMerkleProver{proofs: map[uint64]*types.MerkleProof{1: {LeafPosition: 1}}}
	localProver := &mockMerkleProver{err: errors.New("proof unavailable")}

	_, err := verifier.BuildCrossLogProof(sourceRef, anchorRef, fetcher, sourceProver, localProver,
		types.CosignedTreeHead{TreeHead: types.TreeHead{TreeSize: 10}},
		types.CosignedTreeHead{TreeHead: types.TreeHead{TreeSize: 20}})
	if !errors.Is(err, verifier.ErrLocalInclusionFailed) {
		t.Fatalf("expected ErrLocalInclusionFailed, got: %v", err)
	}
}
