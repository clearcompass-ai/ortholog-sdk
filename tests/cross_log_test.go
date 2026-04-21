/*
tests/cross_log_test.go — Black-box tests for cross-log proof building.

These tests exercise verifier.BuildCrossLogProof as an external
consumer would, using mock implementations of EntryFetcher and
MerkleProver. The happy and four early-exit error paths of the
builder are covered:

	Happy:   TestCrossLog_Build_Valid
	Errors:  TestCrossLog_Build_SourceNotFound_Error    (ErrSourceEntryNotFound)
	         TestCrossLog_Build_SourceProofFails_Error  (ErrSourceInclusionFailed)
	         TestCrossLog_Build_AnchorNotFound_Error    (ErrAnchorEntryNotFound)
	         TestCrossLog_Build_LocalProofFails_Error   (ErrLocalInclusionFailed)

WHY NO VERIFY TESTS HERE
────────────────────────
Verifier-path tests (where the semantic checks — hash binding,
witness quorum, anchor content binding — are exercised) live in
verifier/cross_log_test.go alongside the real envelope and SMT
fixtures. Those tests depend on the real primitives rather than
mocks, and duplicating the fixture setup in an external package
would be wasteful. The attack-matrix coverage (A1–A9 of the
ORTHO-BUG-001 matrix) is complete there.

WHY BUILD TESTS LIVE HERE
─────────────────────────
BuildCrossLogProof's contract with its callers (EntryFetcher,
MerkleProver) is pure mock territory — no cryptographic semantics
need to hold for these error paths to be exercised. Testing them
from an external package catches accidental dependencies on the
verifier package's internal helpers.
*/
package tests

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/verifier"
)

// ─────────────────────────────────────────────────────────────────────
// Mocks
// ─────────────────────────────────────────────────────────────────────

// mockEntryFetcher satisfies verifier.EntryFetcher. Keyed by the
// LogPosition's String() form because LogPosition is a composite type
// (LogDID + Sequence) and Go map keys must be comparable exactly —
// the String() form collapses that to a stable scalar key.
type mockEntryFetcher struct {
	entries map[string]*types.EntryWithMetadata
}

func (f *mockEntryFetcher) Fetch(pos types.LogPosition) (*types.EntryWithMetadata, error) {
	entry, ok := f.entries[pos.String()]
	if !ok {
		return nil, errors.New("mockEntryFetcher: entry not found: " + pos.String())
	}
	return entry, nil
}

// mockMerkleProver satisfies verifier.MerkleProver. If err is non-nil,
// every call returns it (for testing builder error paths). Otherwise
// returns the proof stored at `position` in the map, or a missing-proof
// error.
type mockMerkleProver struct {
	proofs map[uint64]*types.MerkleProof
	err    error
}

func (p *mockMerkleProver) InclusionProof(position, treeSize uint64) (*types.MerkleProof, error) {
	if p.err != nil {
		return nil, p.err
	}
	proof, ok := p.proofs[position]
	if !ok {
		return nil, errors.New("mockMerkleProver: no proof for position")
	}
	return proof, nil
}

// ─────────────────────────────────────────────────────────────────────
// Happy path
// ─────────────────────────────────────────────────────────────────────

// TestCrossLog_Build_Valid exercises the builder's complete happy
// path. Asserts:
//
//   - Positions flow through unchanged (SourceEntry, AnchorEntry).
//   - Entry hashes are RFC 6962 leaf hashes — NOT plain SHA-256.
//     This is the original BUG-001 trigger: confusing
//     sha256.Sum256(canonical) with envelope.EntryLeafHashBytes
//     (sha256(0x00 || canonical)) silently broke every Merkle
//     inclusion proof. The assertion guards against that regression.
//   - MerkleProof.LeafHash is bound to the entry hash on both
//     inclusion proofs. The builder does this explicitly as defense
//     against MerkleProver implementations that leave LeafHash zero.
//   - AnchorEntryCanonical is populated from the fetched anchor.
//     This is the field that makes the verifier a pure function;
//     without it the anchor-content-binding check (ORTHO-BUG-001
//     step 9) cannot run.
func TestCrossLog_Build_Valid(t *testing.T) {
	sourceRef := types.LogPosition{LogDID: "did:web:source", Sequence: 5}
	anchorRef := types.LogPosition{LogDID: "did:web:local", Sequence: 10}

	sourceEntry := &types.EntryWithMetadata{
		CanonicalBytes: []byte("source-entry-data"),
		Position:       sourceRef,
	}
	anchorEntry := &types.EntryWithMetadata{
		CanonicalBytes: []byte("anchor-entry-data"),
		Position:       anchorRef,
	}

	fetcher := &mockEntryFetcher{
		entries: map[string]*types.EntryWithMetadata{
			sourceRef.String(): sourceEntry,
			anchorRef.String(): anchorEntry,
		},
	}

	sourceProver := &mockMerkleProver{
		proofs: map[uint64]*types.MerkleProof{5: {LeafPosition: 5, TreeSize: 100}},
	}
	localProver := &mockMerkleProver{
		proofs: map[uint64]*types.MerkleProof{10: {LeafPosition: 10, TreeSize: 500}},
	}

	sourceHead := types.CosignedTreeHead{
		TreeHead: types.TreeHead{
			RootHash: sha256.Sum256([]byte("src-root")),
			TreeSize: 100,
		},
	}
	localHead := types.CosignedTreeHead{
		TreeHead: types.TreeHead{
			RootHash: sha256.Sum256([]byte("lcl-root")),
			TreeSize: 500,
		},
	}

	proof, err := verifier.BuildCrossLogProof(
		sourceRef, anchorRef,
		fetcher, sourceProver, localProver,
		sourceHead, localHead,
	)
	if err != nil {
		t.Fatalf("BuildCrossLogProof: %v", err)
	}

	// Positions flow through unchanged.
	if proof.SourceEntry != sourceRef {
		t.Errorf("SourceEntry:\n  got  %v\n  want %v", proof.SourceEntry, sourceRef)
	}
	if proof.AnchorEntry != anchorRef {
		t.Errorf("AnchorEntry:\n  got  %v\n  want %v", proof.AnchorEntry, anchorRef)
	}

	// Hashes are RFC 6962 leaf hashes. If plain sha256.Sum256 is used,
	// these assertions fail — catching the original BUG-001 trigger.
	wantSourceHash := envelope.EntryLeafHashBytes(sourceEntry.CanonicalBytes)
	if proof.SourceEntryHash != wantSourceHash {
		t.Errorf("SourceEntryHash is not RFC 6962 leaf hash:\n  got  %x\n  want %x",
			proof.SourceEntryHash, wantSourceHash)
	}
	wantAnchorHash := envelope.EntryLeafHashBytes(anchorEntry.CanonicalBytes)
	if proof.AnchorEntryHash != wantAnchorHash {
		t.Errorf("AnchorEntryHash is not RFC 6962 leaf hash:\n  got  %x\n  want %x",
			proof.AnchorEntryHash, wantAnchorHash)
	}

	// Builder binds MerkleProof.LeafHash to the entry hash on both
	// inclusion proofs. A zero LeafHash here means the builder is
	// trusting the MerkleProver's output blindly.
	if proof.SourceInclusion.LeafHash != wantSourceHash {
		t.Errorf("SourceInclusion.LeafHash not bound to SourceEntryHash:\n  got  %x\n  want %x",
			proof.SourceInclusion.LeafHash, wantSourceHash)
	}
	if proof.LocalInclusion.LeafHash != wantAnchorHash {
		t.Errorf("LocalInclusion.LeafHash not bound to AnchorEntryHash:\n  got  %x\n  want %x",
			proof.LocalInclusion.LeafHash, wantAnchorHash)
	}

	// AnchorEntryCanonical is the field that makes the verifier a pure
	// function. Without it, the verifier cannot deserialize the anchor
	// entry to run the content-binding check.
	if !bytes.Equal(proof.AnchorEntryCanonical, anchorEntry.CanonicalBytes) {
		t.Errorf("AnchorEntryCanonical not propagated:\n  got  %x\n  want %x",
			proof.AnchorEntryCanonical, anchorEntry.CanonicalBytes)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Error paths (in order of builder early-exit)
// ─────────────────────────────────────────────────────────────────────

// TestCrossLog_Build_SourceNotFound_Error — fetcher has no entry at
// the source position. Builder returns ErrSourceEntryNotFound at step 1
// without touching the provers.
func TestCrossLog_Build_SourceNotFound_Error(t *testing.T) {
	fetcher := &mockEntryFetcher{entries: map[string]*types.EntryWithMetadata{}}

	_, err := verifier.BuildCrossLogProof(
		types.LogPosition{LogDID: "did:web:missing", Sequence: 1},
		types.LogPosition{LogDID: "did:web:local", Sequence: 2},
		fetcher,
		&mockMerkleProver{proofs: map[uint64]*types.MerkleProof{}},
		&mockMerkleProver{proofs: map[uint64]*types.MerkleProof{}},
		types.CosignedTreeHead{}, types.CosignedTreeHead{},
	)
	if !errors.Is(err, verifier.ErrSourceEntryNotFound) {
		t.Fatalf("expected ErrSourceEntryNotFound, got: %v", err)
	}
}

// TestCrossLog_Build_SourceProofFails_Error — source fetch succeeds
// but source MerkleProver returns an error. Builder wraps it as
// ErrSourceInclusionFailed and returns at step 2.
func TestCrossLog_Build_SourceProofFails_Error(t *testing.T) {
	sourceRef := types.LogPosition{LogDID: "did:web:src", Sequence: 1}
	anchorRef := types.LogPosition{LogDID: "did:web:lcl", Sequence: 2}

	fetcher := &mockEntryFetcher{
		entries: map[string]*types.EntryWithMetadata{
			sourceRef.String(): {CanonicalBytes: []byte("data"), Position: sourceRef},
		},
	}

	_, err := verifier.BuildCrossLogProof(
		sourceRef, anchorRef, fetcher,
		&mockMerkleProver{err: errors.New("source prover unavailable")},
		&mockMerkleProver{proofs: map[uint64]*types.MerkleProof{}},
		types.CosignedTreeHead{}, types.CosignedTreeHead{},
	)
	if !errors.Is(err, verifier.ErrSourceInclusionFailed) {
		t.Fatalf("expected ErrSourceInclusionFailed, got: %v", err)
	}
}

// TestCrossLog_Build_AnchorNotFound_Error — source side completes
// successfully, but fetcher has no entry at the anchor position.
// Builder returns ErrAnchorEntryNotFound at step 3.
func TestCrossLog_Build_AnchorNotFound_Error(t *testing.T) {
	sourceRef := types.LogPosition{LogDID: "did:web:src", Sequence: 1}
	anchorRef := types.LogPosition{LogDID: "did:web:lcl", Sequence: 2}

	fetcher := &mockEntryFetcher{
		entries: map[string]*types.EntryWithMetadata{
			sourceRef.String(): {CanonicalBytes: []byte("data"), Position: sourceRef},
			// anchor intentionally absent
		},
	}

	_, err := verifier.BuildCrossLogProof(
		sourceRef, anchorRef, fetcher,
		&mockMerkleProver{proofs: map[uint64]*types.MerkleProof{1: {LeafPosition: 1}}},
		&mockMerkleProver{proofs: map[uint64]*types.MerkleProof{}},
		types.CosignedTreeHead{TreeHead: types.TreeHead{TreeSize: 10}},
		types.CosignedTreeHead{TreeHead: types.TreeHead{TreeSize: 20}},
	)
	if !errors.Is(err, verifier.ErrAnchorEntryNotFound) {
		t.Fatalf("expected ErrAnchorEntryNotFound, got: %v", err)
	}
}

// TestCrossLog_Build_LocalProofFails_Error — everything succeeds
// except the local MerkleProver, which returns an error. Builder
// wraps it as ErrLocalInclusionFailed at step 4.
func TestCrossLog_Build_LocalProofFails_Error(t *testing.T) {
	sourceRef := types.LogPosition{LogDID: "did:web:src", Sequence: 1}
	anchorRef := types.LogPosition{LogDID: "did:web:lcl", Sequence: 2}

	fetcher := &mockEntryFetcher{
		entries: map[string]*types.EntryWithMetadata{
			sourceRef.String(): {CanonicalBytes: []byte("src"), Position: sourceRef},
			anchorRef.String(): {CanonicalBytes: []byte("anc"), Position: anchorRef},
		},
	}

	_, err := verifier.BuildCrossLogProof(
		sourceRef, anchorRef, fetcher,
		&mockMerkleProver{proofs: map[uint64]*types.MerkleProof{1: {LeafPosition: 1}}},
		&mockMerkleProver{err: errors.New("local prover unavailable")},
		types.CosignedTreeHead{TreeHead: types.TreeHead{TreeSize: 10}},
		types.CosignedTreeHead{TreeHead: types.TreeHead{TreeSize: 20}},
	)
	if !errors.Is(err, verifier.ErrLocalInclusionFailed) {
		t.Fatalf("expected ErrLocalInclusionFailed, got: %v", err)
	}
}
