/*
verifier/cross_log_test.go — Cross-log proof verification tests.

Organized around the ORTHO-BUG-001 attack matrix. Every attack vector
has at least one dedicated test that fails if the corresponding check
in VerifyCrossLogProof is removed. Each test is annotated with the row
of the matrix it corresponds to so the mapping survives refactors.

Attack matrix coverage:

	A1 Source entry swap      TestVerifyCrossLogProof_RejectsForgedSourceEntryHash
	                          TestVerifyCrossLogProof_RejectsSHA256IdentityAsLeafHash
	A2 Source inclusion forge TestVerifyCrossLogProof_RejectsCorruptedSourceInclusion
	A3 Fake source head       Covered at the witness package level; integration
	                          test lives in tests/cross_log_test.go.
	A4 Forged anchor entry    TestVerifyCrossLogProof_RejectsForgedAnchorEntry
	A5 Anchor ref tamper      Field removed; attack folded into A4.
	A6 Local inclusion forge  TestVerifyCrossLogProof_RejectsForgedAnchorEntryHash
	A7 Substituted bytes      TestVerifyCrossLogProof_RejectsSubstitutedAnchorBytes
	A8 Tampered payload       TestVerifyCrossLogProof_PropagatesExtractorError
	                          TestVerifyCrossLogProof_RejectsMismatchedExtractorResult
	A9 Nil extractor          TestVerifyCrossLogProof_RejectsNilExtractor

Regression / hygiene tests (not mapped to a specific attack):

	TestBuildCrossLogProof_VerifiesCleanly
	TestBuildCrossLogProof_UsesRFC6962LeafHash
	TestBuildCrossLogProof_PopulatesLeafHash
	TestVerifyCrossLogProof_RejectsZeroSourceEntryHash

Envelope flow used by the fixture (v6, canonical):

	unsigned, _ := envelope.NewUnsignedEntry(header, payload)
	hash := sha256.Sum256(envelope.SigningPayload(unsigned))
	sig, _ := signatures.SignEntry(hash, priv)
	unsigned.Signatures = []envelope.Signature{{
	    SignerDID: header.SignerDID,     // invariant: equals Signatures[0].SignerDID
	    AlgoID:    envelope.SigAlgoECDSA,
	    Bytes:     sig,
	}}
	_ = unsigned.Validate()              // gate before Serialize
	canonical := envelope.Serialize(unsigned)

Mutation discipline: each negative test must fail if the corresponding
block in VerifyCrossLogProof is commented out. If a test still passes
after its guard is removed, the test is not exercising the intended
check. See scripts/verify_ortho_bug_001.sh for an automated probe.
*/
package verifier

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"errors"
	"fmt"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ═══════════════════════════════════════════════════════════════════
// Fixture constants
// ═══════════════════════════════════════════════════════════════════

const (
	testSourceDID = "did:web:source.example"
	testLocalDID  = "did:web:local.example"

	// testEventTime is an arbitrary non-zero EventTime used for all
	// fixture-constructed entries. The value itself is irrelevant to
	// cross-log verification; it just needs to satisfy envelope
	// validation and be reproducible across test runs.
	testEventTime int64 = 1_700_000_000
)

// ═══════════════════════════════════════════════════════════════════
// Fixture: entry fetcher
// ═══════════════════════════════════════════════════════════════════

// stubEntryFetcher is an in-memory EntryFetcher used only by the
// builder. The verifier is a pure function and never fetches.
type stubEntryFetcher struct {
	entries map[types.LogPosition]*types.EntryWithMetadata
}

func newStubFetcher() *stubEntryFetcher {
	return &stubEntryFetcher{
		entries: make(map[types.LogPosition]*types.EntryWithMetadata),
	}
}

func (s *stubEntryFetcher) Add(pos types.LogPosition, canonical []byte) {
	s.entries[pos] = &types.EntryWithMetadata{
		CanonicalBytes: canonical,
		Position:       pos,
	}
}

func (s *stubEntryFetcher) Fetch(pos types.LogPosition) (*types.EntryWithMetadata, error) {
	e, ok := s.entries[pos]
	if !ok {
		return nil, fmt.Errorf("stubEntryFetcher: no entry at %+v", pos)
	}
	return e, nil
}

// ═══════════════════════════════════════════════════════════════════
// Fixture: witness keypair + tree-head cosigning
// ═══════════════════════════════════════════════════════════════════

// testWitness wraps one secp256k1 keypair that plays two roles in the
// fixture:
//
//  1. Witness cosigner on both tree heads (sourceHead, localHead). The
//     verifier enforces source-head witness quorum (step 4) before any
//     binding check, so every test needs at least one witness signature
//     over the source head.
//
//  2. Primary signer of the anchor entry. An anchor entry requires
//     Signatures[0].SignerDID == Header.SignerDID; the anchor entry's
//     header uses testLocalDID as its SignerDID and this keypair as its
//     signing key.
//
// These are conceptually different roles — in production the local log
// operator and the witness quorum are separate parties — but sharing
// the keypair keeps the fixture small, and neither cross-log check
// depends on the two identities being distinct.
type testWitness struct {
	priv      *ecdsa.PrivateKey
	publicKey types.WitnessPublicKey
}

func newTestWitness(t *testing.T) *testWitness {
	t.Helper()
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pubBytes := signatures.PubKeyBytes(&priv.PublicKey)
	id := sha256.Sum256(pubBytes)
	return &testWitness{
		priv: priv,
		publicKey: types.WitnessPublicKey{
			ID:        id,
			PublicKey: pubBytes,
		},
	}
}

// cosign produces a types.WitnessSignature over the given tree head
// using the ECDSA cosignature primitive the production witness cosign
// path uses. The returned signature declares SchemeTag: SchemeECDSA
// so the dispatcher routes it to the ECDSA verification path.
func (w *testWitness) cosign(t *testing.T, head types.TreeHead) types.WitnessSignature {
	t.Helper()
	sig, err := signatures.SignWitnessCosignature(head, w.priv)
	if err != nil {
		t.Fatalf("SignWitnessCosignature: %v", err)
	}
	return types.WitnessSignature{
		PubKeyID:  w.publicKey.ID,
		SchemeTag: signatures.SchemeECDSA,
		SigBytes:  sig,
	}
}

// ═══════════════════════════════════════════════════════════════════
// Fixture: envelope.Entry signing helper
// ═══════════════════════════════════════════════════════════════════

// signTestEntry completes an unsigned envelope.Entry produced by
// envelope.NewUnsignedEntry. Performs the canonical v6 signing flow
// documented in crypto/signatures/entry_verify.go:
//
//  1. Hash the entry's SigningPayload.
//  2. Sign the hash with priv.
//  3. Attach a single Signature with SignerDID = Header.SignerDID.
//  4. Validate — enforces the full invariant set Serialize relies on.
//
// Fails the test if any step errors. After this returns, Serialize is
// guaranteed total on the entry.
func signTestEntry(t *testing.T, entry *envelope.Entry, priv *ecdsa.PrivateKey) {
	t.Helper()
	hash := sha256.Sum256(envelope.SigningPayload(entry))
	sig, err := signatures.SignEntry(hash, priv)
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}
	entry.Signatures = []envelope.Signature{{
		SignerDID: entry.Header.SignerDID, // invariant: matches header
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     sig,
	}}
	if err := entry.Validate(); err != nil {
		t.Fatalf("entry.Validate: %v", err)
	}
}

// newSignedAnchor constructs a fully signed envelope.Entry suitable for
// use as a cross-log anchor. The DomainPayload is the caller-supplied
// tree-head reference (raw 32 bytes), which the test extractor reads
// verbatim.
//
// Returns the entry and its canonical serialized bytes. The canonical
// bytes are what gets appended to the local Merkle tree and what the
// fetcher returns to the builder.
func newSignedAnchor(t *testing.T, priv *ecdsa.PrivateKey, domainPayload []byte) (*envelope.Entry, []byte) {
	t.Helper()
	unsigned, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:   testLocalDID,
		Destination: testSourceDID,
		EventTime:   testEventTime,
	}, domainPayload)
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	signTestEntry(t, unsigned, priv)
	return unsigned, envelope.Serialize(unsigned)
}

// ═══════════════════════════════════════════════════════════════════
// Fixture: anchor payload extractor
// ═══════════════════════════════════════════════════════════════════

// testExtractAnchorPayload is the extractor used in every verify call
// below. It treats the anchor entry's DomainPayload as a raw 32-byte
// source-tree-head hash and returns it verbatim. The fixture constructs
// anchor entries with DomainPayload = TreeHeadHash(sourceHead)[:] so
// this extractor resolves the happy path cleanly, while its length
// check gives A8 tests a clean failure mode for malformed payloads.
//
// A production domain extractor would typically decode JSON or a
// structured binary format (see builder.BuildAnchorEntry for one such
// format). The verifier is indifferent to the extractor's internals;
// it cares only that the returned 32 bytes either match
// TreeHeadHash(SourceTreeHead) or fail to.
func testExtractAnchorPayload(payload []byte) ([32]byte, error) {
	if len(payload) != 32 {
		return [32]byte{}, fmt.Errorf("testExtractAnchorPayload: expected 32 bytes, got %d", len(payload))
	}
	var out [32]byte
	copy(out[:], payload)
	return out, nil
}

// ═══════════════════════════════════════════════════════════════════
// Fixture: well-formed CrossLogProof
// ═══════════════════════════════════════════════════════════════════

// buildWellFormedProof constructs a legitimate CrossLogProof.
//
// Layout:
//   - Source log: 3 raw-byte entries. The verifier never deserializes
//     source entries, so arbitrary bytes are fine — we skip the signing
//     flow on this side to keep the fixture focused on the anchor.
//   - Local log: 2 entries. Position 0 is a real signed envelope.Entry
//     whose DomainPayload is TreeHeadHash(sourceHead)[:] — i.e., the
//     anchor cryptographically commits to the source tree head.
//     Position 1 is unrelated raw bytes.
//   - Both tree heads are cosigned by a single test witness.
//
// Returns:
//   - the proof
//   - source entry canonical bytes at sequence 1 (for tests that
//     recompute SourceEntryHash)
//   - anchor entry canonical bytes at sequence 0 (envelope-serialized)
//   - the witness key slice for VerifyCrossLogProof
func buildWellFormedProof(t *testing.T) (
	*types.CrossLogProof,
	[]byte, // source canonical bytes at sequence 1
	[]byte, // anchor canonical bytes at sequence 0
	[]types.WitnessPublicKey,
) {
	t.Helper()

	witness := newTestWitness(t)

	// ── Source log (raw bytes; verifier doesn't deserialize) ─────────
	sourceTree := smt.NewStubMerkleTree()
	sourceEntries := [][]byte{
		[]byte("source entry 0"),
		[]byte("source entry 1"),
		[]byte("source entry 2"),
	}
	for _, data := range sourceEntries {
		if _, err := sourceTree.AppendLeaf(data); err != nil {
			t.Fatalf("source AppendLeaf: %v", err)
		}
	}
	sourceHead, err := sourceTree.Head()
	if err != nil {
		t.Fatalf("source Head: %v", err)
	}

	// Compute the source tree head hash — the value the anchor entry's
	// DomainPayload must contain for the content-binding check to pass.
	sourceTreeHeadHash := TreeHeadHash(sourceHead)

	// ── Anchor entry (real signed envelope.Entry) ────────────────────
	_, anchorCanonical := newSignedAnchor(t, witness.priv, sourceTreeHeadHash[:])

	// ── Local log ────────────────────────────────────────────────────
	localTree := smt.NewStubMerkleTree()
	if _, err := localTree.AppendLeaf(anchorCanonical); err != nil {
		t.Fatalf("local AppendLeaf(anchor): %v", err)
	}
	if _, err := localTree.AppendLeaf([]byte("unrelated local entry")); err != nil {
		t.Fatalf("local AppendLeaf: %v", err)
	}
	localHead, err := localTree.Head()
	if err != nil {
		t.Fatalf("local Head: %v", err)
	}

	sourceCosigned := types.CosignedTreeHead{
		TreeHead:   sourceHead,
		Signatures: []types.WitnessSignature{witness.cosign(t, sourceHead)},
	}
	localCosigned := types.CosignedTreeHead{
		TreeHead:   localHead,
		Signatures: []types.WitnessSignature{witness.cosign(t, localHead)},
	}

	fetcher := newStubFetcher()
	for i, data := range sourceEntries {
		fetcher.Add(types.LogPosition{LogDID: testSourceDID, Sequence: uint64(i)}, data)
	}
	fetcher.Add(types.LogPosition{LogDID: testLocalDID, Sequence: 0}, anchorCanonical)
	fetcher.Add(types.LogPosition{LogDID: testLocalDID, Sequence: 1}, []byte("unrelated local entry"))

	proof, err := BuildCrossLogProof(
		types.LogPosition{LogDID: testSourceDID, Sequence: 1},
		types.LogPosition{LogDID: testLocalDID, Sequence: 0},
		fetcher,
		sourceTree,
		localTree,
		sourceCosigned,
		localCosigned,
	)
	if err != nil {
		t.Fatalf("BuildCrossLogProof: %v", err)
	}

	return proof, sourceEntries[1], anchorCanonical, []types.WitnessPublicKey{witness.publicKey}
}

// verifyArgs is a convenience bundle for the verifier's non-proof args.
type verifyArgs struct {
	witnessKeys []types.WitnessPublicKey
	quorumK     int
}

// call invokes VerifyCrossLogProof with the default test extractor.
// Tests that need a different extractor invoke VerifyCrossLogProof
// directly.
func (v verifyArgs) call(proof types.CrossLogProof) error {
	return VerifyCrossLogProof(proof, v.witnessKeys, v.quorumK, nil, testExtractAnchorPayload)
}

func defaultArgs(witnessKeys []types.WitnessPublicKey) verifyArgs {
	return verifyArgs{witnessKeys: witnessKeys, quorumK: 1}
}

// ═══════════════════════════════════════════════════════════════════
// Happy path + builder hygiene
// ═══════════════════════════════════════════════════════════════════

// TestBuildCrossLogProof_VerifiesCleanly is the control for every
// negative test below: if this fails, the fixture itself is broken
// rather than any specific attack block.
func TestBuildCrossLogProof_VerifiesCleanly(t *testing.T) {
	proof, _, _, witnessKeys := buildWellFormedProof(t)
	if err := defaultArgs(witnessKeys).call(*proof); err != nil {
		t.Fatalf("well-formed proof rejected: %v", err)
	}
}

// TestBuildCrossLogProof_UsesRFC6962LeafHash guards against any future
// regression that substitutes sha256.Sum256 (EntryIdentity) for
// envelope.EntryLeafHashBytes in the builder.
func TestBuildCrossLogProof_UsesRFC6962LeafHash(t *testing.T) {
	proof, sourceCanonical, anchorCanonical, _ := buildWellFormedProof(t)

	wantSource := envelope.EntryLeafHashBytes(sourceCanonical)
	if proof.SourceEntryHash != wantSource {
		t.Errorf("SourceEntryHash is not RFC 6962 leaf hash:\n  got  %x\n  want %x",
			proof.SourceEntryHash, wantSource)
	}

	wantAnchor := envelope.EntryLeafHashBytes(anchorCanonical)
	if proof.AnchorEntryHash != wantAnchor {
		t.Errorf("AnchorEntryHash is not RFC 6962 leaf hash:\n  got  %x\n  want %x",
			proof.AnchorEntryHash, wantAnchor)
	}
}

// TestBuildCrossLogProof_PopulatesLeafHash guards against MerkleProver
// implementations that leave MerkleProof.LeafHash zero. The builder
// overwrites it explicitly; if this test fails, BuildCrossLogProof
// dropped that discipline.
func TestBuildCrossLogProof_PopulatesLeafHash(t *testing.T) {
	proof, _, _, _ := buildWellFormedProof(t)

	if proof.SourceInclusion.LeafHash == [32]byte{} {
		t.Error("SourceInclusion.LeafHash is zero; builder must populate it explicitly")
	}
	if proof.LocalInclusion.LeafHash == [32]byte{} {
		t.Error("LocalInclusion.LeafHash is zero; builder must populate it explicitly")
	}
	if proof.SourceInclusion.LeafHash != proof.SourceEntryHash {
		t.Errorf("SourceInclusion.LeafHash != SourceEntryHash:\n  leaf  %x\n  entry %x",
			proof.SourceInclusion.LeafHash, proof.SourceEntryHash)
	}
	if proof.LocalInclusion.LeafHash != proof.AnchorEntryHash {
		t.Errorf("LocalInclusion.LeafHash != AnchorEntryHash:\n  leaf  %x\n  entry %x",
			proof.LocalInclusion.LeafHash, proof.AnchorEntryHash)
	}
}

// ═══════════════════════════════════════════════════════════════════
// A1 — Source entry swap
// ═══════════════════════════════════════════════════════════════════

// TestVerifyCrossLogProof_RejectsForgedSourceEntryHash is the original
// BUG-001 regression. Attacker pairs a real source inclusion proof
// with a fabricated SourceEntryHash. Must fail at step 2.
func TestVerifyCrossLogProof_RejectsForgedSourceEntryHash(t *testing.T) {
	proof, _, _, witnessKeys := buildWellFormedProof(t)

	fabricated := envelope.EntryLeafHashBytes([]byte("fabricated entry never in log"))
	proof.SourceEntryHash = fabricated

	err := defaultArgs(witnessKeys).call(*proof)
	if err == nil {
		t.Fatal("BUG-001 REGRESSION: verifier accepted forged SourceEntryHash")
	}
	if !errors.Is(err, ErrSourceInclusionFailed) {
		t.Errorf("wrong error type: got %v, want wrapped ErrSourceInclusionFailed", err)
	}
}

// TestVerifyCrossLogProof_RejectsSHA256IdentityAsLeafHash documents
// the specific trigger of BUG-001: confusing SHA-256(canonical) with
// envelope.EntryLeafHashBytes (SHA-256(0x00 || canonical)). Must fail
// at step 2.
func TestVerifyCrossLogProof_RejectsSHA256IdentityAsLeafHash(t *testing.T) {
	proof, sourceCanonical, _, witnessKeys := buildWellFormedProof(t)

	wrongHash := sha256.Sum256(sourceCanonical)
	proof.SourceEntryHash = wrongHash

	err := defaultArgs(witnessKeys).call(*proof)
	if err == nil {
		t.Fatal("verifier accepted SHA-256 Identity as SourceEntryHash")
	}
	if !errors.Is(err, ErrSourceInclusionFailed) {
		t.Errorf("wrong error type: got %v, want wrapped ErrSourceInclusionFailed", err)
	}
}

// ═══════════════════════════════════════════════════════════════════
// A2 — Source inclusion forge
// ═══════════════════════════════════════════════════════════════════

// TestVerifyCrossLogProof_RejectsCorruptedSourceInclusion flips a
// sibling hash. Binding check still passes (LeafHash unchanged), but
// the Merkle path recomputes to a different root. Must fail at step 3.
func TestVerifyCrossLogProof_RejectsCorruptedSourceInclusion(t *testing.T) {
	proof, _, _, witnessKeys := buildWellFormedProof(t)

	if len(proof.SourceInclusion.Siblings) == 0 {
		t.Skip("proof has no siblings to corrupt")
	}
	proof.SourceInclusion.Siblings[0][0] ^= 0x01

	err := defaultArgs(witnessKeys).call(*proof)
	if err == nil {
		t.Fatal("verifier accepted corrupted source inclusion siblings")
	}
	if !errors.Is(err, ErrSourceInclusionFailed) {
		t.Errorf("wrong error type: got %v, want wrapped ErrSourceInclusionFailed", err)
	}
}

// ═══════════════════════════════════════════════════════════════════
// A4 — Forged anchor entry (the headline ORTHO-BUG-001 attack)
// ═══════════════════════════════════════════════════════════════════

// TestVerifyCrossLogProof_RejectsForgedAnchorEntry builds a COMPLETE,
// internally-consistent proof whose anchor entry is a real signed
// envelope.Entry in a real local log, BUT whose DomainPayload does
// NOT contain the source tree head hash. Every hash chains; both
// inclusion proofs verify; only step 10 (payload content binding)
// can catch this attack.
//
// If this test ever passes with err == nil, the content-binding check
// has been removed and the Forged Anchor Attack has been re-introduced.
// This is the single most important test in the file.
func TestVerifyCrossLogProof_RejectsForgedAnchorEntry(t *testing.T) {
	// Start from a legitimate proof for the source tree head and witness.
	legitProof, _, _, witnessKeys := buildWellFormedProof(t)
	signer := newTestWitness(t)

	// Forged anchor: a properly signed envelope.Entry whose DomainPayload
	// is a valid 32-byte value that is NOT the source tree head hash.
	forgedPayload := bytes.Repeat([]byte{0xAA}, 32)
	_, forgedCanonical := newSignedAnchor(t, signer.priv, forgedPayload)
	forgedHash := envelope.EntryLeafHashBytes(forgedCanonical)

	// Build a parallel local tree that actually contains the forged
	// anchor at position 0. Every step before 10 must succeed.
	forgedLocalTree := smt.NewStubMerkleTree()
	if _, err := forgedLocalTree.AppendLeaf(forgedCanonical); err != nil {
		t.Fatalf("forged AppendLeaf: %v", err)
	}
	if _, err := forgedLocalTree.AppendLeaf([]byte("unrelated")); err != nil {
		t.Fatalf("forged AppendLeaf: %v", err)
	}
	forgedLocalHead, err := forgedLocalTree.Head()
	if err != nil {
		t.Fatalf("forged Head: %v", err)
	}
	forgedInclusion, err := forgedLocalTree.InclusionProof(0, forgedLocalHead.TreeSize)
	if err != nil {
		t.Fatalf("forged InclusionProof: %v", err)
	}
	forgedInclusion.LeafHash = forgedHash

	// Assemble the forged proof. Source side untouched; anchor side
	// fully swapped. The verifier does not cosign-check LocalTreeHead,
	// so an unsigned CosignedTreeHead is acceptable here.
	forgedProof := *legitProof
	forgedProof.AnchorEntryHash = forgedHash
	forgedProof.AnchorEntryCanonical = forgedCanonical
	forgedProof.LocalTreeHead = types.CosignedTreeHead{
		TreeHead: forgedLocalHead,
	}
	forgedProof.LocalInclusion = *forgedInclusion

	err = defaultArgs(witnessKeys).call(forgedProof)
	if err == nil {
		t.Fatal("FORGED ANCHOR ATTACK REGRESSION: verifier accepted a proof " +
			"whose anchor entry does not commit to the source tree head")
	}
	if !errors.Is(err, ErrAnchorMismatch) {
		t.Errorf("wrong error type: got %v, want wrapped ErrAnchorMismatch", err)
	}
}

// ═══════════════════════════════════════════════════════════════════
// A6 — Local inclusion forge (forged anchor entry hash)
// ═══════════════════════════════════════════════════════════════════

// TestVerifyCrossLogProof_RejectsForgedAnchorEntryHash fabricates
// AnchorEntryHash to mismatch LocalInclusion.LeafHash. Must fail at
// step 5 (LocalInclusion leaf-hash binding).
func TestVerifyCrossLogProof_RejectsForgedAnchorEntryHash(t *testing.T) {
	proof, _, _, witnessKeys := buildWellFormedProof(t)

	fabricated := envelope.EntryLeafHashBytes([]byte("fabricated anchor never in log"))
	proof.AnchorEntryHash = fabricated

	err := defaultArgs(witnessKeys).call(*proof)
	if err == nil {
		t.Fatal("verifier accepted forged AnchorEntryHash")
	}
	if !errors.Is(err, ErrLocalInclusionFailed) {
		t.Errorf("wrong error type: got %v, want wrapped ErrLocalInclusionFailed", err)
	}
}

// ═══════════════════════════════════════════════════════════════════
// A7 — Substituted anchor bytes
// ═══════════════════════════════════════════════════════════════════

// TestVerifyCrossLogProof_RejectsSubstitutedAnchorBytes flips a byte
// in AnchorEntryCanonical without updating AnchorEntryHash. Steps 5
// and 6 still pass (inclusion proof unchanged), but step 7 rehashes
// the canonical bytes and detects the mismatch.
func TestVerifyCrossLogProof_RejectsSubstitutedAnchorBytes(t *testing.T) {
	proof, _, _, witnessKeys := buildWellFormedProof(t)

	if len(proof.AnchorEntryCanonical) == 0 {
		t.Fatal("AnchorEntryCanonical is empty; fixture broken")
	}
	tampered := append([]byte(nil), proof.AnchorEntryCanonical...)
	tampered[0] ^= 0xFF
	proof.AnchorEntryCanonical = tampered

	err := defaultArgs(witnessKeys).call(*proof)
	if err == nil {
		t.Fatal("verifier accepted substituted AnchorEntryCanonical")
	}
	if !errors.Is(err, ErrAnchorMismatch) {
		t.Errorf("wrong error type: got %v, want wrapped ErrAnchorMismatch", err)
	}
}

// ═══════════════════════════════════════════════════════════════════
// A8 — Tampered anchor payload (extractor paths)
// ═══════════════════════════════════════════════════════════════════

// TestVerifyCrossLogProof_PropagatesExtractorError confirms an error
// returned by the extractor surfaces to the caller with context rather
// than being swallowed or masked.
func TestVerifyCrossLogProof_PropagatesExtractorError(t *testing.T) {
	proof, _, _, witnessKeys := buildWellFormedProof(t)

	failingExtractor := func([]byte) ([32]byte, error) {
		return [32]byte{}, errors.New("test extractor: payload unparseable")
	}

	err := VerifyCrossLogProof(*proof, witnessKeys, 1, nil, failingExtractor)
	if err == nil {
		t.Fatal("verifier accepted proof despite extractor error")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("extract")) {
		t.Errorf("error does not mention extraction stage: %v", err)
	}
}

// TestVerifyCrossLogProof_RejectsMismatchedExtractorResult uses an
// extractor that returns a valid-looking but WRONG 32-byte value.
// Step 10 must catch this.
func TestVerifyCrossLogProof_RejectsMismatchedExtractorResult(t *testing.T) {
	proof, _, _, witnessKeys := buildWellFormedProof(t)

	wrongExtractor := func([]byte) ([32]byte, error) {
		return [32]byte{0x01, 0x02, 0x03}, nil
	}

	err := VerifyCrossLogProof(*proof, witnessKeys, 1, nil, wrongExtractor)
	if err == nil {
		t.Fatal("verifier accepted proof with mismatched embedded ref")
	}
	if !errors.Is(err, ErrAnchorMismatch) {
		t.Errorf("wrong error type: got %v, want wrapped ErrAnchorMismatch", err)
	}
}

// ═══════════════════════════════════════════════════════════════════
// A9 — Nil extractor (hygiene gap)
// ═══════════════════════════════════════════════════════════════════

// TestVerifyCrossLogProof_RejectsNilExtractor confirms the verifier
// returns a clean error rather than nil-deref panicking when the
// caller forgets to pass an extractor. Not a security test — the
// attacker cannot force the caller to pass nil — but a panic instead
// of an error makes the failure mode unhelpful.
//
// Requires: VerifyCrossLogProof has an early `if extractAnchor == nil`
// guard. If the guard is missing, this test panics rather than fails
// cleanly; the recover below converts the panic into a directed t.Fatal
// pointing at the fix.
func TestVerifyCrossLogProof_RejectsNilExtractor(t *testing.T) {
	proof, _, _, witnessKeys := buildWellFormedProof(t)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("VerifyCrossLogProof panicked on nil extractor: %v "+
				"(add a nil-guard before step 9)", r)
		}
	}()
	err := VerifyCrossLogProof(*proof, witnessKeys, 1, nil, nil)
	if err == nil {
		t.Fatal("verifier accepted proof with nil extractor")
	}
}

// ═══════════════════════════════════════════════════════════════════
// Defensive rejection (not mapped to an attack)
// ═══════════════════════════════════════════════════════════════════

// TestVerifyCrossLogProof_RejectsZeroSourceEntryHash guards against
// a common caller bug: default-constructing CrossLogProof and
// forgetting to populate SourceEntryHash.
func TestVerifyCrossLogProof_RejectsZeroSourceEntryHash(t *testing.T) {
	proof, _, _, witnessKeys := buildWellFormedProof(t)
	proof.SourceEntryHash = [32]byte{}

	err := defaultArgs(witnessKeys).call(*proof)
	if err == nil {
		t.Fatal("verifier accepted zero SourceEntryHash")
	}
	if !errors.Is(err, ErrSourceInclusionFailed) {
		t.Errorf("wrong error type: got %v, want wrapped ErrSourceInclusionFailed", err)
	}
}
