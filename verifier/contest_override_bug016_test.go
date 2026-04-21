/*
FILE PATH:

	verifier/contest_override_bug016_test.go

DESCRIPTION:

	Tests for BUG-016 fix. Two call sites in contest_override.go were
	admitting unrelated evidence as approval:

	  collectEvidenceSigners counted every signer regardless of what
	  their entry was for. Fix: bind to contestPos via IsCosignatureOf.

	  hasWitnessCosig accepted any `CosignatureOf != nil` from a
	  non-authority signer. Fix: same IsCosignatureOf binding, with
	  independence check preserved.

	If a contest_override_test.go already exists, merge these tests
	into it and delete this file.

MUTATION PROBES
───────────────

 1. In collectEvidenceSigners, remove the IsCosignatureOf guard:
    if !IsCosignatureOf(entry, contestPos) { continue }
    Run TestCollectEvidenceSigners_RejectsUnboundEntries — must FAIL.

 2. In hasWitnessCosig, replace the IsCosignatureOf check with the old
    raw `CosignatureOf == nil` check.
    Run TestHasWitnessCosig_RejectsUnboundCosignature — must FAIL.

3. Restore both fixes. All tests pass.
*/
package verifier

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ═══════════════════════════════════════════════════════════════════
// Test helpers (shared within this file)
// ═══════════════════════════════════════════════════════════════════

// signTestEntryBug016 completes a signed envelope.Entry.
func signTestEntryBug016(t *testing.T, entry *envelope.Entry, priv *ecdsa.PrivateKey) {
	t.Helper()
	hash := sha256.Sum256(envelope.SigningPayload(entry))
	sig, err := signatures.SignEntry(hash, priv)
	if err != nil {
		t.Fatalf("SignEntry: %v", err)
	}
	entry.Signatures = []envelope.Signature{{
		SignerDID: entry.Header.SignerDID,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     sig,
	}}
	if err := entry.Validate(); err != nil {
		t.Fatalf("entry.Validate: %v", err)
	}
}

// buildCosigMetaBug016 produces an EntryWithMetadata for a cosignature
// that references the provided position.
func buildCosigMetaBug016(t *testing.T, signerDID string, cosigOf *types.LogPosition) *types.EntryWithMetadata {
	t.Helper()

	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	unsigned, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:     signerDID,
		Destination:   "did:web:target",
		CosignatureOf: cosigOf,
		EventTime:     1_700_000_000,
	}, []byte("cosig-payload"))
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}

	signTestEntryBug016(t, unsigned, priv)

	return &types.EntryWithMetadata{
		CanonicalBytes: envelope.Serialize(unsigned),
	}
}

// buildUnrelatedMetaBug016 produces an EntryWithMetadata for a
// non-cosignature entry — CosignatureOf is nil. Used to test that
// "entries listed as evidence but not actually cosigning" are
// correctly excluded by the BUG-016a fix.
func buildUnrelatedMetaBug016(t *testing.T, signerDID string) *types.EntryWithMetadata {
	t.Helper()

	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	unsigned, err := envelope.NewUnsignedEntry(envelope.ControlHeader{
		SignerDID:   signerDID,
		Destination: "did:web:target",
		EventTime:   1_700_000_000,
	}, []byte("unrelated-payload"))
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}

	signTestEntryBug016(t, unsigned, priv)

	return &types.EntryWithMetadata{
		CanonicalBytes: envelope.Serialize(unsigned),
	}
}

// stubFetcherBug016 is a minimal EntryFetcher for these tests.
type stubFetcherBug016 struct {
	entries map[types.LogPosition]*types.EntryWithMetadata
}

func newStubFetcherBug016() *stubFetcherBug016 {
	return &stubFetcherBug016{entries: make(map[types.LogPosition]*types.EntryWithMetadata)}
}

func (s *stubFetcherBug016) Add(pos types.LogPosition, meta *types.EntryWithMetadata) {
	s.entries[pos] = meta
}

func (s *stubFetcherBug016) Fetch(pos types.LogPosition) (*types.EntryWithMetadata, error) {
	m, ok := s.entries[pos]
	if !ok {
		return nil, nil
	}
	return m, nil
}

// ═══════════════════════════════════════════════════════════════════
// BUG-016a: collectEvidenceSigners binding
// ═══════════════════════════════════════════════════════════════════

// TestCollectEvidenceSigners_RejectsUnboundEntries is the BUG-016a
// regression guard. Evidence pointers leading to entries that are
// NOT cosignatures of the contest must not contribute signers.
func TestCollectEvidenceSigners_RejectsUnboundEntries(t *testing.T) {
	contestPos := types.LogPosition{LogDID: "did:web:log", Sequence: 100}
	unrelatedPos := types.LogPosition{LogDID: "did:web:log", Sequence: 999}

	fetcher := newStubFetcherBug016()

	// Five unrelated entries (not cosignatures of anything),
	// each signed by a distinct authority.
	evidencePointers := []types.LogPosition{}
	for i := 0; i < 5; i++ {
		entryPos := types.LogPosition{LogDID: "did:web:log", Sequence: uint64(200 + i)}
		signerDID := "did:web:authority-" + string(rune('A'+i))
		fetcher.Add(entryPos, buildUnrelatedMetaBug016(t, signerDID))
		evidencePointers = append(evidencePointers, entryPos)
	}

	// One cosignature of the WRONG position.
	trickyPos := types.LogPosition{LogDID: "did:web:log", Sequence: 250}
	fetcher.Add(trickyPos, buildCosigMetaBug016(t, "did:web:authority-X", &unrelatedPos))
	evidencePointers = append(evidencePointers, trickyPos)

	signers := collectEvidenceSigners(evidencePointers, fetcher, contestPos)

	if len(signers) != 0 {
		t.Fatalf("BUG-016a REGRESSION: collectEvidenceSigners returned %d "+
			"signers for evidence not bound to contest position %v. "+
			"Signers collected: %v. The binding check is missing or broken.",
			len(signers), contestPos, signers)
	}
}

// TestCollectEvidenceSigners_AcceptsBoundCosignatures is the positive
// control. Evidence entries correctly bound to the contest contribute
// their signers.
func TestCollectEvidenceSigners_AcceptsBoundCosignatures(t *testing.T) {
	contestPos := types.LogPosition{LogDID: "did:web:log", Sequence: 100}

	fetcher := newStubFetcherBug016()
	evidencePointers := []types.LogPosition{}
	for i := 0; i < 3; i++ {
		entryPos := types.LogPosition{LogDID: "did:web:log", Sequence: uint64(200 + i)}
		signerDID := "did:web:authority-" + string(rune('A'+i))
		fetcher.Add(entryPos, buildCosigMetaBug016(t, signerDID, &contestPos))
		evidencePointers = append(evidencePointers, entryPos)
	}

	signers := collectEvidenceSigners(evidencePointers, fetcher, contestPos)

	if len(signers) != 3 {
		t.Fatalf("expected 3 signers for 3 bound cosignatures, got %d. "+
			"Signers: %v. The binding check is over-restrictive; "+
			"legitimate evidence is being rejected.",
			len(signers), signers)
	}
}

// ═══════════════════════════════════════════════════════════════════
// BUG-016b: hasWitnessCosig binding
// ═══════════════════════════════════════════════════════════════════

// TestHasWitnessCosig_RejectsUnboundCosignature is the BUG-016b
// regression guard. A cosignature from a non-authority signer pointing
// at a position OTHER than the contest must not count as witness
// evidence.
func TestHasWitnessCosig_RejectsUnboundCosignature(t *testing.T) {
	contestPos := types.LogPosition{LogDID: "did:web:log", Sequence: 100}
	unrelatedPos := types.LogPosition{LogDID: "did:web:log", Sequence: 500}

	fetcher := newStubFetcherBug016()
	evPos := types.LogPosition{LogDID: "did:web:log", Sequence: 200}
	// Non-authority signer, but cosignature is of unrelatedPos.
	fetcher.Add(evPos, buildCosigMetaBug016(t, "did:web:non-authority", &unrelatedPos))

	authorityMembers := map[string]bool{
		"did:web:authority-A": true,
		"did:web:authority-B": true,
	}

	result := hasWitnessCosig(
		[]types.LogPosition{evPos},
		fetcher,
		authorityMembers,
		contestPos,
	)

	if result {
		t.Fatal("BUG-016b REGRESSION: hasWitnessCosig accepted a " +
			"cosignature bound to unrelated position as witness " +
			"evidence. The binding check is missing or broken.")
	}
}

// TestHasWitnessCosig_AcceptsBoundNonAuthorityCosignature is the
// positive control for the witness path.
func TestHasWitnessCosig_AcceptsBoundNonAuthorityCosignature(t *testing.T) {
	contestPos := types.LogPosition{LogDID: "did:web:log", Sequence: 100}

	fetcher := newStubFetcherBug016()
	evPos := types.LogPosition{LogDID: "did:web:log", Sequence: 200}
	fetcher.Add(evPos, buildCosigMetaBug016(t, "did:web:independent-witness", &contestPos))

	authorityMembers := map[string]bool{
		"did:web:authority-A": true,
	}

	result := hasWitnessCosig(
		[]types.LogPosition{evPos},
		fetcher,
		authorityMembers,
		contestPos,
	)

	if !result {
		t.Fatal("positive control failed: hasWitnessCosig rejected a " +
			"correctly bound non-authority cosignature. The binding " +
			"check is over-restrictive.")
	}
}

// TestHasWitnessCosig_RejectsAuthorityMember is the independence
// regression guard. A cosignature correctly bound to the contest, but
// signed by an authority-set member, must NOT count as witness
// evidence.
func TestHasWitnessCosig_RejectsAuthorityMember(t *testing.T) {
	contestPos := types.LogPosition{LogDID: "did:web:log", Sequence: 100}

	fetcher := newStubFetcherBug016()
	evPos := types.LogPosition{LogDID: "did:web:log", Sequence: 200}
	fetcher.Add(evPos, buildCosigMetaBug016(t, "did:web:authority-A", &contestPos))

	authorityMembers := map[string]bool{
		"did:web:authority-A": true,
	}

	result := hasWitnessCosig(
		[]types.LogPosition{evPos},
		fetcher,
		authorityMembers,
		contestPos,
	)

	if result {
		t.Fatal("independence check broken: authority member accepted " +
			"as witness evidence. hasWitnessCosig must reject " +
			"authority-set signers regardless of binding.")
	}
}
