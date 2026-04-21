/*
FILE PATH:

	verifier/condition_evaluator_bug015_test.go

DESCRIPTION:

	Tests for BUG-015 fix: countValidCosignatures must bind cosignatures
	to the pending operation's position via IsCosignatureOf rather than
	the raw CosignatureOf != nil check.

	If a condition_evaluator_test.go already exists in this package,
	merge these tests into it and delete this file. The separation here
	is for the BUG-015 patch's reviewability.

MUTATION PROBE
──────────────
In countValidCosignatures, replace:

	if !IsCosignatureOf(entry, pendingPos) { continue }

with:

	if entry.Header.CosignatureOf == nil { continue }

Run: go test -v -run TestCountValidCosignatures_RejectsUnboundCosignature ./verifier/
Expected: FAIL with "BUG-015 REGRESSION: counted 1 cosignature..."

Restore the fix. Re-run. All four tests pass.
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
// Test helpers (shared across BUG-015 tests in this file only)
// ═══════════════════════════════════════════════════════════════════

// signTestEntryBug015 completes a signed envelope.Entry using the
// canonical v6 flow: hash signing payload, sign, attach signature
// with SignerDID matching header, Validate.
func signTestEntryBug015(t *testing.T, entry *envelope.Entry, priv *ecdsa.PrivateKey) {
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

// buildCosigMetaBug015 produces an EntryWithMetadata for a cosignature
// entry, signed with a fresh ECDSA key.
func buildCosigMetaBug015(t *testing.T, signerDID string, cosigOf *types.LogPosition) types.EntryWithMetadata {
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

	signTestEntryBug015(t, unsigned, priv)

	return types.EntryWithMetadata{
		CanonicalBytes: envelope.Serialize(unsigned),
	}
}

// buildPendingEntryBug015 returns a minimal *envelope.Entry suitable
// for countValidCosignatures. The function only reads
// Header.SignerDID from the pending entry.
func buildPendingEntryBug015(signerDID string) *envelope.Entry {
	return &envelope.Entry{
		Header: envelope.ControlHeader{
			SignerDID: signerDID,
		},
	}
}

// ═══════════════════════════════════════════════════════════════════
// BUG-015 headline test
// ═══════════════════════════════════════════════════════════════════

// TestCountValidCosignatures_RejectsUnboundCosignature confirms a
// cosignature bound to a position OTHER than pendingPos is NOT
// counted. Before the BUG-015 fix, the raw nil-check admitted this
// cosignature and enabled cosignature replay from unrelated approvals.
func TestCountValidCosignatures_RejectsUnboundCosignature(t *testing.T) {
	pendingPos := types.LogPosition{LogDID: "did:web:target-log", Sequence: 100}
	unrelatedPos := types.LogPosition{LogDID: "did:web:target-log", Sequence: 999}

	pendingEntry := buildPendingEntryBug015("did:web:issuer")

	cosigs := []types.EntryWithMetadata{
		buildCosigMetaBug015(t, "did:web:attacker-witness", &unrelatedPos),
	}

	count := countValidCosignatures(cosigs, pendingEntry, pendingPos)

	if count != 0 {
		t.Fatalf("BUG-015 REGRESSION: counted %d cosignatures bound to "+
			"position %v as approval for position %v. The binding check "+
			"in countValidCosignatures is missing or broken.",
			count, unrelatedPos, pendingPos)
	}
}

// TestCountValidCosignatures_AcceptsBoundCosignature is the positive
// control. A correctly bound cosignature must count.
func TestCountValidCosignatures_AcceptsBoundCosignature(t *testing.T) {
	pendingPos := types.LogPosition{LogDID: "did:web:target-log", Sequence: 100}

	pendingEntry := buildPendingEntryBug015("did:web:issuer")

	cosigs := []types.EntryWithMetadata{
		buildCosigMetaBug015(t, "did:web:witness-1", &pendingPos),
	}

	count := countValidCosignatures(cosigs, pendingEntry, pendingPos)

	if count != 1 {
		t.Fatalf("expected 1 valid cosignature, got %d. The binding "+
			"check is over-restrictive; legitimate cosignatures are "+
			"being rejected.", count)
	}
}

// TestCountValidCosignatures_ExcludesSelfCosignature guards the
// pre-existing self-cosignature exclusion: an entry's own signer
// cannot count as their own approver.
func TestCountValidCosignatures_ExcludesSelfCosignature(t *testing.T) {
	pendingPos := types.LogPosition{LogDID: "did:web:target-log", Sequence: 100}
	issuerDID := "did:web:issuer"

	pendingEntry := buildPendingEntryBug015(issuerDID)

	cosigs := []types.EntryWithMetadata{
		buildCosigMetaBug015(t, issuerDID, &pendingPos),
	}

	count := countValidCosignatures(cosigs, pendingEntry, pendingPos)

	if count != 0 {
		t.Fatalf("self-cosignature exclusion broken: count = %d, want 0", count)
	}
}

// TestCountValidCosignatures_DeduplicatesSameSigner guards the dedup
// behavior: multiple bound cosignatures from the same signer count
// as one.
func TestCountValidCosignatures_DeduplicatesSameSigner(t *testing.T) {
	pendingPos := types.LogPosition{LogDID: "did:web:target-log", Sequence: 100}

	pendingEntry := buildPendingEntryBug015("did:web:issuer")

	cosigs := []types.EntryWithMetadata{
		buildCosigMetaBug015(t, "did:web:witness-1", &pendingPos),
		buildCosigMetaBug015(t, "did:web:witness-1", &pendingPos),
	}

	count := countValidCosignatures(cosigs, pendingEntry, pendingPos)

	if count != 1 {
		t.Fatalf("dedup semantics broken: count = %d, want 1", count)
	}
}
