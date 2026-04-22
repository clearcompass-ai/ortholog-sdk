package verifier

import (
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// TestCountValidCosignatures_DiscardsUnauthorizedSigner is the Sybil
// fix regression guard: a cosignature entry correctly bound to the
// pending position and signed by a valid DID must NOT count toward
// the threshold when that DID is absent from the authorized set.
// Before this fix a nil-vs-empty map distinction was the only gate,
// and any signer could satisfy a threshold.
func TestCountValidCosignatures_DiscardsUnauthorizedSigner(t *testing.T) {
	pendingPos := types.LogPosition{LogDID: "did:web:target-log", Sequence: 100}
	pendingEntry := buildPendingEntryBug015("did:web:issuer")

	cosigs := []types.EntryWithMetadata{
		buildCosigMetaBug015(t, "did:web:authorized-cosigner", &pendingPos),
		buildCosigMetaBug015(t, "did:web:outsider-cosigner", &pendingPos),
	}

	// Only "authorized-cosigner" is in the scope's AuthoritySet.
	authorizedSet := map[string]struct{}{
		"did:web:authorized-cosigner": {},
	}

	count := countValidCosignatures(cosigs, pendingEntry, pendingPos, authorizedSet)
	if count != 1 {
		t.Fatalf("Sybil regression: want 1 cosignature (authorised only), got %d. "+
			"The authorizedSet filter in countValidCosignatures is missing or "+
			"broken — outsider-cosigner counted toward the threshold.", count)
	}
}

// TestCountValidCosignatures_EmptyAuthorizedSetCountsNothing asserts
// that an explicit empty map (distinct from nil) is a valid "no one
// is authorised" policy — every cosignature is discarded. This lets
// callers express "reject all cosignatures" without having to branch
// around the counter.
func TestCountValidCosignatures_EmptyAuthorizedSetCountsNothing(t *testing.T) {
	pendingPos := types.LogPosition{LogDID: "did:web:target-log", Sequence: 100}
	pendingEntry := buildPendingEntryBug015("did:web:issuer")

	cosigs := []types.EntryWithMetadata{
		buildCosigMetaBug015(t, "did:web:alice", &pendingPos),
		buildCosigMetaBug015(t, "did:web:bob", &pendingPos),
	}

	count := countValidCosignatures(cosigs, pendingEntry, pendingPos, map[string]struct{}{})
	if count != 0 {
		t.Fatalf("empty authorizedSet: want 0, got %d", count)
	}
}

// TestCountValidCosignatures_NilAuthorizedSetPreservesLegacyBehaviour
// locks in the explicit contract: nil means "no Sybil check" (every
// bound cosignature counts). This makes the migration low-risk for
// callers that haven't yet been audited to supply an AuthorizedSet.
func TestCountValidCosignatures_NilAuthorizedSetPreservesLegacyBehaviour(t *testing.T) {
	pendingPos := types.LogPosition{LogDID: "did:web:target-log", Sequence: 100}
	pendingEntry := buildPendingEntryBug015("did:web:issuer")

	cosigs := []types.EntryWithMetadata{
		buildCosigMetaBug015(t, "did:web:alice", &pendingPos),
		buildCosigMetaBug015(t, "did:web:bob", &pendingPos),
	}

	count := countValidCosignatures(cosigs, pendingEntry, pendingPos, nil)
	if count != 2 {
		t.Fatalf("nil authorizedSet: want 2 (legacy behaviour), got %d", count)
	}
}
