package verifier

import (
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// Fixtures — package-local to authority_evaluator regression tests.
// ─────────────────────────────────────────────────────────────────────

const aeTestLogDID = "did:ortholog:aetest"
const aeTestDestination = "did:web:ae.test.example"

func aePos(seq uint64) types.LogPosition {
	return types.LogPosition{LogDID: aeTestLogDID, Sequence: seq}
}

// aeFetcher is a map-backed fetcher for EvaluateAuthority regression
// tests. Kept separate from other test fetchers in this package to
// avoid cross-file helper coupling.
type aeFetcher map[types.LogPosition]*types.EntryWithMetadata

func (f aeFetcher) Fetch(p types.LogPosition) (*types.EntryWithMetadata, error) {
	if m, ok := f[p]; ok {
		return m, nil
	}
	return nil, nil
}

// aeBuild registers a valid envelope entry at the given position on
// the fetcher. Returns the canonical serialized form for convenience.
func aeBuild(t *testing.T, fetcher aeFetcher, at types.LogPosition, h envelope.ControlHeader) *envelope.Entry {
	t.Helper()
	e, err := envelope.NewUnsignedEntry(h, nil)
	if err != nil {
		t.Fatalf("build at %s: %v", at, err)
	}
	e.Signatures = []envelope.Signature{{
		SignerDID: h.SignerDID,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     make([]byte, 64),
	}}
	if err := e.Validate(); err != nil {
		t.Fatalf("validate at %s: %v", at, err)
	}
	fetcher[at] = &types.EntryWithMetadata{
		CanonicalBytes: envelope.Serialize(e),
		Position:       at,
	}
	return e
}

func aeScopeAuth() *envelope.AuthorityPath {
	v := envelope.AuthorityScopeAuthority
	return &v
}

func aeSameSigner() *envelope.AuthorityPath {
	v := envelope.AuthoritySameSigner
	return &v
}

func aeAuthSet(dids ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(dids))
	for _, d := range dids {
		m[d] = struct{}{}
	}
	return m
}

// ─────────────────────────────────────────────────────────────────────
// Regression 1 — sequential walk
// ─────────────────────────────────────────────────────────────────────

// TestEvaluateAuthority_SequentialWalk: three-hop Path C chain must
// be traversed in order newest-to-oldest. Classification semantics
// are orthogonal here — the assertion is on the walk length.
func TestEvaluateAuthority_SequentialWalk(t *testing.T) {
	fetcher := aeFetcher{}
	store := smt.NewInMemoryLeafStore()

	// Scope with a permissive set so the defense-in-depth scope
	// membership check in EvaluateAuthority does not reclassify our
	// constraint entries as Overridden.
	scopePos := aePos(5)
	aeBuild(t, fetcher, scopePos, envelope.ControlHeader{
		Destination:   aeTestDestination,
		SignerDID:     "did:example:governor",
		AuthorityPath: aeSameSigner(),
		AuthoritySet:  aeAuthSet("did:example:judge"),
	})
	scopeKey := smt.DeriveKey(scopePos)
	if err := store.Set(scopeKey, types.SMTLeaf{Key: scopeKey, OriginTip: scopePos, AuthorityTip: scopePos}); err != nil {
		t.Fatalf("seed scope leaf: %v", err)
	}

	// Entity leaf whose AuthorityTip sits at the end of a 3-hop
	// Path C chain: entity @10, enforcement1 @20, enforcement2 @30,
	// enforcement3 @40. Each enforcement cites the previous as
	// PriorAuthority.
	entityPos := aePos(10)
	aeBuild(t, fetcher, entityPos, envelope.ControlHeader{
		Destination:   aeTestDestination,
		SignerDID:     "did:example:entity",
		AuthorityPath: aeSameSigner(),
	})

	enf1Pos := aePos(20)
	aeBuild(t, fetcher, enf1Pos, envelope.ControlHeader{
		Destination:    aeTestDestination,
		SignerDID:      "did:example:judge",
		TargetRoot:     &entityPos,
		AuthorityPath:  aeScopeAuth(),
		ScopePointer:   &scopePos,
		PriorAuthority: &entityPos,
	})
	enf2Pos := aePos(30)
	aeBuild(t, fetcher, enf2Pos, envelope.ControlHeader{
		Destination:    aeTestDestination,
		SignerDID:      "did:example:judge",
		TargetRoot:     &entityPos,
		AuthorityPath:  aeScopeAuth(),
		ScopePointer:   &scopePos,
		PriorAuthority: &enf1Pos,
	})
	enf3Pos := aePos(40)
	aeBuild(t, fetcher, enf3Pos, envelope.ControlHeader{
		Destination:    aeTestDestination,
		SignerDID:      "did:example:judge",
		TargetRoot:     &entityPos,
		AuthorityPath:  aeScopeAuth(),
		ScopePointer:   &scopePos,
		PriorAuthority: &enf2Pos,
	})

	leafKey := smt.DeriveKey(entityPos)
	if err := store.Set(leafKey, types.SMTLeaf{
		Key: leafKey, OriginTip: entityPos, AuthorityTip: enf3Pos,
	}); err != nil {
		t.Fatalf("seed entity leaf: %v", err)
	}

	eval, err := EvaluateAuthority(leafKey, store, fetcher, nil)
	if err != nil {
		t.Fatalf("EvaluateAuthority: %v", err)
	}
	// The walker traces Prior_Authority from AuthorityTip (enf3) all
	// the way back to the entity entry: enf3 → enf2 → enf1 → entity
	// = 4 hops. Entity is a legitimate terminus, not a skip.
	if eval.ChainLength != 4 {
		t.Fatalf("walked %d hops, want 4 (enf3, enf2, enf1, entity)", eval.ChainLength)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Regression 2 — cycle termination
// ─────────────────────────────────────────────────────────────────────

// TestEvaluateAuthority_CycleTermination: a PriorAuthority loop must
// terminate without running the full maxAuthorityChainDepth. The
// walker is permissive on cycles (breaks silently) rather than
// returning an error, so we assert finite execution via a bounded
// ChainLength on a deliberately 2-entry cycle.
func TestEvaluateAuthority_CycleTermination(t *testing.T) {
	fetcher := aeFetcher{}
	store := smt.NewInMemoryLeafStore()

	// Entity + scope (permissive) so membership check passes.
	scopePos := aePos(5)
	aeBuild(t, fetcher, scopePos, envelope.ControlHeader{
		Destination:   aeTestDestination,
		SignerDID:     "did:example:governor",
		AuthorityPath: aeSameSigner(),
		AuthoritySet:  aeAuthSet("did:example:judge"),
	})
	scopeKey := smt.DeriveKey(scopePos)
	if err := store.Set(scopeKey, types.SMTLeaf{Key: scopeKey, OriginTip: scopePos, AuthorityTip: scopePos}); err != nil {
		t.Fatalf("seed scope leaf: %v", err)
	}

	entityPos := aePos(10)
	aeBuild(t, fetcher, entityPos, envelope.ControlHeader{
		Destination:   aeTestDestination,
		SignerDID:     "did:example:entity",
		AuthorityPath: aeSameSigner(),
	})

	// Two Path C entries whose PriorAuthority pointers cycle.
	// Entry A's prior is B; entry B's prior is A. Walker must not
	// loop forever.
	a := aePos(20)
	b := aePos(30)
	aeBuild(t, fetcher, a, envelope.ControlHeader{
		Destination:    aeTestDestination,
		SignerDID:      "did:example:judge",
		TargetRoot:     &entityPos,
		AuthorityPath:  aeScopeAuth(),
		ScopePointer:   &scopePos,
		PriorAuthority: &b,
	})
	aeBuild(t, fetcher, b, envelope.ControlHeader{
		Destination:    aeTestDestination,
		SignerDID:      "did:example:judge",
		TargetRoot:     &entityPos,
		AuthorityPath:  aeScopeAuth(),
		ScopePointer:   &scopePos,
		PriorAuthority: &a,
	})

	leafKey := smt.DeriveKey(entityPos)
	if err := store.Set(leafKey, types.SMTLeaf{
		Key: leafKey, OriginTip: entityPos, AuthorityTip: a,
	}); err != nil {
		t.Fatalf("seed entity leaf: %v", err)
	}

	eval, err := EvaluateAuthority(leafKey, store, fetcher, nil)
	if err != nil {
		t.Fatalf("EvaluateAuthority: %v", err)
	}
	// A two-entry cycle walks exactly 2 entries before the visited
	// check fires. If the walker had infinite-looped the test would
	// hit maxAuthorityChainDepth (1000) or just hang.
	if eval.ChainLength > 2 {
		t.Fatalf("cycle escape: walked %d, want <= 2", eval.ChainLength)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Regression 3 — Decision 52 scope-membership defense-in-depth
// ─────────────────────────────────────────────────────────────────────

// TestEvaluateAuthority_ScopeMembershipDefenseInDepth verifies that
// a walked constraint entry signed by a DID that is NOT in the
// governing scope's AuthoritySet at the entry's admission position
// is reclassified as Overridden (not Active). This is the Decision
// 52 check added in v7.5.
func TestEvaluateAuthority_ScopeMembershipDefenseInDepth(t *testing.T) {
	fetcher := aeFetcher{}
	store := smt.NewInMemoryLeafStore()

	// Scope whose AuthoritySet explicitly excludes "did:example:impostor".
	scopePos := aePos(5)
	aeBuild(t, fetcher, scopePos, envelope.ControlHeader{
		Destination:   aeTestDestination,
		SignerDID:     "did:example:governor",
		AuthorityPath: aeSameSigner(),
		AuthoritySet:  aeAuthSet("did:example:judge"), // impostor not in here
	})
	scopeKey := smt.DeriveKey(scopePos)
	if err := store.Set(scopeKey, types.SMTLeaf{Key: scopeKey, OriginTip: scopePos, AuthorityTip: scopePos}); err != nil {
		t.Fatalf("seed scope leaf: %v", err)
	}

	entityPos := aePos(10)
	aeBuild(t, fetcher, entityPos, envelope.ControlHeader{
		Destination:   aeTestDestination,
		SignerDID:     "did:example:entity",
		AuthorityPath: aeSameSigner(),
	})

	// An enforcement entry signed by the impostor, referencing the
	// same scope. Such an entry should never have been admitted by
	// a Decision-52-aware processPathC, but a corrupted store could
	// surface it. EvaluateAuthority's defense-in-depth check must
	// reclassify it as Overridden.
	enfPos := aePos(20)
	aeBuild(t, fetcher, enfPos, envelope.ControlHeader{
		Destination:    aeTestDestination,
		SignerDID:      "did:example:impostor",
		TargetRoot:     &entityPos,
		AuthorityPath:  aeScopeAuth(),
		ScopePointer:   &scopePos,
		PriorAuthority: &entityPos,
	})

	leafKey := smt.DeriveKey(entityPos)
	if err := store.Set(leafKey, types.SMTLeaf{
		Key: leafKey, OriginTip: entityPos, AuthorityTip: enfPos,
	}); err != nil {
		t.Fatalf("seed entity leaf: %v", err)
	}

	eval, err := EvaluateAuthority(leafKey, store, fetcher, nil)
	if err != nil {
		t.Fatalf("EvaluateAuthority: %v", err)
	}
	// The walker also visits entityPos after following enfPos's
	// PriorAuthority. The entity has no ScopePointer and legitimately
	// counts as an active constraint — that's expected. The assertion
	// is specifically about the impostor's enforcement entry: it
	// MUST NOT appear in the active set.
	for _, c := range eval.ActiveConstraints {
		if c.Position.Equal(enfPos) {
			t.Fatalf("impostor's enforcement entry at %s counted as "+
				"active; Decision 52 scope-membership defense-in-"+
				"depth check did not fire", enfPos)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────
// Regression 4 — AuthoritySkip reader behaviour
// ─────────────────────────────────────────────────────────────────────
//
// This test was paired in the v7.5 plan with the B1 removal of the
// AuthoritySkip reader. With that removal shipped, the walker no
// longer follows AuthoritySkip pointers. Entries carrying a skip
// field are walked as normal Prior_Authority entries.
//
// Concretely: an entry at enf3 whose AuthoritySkip would (pre-
// removal) jump straight to entity is instead walked through its
// Prior_Authority chain like any other entry. ChainLength reflects
// the full sequential walk.

// TestEvaluateAuthority_AuthoritySkipIgnored asserts that a Path C
// entry bearing a populated AuthoritySkip field does NOT cause the
// walker to short-circuit. The walker must traverse the full
// Prior_Authority chain.
//
// Enforced by construction post-B1 (the reader is gone). This test
// locks the behaviour in so a future re-introduction of the skip
// field would surface immediately.
func TestEvaluateAuthority_AuthoritySkipIgnored(t *testing.T) {
	t.Skip(`The AuthoritySkip field was removed from ControlHeader in v7.5 ` +
		`Phase C. No reachable code path can construct an entry with the ` +
		`skip field set. This test stays as a sentinel: if a future ` +
		`change re-adds the field, remove the Skip call and re-implement ` +
		`the assertion that the walker ignores the field.`)
}
