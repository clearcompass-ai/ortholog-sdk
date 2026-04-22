package builder

import (
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// Minimal test doubles for the classifier — avoids cross-package
// helpers so these tests live alongside the code they cover.
// ─────────────────────────────────────────────────────────────────────

const occTestLogDID = "did:ortholog:occtestlog"
const occTestDestination = "did:web:occ.test.example"

func occPos(seq uint64) types.LogPosition {
	return types.LogPosition{LogDID: occTestLogDID, Sequence: seq}
}

// occFetcher is a narrow EntryFetcher stub keyed by LogPosition.
type occFetcher map[types.LogPosition]*types.EntryWithMetadata

func (f occFetcher) Fetch(p types.LogPosition) (*types.EntryWithMetadata, error) {
	if meta, ok := f[p]; ok {
		return meta, nil
	}
	return nil, nil
}

func (f occFetcher) store(t *testing.T, p types.LogPosition, entry *envelope.Entry) {
	t.Helper()
	// Attach a deterministic zero-signature so Validate() passes.
	// The classifier only reads Header fields; signatures are inert here.
	entry.Signatures = []envelope.Signature{{
		SignerDID: entry.Header.SignerDID,
		AlgoID:    envelope.SigAlgoECDSA,
		Bytes:     make([]byte, 64),
	}}
	if err := entry.Validate(); err != nil {
		t.Fatalf("occFetcher.store: entry invalid: %v", err)
	}
	f[p] = &types.EntryWithMetadata{
		CanonicalBytes: envelope.Serialize(entry),
		Position:       p,
	}
}

// fakeSchemaResolver returns a fixed SchemaResolution regardless of input.
// Mirrors the behaviour of CachingResolver for a specific schema ref
// without pulling in the schema package's heavier dependencies.
type fakeSchemaResolver struct {
	result *SchemaResolution
	err    error
}

func (r *fakeSchemaResolver) Resolve(_ types.LogPosition, _ types.EntryFetcher) (*SchemaResolution, error) {
	return r.result, r.err
}

func occMustEntry(t *testing.T, h envelope.ControlHeader, payload []byte) *envelope.Entry {
	t.Helper()
	entry, err := envelope.NewUnsignedEntry(h, payload)
	if err != nil {
		t.Fatalf("NewUnsignedEntry: %v", err)
	}
	return entry
}

// occSameSigner returns a pointer to the SameSigner AuthorityPath.
func occSameSigner() *envelope.AuthorityPath {
	v := envelope.AuthoritySameSigner
	return &v
}

// occScopeAuth returns a pointer to the ScopeAuthority AuthorityPath.
func occScopeAuth() *envelope.AuthorityPath {
	v := envelope.AuthorityScopeAuthority
	return &v
}

// buildPathCMismatchFixture constructs the shared setup for OCC
// classifier tests: an entity at pos(1), a scope at pos(2), an
// enforcement entry whose Prior_Authority is stale relative to the
// leaf's current Authority_Tip. The caller supplies the SchemaResolver
// and asserts on the resulting Classification.
func buildPathCMismatchFixture(t *testing.T) (
	entry *envelope.Entry,
	reader smt.LeafReader,
	fetcher occFetcher,
	schemaRefPos types.LogPosition,
) {
	t.Helper()

	store := smt.NewInMemoryLeafStore()
	fetcher = occFetcher{}

	entityPos := occPos(1)
	scopePos := occPos(2)
	enfPos := occPos(5)           // current leaf Authority_Tip
	stalePriorPos := occPos(4)    // writer's Prior_Authority (stale)
	schemaRefPos = occPos(9)

	// Entity the Path C entry targets.
	entity := occMustEntry(t, envelope.ControlHeader{
		Destination:   occTestDestination,
		SignerDID:     "did:example:entity",
		AuthorityPath: occSameSigner(),
	}, nil)
	fetcher.store(t, entityPos, entity)

	// Scope: judge is in the authority set.
	scope := occMustEntry(t, envelope.ControlHeader{
		Destination:   occTestDestination,
		SignerDID:     "did:example:judge",
		AuthorityPath: occSameSigner(),
		AuthoritySet:  map[string]struct{}{"did:example:judge": {}},
	}, nil)
	fetcher.store(t, scopePos, scope)

	// Seed SMT leaves.
	entityKey := smt.DeriveKey(entityPos)
	if err := store.Set(entityKey, types.SMTLeaf{Key: entityKey, OriginTip: entityPos, AuthorityTip: enfPos}); err != nil {
		t.Fatalf("seed entity leaf: %v", err)
	}
	scopeKey := smt.DeriveKey(scopePos)
	if err := store.Set(scopeKey, types.SMTLeaf{Key: scopeKey, OriginTip: scopePos, AuthorityTip: scopePos}); err != nil {
		t.Fatalf("seed scope leaf: %v", err)
	}

	// Path C enforcement entry with stale Prior_Authority.
	entry = occMustEntry(t, envelope.ControlHeader{
		Destination:    occTestDestination,
		SignerDID:      "did:example:judge",
		TargetRoot:     ptrTo(entityPos),
		AuthorityPath:  occScopeAuth(),
		ScopePointer:   ptrTo(scopePos),
		PriorAuthority: ptrTo(stalePriorPos),
		SchemaRef:      ptrTo(schemaRefPos),
	}, []byte("seal"))

	return entry, store, fetcher, schemaRefPos
}

func ptrTo[T any](v T) *T { return &v }

// ─────────────────────────────────────────────────────────────────────
// Tests — ORTHO-BUG-004: classifier must mirror the live builder's
// OCC-mode decision so CMS bridges never admit entries the log will
// subsequently reject.
// ─────────────────────────────────────────────────────────────────────

// TestClassifyPathC_StrictOCCRejectsPriorMismatch asserts the core fix:
// when the schema is not commutative (nil resolver → strict OCC by
// Decision 37 default), a Prior_Authority mismatch must classify as
// PathResultRejected, matching verifyPriorAuthority's behaviour.
func TestClassifyPathC_StrictOCCRejectsPriorMismatch(t *testing.T) {
	entry, reader, fetcher, _ := buildPathCMismatchFixture(t)

	result, err := ClassifyEntry(ClassifyParams{
		Entry:          entry,
		Position:       occPos(10),
		LeafReader:     reader,
		Fetcher:        fetcher,
		LocalLogDID:    occTestLogDID,
		SchemaResolver: nil, // strict OCC
	})
	if err != nil {
		t.Fatalf("ClassifyEntry: %v", err)
	}
	if result.Path != PathResultRejected {
		t.Fatalf("strict OCC mismatch: want PathResultRejected, got %s (reason=%q)", pathName(result.Path), result.Reason)
	}
}

// TestClassifyPathC_StrictResolverAlsoRejects covers the case where a
// resolver is supplied but the schema reports IsCommutative=false.
// Equivalent to strict OCC: must reject.
func TestClassifyPathC_StrictResolverAlsoRejects(t *testing.T) {
	entry, reader, fetcher, _ := buildPathCMismatchFixture(t)
	resolver := &fakeSchemaResolver{result: &SchemaResolution{IsCommutative: false}}

	result, err := ClassifyEntry(ClassifyParams{
		Entry:          entry,
		Position:       occPos(10),
		LeafReader:     reader,
		Fetcher:        fetcher,
		LocalLogDID:    occTestLogDID,
		SchemaResolver: resolver,
	})
	if err != nil {
		t.Fatalf("ClassifyEntry: %v", err)
	}
	if result.Path != PathResultRejected {
		t.Fatalf("non-commutative schema mismatch: want PathResultRejected, got %s (reason=%q)", pathName(result.Path), result.Reason)
	}
}

// TestClassifyPathC_CommutativeSchemaAdmitsProvisionally covers the
// commutative branch: a resolver reporting IsCommutative=true means the
// Δ-window check will happen at runtime. The classifier admits the
// entry as PathResultPathC with OCCNoteReadOnly=true so bridges know
// final acceptance still requires the runtime check.
func TestClassifyPathC_CommutativeSchemaAdmitsProvisionally(t *testing.T) {
	entry, reader, fetcher, _ := buildPathCMismatchFixture(t)
	resolver := &fakeSchemaResolver{result: &SchemaResolution{IsCommutative: true, DeltaWindowSize: 10}}

	result, err := ClassifyEntry(ClassifyParams{
		Entry:          entry,
		Position:       occPos(10),
		LeafReader:     reader,
		Fetcher:        fetcher,
		LocalLogDID:    occTestLogDID,
		SchemaResolver: resolver,
	})
	if err != nil {
		t.Fatalf("ClassifyEntry: %v", err)
	}
	if result.Path != PathResultPathC {
		t.Fatalf("commutative mismatch: want PathResultPathC, got %s (reason=%q)", pathName(result.Path), result.Reason)
	}
	if !result.Details.OCCNoteReadOnly {
		t.Fatalf("commutative mismatch: expected OCCNoteReadOnly=true flag to signal runtime Δ-window recheck")
	}
}

// TestClassifyPathC_ResolverErrorDefaultsToStrict asserts the
// conservative default: if the resolver errors or returns nil, the
// classifier treats the schema as non-commutative and rejects a
// Prior_Authority mismatch. This matches verifyPriorAuthority, which
// also defaults to strict OCC on resolver failure.
func TestClassifyPathC_ResolverErrorDefaultsToStrict(t *testing.T) {
	entry, reader, fetcher, _ := buildPathCMismatchFixture(t)
	resolver := &fakeSchemaResolver{err: errResolver}

	result, err := ClassifyEntry(ClassifyParams{
		Entry:          entry,
		Position:       occPos(10),
		LeafReader:     reader,
		Fetcher:        fetcher,
		LocalLogDID:    occTestLogDID,
		SchemaResolver: resolver,
	})
	if err != nil {
		t.Fatalf("ClassifyEntry: %v", err)
	}
	if result.Path != PathResultRejected {
		t.Fatalf("resolver error: want PathResultRejected (strict default), got %s (reason=%q)", pathName(result.Path), result.Reason)
	}
}

// ─────────────────────────────────────────────────────────────────────
// resolveCommutativity unit coverage
// ─────────────────────────────────────────────────────────────────────

func TestResolveCommutativity_NilHeaderOrResolver(t *testing.T) {
	// All nil-input combinations must return false — the conservative default.
	if resolveCommutativity(nil, nil, nil) {
		t.Fatalf("nil header+resolver: want false")
	}
	h := &envelope.ControlHeader{}
	if resolveCommutativity(h, nil, nil) {
		t.Fatalf("nil resolver: want false")
	}
	if resolveCommutativity(h, &fakeSchemaResolver{result: &SchemaResolution{IsCommutative: true}}, nil) {
		t.Fatalf("header without SchemaRef: want false")
	}
}

func TestResolveCommutativity_ResolverFailureReturnsFalse(t *testing.T) {
	ref := occPos(9)
	h := &envelope.ControlHeader{SchemaRef: &ref}
	r := &fakeSchemaResolver{err: errResolver}
	if resolveCommutativity(h, r, nil) {
		t.Fatalf("resolver error: want false")
	}
}

func TestResolveCommutativity_SuccessReturnsSchemaFlag(t *testing.T) {
	ref := occPos(9)
	h := &envelope.ControlHeader{SchemaRef: &ref}
	if !resolveCommutativity(h, &fakeSchemaResolver{result: &SchemaResolution{IsCommutative: true}}, nil) {
		t.Fatalf("commutative schema: want true")
	}
	if resolveCommutativity(h, &fakeSchemaResolver{result: &SchemaResolution{IsCommutative: false}}, nil) {
		t.Fatalf("non-commutative schema: want false")
	}
}

// errResolver is a sentinel error used by the resolver stubs above.
var errResolver = &resolverErr{msg: "resolver failed"}

type resolverErr struct{ msg string }

func (e *resolverErr) Error() string { return e.msg }
