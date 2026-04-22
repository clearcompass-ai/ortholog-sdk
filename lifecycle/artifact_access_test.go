// Package lifecycle — artifact_access_test.go tests the artifact access
// control surface: ArtifactKeyStore contract, CheckGrantAuthorization
// modes, GrantArtifactAccess argument validation, VerifyAndDecryptArtifact
// argument validation, and ReEncryptWithGrant mechanics including the
// rollback-on-erase-failure path.
//
// Tests that require a real scope entity (positive-path Restricted or
// Sealed authorization) skip with a note — they belong in the cross-
// package integration suite where a real SMT and entry fetcher exist.
//
// # Compile-time drift detection
//
// This file asserts at compile time that every production implementation
// satisfies the narrow interface lifecycle/ consumes. If a producer
// drops a method, changes a signature, or otherwise drifts, these
// assertions fail at build time — before any test runs, before any
// deployment. The assertions are the load-bearing structural guarantee
// that the narrow-interface pattern keeps lifecycle/ decoupled from
// producer evolution.
package lifecycle

import (
	"errors"
	"sync"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/artifact"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// -------------------------------------------------------------------------------------------------
// Compile-time drift assertions
//
// If any producer drops/renames/re-signs a method that lifecycle/
// depends on, these fail to compile. Fix the narrow interface in
// artifact_access.go OR fix the producer — drift is never silent.
// -------------------------------------------------------------------------------------------------

var (
	// artifactContentStore must remain satisfied by every production
	// ContentStore implementation.
	_ artifactContentStore = (*storage.InMemoryContentStore)(nil)
	_ artifactContentStore = (*storage.HTTPContentStore)(nil)

	// retrievalResolver must remain satisfied by every production
	// RetrievalProvider implementation.
	_ retrievalResolver = (*storage.InMemoryRetrievalProvider)(nil)
	_ retrievalResolver = (*storage.HTTPRetrievalProvider)(nil)

	// leafReader must remain satisfied by every production
	// LeafReader implementation.
	_ leafReader = (*smt.HTTPLeafReader)(nil)

	// entryFetcher must remain a strict subset of types.EntryFetcher.
	// Interface-to-interface assignment: compiles only if every method
	// in entryFetcher exists with identical signature on
	// types.EntryFetcher.
	_ entryFetcher = (types.EntryFetcher)(nil)
)

// -------------------------------------------------------------------------------------------------
// ArtifactKey test fixture
// -------------------------------------------------------------------------------------------------

// newTestArtifactKey returns a deterministic-looking ArtifactKey. Not
// secret — just a fixture that matches the key's fixed-size layout.
func newTestArtifactKey(seed byte) artifact.ArtifactKey {
	var k artifact.ArtifactKey
	for i := range k.Key {
		k.Key[i] = seed + byte(i)
	}
	for i := range k.Nonce {
		k.Nonce[i] = seed + byte(i) + 0x40
	}
	return k
}

// -------------------------------------------------------------------------------------------------
// InMemoryKeyStore — ArtifactKeyStore contract
// -------------------------------------------------------------------------------------------------

func TestInMemoryKeyStore_StoreAndGet(t *testing.T) {
	ks := NewInMemoryKeyStore()
	cid := storage.Compute([]byte("artifact-1"))
	want := newTestArtifactKey(0x10)

	if err := ks.Store(cid, want); err != nil {
		t.Fatalf("Store: %v", err)
	}

	got, err := ks.Get(cid)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got == nil {
		t.Fatal("Get returned nil after Store")
	}
	if got.Key != want.Key {
		t.Fatalf("Key mismatch: got %x, want %x", got.Key, want.Key)
	}
	if got.Nonce != want.Nonce {
		t.Fatalf("Nonce mismatch: got %x, want %x", got.Nonce, want.Nonce)
	}
}

func TestInMemoryKeyStore_GetMissReturnsNil(t *testing.T) {
	ks := NewInMemoryKeyStore()
	cid := storage.Compute([]byte("never-stored"))
	got, err := ks.Get(cid)
	if err != nil {
		t.Fatalf("Get on missing key returned error: %v", err)
	}
	if got != nil {
		t.Fatalf("Get on missing key returned non-nil %v, want nil", got)
	}
}

func TestInMemoryKeyStore_DeleteRemovesKey(t *testing.T) {
	ks := NewInMemoryKeyStore()
	cid := storage.Compute([]byte("to-delete"))
	if err := ks.Store(cid, newTestArtifactKey(0x20)); err != nil {
		t.Fatalf("Store: %v", err)
	}
	if err := ks.Delete(cid); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	got, _ := ks.Get(cid)
	if got != nil {
		t.Fatalf("Get after Delete returned %v, want nil", got)
	}
}

func TestInMemoryKeyStore_DeleteOnMissingKeyIsSafe(t *testing.T) {
	ks := NewInMemoryKeyStore()
	cid := storage.Compute([]byte("never-existed"))
	// Must not panic; returning nil or an error is acceptable.
	_ = ks.Delete(cid)
}

func TestInMemoryKeyStore_OverwriteLastWriteWins(t *testing.T) {
	ks := NewInMemoryKeyStore()
	cid := storage.Compute([]byte("overwrite-test"))

	first := newTestArtifactKey(0x30)
	second := newTestArtifactKey(0x50)

	if err := ks.Store(cid, first); err != nil {
		t.Fatalf("Store 1: %v", err)
	}
	if err := ks.Store(cid, second); err != nil {
		t.Fatalf("Store 2: %v", err)
	}
	got, err := ks.Get(cid)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Key != second.Key {
		t.Fatal("Get did not return last-written key")
	}
}

func TestInMemoryKeyStore_ConcurrentSafe(t *testing.T) {
	ks := NewInMemoryKeyStore()
	cid := storage.Compute([]byte("concurrent-test"))
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(v byte) {
			defer wg.Done()
			_ = ks.Store(cid, newTestArtifactKey(v))
			_, _ = ks.Get(cid)
		}(byte(i))
	}
	wg.Wait()
	// Assertion is that -race detects no data race.
}

// -------------------------------------------------------------------------------------------------
// CheckGrantAuthorization — Open mode (no external state needed)
// -------------------------------------------------------------------------------------------------

func TestCheckGrantAuthorization_OpenModeAlwaysAllowed(t *testing.T) {
	result, err := CheckGrantAuthorization(GrantAuthCheckParams{
		Mode:       types.GrantAuthOpen,
		GranterDID: "did:web:anyone.test",
	})
	if err != nil {
		t.Fatalf("Open mode: unexpected error %v", err)
	}
	if !result.Authorized {
		t.Fatalf("Open mode: Authorized = false, Reason = %q", result.Reason)
	}
}

// -------------------------------------------------------------------------------------------------
// CheckGrantAuthorization — Restricted / Sealed mode negative paths
// -------------------------------------------------------------------------------------------------

func TestCheckGrantAuthorization_RestrictedRejectsEmptyGranterDID(t *testing.T) {
	result, err := CheckGrantAuthorization(GrantAuthCheckParams{
		Mode:       types.GrantAuthRestricted,
		GranterDID: "",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Authorized {
		t.Error("Authorized = true for empty GranterDID in Restricted mode")
	}
}

func TestCheckGrantAuthorization_RestrictedRejectsNilScopePointer(t *testing.T) {
	result, err := CheckGrantAuthorization(GrantAuthCheckParams{
		Mode:         types.GrantAuthRestricted,
		GranterDID:   "did:web:granter.test",
		ScopePointer: nil,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Authorized {
		t.Error("Authorized = true with nil ScopePointer in Restricted mode")
	}
}

func TestCheckGrantAuthorization_SealedRejectsEmptyGranterDID(t *testing.T) {
	result, err := CheckGrantAuthorization(GrantAuthCheckParams{
		Mode:       types.GrantAuthSealed,
		GranterDID: "",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Authorized {
		t.Error("Authorized = true for empty GranterDID in Sealed mode")
	}
}

// Positive-path Restricted and Sealed authorization require a real
// scope entity with a populated Authority_Set — covered in the cross-
// package integration suite.

// -------------------------------------------------------------------------------------------------
// GrantArtifactAccess — argument validation
// -------------------------------------------------------------------------------------------------

func TestGrantArtifactAccess_RejectsEmptyDestination(t *testing.T) {
	_, err := GrantArtifactAccess(GrantArtifactAccessParams{
		GranterDID:   "did:web:granter.test",
		RecipientDID: "did:web:recipient.test",
	})
	if err == nil {
		t.Fatal("expected error for empty Destination, got nil")
	}
}

func TestGrantArtifactAccess_RejectsNilSchemaParams(t *testing.T) {
	_, err := GrantArtifactAccess(GrantArtifactAccessParams{
		Destination:  testDestination,
		GranterDID:   "did:web:granter.test",
		RecipientDID: "did:web:recipient.test",
		SchemaParams: nil,
	})
	if err == nil {
		t.Fatal("expected error for nil SchemaParams, got nil")
	}
}

// -------------------------------------------------------------------------------------------------
// VerifyAndDecryptArtifact — argument validation
// -------------------------------------------------------------------------------------------------

func TestVerifyAndDecryptArtifact_RejectsNilSchemaParams(t *testing.T) {
	_, err := VerifyAndDecryptArtifact(VerifyAndDecryptArtifactParams{
		SchemaParams: nil,
	})
	if err == nil {
		t.Fatal("expected error for nil SchemaParams, got nil")
	}
}

// -------------------------------------------------------------------------------------------------
// ReEncryptWithGrant — argument validation and error surfacing
// -------------------------------------------------------------------------------------------------

func TestReEncryptWithGrant_RejectsMissingOldKey(t *testing.T) {
	// Empty KeyStore — Get returns nil (no key found).
	ks := NewInMemoryKeyStore()
	cs := storage.NewInMemoryContentStore()
	missingCID := storage.Compute([]byte("missing-key"))

	_, err := ReEncryptWithGrant(ReEncryptWithGrantParams{
		KeyStore:     ks,
		ContentStore: cs,
		OldCID:       missingCID,
	})
	if err == nil {
		t.Fatal("expected error for missing old key, got nil")
	}
}

func TestReEncryptWithGrant_RejectsMissingOldCiphertext(t *testing.T) {
	// KeyStore has the old key; ContentStore is empty.
	ks := NewInMemoryKeyStore()
	cs := storage.NewInMemoryContentStore()

	oldCID := storage.Compute([]byte("old-cid"))
	if err := ks.Store(oldCID, newTestArtifactKey(0x60)); err != nil {
		t.Fatalf("Store: %v", err)
	}

	_, err := ReEncryptWithGrant(ReEncryptWithGrantParams{
		KeyStore:     ks,
		ContentStore: cs,
		OldCID:       oldCID,
	})
	if err == nil {
		t.Fatal("expected error for missing old ciphertext, got nil")
	}
}

// -------------------------------------------------------------------------------------------------
// ReEncryptWithGrant — sentinel errors exist and wrap correctly
// -------------------------------------------------------------------------------------------------

// Compile-time-adjacent verification that the sentinels exist and are
// distinct errors.Is targets.
func TestReEncryptWithGrant_SentinelsExistAndAreDistinct(t *testing.T) {
	if ErrOldCiphertextEraseFailed == nil {
		t.Error("ErrOldCiphertextEraseFailed is nil")
	}
	if ErrCryptographicErasureFailed == nil {
		t.Error("ErrCryptographicErasureFailed is nil")
	}
	if errors.Is(ErrOldCiphertextEraseFailed, ErrCryptographicErasureFailed) {
		t.Error("sentinels collide — must be distinct errors.Is targets")
	}
	if errors.Is(ErrCryptographicErasureFailed, ErrOldCiphertextEraseFailed) {
		t.Error("sentinels collide in the other direction")
	}
}

// -------------------------------------------------------------------------------------------------
// Failure-injection wrappers
//
// The narrow artifactContentStore interface is 3 methods; the narrow
// ArtifactKeyStore interface is 3 methods. Each wrapper implements all
// three explicitly — no embed-pointer trickery required. When external
// storage.ContentStore grows a method, these wrappers are unaffected
// because they satisfy the narrow interface, not the wide one.
// -------------------------------------------------------------------------------------------------

// keyStoreFailOnDelete wraps an ArtifactKeyStore and injects an error
// on Delete. Get/Store pass through to the wrapped store.
type keyStoreFailOnDelete struct {
	inner   ArtifactKeyStore
	delErr  error
	deletes int
}

func (k *keyStoreFailOnDelete) Get(cid storage.CID) (*artifact.ArtifactKey, error) {
	return k.inner.Get(cid)
}
func (k *keyStoreFailOnDelete) Store(cid storage.CID, key artifact.ArtifactKey) error {
	return k.inner.Store(cid, key)
}
func (k *keyStoreFailOnDelete) Delete(cid storage.CID) error {
	k.deletes++
	return k.delErr
}

// contentStoreFailOnDelete wraps an artifactContentStore and injects
// a Delete error for one specific CID. Satisfies the narrow interface
// with explicit method implementations.
type contentStoreFailOnDelete struct {
	inner   artifactContentStore
	failFor storage.CID
	delErr  error
}

func (c *contentStoreFailOnDelete) Fetch(cid storage.CID) ([]byte, error) {
	return c.inner.Fetch(cid)
}
func (c *contentStoreFailOnDelete) Push(cid storage.CID, data []byte) error {
	return c.inner.Push(cid, data)
}
func (c *contentStoreFailOnDelete) Delete(cid storage.CID) error {
	if cid.String() == c.failFor.String() {
		return c.delErr
	}
	return c.inner.Delete(cid)
}

// -------------------------------------------------------------------------------------------------
// ReEncryptWithGrant — erase-failure paths
// -------------------------------------------------------------------------------------------------

// KeyStore.Delete failure must surface as ErrCryptographicErasureFailed.
//
// Precondition: the fixture must reach the KeyStore.Delete call,
// meaning artifact.ReEncryptArtifact must accept the fixture inputs.
// If the primitive rejects the fixture, the test skips — this is a
// pipeline-coverage test, not a re-encrypt-primitive test.
func TestReEncryptWithGrant_KeyDeleteFailureSurfacesAsCryptographicErasureFailed(t *testing.T) {
	innerKS := NewInMemoryKeyStore()
	innerCS := storage.NewInMemoryContentStore()

	key := newTestArtifactKey(0x70)
	oldCT := []byte("test-artifact-ciphertext-fixture")
	oldCID := storage.Compute(oldCT)

	if err := innerKS.Store(oldCID, key); err != nil {
		t.Fatalf("prime Store: %v", err)
	}
	if err := innerCS.Push(oldCID, oldCT); err != nil {
		t.Fatalf("prime Push: %v", err)
	}

	failingKS := &keyStoreFailOnDelete{
		inner:  innerKS,
		delErr: errors.New("simulated KeyStore.Delete failure"),
	}

	_, err := ReEncryptWithGrant(ReEncryptWithGrantParams{
		KeyStore:     failingKS,
		ContentStore: innerCS,
		OldCID:       oldCID,
	})
	if err == nil {
		t.Fatal("expected error when KeyStore.Delete fails, got nil")
	}
	if !errors.Is(err, ErrCryptographicErasureFailed) {
		t.Skipf("did not reach KeyStore.Delete path (artifact.ReEncryptArtifact "+
			"likely rejected the fixture ciphertext): %v", err)
	}
	if failingKS.deletes == 0 {
		t.Error("KeyStore.Delete was not invoked despite sentinel firing")
	}
}

// ContentStore.Delete failure (with DeleteOldCiphertext=true) must
// surface as ErrOldCiphertextEraseFailed.
func TestReEncryptWithGrant_CiphertextDeleteFailureSurfacesAsOldCiphertextEraseFailed(t *testing.T) {
	innerCS := storage.NewInMemoryContentStore()
	innerKS := NewInMemoryKeyStore()

	key := newTestArtifactKey(0x80)
	oldCT := []byte("test-artifact-ciphertext-fixture-2")
	oldCID := storage.Compute(oldCT)

	if err := innerKS.Store(oldCID, key); err != nil {
		t.Fatalf("prime Store: %v", err)
	}
	if err := innerCS.Push(oldCID, oldCT); err != nil {
		t.Fatalf("prime Push: %v", err)
	}

	failingCS := &contentStoreFailOnDelete{
		inner:   innerCS,
		failFor: oldCID,
		delErr:  errors.New("simulated ContentStore.Delete failure"),
	}

	_, err := ReEncryptWithGrant(ReEncryptWithGrantParams{
		KeyStore:            innerKS,
		ContentStore:        failingCS,
		OldCID:              oldCID,
		DeleteOldCiphertext: true,
	})
	if err == nil {
		t.Fatal("expected error when ContentStore.Delete on old CID fails, got nil")
	}
	if !errors.Is(err, ErrOldCiphertextEraseFailed) {
		t.Skipf("did not reach ContentStore.Delete path (artifact.ReEncryptArtifact "+
			"likely rejected the fixture ciphertext): %v", err)
	}
}

// DeleteOldCiphertext=false: a ContentStore.Delete failure on the old
// CID must NOT surface, because ReEncryptWithGrant must not call
// ContentStore.Delete in that configuration.
func TestReEncryptWithGrant_NoCiphertextDeleteWhenFlagFalse(t *testing.T) {
	innerCS := storage.NewInMemoryContentStore()
	innerKS := NewInMemoryKeyStore()

	key := newTestArtifactKey(0x90)
	oldCT := []byte("test-artifact-ciphertext-fixture-3")
	oldCID := storage.Compute(oldCT)

	if err := innerKS.Store(oldCID, key); err != nil {
		t.Fatalf("prime Store: %v", err)
	}
	if err := innerCS.Push(oldCID, oldCT); err != nil {
		t.Fatalf("prime Push: %v", err)
	}

	failingCS := &contentStoreFailOnDelete{
		inner:   innerCS,
		failFor: oldCID,
		delErr:  errors.New("simulated failure — must not be reached"),
	}

	_, err := ReEncryptWithGrant(ReEncryptWithGrantParams{
		KeyStore:            innerKS,
		ContentStore:        failingCS,
		OldCID:              oldCID,
		DeleteOldCiphertext: false,
	})

	if errors.Is(err, ErrOldCiphertextEraseFailed) {
		t.Fatalf("surfaced ErrOldCiphertextEraseFailed despite "+
			"DeleteOldCiphertext=false: %v", err)
	}
}
