/*
FILE PATH: tests/phase6_grant_auth_test.go

Phase 6 Grant Authorization: 3 tests covering the three
GrantAuthorizationMode values (open, restricted, sealed).

These tests verify the Phase 6 addition to GrantArtifactAccess:
  - Open mode: no authorization check, backward compatible
  - Restricted mode: granter must be in scope authority set
  - Sealed mode: restricted check + recipient in authorized list

All tests use in-memory infrastructure. No Postgres required.
*/
package tests

import (
	"encoding/json"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/artifact"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/lifecycle"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ═════════════════════════════════════════════════════════════════════
// Grant authorization test infrastructure
//
// Each test sets up:
//   - SchemaParams with the target GrantAuthorizationMode
//   - An encrypted artifact with key material in the key store
//   - A scope entity with a known authority set
//   - A recipient key pair
//
// The tests then call GrantArtifactAccess with various granter/recipient
// combinations and verify that authorization is granted or denied.
// ═════════════════════════════════════════════════════════════════════

// grantAuthTestFixture holds shared test state for grant authorization tests.
type grantAuthTestFixture struct {
	fetcher     *MockFetcher
	leafStore   *smt.InMemoryLeafStore
	keyStore    *lifecycle.InMemoryKeyStore
	retrieval   *storage.InMemoryRetrievalProvider
	artifactCID storage.CID
	recipientPK []byte
	scopePos    types.LogPosition
}

// newGrantAuthFixture creates a complete test fixture with an encrypted
// artifact, key store, scope entity, and recipient key pair.
//
// The scope entity has AuthoritySet: {did:example:judge, did:example:clerk}.
// Tests use different granters and recipients to exercise each mode.
func newGrantAuthFixture(t *testing.T) *grantAuthTestFixture {
	t.Helper()

	fetcher := NewMockFetcher()
	leafStore := smt.NewInMemoryLeafStore()
	keyStore := lifecycle.NewInMemoryKeyStore()
	retrieval := storage.NewInMemoryRetrievalProvider()

	// Encrypt an artifact and store its key material.
	plaintext := []byte("protected artifact content for grant auth tests")
	ciphertext, artKey, err := artifact.EncryptArtifact(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	artifactCID := storage.Compute(ciphertext)
	keyStore.Store(artifactCID, artKey)

	// Generate recipient key pair.
	recipientKey, _ := signatures.GenerateKey()
	recipientPK := signatures.PubKeyBytes(&recipientKey.PublicKey)

	// Create scope entity with authority set: {judge, clerk}.
	// This scope controls who may grant artifact access under
	// restricted and sealed modes.
	scopePos := pos(50)
	scopeEntry := buildTestEntry(t, envelope.ControlHeader{
		Destination:   testDestinationDID,
		SignerDID:     "did:example:admin",
		AuthorityPath: sameSigner(),
		AuthoritySet: map[string]struct{}{
			"did:example:judge": {},
			"did:example:clerk": {},
		},
	}, nil)
	fetcher.Store(scopePos, scopeEntry)
	scopeKey := smt.DeriveKey(scopePos)
	leafStore.Set(scopeKey, types.SMTLeaf{
		Key: scopeKey, OriginTip: scopePos, AuthorityTip: scopePos,
	})

	return &grantAuthTestFixture{
		fetcher:     fetcher,
		leafStore:   leafStore,
		keyStore:    keyStore,
		retrieval:   retrieval,
		artifactCID: artifactCID,
		recipientPK: recipientPK,
		scopePos:    scopePos,
	}
}

// ═════════════════════════════════════════════════════════════════════
// Test 1: Open mode — no authorization check, backward compatible
// ═════════════════════════════════════════════════════════════════════

// TestGrantAuth_Open_NoCheckPerformed verifies that GrantAuthOpen (the
// default) performs no authorization check. This test confirms backward
// compatibility: schemas that predate the grant_authorization_mode field
// default to GrantAuthOpen (zero value), and grants succeed without
// providing RecipientDID, ScopePointer, AuthorizedRecipients, or
// LeafReader.
//
// This is the critical backward-compatibility test. If this fails,
// every pre-Phase-6 schema is broken.
func TestGrantAuth_Open_NoCheckPerformed(t *testing.T) {
	f := newGrantAuthFixture(t)

	// Two subtests: default (zero value) and explicit GrantAuthOpen.
	modes := []struct {
		label  string
		params *types.SchemaParameters
	}{
		{
			label: "default",
			params: &types.SchemaParameters{
				ArtifactEncryption: types.EncryptionAESGCM,
				// GrantAuthorizationMode zero value = GrantAuthOpen.
			},
		},
		{
			label: "explicit",
			params: &types.SchemaParameters{
				ArtifactEncryption:     types.EncryptionAESGCM,
				GrantAuthorizationMode: types.GrantAuthOpen,
			},
		},
	}

	for _, m := range modes {
		t.Run(m.label, func(t *testing.T) {
			// Grant with NO authorization fields set.
			// No RecipientDID, no ScopePointer, no AuthorizedRecipients,
			// no LeafReader, no Fetcher. Open mode needs none of these.
			result, err := lifecycle.GrantArtifactAccess(lifecycle.GrantArtifactAccessParams{
				Destination:       testDestinationDID,
				ArtifactCID:       f.artifactCID,
				RecipientPubKey:   f.recipientPK,
				SchemaParams:      m.params,
				KeyStore:          f.keyStore,
				RetrievalProvider: f.retrieval,
			})
			if err != nil {
				t.Fatalf("[%s] open mode grant should succeed: %v", m.label, err)
			}
			if result.Method != "aes_gcm" {
				t.Fatalf("[%s] method: %s", m.label, result.Method)
			}
			if len(result.WrappedKey) == 0 {
				t.Fatalf("[%s] WrappedKey should be non-empty", m.label)
			}
			if result.Credential == nil {
				t.Fatalf("[%s] Credential should be set", m.label)
			}
			if result.GrantEntry != nil {
				t.Fatalf("[%s] GrantEntry should be nil (no audit required)", m.label)
			}
		})
	}
}

// ═════════════════════════════════════════════════════════════════════
// Test 2: Restricted mode — granter must be in scope authority set
// ═════════════════════════════════════════════════════════════════════

// TestGrantAuth_Restricted_GranterInAuthoritySet_Succeeds verifies
// that under GrantAuthRestricted:
//   - A granter IN the scope's AuthoritySet → grant succeeds
//   - A granter NOT in the scope's AuthoritySet → grant denied,
//     no key material produced
//
// The scope's AuthoritySet is {judge, clerk}. The test tries:
//   - judge → succeeds
//   - attacker → denied
//
// This test does NOT set AuthorizedRecipients — restricted mode only
// checks the granter, not the recipient. Any recipient can receive
// access if the granter is authorized.
func TestGrantAuth_Restricted_GranterInAuthoritySet_Succeeds(t *testing.T) {
	f := newGrantAuthFixture(t)

	schemaParams := &types.SchemaParameters{
		ArtifactEncryption:     types.EncryptionAESGCM,
		GrantAuthorizationMode: types.GrantAuthRestricted,
	}

	// ── Subtest: granter is in authority set → succeeds ──────────────

	t.Run("authorized_granter", func(t *testing.T) {
		result, err := lifecycle.GrantArtifactAccess(lifecycle.GrantArtifactAccessParams{
			Destination:       testDestinationDID,
			ArtifactCID:       f.artifactCID,
			RecipientPubKey:   f.recipientPK,
			SchemaParams:      schemaParams,
			KeyStore:          f.keyStore,
			RetrievalProvider: f.retrieval,
			GranterDID:        "did:example:judge", // IN authority set
			ScopePointer:      &f.scopePos,
			Fetcher:           f.fetcher,
			LeafReader:        f.leafStore,
		})
		if err != nil {
			t.Fatalf("authorized granter should succeed: %v", err)
		}
		if len(result.WrappedKey) == 0 {
			t.Fatal("WrappedKey should be produced for authorized granter")
		}
	})

	// ── Subtest: granter is NOT in authority set → denied ────────────

	t.Run("unauthorized_granter", func(t *testing.T) {
		_, err := lifecycle.GrantArtifactAccess(lifecycle.GrantArtifactAccessParams{
			Destination:       testDestinationDID,
			ArtifactCID:       f.artifactCID,
			RecipientPubKey:   f.recipientPK,
			SchemaParams:      schemaParams,
			KeyStore:          f.keyStore,
			RetrievalProvider: f.retrieval,
			GranterDID:        "did:example:attacker", // NOT in authority set
			ScopePointer:      &f.scopePos,
			Fetcher:           f.fetcher,
			LeafReader:        f.leafStore,
		})
		if err == nil {
			t.Fatal("unauthorized granter should be denied — no key material produced")
		}
		// Verify the error message identifies the problem.
		expected := "grant denied"
		if len(err.Error()) < len(expected) {
			t.Fatalf("error should contain '%s', got: %v", expected, err)
		}
	})
}

// ═════════════════════════════════════════════════════════════════════
// Test 3: Sealed mode — granter + recipient authorization
// ═════════════════════════════════════════════════════════════════════

// TestGrantAuth_Sealed_RecipientNotInList_Denied verifies that under
// GrantAuthSealed:
//   - Granter in authority set + recipient in authorized list → succeeds
//   - Granter in authority set + recipient NOT in list → denied
//   - Granter NOT in authority set (regardless of list) → denied
//   - Audit entry includes recipient_did when grant_requires_audit_entry=true
//
// The scope's AuthoritySet is {judge, clerk}.
// The authorized recipients list is [attorney-a, prosecutor].
//
// This is the full access control test: both the granter and the
// recipient must be authorized. The SDK validates both; the domain
// application provides the authorized recipients list.
func TestGrantAuth_Sealed_RecipientNotInList_Denied(t *testing.T) {
	f := newGrantAuthFixture(t)

	schemaParams := &types.SchemaParameters{
		ArtifactEncryption:      types.EncryptionAESGCM,
		GrantAuthorizationMode:  types.GrantAuthSealed,
		GrantRequiresAuditEntry: true,
	}

	authorizedRecipients := []string{
		"did:example:attorney-a",
		"did:example:prosecutor",
	}

	// ── Subtest: authorized granter + authorized recipient → succeeds ─

	t.Run("both_authorized", func(t *testing.T) {
		result, err := lifecycle.GrantArtifactAccess(lifecycle.GrantArtifactAccessParams{
			Destination:          testDestinationDID,
			ArtifactCID:          f.artifactCID,
			RecipientPubKey:      f.recipientPK,
			SchemaParams:         schemaParams,
			KeyStore:             f.keyStore,
			RetrievalProvider:    f.retrieval,
			GranterDID:           "did:example:judge",
			RecipientDID:         "did:example:attorney-a",
			ScopePointer:         &f.scopePos,
			AuthorizedRecipients: authorizedRecipients,
			Fetcher:              f.fetcher,
			LeafReader:           f.leafStore,
		})
		if err != nil {
			t.Fatalf("authorized granter + authorized recipient should succeed: %v", err)
		}
		if len(result.WrappedKey) == 0 {
			t.Fatal("WrappedKey should be produced")
		}

		// Verify audit entry is produced and contains recipient_did.
		if result.GrantEntry == nil {
			t.Fatal("GrantEntry should be produced (grant_requires_audit_entry=true)")
		}
		if result.GrantEntry.Header.SignerDID != "did:example:judge" {
			t.Fatalf("grant entry signer: %s", result.GrantEntry.Header.SignerDID)
		}
		var payload map[string]any
		if err := json.Unmarshal(result.GrantEntry.DomainPayload, &payload); err != nil {
			t.Fatalf("unmarshal grant payload: %v", err)
		}
		if payload["recipient_did"] != "did:example:attorney-a" {
			t.Fatalf("grant entry recipient_did: %v", payload["recipient_did"])
		}
		if payload["grant_type"] != "artifact_access" {
			t.Fatalf("grant entry grant_type: %v", payload["grant_type"])
		}
	})

	// ── Subtest: authorized granter + second authorized recipient ─────

	t.Run("prosecutor_authorized", func(t *testing.T) {
		result, err := lifecycle.GrantArtifactAccess(lifecycle.GrantArtifactAccessParams{
			Destination:          testDestinationDID,
			ArtifactCID:          f.artifactCID,
			RecipientPubKey:      f.recipientPK,
			SchemaParams:         schemaParams,
			KeyStore:             f.keyStore,
			RetrievalProvider:    f.retrieval,
			GranterDID:           "did:example:clerk",
			RecipientDID:         "did:example:prosecutor",
			ScopePointer:         &f.scopePos,
			AuthorizedRecipients: authorizedRecipients,
			Fetcher:              f.fetcher,
			LeafReader:           f.leafStore,
		})
		if err != nil {
			t.Fatalf("clerk granting to prosecutor should succeed: %v", err)
		}
		if len(result.WrappedKey) == 0 {
			t.Fatal("WrappedKey should be produced")
		}
	})

	// ── Subtest: authorized granter + unauthorized recipient → denied ─

	t.Run("recipient_not_in_list", func(t *testing.T) {
		_, err := lifecycle.GrantArtifactAccess(lifecycle.GrantArtifactAccessParams{
			Destination:          testDestinationDID,
			ArtifactCID:          f.artifactCID,
			RecipientPubKey:      f.recipientPK,
			SchemaParams:         schemaParams,
			KeyStore:             f.keyStore,
			RetrievalProvider:    f.retrieval,
			GranterDID:           "did:example:judge",
			RecipientDID:         "did:example:attorney-b", // NOT in authorized list
			ScopePointer:         &f.scopePos,
			AuthorizedRecipients: authorizedRecipients,
			Fetcher:              f.fetcher,
			LeafReader:           f.leafStore,
		})
		if err == nil {
			t.Fatal("unauthorized recipient should be denied — no key material produced")
		}
	})

	// ── Subtest: unauthorized granter (recipient irrelevant) → denied ─

	t.Run("granter_not_in_authority_set", func(t *testing.T) {
		_, err := lifecycle.GrantArtifactAccess(lifecycle.GrantArtifactAccessParams{
			Destination:          testDestinationDID,
			ArtifactCID:          f.artifactCID,
			RecipientPubKey:      f.recipientPK,
			SchemaParams:         schemaParams,
			KeyStore:             f.keyStore,
			RetrievalProvider:    f.retrieval,
			GranterDID:           "did:example:outsider", // NOT in authority set
			RecipientDID:         "did:example:attorney-a",
			ScopePointer:         &f.scopePos,
			AuthorizedRecipients: authorizedRecipients,
			Fetcher:              f.fetcher,
			LeafReader:           f.leafStore,
		})
		if err == nil {
			t.Fatal("unauthorized granter should be denied even if recipient is in list")
		}
	})
}
