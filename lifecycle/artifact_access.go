/*
File: lifecycle/artifact_access.go
Package lifecycle — artifact_access.go composes artifact access control.

Four responsibilities:

 1. KEY STORE: ArtifactKeyStore interface + InMemoryKeyStore. Maps CID to
    ArtifactKey (Key[32] + Nonce[12]). AES-GCM only — one key per artifact.
    PRE owner keys have a different lifecycle (per-identity, HSM-held) and
    arrive via OwnerSecretKey on the grant params, not the key store.

 2. GRANT AUTHORIZATION (Phase 6): CheckGrantAuthorization gates key
    material production. Dispatches on GrantAuthorizationMode:
    GrantAuthOpen(0):       no check.
    GrantAuthRestricted(1): granter in scope AuthoritySet.
    GrantAuthSealed(2):     restricted + recipient in authorized list.

 3. KEY MATERIAL PRODUCTION: GrantArtifactAccess routes to AES-GCM
    (ECIES key wrapping via escrow.EncryptForNode) or Umbral PRE
    (threshold re-encryption with DLEQ proofs + Pedersen binding).

 4. CONTENT VERIFICATION: VerifyAndDecryptArtifact decrypts and verifies
    ciphertext integrity (ArtifactCID) and plaintext integrity
    (ContentDigest).

ECIES key wrapping reuses escrow.EncryptForNode — same ECIES primitive
over secp256k1. The recipient is an artifact requester rather than an
escrow node, but the cryptographic operation is identical.

The SDK is domain-agnostic. None of this code knows whether it protects
physician credentials, sealed court evidence, or insurance policies.

Destination binding: GrantArtifactAccessParams carries a Destination
field (DID of the target exchange). When a grant audit entry is
produced, it is bound to this destination via the canonical hash —
cross-exchange replay of a grant entry is cryptographically impossible.

v7.75 Phase C (ADR-005): PRE mode produces a Pedersen commitment set
alongside KFrags and CFrags. The commitment set is returned on
GrantArtifactAccessResult for Phase D on-log publication under the
pre-grant-commitment-v1 schema. Phase D callers emit this commitment
entry atomically with the grant so downstream verifiers can fetch
commitments from the log and gate decryption on polynomial consistency.

TRUST BOUNDARY (AuthorizedRecipients in sealed mode):

	The SDK enforces membership. The domain application is responsible for
	correctness. Same pattern as CosignaturePositions in EvaluateConditions
	and CandidatePositions in AssemblePathB.

# Interface segregation

Every external interface this file consumes is declared locally as a
narrow interface containing only the methods lifecycle/ calls. External
implementations satisfy these via Go's structural typing — producers
don't import lifecycle/, and consumers don't depend on producer
surfaces they don't use. When a producer package grows methods,
lifecycle/ and its tests are unaffected.

Narrow interfaces declared in this file:

	artifactContentStore — Fetch/Push/Delete subset of storage.ContentStore
	retrievalResolver    — Resolve subset of storage.RetrievalProvider
	entryFetcher         — Fetch subset of types.EntryFetcher
	leafReader           — Get subset of smt.LeafReader

Compile-time drift detection lives in artifact_access_test.go: every
narrow interface has a `var _ narrow = (producer)(nil)` assertion that
fails at build time if the producer removes or re-signs a method.
*/
package lifecycle

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/core/vss"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/artifact"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/escrow"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ═════════════════════════════════════════════════════════════════════
// Sentinel errors
// ═════════════════════════════════════════════════════════════════════

var (
	// ErrOldCiphertextEraseFailed is returned by ReEncryptWithGrant
	// when re-encryption succeeded but deleting the old ciphertext
	// (requested via DeleteOldCiphertext=true) failed. The new
	// ciphertext has been rolled back (best effort) to restore the
	// pre-call state. Callers should retry or escalate to operations
	// — the rotation is a no-op from the caller's perspective.
	ErrOldCiphertextEraseFailed = errors.New(
		"lifecycle/artifact: failed to erase old ciphertext",
	)

	// ErrCryptographicErasureFailed is returned by ReEncryptWithGrant
	// when re-encryption succeeded but deleting the old key failed.
	// This is the most severe failure mode — the old key remains
	// reachable in the key store and any holder of the old ciphertext
	// could still decrypt. The new ciphertext has been rolled back
	// (best effort). Callers MUST either retry until the old key is
	// deleted or treat the rotation as having not happened.
	ErrCryptographicErasureFailed = errors.New(
		"lifecycle/artifact: cryptographic erasure failed (old key still present)",
	)

	// ErrMissingCommitments is returned by VerifyAndDecryptArtifact in
	// PRE mode when the caller did not supply the Pedersen commitment
	// set. v7.75 Phase C requires commitments at decrypt time — the
	// primitive verifies every CFrag against the commitments before
	// Lagrange combination (ADR-005 §3.5). Callers fetch the
	// commitment set from the on-log pre-grant-commitment-v1 entry
	// before invoking VerifyAndDecryptArtifact.
	ErrMissingCommitments = errors.New(
		"lifecycle/artifact: PRE decryption requires commitments (from pre-grant-commitment-v1)",
	)
)

// ═════════════════════════════════════════════════════════════════════
// Consumed interfaces (narrow subsets of external producers)
// ═════════════════════════════════════════════════════════════════════

// artifactContentStore is the blob-store surface lifecycle/ consumes
// from storage.ContentStore. Satisfied by *storage.InMemoryContentStore,
// *storage.HTTPContentStore, and any future ContentStore implementation
// — they all have Fetch/Push/Delete whether or not they also have
// Pin/Exists/etc.
type artifactContentStore interface {
	Fetch(cid storage.CID) ([]byte, error)
	Push(cid storage.CID, data []byte) error
	Delete(cid storage.CID) error
}

// retrievalResolver is the credential-resolution surface lifecycle/
// consumes from storage.RetrievalProvider. A single method — narrow by
// construction but declared locally for symmetry with the other three
// and for compile-time drift detection.
type retrievalResolver interface {
	Resolve(artifactCID storage.CID, expiry time.Duration) (*storage.RetrievalCredential, error)
}

// entryFetcher is the entry-by-position surface lifecycle/ consumes
// from types.EntryFetcher. Used to dereference scope-entity pointers
// during grant authorization.
type entryFetcher interface {
	Fetch(pos types.LogPosition) (*types.EntryWithMetadata, error)
}

// leafReader is the SMT-leaf-by-key surface lifecycle/ consumes from
// smt.LeafReader. Used to look up the current OriginTip of a scope
// entity before fetching its backing entry.
type leafReader interface {
	Get(key [32]byte) (*types.SMTLeaf, error)
}

// ═════════════════════════════════════════════════════════════════════
// ArtifactKeyStore
// ═════════════════════════════════════════════════════════════════════

// ArtifactKeyStore maps artifact CID to AES-GCM key material.
// Used by GrantArtifactAccess (AES-GCM path) and ReEncryptWithGrant.
// Not used by ExecuteRecovery — identity recovery reconstructs the
// holder's Master Identity Key only; any per-artifact re-encryption
// is orchestrated by the domain layer AFTER recovery, by calling
// ReEncryptWithGrant per artifact CID.
// Not used by the PRE path either — PRE owner keys have a different
// lifecycle (per-identity, HSM-held) and arrive via OwnerSecretKey on
// the grant params, not the key store.
type ArtifactKeyStore interface {
	Get(cid storage.CID) (*artifact.ArtifactKey, error)
	Store(cid storage.CID, key artifact.ArtifactKey) error
	Delete(cid storage.CID) error
}

// InMemoryKeyStore is the reference implementation for testing and
// development. Production deployments back this with an HSM or KMS.
type InMemoryKeyStore struct {
	mu    sync.RWMutex
	store map[string]artifact.ArtifactKey
}

// NewInMemoryKeyStore creates an empty key store.
func NewInMemoryKeyStore() *InMemoryKeyStore {
	return &InMemoryKeyStore{store: make(map[string]artifact.ArtifactKey)}
}

func (s *InMemoryKeyStore) Get(cid storage.CID) (*artifact.ArtifactKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.store[cid.String()]
	if !ok {
		return nil, nil
	}
	cp := k
	return &cp, nil
}

func (s *InMemoryKeyStore) Store(cid storage.CID, key artifact.ArtifactKey) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.store[cid.String()] = key
	return nil
}

func (s *InMemoryKeyStore) Delete(cid storage.CID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.store, cid.String())
	return nil
}

// ═════════════════════════════════════════════════════════════════════
// Grant authorization (Phase 6)
// ═════════════════════════════════════════════════════════════════════

// GrantAuthCheckParams configures grant authorization verification.
type GrantAuthCheckParams struct {
	// Mode is the grant authorization policy from the schema.
	Mode types.GrantAuthorizationMode

	// GranterDID is the party calling GrantArtifactAccess.
	// Must be in scope AuthoritySet for restricted/sealed modes.
	GranterDID string

	// RecipientDID is the party receiving key material.
	// Must be in AuthorizedRecipients for sealed mode.
	RecipientDID string

	// ScopePointer identifies the scope whose AuthoritySet governs
	// this grant. Required for restricted and sealed modes.
	ScopePointer *types.LogPosition

	// AuthorizedRecipients is the allowlist for sealed mode.
	// SDK enforces membership; domain app ensures correctness.
	AuthorizedRecipients []string

	// Fetcher retrieves entries by position (scope entry lookup).
	// types.EntryFetcher satisfies this interface via structural
	// typing; test mocks implement only Fetch.
	Fetcher entryFetcher

	// LeafReader reads SMT leaves (scope OriginTip lookup).
	// smt.LeafReader satisfies this interface via structural typing;
	// test mocks implement only Get.
	LeafReader leafReader
}

// GrantAuthCheckResult holds the authorization outcome.
type GrantAuthCheckResult struct {
	Authorized bool
	Reason     string
}

// CheckGrantAuthorization determines whether a granter may produce key
// material for a recipient under the schema's grant authorization policy.
//
// Called by GrantArtifactAccess before any key material is produced.
// If Authorized=false, no ECIES wrapping occurs, no KFrags are
// generated, no retrieval credential is issued.
func CheckGrantAuthorization(params GrantAuthCheckParams) (*GrantAuthCheckResult, error) {
	// Open: no check.
	if params.Mode == types.GrantAuthOpen {
		return &GrantAuthCheckResult{
			Authorized: true,
			Reason:     "grant_authorization_mode is open",
		}, nil
	}

	// Restricted and sealed: granter must be in scope AuthoritySet.
	if params.GranterDID == "" {
		return &GrantAuthCheckResult{
			Authorized: false,
			Reason:     "granter DID is empty",
		}, nil
	}
	if params.ScopePointer == nil {
		return &GrantAuthCheckResult{
			Authorized: false,
			Reason:     "scope pointer is nil (required for restricted/sealed mode)",
		}, nil
	}

	// Read current scope: LeafReader → OriginTip → Fetcher → Deserialize.
	// Same read-only pattern as classifyPathC in entry_classification.go.
	scopeLeafKey := smt.DeriveKey(*params.ScopePointer)
	scopeLeaf, err := params.LeafReader.Get(scopeLeafKey)
	if err != nil || scopeLeaf == nil {
		return &GrantAuthCheckResult{
			Authorized: false,
			Reason:     fmt.Sprintf("scope leaf not found at %s", params.ScopePointer),
		}, nil
	}

	scopeMeta, err := params.Fetcher.Fetch(scopeLeaf.OriginTip)
	if err != nil || scopeMeta == nil {
		return &GrantAuthCheckResult{
			Authorized: false,
			Reason:     fmt.Sprintf("scope entry not found at OriginTip %s", scopeLeaf.OriginTip),
		}, nil
	}

	scopeEntry, err := envelope.Deserialize(scopeMeta.CanonicalBytes)
	if err != nil {
		return &GrantAuthCheckResult{
			Authorized: false,
			Reason:     fmt.Sprintf("scope deserialization failed: %v", err),
		}, nil
	}

	if !scopeEntry.Header.AuthoritySetContains(params.GranterDID) {
		return &GrantAuthCheckResult{
			Authorized: false,
			Reason: fmt.Sprintf("granter %s is not in scope authority set (size %d)",
				params.GranterDID, scopeEntry.Header.AuthoritySetSize()),
		}, nil
	}

	// Restricted: granter check passed, done.
	if params.Mode == types.GrantAuthRestricted {
		return &GrantAuthCheckResult{
			Authorized: true,
			Reason:     "granter is in scope authority set",
		}, nil
	}

	// Sealed: additionally check recipient in authorized list.
	if params.RecipientDID == "" {
		return &GrantAuthCheckResult{
			Authorized: false,
			Reason:     "recipient DID is empty (required for sealed mode)",
		}, nil
	}
	for _, did := range params.AuthorizedRecipients {
		if did == params.RecipientDID {
			return &GrantAuthCheckResult{
				Authorized: true,
				Reason:     "granter in authority set and recipient in authorized list",
			}, nil
		}
	}
	return &GrantAuthCheckResult{
		Authorized: false,
		Reason: fmt.Sprintf("recipient %s is not in authorized recipients list (size %d)",
			params.RecipientDID, len(params.AuthorizedRecipients)),
	}, nil
}

// ═════════════════════════════════════════════════════════════════════
// GrantArtifactAccess
// ═════════════════════════════════════════════════════════════════════

// GrantArtifactAccessParams configures artifact access grant.
type GrantArtifactAccessParams struct {
	// Destination is the DID of the target exchange for any grant
	// audit entry produced by this call. Required. Validated by
	// envelope.ValidateDestination.
	Destination string

	ArtifactCID     storage.CID
	ContentDigest   storage.CID      // CID of plaintext, for audit entries.
	RecipientPubKey []byte           // 65-byte uncompressed secp256k1 public key.
	KeyStore        ArtifactKeyStore // AES-GCM key material.

	// RetrievalProvider resolves retrieval credentials. Any
	// storage.RetrievalProvider implementation satisfies this interface
	// via structural typing.
	RetrievalProvider retrievalResolver

	SchemaParams *types.SchemaParameters // Caller provides directly.

	// Audit entry fields.
	GranterDID   string
	RecipientDID string

	// Grant authorization (Phase 6). Required when
	// SchemaParams.GrantAuthorizationMode != GrantAuthOpen. Any
	// types.EntryFetcher / smt.LeafReader satisfies these interfaces
	// via structural typing.
	ScopePointer         *types.LogPosition
	AuthorizedRecipients []string
	Fetcher              entryFetcher
	LeafReader           leafReader

	// PRE-specific fields. Nil/zero for AES-GCM mode.
	Capsule        *artifact.Capsule
	OwnerSecretKey []byte // 32-byte secp256k1 private key scalar (unwrapped sk_del provided by caller)

	RetrievalExpiry time.Duration
}

// GrantArtifactAccessResult holds the grant output.
type GrantArtifactAccessResult struct {
	Method     string                       // "aes_gcm" or "umbral_pre".
	Credential *storage.RetrievalCredential // Retrieval path for ciphertext.
	WrappedKey []byte                       // AES-GCM: ECIES-wrapped key material.
	GrantEntry *envelope.Entry              // Nil if no audit entry required.
	CFrags     []*artifact.CFrag            // PRE mode only.
	Capsule    *artifact.Capsule            // PRE mode only.

	// Commitments is the Pedersen commitment set produced by
	// PRE_GenerateKFrags during umbral_pre grants. v7.75 Phase C
	// (ADR-005 §3.5). Empty for aes_gcm grants.
	//
	// Phase D REQUIREMENT: the domain layer MUST publish this
	// commitment set on-log via the pre-grant-commitment-v1 schema
	// BEFORE distributing CFrags to proxies. Verifiers fetch the
	// commitment set from the log (via the grant's deterministic
	// SplitID — see ADR-005 §6.2) and pass it to
	// VerifyAndDecryptArtifact at decryption time. The primitive
	// rejects any CFrag that fails the polynomial consistency check
	// against this commitment set.
	Commitments vss.Commitments
}

// GrantArtifactAccess composes a grant for artifact access.
//
// Phase 1 — Authorization: if mode != open, CheckGrantAuthorization
// gates all subsequent work. Denied → error, no key material produced.
//
// Phase 2 — Key material: AES-GCM wraps via ECIES (KeyStore → wrap).
// PRE generates KFrags, Pedersen commitments, and CFrags
// (OwnerSecretKey → KFrags + Commitments → CFrags).
//
// Phase 3 — Retrieval + audit: resolve retrieval credential, optionally
// build a commentary entry recording the grant.
func GrantArtifactAccess(params GrantArtifactAccessParams) (*GrantArtifactAccessResult, error) {
	if err := envelope.ValidateDestination(params.Destination); err != nil {
		return nil, fmt.Errorf("lifecycle/artifact: %w", err)
	}
	if params.SchemaParams == nil {
		return nil, fmt.Errorf("lifecycle/artifact: nil schema params")
	}

	// ── Phase 1: Grant authorization ────────────────────────────────
	if params.SchemaParams.GrantAuthorizationMode != types.GrantAuthOpen {
		check, err := CheckGrantAuthorization(GrantAuthCheckParams{
			Mode:                 params.SchemaParams.GrantAuthorizationMode,
			GranterDID:           params.GranterDID,
			RecipientDID:         params.RecipientDID,
			ScopePointer:         params.ScopePointer,
			AuthorizedRecipients: params.AuthorizedRecipients,
			Fetcher:              params.Fetcher,
			LeafReader:           params.LeafReader,
		})
		if err != nil {
			return nil, fmt.Errorf("lifecycle/artifact: grant authorization: %w", err)
		}
		if !check.Authorized {
			return nil, fmt.Errorf("lifecycle/artifact: grant denied: %s", check.Reason)
		}
	}

	// ── Phase 2: Key material production ────────────────────────────
	result := &GrantArtifactAccessResult{}
	switch params.SchemaParams.ArtifactEncryption {
	case types.EncryptionAESGCM:
		if err := grantAESGCM(params, result); err != nil {
			return nil, err
		}
	case types.EncryptionUmbralPRE:
		if err := grantUmbralPRE(params, result); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("lifecycle/artifact: unknown encryption scheme %d",
			params.SchemaParams.ArtifactEncryption)
	}

	// ── Phase 3: Retrieval credential + audit entry ─────────────────
	if params.RetrievalProvider != nil {
		cred, err := params.RetrievalProvider.Resolve(params.ArtifactCID, params.RetrievalExpiry)
		if err != nil {
			return nil, fmt.Errorf("lifecycle/artifact: resolve retrieval: %w", err)
		}
		result.Credential = cred
	}

	needsAudit := params.SchemaParams.GrantEntryRequired || params.SchemaParams.GrantRequiresAuditEntry
	if needsAudit && params.GranterDID != "" {
		entry, err := buildGrantEntry(params, result.Method)
		if err != nil {
			return nil, fmt.Errorf("lifecycle/artifact: build grant entry: %w", err)
		}
		result.GrantEntry = entry
	}

	return result, nil
}

// grantAESGCM: KeyStore.Get → serialize → ECIES wrap for recipient.
func grantAESGCM(params GrantArtifactAccessParams, result *GrantArtifactAccessResult) error {
	artKey, err := params.KeyStore.Get(params.ArtifactCID)
	if err != nil || artKey == nil {
		return fmt.Errorf("lifecycle/artifact: key not found for %s", params.ArtifactCID)
	}

	recipientPub, err := parseSecp256k1PubKey(params.RecipientPubKey)
	if err != nil {
		return fmt.Errorf("lifecycle/artifact: parse recipient key: %w", err)
	}

	// Serialize Key(32) + Nonce(12) for ECIES wrapping.
	keyMaterial := make([]byte, artifact.KeySize+artifact.NonceSize)
	copy(keyMaterial[:artifact.KeySize], artKey.Key[:])
	copy(keyMaterial[artifact.KeySize:], artKey.Nonce[:])

	wrapped, err := escrow.EncryptForNode(keyMaterial, recipientPub)
	if err != nil {
		return fmt.Errorf("lifecycle/artifact: wrap key: %w", err)
	}

	result.Method = "aes_gcm"
	result.WrappedKey = wrapped
	return nil
}

// grantUmbralPRE: OwnerSecretKey → KFrags + Pedersen commitments → CFrags.
//
// v7.75 Phase C (ADR-005 §3.5): PRE_GenerateKFrags produces a Pedersen
// commitment set alongside the KFrags. The commitment set is captured
// on the result for Phase D on-log publication via the
// pre-grant-commitment-v1 schema. Each CFrag's DLEQ challenge is
// computed over a transcript that absorbs the commitments and BK_i
// (ADR-005 §5.2), binding the proxy's re-encryption to the committed
// polynomial.
//
// The private key scalar (sk_del) comes from params, already unwrapped
// by the caller.
func grantUmbralPRE(params GrantArtifactAccessParams, result *GrantArtifactAccessResult) error {
	if params.Capsule == nil {
		return fmt.Errorf("lifecycle/artifact: capsule required for PRE mode")
	}
	if len(params.OwnerSecretKey) == 0 {
		return fmt.Errorf("lifecycle/artifact: owner secret key required for PRE mode")
	}

	m, n := 3, 5
	if params.SchemaParams.ReEncryptionThreshold != nil {
		m = params.SchemaParams.ReEncryptionThreshold.M
		n = params.SchemaParams.ReEncryptionThreshold.N
	}

	// Generate KFrags + Pedersen commitment set (v7.75 breaking change
	// vs v7.5 — three return values).
	kfrags, commitments, err := artifact.PRE_GenerateKFrags(
		params.OwnerSecretKey, params.RecipientPubKey, m, n,
	)
	if err != nil {
		return fmt.Errorf("lifecycle/artifact: generate kfrags: %w", err)
	}

	// Produce CFrags. Each re-encryption threads the commitment set
	// into the DLEQ transcript (ADR-005 §5.2).
	cfrags := make([]*artifact.CFrag, len(kfrags))
	for i, kf := range kfrags {
		cf, reErr := artifact.PRE_ReEncrypt(kf, params.Capsule, commitments)
		if reErr != nil {
			return fmt.Errorf("lifecycle/artifact: re-encrypt kfrag %d: %w", i, reErr)
		}
		cfrags[i] = cf
	}

	result.Method = "umbral_pre"
	result.CFrags = cfrags
	result.Capsule = params.Capsule
	result.Commitments = commitments
	return nil
}

// buildGrantEntry creates a commentary entry recording the grant.
// Destination is copied verbatim from the params; validation of the
// destination happened at the top of GrantArtifactAccess.
func buildGrantEntry(params GrantArtifactAccessParams, method string) (*envelope.Entry, error) {
	payloadMap := map[string]any{
		"grant_type":     "artifact_access",
		"artifact_cid":   params.ArtifactCID.String(),
		"recipient_key":  fmt.Sprintf("%x", params.RecipientPubKey),
		"content_digest": params.ContentDigest.String(),
		"scheme":         method,
	}
	if params.RecipientDID != "" {
		payloadMap["recipient_did"] = params.RecipientDID
	}
	payload, err := json.Marshal(payloadMap)
	if err != nil {
		return nil, err
	}
	return builder.BuildCommentary(builder.CommentaryParams{
		Destination: params.Destination,
		SignerDID:   params.GranterDID,
		Payload:     payload,
	})
}

// ═════════════════════════════════════════════════════════════════════
// VerifyAndDecryptArtifact
// ═════════════════════════════════════════════════════════════════════

// VerifyAndDecryptArtifactParams configures decryption and verification.
type VerifyAndDecryptArtifactParams struct {
	Ciphertext    []byte
	ArtifactCID   storage.CID             // Expected CID of ciphertext.
	ContentDigest storage.CID             // Expected CID of plaintext.
	SchemaParams  *types.SchemaParameters // Encryption scheme selector.
	Key           *artifact.ArtifactKey   // AES-GCM mode.

	// PRE fields:
	CFrags       []*artifact.CFrag
	Capsule      *artifact.Capsule
	RecipientKey []byte // 32-byte private key scalar.
	OwnerPubKey  []byte // 65-byte uncompressed public key.

	// Commitments is the Pedersen commitment set for the grant,
	// fetched from the on-log pre-grant-commitment-v1 entry using
	// the grant's deterministic SplitID (ADR-005 §6.2).
	//
	// REQUIRED for PRE mode (v7.75 Phase C). Empty/zero-threshold
	// commitments return ErrMissingCommitments.
	//
	// The primitive (artifact.PRE_DecryptFrags) verifies every CFrag
	// against this commitment set BEFORE Lagrange combination.
	// Unverified CFrags entering combination is the substitution
	// vulnerability ADR-005 closes (§3.5).
	//
	// Ignored in AES-GCM mode.
	Commitments vss.Commitments
}

// VerifyAndDecryptArtifact decrypts artifact content and verifies
// integrity at both layers:
//
//  1. Ciphertext integrity: ArtifactCID must match the ciphertext.
//  2. Decrypt via schema's ArtifactEncryption scheme.
//     - AES-GCM: direct decryption with artifact key.
//     - PRE: verify every CFrag against commitments (DLEQ + Pedersen),
//     combine via Lagrange, decrypt.
//  3. Plaintext integrity: ContentDigest must match the plaintext.
//
// Returns the verified plaintext. Returns ErrMissingCommitments in
// PRE mode if the caller did not supply the Pedersen commitment set.
func VerifyAndDecryptArtifact(params VerifyAndDecryptArtifactParams) ([]byte, error) {
	if params.SchemaParams == nil {
		return nil, fmt.Errorf("lifecycle/artifact: nil schema params")
	}

	// Ciphertext integrity.
	if !params.ArtifactCID.IsZero() && !params.ArtifactCID.Verify(params.Ciphertext) {
		return nil, fmt.Errorf("lifecycle/artifact: ciphertext does not match artifact CID")
	}

	// Decrypt.
	var plaintext []byte
	var err error
	switch params.SchemaParams.ArtifactEncryption {
	case types.EncryptionAESGCM:
		if params.Key == nil {
			return nil, fmt.Errorf("lifecycle/artifact: nil AES key")
		}
		plaintext, err = artifact.DecryptArtifact(params.Ciphertext, *params.Key)

	case types.EncryptionUmbralPRE:
		if params.Capsule == nil || len(params.CFrags) == 0 {
			return nil, fmt.Errorf("lifecycle/artifact: capsule and cfrags required for PRE")
		}
		// v7.75 Phase C: commitments are required at decrypt time so
		// PRE_DecryptFrags can verify every CFrag before combination.
		if params.Commitments.Threshold() == 0 {
			return nil, ErrMissingCommitments
		}
		plaintext, err = artifact.PRE_DecryptFrags(
			params.RecipientKey, params.CFrags, params.Capsule,
			params.Ciphertext, params.OwnerPubKey, params.Commitments,
		)

	default:
		return nil, fmt.Errorf("lifecycle/artifact: unknown scheme %d",
			params.SchemaParams.ArtifactEncryption)
	}
	if err != nil {
		return nil, fmt.Errorf("lifecycle/artifact: decrypt: %w", err)
	}

	// Plaintext integrity.
	if !params.ContentDigest.IsZero() && !params.ContentDigest.Verify(plaintext) {
		return nil, fmt.Errorf("lifecycle/artifact: plaintext does not match content digest")
	}

	return plaintext, nil
}

// ═════════════════════════════════════════════════════════════════════
// ReEncryptWithGrant — artifact key rotation
// ═════════════════════════════════════════════════════════════════════

// ReEncryptWithGrantParams configures artifact re-encryption.
type ReEncryptWithGrantParams struct {
	OldCID   storage.CID
	KeyStore ArtifactKeyStore

	// ContentStore provides the blob-level operations this function
	// needs: Fetch the old ciphertext, Push the new ciphertext, Delete
	// the old one. Every storage.ContentStore implementation satisfies
	// this interface via structural typing.
	ContentStore artifactContentStore

	DeleteOldCiphertext bool
}

// ReEncryptWithGrantResult holds the re-encryption outcome.
type ReEncryptWithGrantResult struct {
	NewCID storage.CID
	NewKey artifact.ArtifactKey
}

// ReEncryptWithGrant fetches an artifact by CID, decrypts with the old
// key, re-encrypts with a fresh key, pushes the new ciphertext, and
// deletes the old key from the store (cryptographic erasure).
//
// Called by the domain layer during identity recovery and artifact
// migration. After lifecycle.ExecuteRecovery returns the holder's
// Master Identity Key, the domain iterates its own artifact CIDs and
// calls this function per artifact. The SDK identity-recovery pathway
// does NOT call this function — it has no awareness of artifacts,
// content stores, or artifact key stores. The architectural boundary
// is: SDK recovers identity; domain orchestrates artifacts.
//
// # Erasure semantics
//
// The old-key delete is CRYPTOGRAPHIC ERASURE — a security-critical
// operation, not best-effort cleanup. If the key delete fails, the
// old key remains reachable in the key store; any holder of the old
// ciphertext can still decrypt; the access-revocation invariant is
// violated. ReEncryptWithGrant surfaces erasure failures as
// ErrCryptographicErasureFailed. When configured with
// DeleteOldCiphertext=true, an old-ciphertext delete failure surfaces
// as ErrOldCiphertextEraseFailed.
//
// On either erasure failure, ReEncryptWithGrant best-effort deletes
// the NEW ciphertext it just pushed, restoring the pre-call state
// from the caller's perspective. A rollback failure is wrapped into
// the returned error so operators can reconcile manually.
func ReEncryptWithGrant(params ReEncryptWithGrantParams) (*ReEncryptWithGrantResult, error) {
	oldKey, err := params.KeyStore.Get(params.OldCID)
	if err != nil || oldKey == nil {
		return nil, fmt.Errorf("lifecycle/artifact: old key not found for %s", params.OldCID)
	}

	ciphertext, err := params.ContentStore.Fetch(params.OldCID)
	if err != nil {
		return nil, fmt.Errorf("lifecycle/artifact: fetch ciphertext: %w", err)
	}

	newCT, newKey, err := artifact.ReEncryptArtifact(ciphertext, *oldKey)
	if err != nil {
		return nil, fmt.Errorf("lifecycle/artifact: re-encrypt: %w", err)
	}

	newCID := storage.Compute(newCT)
	if err := params.ContentStore.Push(newCID, newCT); err != nil {
		return nil, fmt.Errorf("lifecycle/artifact: push: %w", err)
	}

	// Erase old ciphertext if requested. On failure, best-effort
	// roll back the new ciphertext so the store is restored to its
	// pre-call state before the caller observes the error.
	if params.DeleteOldCiphertext {
		if delErr := params.ContentStore.Delete(params.OldCID); delErr != nil {
			if rbErr := params.ContentStore.Delete(newCID); rbErr != nil {
				return nil, fmt.Errorf(
					"%w: %v (rollback of new ciphertext also failed: %v)",
					ErrOldCiphertextEraseFailed, delErr, rbErr,
				)
			}
			return nil, fmt.Errorf("%w: %v", ErrOldCiphertextEraseFailed, delErr)
		}
	}

	// Cryptographic erasure: old key no longer valid. On failure,
	// best-effort roll back the new ciphertext — from the caller's
	// perspective the rotation is a no-op.
	if delErr := params.KeyStore.Delete(params.OldCID); delErr != nil {
		if rbErr := params.ContentStore.Delete(newCID); rbErr != nil {
			return nil, fmt.Errorf(
				"%w: %v (rollback of new ciphertext also failed: %v)",
				ErrCryptographicErasureFailed, delErr, rbErr,
			)
		}
		return nil, fmt.Errorf("%w: %v", ErrCryptographicErasureFailed, delErr)
	}

	return &ReEncryptWithGrantResult{NewCID: newCID, NewKey: newKey}, nil
}
