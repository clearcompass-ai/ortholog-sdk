/*
Package lifecycle — artifact_access.go composes artifact access control.

Three responsibilities:

1. GRANT AUTHORIZATION (Phase 6): CheckGrantAuthorization determines
   whether a granter is allowed to produce key material for a recipient.
   Dispatches on GrantAuthorizationMode from the schema:
     - GrantAuthOpen: no check, produce key material for anyone.
     - GrantAuthRestricted: granter must be in scope's AuthoritySet.
     - GrantAuthSealed: restricted check + recipient must be in the
       caller-provided authorized recipients list.

2. KEY MATERIAL PRODUCTION: GrantArtifactAccess routes to AES-GCM
   (ECIES key wrapping via escrow.EncryptForNode) or Umbral PRE
   (threshold re-encryption with DLEQ proofs) based on schema parameters.

3. CONTENT VERIFICATION: VerifyAndDecrypt validates content integrity
   after decryption by checking the content digest (SHA-256 of plaintext).
   The CID check (ciphertext integrity) is NOT performed here — the
   content store already verifies CID integrity on fetch. The content
   digest is the only check the decryptor can exclusively perform.

ECIES key wrapping reuses escrow.EncryptForNode — same ECIES primitive
over secp256k1. The recipient is an artifact requester rather than an
escrow node, but the cryptographic operation is identical.

The SDK is domain-agnostic. CheckGrantAuthorization does not know whether
it is protecting a physician's rotation evaluation, sealed court evidence,
or insurance policy details. It checks structural membership (DID in set)
and produces or withholds key material. The domain application provides
the inputs; the SDK validates them.

TRUST BOUNDARY (applies to AuthorizedRecipients):
  The SDK enforces membership in the authorized recipients list. The
  domain application is responsible for the list's correctness. The SDK
  cannot verify that the list matches a sealing order or consent decision
  because the SDK does not read Domain Payload (SDK-D6). An incorrect
  list is a domain bug, not a protocol violation. Same caller-provides-
  SDK-validates pattern as CosignaturePositions in EvaluateConditions
  and CandidatePositions in AssemblePathB.

Consumed by:
  - enforcement/evidence_access.go (grant artifact access for evidence)
  - cases/artifact/retrieve.go (verify and decrypt retrieved artifacts)
  - Any domain application that grants per-recipient artifact access
*/
package lifecycle

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/artifact"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/escrow"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/schema"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// ArtifactKeyStore — key material storage for artifact access control
// ─────────────────────────────────────────────────────────────────────

// ArtifactKeyStore stores and retrieves key material by artifact CID.
// For AES-GCM mode: stores AES key + nonce (44 bytes).
// For Umbral PRE mode: stores the owner's private key (32 bytes).
type ArtifactKeyStore interface {
	Get(cid storage.CID) ([]byte, error)
	Store(cid storage.CID, key []byte) error
	Delete(cid storage.CID) error
}

// ═════════════════════════════════════════════════════════════════════
// Grant authorization — who may grant, who may receive
// ═════════════════════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────────────────
// Grant authorization types
// ─────────────────────────────────────────────────────────────────────

// GrantAuthCheckParams configures grant authorization verification.
type GrantAuthCheckParams struct {
	// Mode is the grant authorization policy from the schema.
	// Determines which checks are performed.
	Mode types.GrantAuthorizationMode

	// GranterDID is the DID of the party calling GrantArtifactAccess.
	// For GrantAuthRestricted and GrantAuthSealed: must be a member of
	// the scope's AuthoritySet.
	GranterDID string

	// RecipientDID is the DID of the party that will receive key material.
	// For GrantAuthSealed: must appear in AuthorizedRecipients.
	// For GrantAuthRestricted: informational only (not checked).
	// For GrantAuthOpen: ignored.
	RecipientDID string

	// ScopePointer identifies the scope entity whose AuthoritySet
	// governs grant authorization. Required for restricted and sealed
	// modes. The SDK fetches the scope entry at this position and reads
	// its AuthoritySet — same read-only pattern as classifyPathC in
	// entry_classification.go.
	ScopePointer *types.LogPosition

	// AuthorizedRecipients is the list of DIDs permitted to receive
	// artifact access. Required for GrantAuthSealed only.
	//
	// TRUST BOUNDARY: The SDK enforces membership in this list. The
	// domain application is responsible for the list's correctness.
	// See package-level doc comment for full trust boundary discussion.
	AuthorizedRecipients []string

	// Fetcher retrieves entries by position (for scope entry lookup).
	Fetcher builder.EntryFetcher

	// LeafReader reads SMT leaves (for scope leaf OriginTip lookup).
	LeafReader smt.LeafReader
}

// GrantAuthCheckResult holds the outcome of grant authorization.
type GrantAuthCheckResult struct {
	// Authorized is true when the granter may produce key material
	// for the recipient under the schema's grant authorization policy.
	Authorized bool

	// Reason describes why authorization was granted or denied.
	// Human-readable, for logging and diagnostics.
	Reason string
}

// ─────────────────────────────────────────────────────────────────────
// CheckGrantAuthorization
// ─────────────────────────────────────────────────────────────────────

// CheckGrantAuthorization determines whether a granter is authorized to
// produce key material for a recipient, according to the schema's
// GrantAuthorizationMode.
//
// Three modes:
//
//	GrantAuthOpen (0):
//	  No check. Returns Authorized=true immediately.
//	  Every pre-Phase-6 schema defaults to this mode.
//
//	GrantAuthRestricted (1):
//	  Fetches the scope entry at ScopePointer. Reads the current scope
//	  state (via LeafReader → OriginTip → Fetcher). Checks that
//	  GranterDID is in the scope's AuthoritySet. If yes → authorized.
//	  If no → denied.
//
//	GrantAuthSealed (2):
//	  Restricted check (granter in authority set) PLUS: scans
//	  AuthorizedRecipients for RecipientDID. Both must pass.
//
// This function is called by GrantArtifactAccess BEFORE any key material
// is produced. If it returns Authorized=false, no ECIES wrapping occurs,
// no KFrags are generated, no retrieval credential is issued. The
// recipient gets nothing.
func CheckGrantAuthorization(params GrantAuthCheckParams) (*GrantAuthCheckResult, error) {

	// ── GrantAuthOpen: no check ─────────────────────────────────────
	if params.Mode == types.GrantAuthOpen {
		return &GrantAuthCheckResult{
			Authorized: true,
			Reason:     "grant_authorization_mode is open",
		}, nil
	}

	// ── GrantAuthRestricted and GrantAuthSealed: granter must be in
	//    the scope's AuthoritySet ─────────────────────────────────────

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

	// Fetch the current scope entry. The scope is an SMT leaf whose
	// OriginTip may have advanced (scope amendment). We read the leaf
	// to find the current OriginTip, then fetch the entry at that tip
	// to get the current AuthoritySet.
	//
	// This is the same read-only scope lookup that classifyPathC in
	// entry_classification.go performs. No SMT mutation.
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
			Reason:     fmt.Sprintf("scope entry deserialization failed: %v", err),
		}, nil
	}

	// Check: granter is in the scope's AuthoritySet.
	if !scopeEntry.Header.AuthoritySetContains(params.GranterDID) {
		return &GrantAuthCheckResult{
			Authorized: false,
			Reason: fmt.Sprintf("granter %s is not in scope authority set (size %d)",
				params.GranterDID, scopeEntry.Header.AuthoritySetSize()),
		}, nil
	}

	// ── GrantAuthRestricted: granter check passed, done ─────────────
	if params.Mode == types.GrantAuthRestricted {
		return &GrantAuthCheckResult{
			Authorized: true,
			Reason:     "granter is in scope authority set",
		}, nil
	}

	// ── GrantAuthSealed: additionally check recipient in list ────────

	if params.RecipientDID == "" {
		return &GrantAuthCheckResult{
			Authorized: false,
			Reason:     "recipient DID is empty (required for sealed mode)",
		}, nil
	}

	for _, authorized := range params.AuthorizedRecipients {
		if authorized == params.RecipientDID {
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
// Key material production — GrantArtifactAccess
// ═════════════════════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────────────────
// Grant types
// ─────────────────────────────────────────────────────────────────────

// GrantParams configures artifact access grant.
type GrantParams struct {
	ArtifactCID       storage.CID
	RequesterPubKey   []byte              // Recipient's secp256k1 public key (65 bytes uncompressed).
	SchemaRef         types.LogPosition   // Schema governing this artifact.
	Fetcher           builder.EntryFetcher
	Extractor         schema.SchemaParameterExtractor
	KeyStore          ArtifactKeyStore
	RetrievalProvider storage.RetrievalProvider

	// GranterDID is the signer for the optional grant commentary entry
	// and the subject of grant authorization checks.
	// Required when the schema sets GrantAuthRestricted or GrantAuthSealed.
	// Required when GrantEntryRequired or GrantRequiresAuditEntry is true.
	GranterDID string

	// ContentDigest is SHA-256(plaintext). Included in grant entries
	// for recipient-side verification.
	ContentDigest [32]byte

	// ── Grant authorization fields ───────────────────────────────────
	// Required when GrantAuthorizationMode != GrantAuthOpen.
	// Ignored when GrantAuthorizationMode == GrantAuthOpen.

	// RecipientDID identifies who is receiving artifact access.
	// Required for GrantAuthSealed (checked against AuthorizedRecipients).
	// Included in audit entries when present.
	RecipientDID string

	// EntityPosition is the entity the artifact belongs to.
	// Used for scope lookup in restricted/sealed modes.
	EntityPosition types.LogPosition

	// ScopePointer is the scope governing the entity.
	// Required for GrantAuthRestricted and GrantAuthSealed.
	// The SDK fetches this scope entry and checks AuthoritySet membership.
	ScopePointer *types.LogPosition

	// AuthorizedRecipients is the list of DIDs authorized to receive
	// access. Required for GrantAuthSealed only.
	// See GrantAuthCheckParams.AuthorizedRecipients for trust boundary docs.
	AuthorizedRecipients []string

	// LeafReader for scope authority verification in restricted/sealed mode.
	LeafReader smt.LeafReader

	// ── PRE-specific fields (nil/zero for AES-GCM mode) ─────────────

	// Capsule is the original capsule from PRE_Encrypt. Required for
	// Umbral PRE mode — the exchange stores this at encryption time.
	Capsule *artifact.Capsule

	// OwnerPubKey is the owner's secp256k1 public key (65 bytes).
	// Required for PRE mode grant entries.
	OwnerPubKey []byte

	// RetrievalExpiry is the duration for retrieval credential validity.
	// Zero uses the provider's default.
	RetrievalExpiry time.Duration
}

// GrantResult holds the output of GrantArtifactAccess.
type GrantResult struct {
	Retrieval    *storage.RetrievalCredential
	GrantEntry   *envelope.Entry      // Nil if no audit entry required.
	Scheme       types.EncryptionScheme

	// AES-GCM mode: ECIES-wrapped key material for the requester.
	EncryptedKey []byte

	// Umbral PRE mode: re-encryption fragments and capsule.
	CFrags  []*artifact.CFrag
	Capsule *artifact.Capsule

	ContentDigest [32]byte
}

// ─────────────────────────────────────────────────────────────────────
// GrantArtifactAccess
// ─────────────────────────────────────────────────────────────────────

// GrantArtifactAccess composes a grant for artifact access. Three phases:
//
// Phase 1 — AUTHORIZATION (Phase 6 addition):
//
//	If the schema's GrantAuthorizationMode is not GrantAuthOpen,
//	CheckGrantAuthorization is called BEFORE any key material is produced.
//	If the check fails, the function returns an error immediately.
//	No ECIES wrapping. No KFrag generation. No retrieval credential.
//	The recipient gets nothing.
//
// Phase 2 — KEY MATERIAL PRODUCTION:
//
//	Dispatches on the schema's ArtifactEncryption field.
//	AES-GCM: KeyStore.Get → ECIES wrap for requester → EncryptedKey.
//	PRE: KeyStore.Get → PRE_GenerateKFrags → PRE_ReEncrypt → CFrags.
//
// Phase 3 — RETRIEVAL + AUDIT:
//
//	RetrievalProvider.Resolve → retrieval credential.
//	If GrantEntryRequired or GrantRequiresAuditEntry → build commentary.
func GrantArtifactAccess(params GrantParams) (*GrantResult, error) {
	// ── Fetch and extract schema parameters ─────────────────────────

	schemaMeta, err := params.Fetcher.Fetch(params.SchemaRef)
	if err != nil || schemaMeta == nil {
		return nil, fmt.Errorf("lifecycle/artifact: schema not found at %s", params.SchemaRef)
	}
	schemaEntry, err := envelope.Deserialize(schemaMeta.CanonicalBytes)
	if err != nil {
		return nil, fmt.Errorf("lifecycle/artifact: deserialize schema: %w", err)
	}
	schemaParams, err := params.Extractor.Extract(schemaEntry)
	if err != nil {
		return nil, fmt.Errorf("lifecycle/artifact: extract schema params: %w", err)
	}

	// ── Phase 1: Grant authorization check ──────────────────────────
	//
	// This is the gate. If the schema declares GrantAuthRestricted or
	// GrantAuthSealed, the granter must pass the authorization check
	// before the SDK produces any key material. This prevents an
	// unauthorized caller from obtaining ECIES-wrapped keys or CFrags.
	//
	// GrantAuthOpen (the default, zero value) skips the check entirely.
	// Every pre-Phase-6 schema takes this path — no behavioral change.

	if schemaParams.GrantAuthorizationMode != types.GrantAuthOpen {
		check, checkErr := CheckGrantAuthorization(GrantAuthCheckParams{
			Mode:                 schemaParams.GrantAuthorizationMode,
			GranterDID:           params.GranterDID,
			RecipientDID:         params.RecipientDID,
			ScopePointer:         params.ScopePointer,
			AuthorizedRecipients: params.AuthorizedRecipients,
			Fetcher:              params.Fetcher,
			LeafReader:           params.LeafReader,
		})
		if checkErr != nil {
			return nil, fmt.Errorf("lifecycle/artifact: grant authorization check: %w", checkErr)
		}
		if !check.Authorized {
			return nil, fmt.Errorf("lifecycle/artifact: grant denied: %s", check.Reason)
		}
	}

	// ── Phase 2: Key material production ────────────────────────────

	result := &GrantResult{
		ContentDigest: params.ContentDigest,
	}

	switch schemaParams.ArtifactEncryption {
	case types.EncryptionAESGCM:
		if err := grantAESGCM(params, result); err != nil {
			return nil, err
		}
	case types.EncryptionUmbralPRE:
		if err := grantUmbralPRE(params, schemaParams, result); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("lifecycle/artifact: unknown encryption scheme %d", schemaParams.ArtifactEncryption)
	}

	// ── Phase 3: Retrieval credential + audit entry ─────────────────

	cred, err := params.RetrievalProvider.Resolve(params.ArtifactCID, params.RetrievalExpiry)
	if err != nil {
		return nil, fmt.Errorf("lifecycle/artifact: resolve retrieval: %w", err)
	}
	result.Retrieval = cred

	// Build audit entry when either flag requests it.
	// GrantEntryRequired:      "record that a grant happened" (any mode)
	// GrantRequiresAuditEntry: "record that an authorized grant happened"
	needsAudit := schemaParams.GrantEntryRequired || schemaParams.GrantRequiresAuditEntry
	if needsAudit && params.GranterDID != "" {
		grantEntry, buildErr := buildGrantEntry(params, result.Scheme)
		if buildErr != nil {
			return nil, fmt.Errorf("lifecycle/artifact: build grant entry: %w", buildErr)
		}
		result.GrantEntry = grantEntry
	}

	return result, nil
}

// grantAESGCM handles the AES-GCM grant path: ECIES key wrapping.
func grantAESGCM(params GrantParams, result *GrantResult) error {
	// Get AES key material from store (32-byte key + 12-byte nonce).
	keyMaterial, err := params.KeyStore.Get(params.ArtifactCID)
	if err != nil {
		return fmt.Errorf("lifecycle/artifact: key store get: %w", err)
	}
	if len(keyMaterial) != artifact.KeySize+artifact.NonceSize {
		return fmt.Errorf("lifecycle/artifact: invalid AES key material length %d, expected %d",
			len(keyMaterial), artifact.KeySize+artifact.NonceSize)
	}

	// Parse requester's public key for ECIES wrapping.
	recipientPub, err := signatures.ParsePubKey(params.RequesterPubKey)
	if err != nil {
		return fmt.Errorf("lifecycle/artifact: parse requester key: %w", err)
	}

	// ECIES-encrypt key material for the requester.
	// Reuses escrow.EncryptForNode — same ECIES primitive over secp256k1.
	// The recipient is an artifact requester, not an escrow node, but the
	// cryptographic operation is identical: ECDH → SHA-256 KDF → AES-256-GCM.
	encryptedKey, err := escrow.EncryptForNode(keyMaterial, recipientPub)
	if err != nil {
		return fmt.Errorf("lifecycle/artifact: wrap key: %w", err)
	}

	result.EncryptedKey = encryptedKey
	result.Scheme = types.EncryptionAESGCM
	return nil
}

// grantUmbralPRE handles the Umbral PRE grant path: KFrag generation + re-encryption.
func grantUmbralPRE(params GrantParams, schemaParams *types.SchemaParameters, result *GrantResult) error {
	if params.Capsule == nil {
		return fmt.Errorf("lifecycle/artifact: capsule required for PRE mode")
	}

	// Get owner private key from store.
	ownerSK, err := params.KeyStore.Get(params.ArtifactCID)
	if err != nil {
		return fmt.Errorf("lifecycle/artifact: key store get: %w", err)
	}

	// Determine M-of-N from schema's ReEncryptionThreshold.
	m, n := 3, 5 // Defaults matching escrow convention.
	if schemaParams.ReEncryptionThreshold != nil {
		m = schemaParams.ReEncryptionThreshold.M
		n = schemaParams.ReEncryptionThreshold.N
	}

	// Generate threshold re-encryption key fragments.
	kfrags, err := artifact.PRE_GenerateKFrags(ownerSK, params.RequesterPubKey, m, n)
	if err != nil {
		return fmt.Errorf("lifecycle/artifact: generate kfrags: %w", err)
	}

	// Re-encrypt with each KFrag to produce CFrags with DLEQ proofs.
	cfrags := make([]*artifact.CFrag, len(kfrags))
	for i, kf := range kfrags {
		cf, reErr := artifact.PRE_ReEncrypt(kf, params.Capsule)
		if reErr != nil {
			return fmt.Errorf("lifecycle/artifact: re-encrypt kfrag %d: %w", i, reErr)
		}
		cfrags[i] = cf
	}

	result.CFrags = cfrags
	result.Capsule = params.Capsule
	result.Scheme = types.EncryptionUmbralPRE
	return nil
}

// buildGrantEntry creates a commentary entry recording the grant.
// This is the audit trail — a permanent, immutable log entry showing
// who authorized access to what artifact for which recipient.
func buildGrantEntry(params GrantParams, scheme types.EncryptionScheme) (*envelope.Entry, error) {
	schemeName := "aes_gcm"
	if scheme == types.EncryptionUmbralPRE {
		schemeName = "umbral_pre"
	}
	payloadMap := map[string]any{
		"grant_type":     "artifact_access",
		"artifact_cid":   params.ArtifactCID.String(),
		"recipient_key":  fmt.Sprintf("%x", params.RequesterPubKey),
		"content_digest": fmt.Sprintf("%x", params.ContentDigest[:]),
		"scheme":         schemeName,
	}
	// Include RecipientDID in the audit entry when available.
	// For sealed-mode grants this is essential — it records which
	// authorized party received access.
	if params.RecipientDID != "" {
		payloadMap["recipient_did"] = params.RecipientDID
	}

	payload, err := json.Marshal(payloadMap)
	if err != nil {
		return nil, fmt.Errorf("marshal grant payload: %w", err)
	}
	return builder.BuildCommentary(builder.CommentaryParams{
		SignerDID: params.GranterDID,
		Payload:   payload,
	})
}

// ═════════════════════════════════════════════════════════════════════
// Content verification — VerifyAndDecrypt
// ═════════════════════════════════════════════════════════════════════

// ─────────────────────────────────────────────────────────────────────
// Decrypt types
// ─────────────────────────────────────────────────────────────────────

// DecryptParams configures artifact decryption and verification.
type DecryptParams struct {
	Ciphertext    []byte
	Scheme        types.EncryptionScheme

	// AES-GCM fields:
	Key []byte // AES key (32 bytes) + nonce (12 bytes) = 44 bytes.

	// Umbral PRE fields:
	CFrags       []*artifact.CFrag
	Capsule      *artifact.Capsule
	RecipientKey []byte // Recipient private key (32 bytes).
	OwnerPubKey  []byte // Owner public key (65 bytes).

	// ContentDigest is SHA-256(original plaintext). Used to verify
	// decrypted content matches the expected plaintext.
	ContentDigest [32]byte
}

// DecryptResult holds the output of VerifyAndDecrypt.
type DecryptResult struct {
	Plaintext      []byte
	DigestVerified bool
}

// ─────────────────────────────────────────────────────────────────────
// VerifyAndDecrypt
// ─────────────────────────────────────────────────────────────────────

// VerifyAndDecrypt decrypts artifact content and verifies the content
// digest. Dispatches on Scheme for decryption, then checks
// SHA-256(plaintext) against ContentDigest.
//
// The CID check (ciphertext integrity) is NOT performed here — the
// content store already verifies CID integrity on fetch. The content
// digest is the only integrity check the decryptor can exclusively
// perform, confirming the plaintext matches what was originally stored.
func VerifyAndDecrypt(params DecryptParams) (*DecryptResult, error) {
	var plaintext []byte
	var err error

	switch params.Scheme {
	case types.EncryptionAESGCM:
		plaintext, err = decryptAESGCM(params)
	case types.EncryptionUmbralPRE:
		plaintext, err = decryptUmbralPRE(params)
	default:
		return nil, fmt.Errorf("lifecycle/artifact: unknown scheme %d", params.Scheme)
	}
	if err != nil {
		return nil, fmt.Errorf("lifecycle/artifact: decrypt: %w", err)
	}

	// Verify content digest: SHA-256(plaintext) must match ContentDigest.
	digest := sha256.Sum256(plaintext)
	digestVerified := digest == params.ContentDigest

	return &DecryptResult{
		Plaintext:      plaintext,
		DigestVerified: digestVerified,
	}, nil
}

// decryptAESGCM handles AES-256-GCM decryption.
func decryptAESGCM(params DecryptParams) ([]byte, error) {
	if len(params.Key) != artifact.KeySize+artifact.NonceSize {
		return nil, fmt.Errorf("invalid AES key length %d, expected %d",
			len(params.Key), artifact.KeySize+artifact.NonceSize)
	}
	var artKey artifact.ArtifactKey
	copy(artKey.Key[:], params.Key[:artifact.KeySize])
	copy(artKey.Nonce[:], params.Key[artifact.KeySize:])
	return artifact.DecryptArtifact(params.Ciphertext, artKey)
}

// decryptUmbralPRE handles Umbral PRE threshold decryption.
func decryptUmbralPRE(params DecryptParams) ([]byte, error) {
	if params.Capsule == nil {
		return nil, fmt.Errorf("capsule required for PRE decryption")
	}
	if len(params.CFrags) == 0 {
		return nil, fmt.Errorf("cfrags required for PRE decryption")
	}
	if len(params.RecipientKey) == 0 {
		return nil, fmt.Errorf("recipient key required for PRE decryption")
	}
	if len(params.OwnerPubKey) == 0 {
		return nil, fmt.Errorf("owner public key required for PRE decryption")
	}
	return artifact.PRE_DecryptFrags(
		params.RecipientKey, params.CFrags, params.Capsule,
		params.Ciphertext, params.OwnerPubKey,
	)
}
