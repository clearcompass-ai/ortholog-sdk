/*
Package lifecycle — artifact_access.go provides schema-aware artifact
access control: the dispatcher that routes between AES-GCM (exchange-mediated)
and Umbral PRE (threshold, exchange-never-sees-plaintext) paths.

Defines the ArtifactKeyStore interface — implemented by the exchange's
key management system, NOT by the operator or artifact store. The three-service
separation holds: operator has no keys, artifact store has no keys, exchange
has keys.

Two exported functions:

GrantArtifactAccess: produces a GrantResult containing a retrieval credential
  (signed URL or IPFS gateway URL) plus either an ECIES-wrapped AES key
  (AES-GCM path) or CFrags + Capsule (PRE path). The judicial network's
  cases/artifact/retrieve.go calls this.

VerifyAndDecryptArtifact: naming clarification #3. This is the schema-aware
  dispatcher that routes to either Phase 1's VerifyAndDecrypt (AES-GCM) or
  the PRE reassembly path (PRE_DecryptFrags). Distinguished from Phase 1's
  VerifyAndDecrypt by the "Artifact" suffix and schema awareness.

Consumed by:
  - judicial-network/cases/artifact/retrieve.go → GrantArtifactAccess
  - judicial-network/cases/artifact/expunge.go → ArtifactKeyStore.Delete
  - judicial-network/cases/artifact/reencrypt.go → ReEncryptWithGrant
  - judicial-network/enforcement/evidence_access.go → GrantArtifactAccess (PRE path)
*/
package lifecycle

import (
	"fmt"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/builder"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/artifact"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/escrow"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// ArtifactKeyStore — exchange-side key management interface
// ─────────────────────────────────────────────────────────────────────

// ArtifactKeyStore manages per-artifact encryption keys. The exchange
// implements this — NOT the operator, NOT the artifact store.
//
// For AES-GCM schemas: stores the ArtifactKey (key + nonce).
// For Umbral PRE schemas: stores KFrag metadata and capsule references.
//
// The key store is the exchange's most sensitive component. HSM-backed
// in production. In-memory for SDK tests.
type ArtifactKeyStore interface {
	// Get retrieves the artifact key for a CID.
	// Returns nil, nil if the key does not exist (cryptographic erasure completed).
	Get(cid storage.CID) (*artifact.ArtifactKey, error)

	// Store saves an artifact key for a CID.
	Store(cid storage.CID, key artifact.ArtifactKey) error

	// Delete removes an artifact key (cryptographic erasure).
	// After deletion, the ciphertext is computationally irrecoverable
	// regardless of whether it remains on CAS.
	Delete(cid storage.CID) error
}

// ─────────────────────────────────────────────────────────────────────
// In-memory ArtifactKeyStore (SDK testing only)
// ─────────────────────────────────────────────────────────────────────

// InMemoryKeyStore is a reference ArtifactKeyStore for testing.
type InMemoryKeyStore struct {
	keys map[string]*artifact.ArtifactKey
}

// NewInMemoryKeyStore creates a test key store.
func NewInMemoryKeyStore() *InMemoryKeyStore {
	return &InMemoryKeyStore{keys: make(map[string]*artifact.ArtifactKey)}
}

func (s *InMemoryKeyStore) Get(cid storage.CID) (*artifact.ArtifactKey, error) {
	k, ok := s.keys[cid.String()]
	if !ok {
		return nil, nil
	}
	cp := *k
	return &cp, nil
}

func (s *InMemoryKeyStore) Store(cid storage.CID, key artifact.ArtifactKey) error {
	s.keys[cid.String()] = &key
	return nil
}

func (s *InMemoryKeyStore) Delete(cid storage.CID) error {
	delete(s.keys, cid.String())
	return nil
}

// ─────────────────────────────────────────────────────────────────────
// Grant types
// ─────────────────────────────────────────────────────────────────────

// GrantResult holds everything the recipient needs to fetch and decrypt
// an artifact. The exchange delivers this to the recipient.
type GrantResult struct {
	// Credential is the retrieval path (signed URL, IPFS gateway, or direct).
	Credential *storage.RetrievalCredential

	// Method is "aes_gcm" or "umbral_pre".
	Method string

	// ── AES-GCM path ────────────────────────────────────────────────
	// WrappedKey is the ECIES-wrapped AES key for the recipient.
	// The recipient unwraps with their private key, then decrypts.
	WrappedKey []byte

	// ── Umbral PRE path ─────────────────────────────────────────────
	// CFrags are the re-encrypted ciphertext fragments (M of N needed).
	CFrags []*artifact.CFrag
	// Capsule is the original encryption capsule from PRE_Encrypt.
	Capsule *artifact.Capsule

	// ── Common ───────────────────────────────────────────────────────
	// ContentDigest is the multihash of the plaintext (for step 3 verification).
	ContentDigest storage.CID
	// ArtifactCID is the multihash of the ciphertext (for step 1 verification).
	ArtifactCID storage.CID

	// GrantEntry is a commentary entry recording the grant on the log.
	// Non-nil only when SchemaParams.GrantEntryRequired is true.
	// The caller submits this to the operator.
	GrantEntry *envelope.Entry
}

// GrantArtifactAccessParams configures an artifact access grant.
type GrantArtifactAccessParams struct {
	// ArtifactCID is the content address of the encrypted artifact.
	ArtifactCID storage.CID

	// ContentDigest is the multihash of the plaintext.
	ContentDigest storage.CID

	// RecipientPubKey is the recipient's secp256k1 public key (65 bytes uncompressed).
	RecipientPubKey []byte

	// ── AES-GCM path dependencies ──────────────────────────────────
	// KeyStore retrieves the artifact key. Required for AES-GCM.
	KeyStore ArtifactKeyStore

	// ── PRE path dependencies ──────────────────────────────────────
	// OwnerSK is the owner's private key (32 bytes). Required for PRE.
	OwnerSK []byte
	// OwnerPK is the owner's public key (65 bytes). Required for PRE.
	OwnerPK []byte
	// Capsule is the original capsule from PRE_Encrypt. Required for PRE.
	Capsule *artifact.Capsule

	// ── Common dependencies ────────────────────────────────────────
	// RetrievalProvider generates retrieval credentials (signed URLs).
	RetrievalProvider storage.RetrievalProvider

	// RetrievalExpiry is the TTL for the retrieval credential.
	// Default: 1 hour.
	RetrievalExpiry time.Duration

	// SchemaParams determines the encryption scheme and grant requirements.
	SchemaParams *types.SchemaParameters

	// ── Grant entry (optional) ──────────────────────────────────────
	// GranterDID is the signer for the grant commentary entry.
	// Only used when SchemaParams.GrantEntryRequired is true.
	GranterDID string

	// RecipientDID is recorded in the grant entry's Domain Payload.
	RecipientDID string
}

// ─────────────────────────────────────────────────────────────────────
// GrantArtifactAccess
// ─────────────────────────────────────────────────────────────────────

// GrantArtifactAccess produces a GrantResult by dispatching on the schema's
// ArtifactEncryption field. This is the central artifact access function
// consumed by every judicial network artifact retrieval path.
//
// AES-GCM path:
//  1. Get artifact key from KeyStore
//  2. Wrap key for recipient via ECIES (escrow.EncryptForNode)
//  3. Get retrieval credential from RetrievalProvider
//  4. Return GrantResult with wrapped key + credential
//
// Umbral PRE path:
//  1. Generate KFrags for recipient (PRE_GenerateKFrags)
//  2. Re-encrypt capsule with each KFrag (PRE_ReEncrypt)
//  3. Verify each CFrag (PRE_VerifyCFrag)
//  4. Get retrieval credential from RetrievalProvider
//  5. Return GrantResult with CFrags + capsule + credential
//
// If SchemaParams.GrantEntryRequired, a commentary entry is built via
// BuildCommentary and included in the result for the caller to submit.
func GrantArtifactAccess(p GrantArtifactAccessParams) (*GrantResult, error) {
	if p.SchemaParams == nil {
		return nil, fmt.Errorf("lifecycle/artifact: nil schema params")
	}
	if p.RetrievalProvider == nil {
		return nil, fmt.Errorf("lifecycle/artifact: nil retrieval provider")
	}

	expiry := p.RetrievalExpiry
	if expiry <= 0 {
		expiry = 1 * time.Hour
	}

	// Get retrieval credential.
	cred, err := p.RetrievalProvider.Resolve(p.ArtifactCID, expiry)
	if err != nil {
		return nil, fmt.Errorf("lifecycle/artifact: resolve retrieval: %w", err)
	}

	result := &GrantResult{
		Credential:    cred,
		ContentDigest: p.ContentDigest,
		ArtifactCID:   p.ArtifactCID,
	}

	switch p.SchemaParams.ArtifactEncryption {
	case types.EncryptionAESGCM:
		if err := grantAESGCM(p, result); err != nil {
			return nil, err
		}
	case types.EncryptionUmbralPRE:
		if err := grantPRE(p, result); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("lifecycle/artifact: unknown encryption scheme %d", p.SchemaParams.ArtifactEncryption)
	}

	// Build grant commentary entry if required.
	if p.SchemaParams.GrantEntryRequired && p.GranterDID != "" {
		grantEntry, err := buildGrantEntry(p, result.Method)
		if err != nil {
			return nil, fmt.Errorf("lifecycle/artifact: build grant entry: %w", err)
		}
		result.GrantEntry = grantEntry
	}

	return result, nil
}

func grantAESGCM(p GrantArtifactAccessParams, result *GrantResult) error {
	if p.KeyStore == nil {
		return fmt.Errorf("lifecycle/artifact: nil key store for AES-GCM grant")
	}
	if len(p.RecipientPubKey) == 0 {
		return fmt.Errorf("lifecycle/artifact: empty recipient public key")
	}

	// 1. Get artifact key.
	artKey, err := p.KeyStore.Get(p.ArtifactCID)
	if err != nil {
		return fmt.Errorf("lifecycle/artifact: get key: %w", err)
	}
	if artKey == nil {
		return fmt.Errorf("lifecycle/artifact: key not found for %s (cryptographic erasure?)", p.ArtifactCID)
	}

	// 2. Serialize key material and wrap for recipient via ECIES.
	keyMaterial := make([]byte, artifact.KeySize+artifact.NonceSize)
	copy(keyMaterial[:artifact.KeySize], artKey.Key[:])
	copy(keyMaterial[artifact.KeySize:], artKey.Nonce[:])

	// Parse recipient pubkey for ECIES encryption.
	recipientPK, err := parseRecipientPubKey(p.RecipientPubKey)
	if err != nil {
		return fmt.Errorf("lifecycle/artifact: parse recipient key: %w", err)
	}

	wrapped, err := escrow.EncryptForNode(keyMaterial, recipientPK)
	if err != nil {
		return fmt.Errorf("lifecycle/artifact: ECIES wrap: %w", err)
	}

	// Zero key material after wrapping.
	for i := range keyMaterial {
		keyMaterial[i] = 0
	}

	result.Method = "aes_gcm"
	result.WrappedKey = wrapped
	return nil
}

func grantPRE(p GrantArtifactAccessParams, result *GrantResult) error {
	if len(p.OwnerSK) == 0 || len(p.RecipientPubKey) == 0 {
		return fmt.Errorf("lifecycle/artifact: owner SK and recipient PK required for PRE grant")
	}
	if p.Capsule == nil {
		return fmt.Errorf("lifecycle/artifact: capsule required for PRE grant")
	}

	// Determine M-of-N from schema or defaults.
	M, N := 3, 5
	if p.SchemaParams.ReEncryptionThreshold != nil {
		M = p.SchemaParams.ReEncryptionThreshold.M
		N = p.SchemaParams.ReEncryptionThreshold.N
	}

	// 1. Generate KFrags.
	kfrags, err := artifact.PRE_GenerateKFrags(p.OwnerSK, p.RecipientPubKey, M, N)
	if err != nil {
		return fmt.Errorf("lifecycle/artifact: generate KFrags: %w", err)
	}

	// 2. Re-encrypt with each KFrag → produce CFrags.
	cfrags := make([]*artifact.CFrag, len(kfrags))
	for i, kf := range kfrags {
		cf, err := artifact.PRE_ReEncrypt(kf, p.Capsule)
		if err != nil {
			return fmt.Errorf("lifecycle/artifact: re-encrypt KFrag %d: %w", i, err)
		}

		// 3. Verify each CFrag (monitoring can also verify independently).
		if err := artifact.PRE_VerifyCFrag(cf, p.Capsule, kf.VKX, kf.VKY); err != nil {
			return fmt.Errorf("lifecycle/artifact: verify CFrag %d: %w", i, err)
		}

		cfrags[i] = cf
	}

	result.Method = "umbral_pre"
	result.CFrags = cfrags
	result.Capsule = p.Capsule
	return nil
}

func buildGrantEntry(p GrantArtifactAccessParams, method string) (*envelope.Entry, error) {
	return builder.BuildCommentary(builder.CommentaryParams{
		SignerDID: p.GranterDID,
		Payload: mustMarshalJSON(map[string]any{
			"grant_type":     "artifact_access",
			"artifact_cid":  p.ArtifactCID.String(),
			"recipient_did": p.RecipientDID,
			"method":        method,
		}),
		EventTime: time.Now().UTC().UnixMicro(),
	})
}

// ─────────────────────────────────────────────────────────────────────
// VerifyAndDecryptArtifact — naming clarification #3
// ─────────────────────────────────────────────────────────────────────

// VerifyAndDecryptArtifactParams configures schema-aware artifact decryption.
type VerifyAndDecryptArtifactParams struct {
	// Ciphertext is the encrypted artifact bytes fetched from CAS.
	Ciphertext []byte

	// ArtifactCID is the content address (step 1: storage integrity).
	ArtifactCID storage.CID

	// ContentDigest is the plaintext hash (step 3: content integrity).
	ContentDigest storage.CID

	// SchemaParams determines the decryption path.
	SchemaParams *types.SchemaParameters

	// ── AES-GCM path ────────────────────────────────────────────────
	// Key is the decrypted AES artifact key. Required for AES-GCM.
	Key *artifact.ArtifactKey

	// ── PRE path ────────────────────────────────────────────────────
	// RecipientSK is the recipient's private key (32 bytes). Required for PRE.
	RecipientSK []byte
	// CFrags are the re-encrypted ciphertext fragments. Required for PRE.
	CFrags []*artifact.CFrag
	// Capsule is the original encryption capsule. Required for PRE.
	Capsule *artifact.Capsule
	// OwnerPK is the owner's public key (65 bytes). Required for PRE.
	OwnerPK []byte
}

// VerifyAndDecryptArtifact is the schema-aware dispatcher for artifact
// decryption. Routes to Phase 1's VerifyAndDecrypt (AES-GCM) or the
// PRE reassembly path (PRE_DecryptFrags) based on SchemaParams.
//
// Distinguished from Phase 1's VerifyAndDecrypt by:
//   - Schema awareness (reads ArtifactEncryption from SchemaParams)
//   - PRE support (combines CFrags before decryption)
//   - Same three-step verification in both paths:
//     Step 1: artifactCID.Verify(ciphertext) — storage integrity
//     Step 2: decrypt → produces plaintext
//     Step 3: contentDigest.Verify(plaintext) — content integrity
//
// Returns plaintext on success. Returns IrrecoverableError on any mismatch.
func VerifyAndDecryptArtifact(p VerifyAndDecryptArtifactParams) ([]byte, error) {
	if p.SchemaParams == nil {
		return nil, fmt.Errorf("lifecycle/artifact: nil schema params")
	}

	switch p.SchemaParams.ArtifactEncryption {
	case types.EncryptionAESGCM:
		return decryptAESGCM(p)
	case types.EncryptionUmbralPRE:
		return decryptPRE(p)
	default:
		return nil, fmt.Errorf("lifecycle/artifact: unknown encryption scheme %d", p.SchemaParams.ArtifactEncryption)
	}
}

func decryptAESGCM(p VerifyAndDecryptArtifactParams) ([]byte, error) {
	if p.Key == nil {
		return nil, &artifact.IrrecoverableError{Cause: fmt.Errorf("nil AES key")}
	}
	// Delegates to Phase 1's three-step VerifyAndDecrypt.
	return artifact.VerifyAndDecrypt(p.Ciphertext, *p.Key, p.ArtifactCID, p.ContentDigest)
}

func decryptPRE(p VerifyAndDecryptArtifactParams) ([]byte, error) {
	if len(p.RecipientSK) == 0 || len(p.CFrags) == 0 || p.Capsule == nil || len(p.OwnerPK) == 0 {
		return nil, &artifact.IrrecoverableError{Cause: fmt.Errorf("PRE decryption requires RecipientSK, CFrags, Capsule, and OwnerPK")}
	}

	// Step 1: storage integrity — verify ciphertext matches CID.
	if !p.ArtifactCID.IsZero() && !p.ArtifactCID.Verify(p.Ciphertext) {
		return nil, &artifact.IrrecoverableError{
			Cause: fmt.Errorf("storage integrity failure: ciphertext does not match artifact CID %s", p.ArtifactCID),
		}
	}

	// Step 2: PRE decrypt — combine CFrags and decrypt with recipient SK.
	plaintext, err := artifact.PRE_DecryptFrags(p.RecipientSK, p.CFrags, p.Capsule, p.Ciphertext, p.OwnerPK)
	if err != nil {
		return nil, &artifact.IrrecoverableError{Cause: fmt.Errorf("PRE decryption failed: %w", err)}
	}

	// Step 3: content integrity — verify plaintext matches content digest.
	if !p.ContentDigest.IsZero() {
		if !p.ContentDigest.Verify(plaintext) {
			for i := range plaintext {
				plaintext[i] = 0
			}
			return nil, &artifact.IrrecoverableError{
				Cause: fmt.Errorf("content integrity failure: plaintext does not match content digest %s", p.ContentDigest),
			}
		}
	}

	return plaintext, nil
}

// ─────────────────────────────────────────────────────────────────────
// ReEncryptWithGrant — re-encrypt under new key with optional grant
// ─────────────────────────────────────────────────────────────────────

// ReEncryptWithGrantParams configures artifact re-encryption.
type ReEncryptWithGrantParams struct {
	// OldCID is the current artifact CID.
	OldCID storage.CID

	// KeyStore manages artifact keys. OldCID's key is read, new key is stored.
	KeyStore ArtifactKeyStore

	// ContentStore pushes the new ciphertext and optionally deletes the old.
	ContentStore storage.ContentStore

	// DeleteOldCiphertext controls whether the old ciphertext is deleted
	// from CAS after re-encryption (cryptographic erasure cleanup).
	DeleteOldCiphertext bool
}

// ReEncryptResult holds the outcome of re-encryption.
type ReEncryptResult struct {
	// NewCID is the content address of the new ciphertext.
	NewCID storage.CID

	// NewKey is the new artifact key (caller may need for grant operations).
	NewKey artifact.ArtifactKey

	// ContentDigest is unchanged — plaintext identity survives re-encryption.
	ContentDigest storage.CID
}

// ReEncryptWithGrant re-encrypts an artifact under a new key and pushes
// the result to ContentStore. Used by Tier 1 key rotation and
// cases/artifact/reencrypt.go.
//
// The invariant: content_digest (hash of plaintext) is unchanged because
// re-encryption does not modify the plaintext. artifact_cid changes because
// the ciphertext is different.
func ReEncryptWithGrant(p ReEncryptWithGrantParams) (*ReEncryptResult, error) {
	// 1. Get old key.
	oldKey, err := p.KeyStore.Get(p.OldCID)
	if err != nil {
		return nil, fmt.Errorf("lifecycle/artifact: get old key: %w", err)
	}
	if oldKey == nil {
		return nil, fmt.Errorf("lifecycle/artifact: old key not found for %s", p.OldCID)
	}

	// 2. Fetch old ciphertext.
	oldCT, err := p.ContentStore.Fetch(p.OldCID)
	if err != nil {
		return nil, fmt.Errorf("lifecycle/artifact: fetch old ciphertext: %w", err)
	}

	// 3. Re-encrypt (decrypt old → encrypt new).
	newCT, newKey, err := artifact.ReEncryptArtifact(oldCT, *oldKey)
	if err != nil {
		return nil, fmt.Errorf("lifecycle/artifact: re-encrypt: %w", err)
	}

	// 4. Compute new CID and push.
	newCID := storage.Compute(newCT)
	if err := p.ContentStore.Push(newCID, newCT); err != nil {
		return nil, fmt.Errorf("lifecycle/artifact: push new ciphertext: %w", err)
	}

	// 5. Store new key.
	if err := p.KeyStore.Store(newCID, newKey); err != nil {
		return nil, fmt.Errorf("lifecycle/artifact: store new key: %w", err)
	}

	// 6. Optionally delete old ciphertext.
	if p.DeleteOldCiphertext {
		_ = p.ContentStore.Delete(p.OldCID) // Best-effort (IPFS returns ErrNotSupported).
	}

	// 7. Delete old key (cryptographic erasure of old access path).
	_ = p.KeyStore.Delete(p.OldCID)

	return &ReEncryptResult{
		NewCID: newCID,
		NewKey: newKey,
	}, nil
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

func parseRecipientPubKey(pubKeyBytes []byte) (*ecdsaPubKey, error) {
	pk, err := parseSecp256k1PubKey(pubKeyBytes)
	if err != nil {
		return nil, err
	}
	return pk, nil
}
