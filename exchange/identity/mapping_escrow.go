/*
Package identity provides identity ↔ credential mapping with escrow
protection for the Ortholog exchange protocol.

mapping_escrow.go implements MappingEscrow:
  - Stores encrypted mapping: identity hash → credential reference
  - Encrypts mappings using artifact encryption (PRE-compatible)
  - Splits encryption keys using GF(256) secret sharing
  - Pushes encrypted mapping blobs to ContentStore
  - Lookups require re-assembly of key shares (escrow release)

Composes SDK primitives + injected ContentStore:
  - crypto/artifact.EncryptArtifact — encrypts the mapping blob
  - crypto/escrow.SplitGF256 — splits encryption key into shares
  - storage.ContentStore — stores encrypted blobs
  - storage.Compute — derives CID from blob bytes

Consumed by:
  - Phase 6 exchange orchestrator
  - Judicial network identity verification flows
*/
package identity

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/artifact"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/escrow"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
)

// ─────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────

var ErrMappingNotFound = errors.New("identity/escrow: mapping not found")
var ErrInvalidIdentity = errors.New("identity/escrow: invalid identity hash")
var ErrInvalidCredentialRef = errors.New("identity/escrow: invalid credential reference")
var ErrShareAssemblyFailed = errors.New("identity/escrow: share assembly failed")

// ─────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────

// CredentialRef identifies a credential entry in a log.
type CredentialRef struct {
	LogDID    string   `json:"log_did"`
	Sequence  uint64   `json:"sequence"`
	EntryHash [32]byte `json:"entry_hash"`
}

// MappingRecord is the plaintext mapping stored (encrypted) in the content store.
type MappingRecord struct {
	IdentityHash  [32]byte      `json:"identity_hash"`
	CredentialRef CredentialRef `json:"credential_ref"`
	SchemaID      string        `json:"schema_id,omitempty"`
	CreatedAt     int64         `json:"created_at"`
}

// StoredMapping holds the metadata for a stored encrypted mapping.
type StoredMapping struct {
	CID         storage.CID
	ArtifactKey artifact.ArtifactKey
	Shares      []escrow.Share
	K           int
	N           int
	IdentityTag [32]byte // SHA-256(identity_hash) for index lookup without decryption.
}

// ─────────────────────────────────────────────────────────────────────
// MappingEscrow
// ─────────────────────────────────────────────────────────────────────

type MappingEscrowConfig struct {
	ShareThreshold int
	TotalShares    int
}

func DefaultMappingEscrowConfig() MappingEscrowConfig {
	return MappingEscrowConfig{ShareThreshold: 3, TotalShares: 5}
}

type MappingEscrow struct {
	store storage.ContentStore
	cfg   MappingEscrowConfig
	mu    sync.RWMutex
	index map[[32]byte]*StoredMapping
}

func NewMappingEscrow(store storage.ContentStore, cfg MappingEscrowConfig) *MappingEscrow {
	if cfg.ShareThreshold <= 0 {
		cfg.ShareThreshold = 3
	}
	if cfg.TotalShares <= 0 || cfg.TotalShares < cfg.ShareThreshold {
		cfg.TotalShares = cfg.ShareThreshold + 2
	}
	return &MappingEscrow{
		store: store,
		cfg:   cfg,
		index: make(map[[32]byte]*StoredMapping),
	}
}

// ─────────────────────────────────────────────────────────────────────
// StoreMapping
// ─────────────────────────────────────────────────────────────────────

func (me *MappingEscrow) StoreMapping(record MappingRecord) (*StoredMapping, error) {
	if record.IdentityHash == [32]byte{} {
		return nil, ErrInvalidIdentity
	}
	if record.CredentialRef.LogDID == "" {
		return nil, ErrInvalidCredentialRef
	}

	// 1. Serialize.
	plaintext, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("identity/escrow: marshal: %w", err)
	}

	// 2. Encrypt. EncryptArtifact returns (ciphertext, ArtifactKey, error).
	ciphertext, artKey, err := artifact.EncryptArtifact(plaintext)
	if err != nil {
		return nil, fmt.Errorf("identity/escrow: encrypt: %w", err)
	}

	// 3. Split the ArtifactKey into Shamir shares.
	// Serialize Key (32 bytes) + Nonce (12 bytes) = 44 bytes as the secret.
	keyMaterial := make([]byte, artifact.KeySize+artifact.NonceSize)
	copy(keyMaterial[:artifact.KeySize], artKey.Key[:])
	copy(keyMaterial[artifact.KeySize:], artKey.Nonce[:])

	shares, err := escrow.SplitGF256(keyMaterial, me.cfg.ShareThreshold, me.cfg.TotalShares)
	if err != nil {
		return nil, fmt.Errorf("identity/escrow: split key: %w", err)
	}

	// 4. Push ciphertext to content store.
	cid := storage.Compute(ciphertext)
	if err := me.store.Push(cid, ciphertext); err != nil {
		return nil, fmt.Errorf("identity/escrow: push: %w", err)
	}

	// 5. Build stored mapping.
	identityTag := sha256.Sum256(record.IdentityHash[:])

	stored := &StoredMapping{
		CID:         cid,
		ArtifactKey: artKey,
		Shares:      shares,
		K:           me.cfg.ShareThreshold,
		N:           me.cfg.TotalShares,
		IdentityTag: identityTag,
	}

	me.mu.Lock()
	me.index[identityTag] = stored
	me.mu.Unlock()

	return stored, nil
}

// ─────────────────────────────────────────────────────────────────────
// LookupMapping
// ─────────────────────────────────────────────────────────────────────

func (me *MappingEscrow) LookupMapping(
	identityHash [32]byte,
	keyShares []escrow.Share,
) (*MappingRecord, error) {
	if identityHash == [32]byte{} {
		return nil, ErrInvalidIdentity
	}

	identityTag := sha256.Sum256(identityHash[:])

	me.mu.RLock()
	stored, ok := me.index[identityTag]
	me.mu.RUnlock()

	if !ok {
		return nil, ErrMappingNotFound
	}

	// Fetch ciphertext.
	ciphertext, err := me.store.Fetch(stored.CID)
	if err != nil {
		return nil, fmt.Errorf("identity/escrow: fetch: %w", err)
	}

	// Reassemble key from shares.
	keyMaterial, err := escrow.ReconstructGF256(keyShares)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrShareAssemblyFailed, err)
	}

	// Deserialize ArtifactKey from reconstructed material.
	if len(keyMaterial) != artifact.KeySize+artifact.NonceSize {
		return nil, fmt.Errorf("identity/escrow: reconstructed key wrong length: %d", len(keyMaterial))
	}
	var artKey artifact.ArtifactKey
	copy(artKey.Key[:], keyMaterial[:artifact.KeySize])
	copy(artKey.Nonce[:], keyMaterial[artifact.KeySize:])

	// Decrypt.
	plaintext, err := artifact.DecryptArtifact(ciphertext, artKey)
	if err != nil {
		return nil, fmt.Errorf("identity/escrow: decrypt: %w", err)
	}

	var record MappingRecord
	if err := json.Unmarshal(plaintext, &record); err != nil {
		return nil, fmt.Errorf("identity/escrow: unmarshal: %w", err)
	}

	return &record, nil
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

func (me *MappingEscrow) HasMapping(identityHash [32]byte) bool {
	identityTag := sha256.Sum256(identityHash[:])
	me.mu.RLock()
	_, ok := me.index[identityTag]
	me.mu.RUnlock()
	return ok
}

func (me *MappingEscrow) MappingCount() int {
	me.mu.RLock()
	defer me.mu.RUnlock()
	return len(me.index)
}

func (me *MappingEscrow) DeleteMapping(identityHash [32]byte) bool {
	identityTag := sha256.Sum256(identityHash[:])
	me.mu.Lock()
	_, ok := me.index[identityTag]
	delete(me.index, identityTag)
	me.mu.Unlock()
	return ok
}
