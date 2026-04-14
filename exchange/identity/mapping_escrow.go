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
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────

// ErrMappingNotFound is returned when no mapping exists for an identity.
var ErrMappingNotFound = errors.New("identity/escrow: mapping not found")

// ErrInvalidIdentity is returned when the identity hash is zero/empty.
var ErrInvalidIdentity = errors.New("identity/escrow: invalid identity hash")

// ErrInvalidCredentialRef is returned when a credential reference is empty.
var ErrInvalidCredentialRef = errors.New("identity/escrow: invalid credential reference")

// ErrShareAssemblyFailed is returned when key shares cannot be reassembled.
var ErrShareAssemblyFailed = errors.New("identity/escrow: share assembly failed")

// ─────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────

// CredentialRef identifies a credential entry in a log.
type CredentialRef struct {
	LogDID   string `json:"log_did"`
	Sequence uint64 `json:"sequence"`
	EntryHash [32]byte `json:"entry_hash"`
}

// MappingRecord is the plaintext mapping stored (encrypted) in the content store.
type MappingRecord struct {
	IdentityHash  [32]byte       `json:"identity_hash"`
	CredentialRef CredentialRef  `json:"credential_ref"`
	SchemaID      string         `json:"schema_id,omitempty"`
	CreatedAt     int64          `json:"created_at"` // Unix timestamp.
}

// StoredMapping holds the metadata for a stored encrypted mapping.
type StoredMapping struct {
	CID         storage.CID
	EscrowPkg   types.EscrowPackage
	IdentityTag [32]byte // SHA-256(identity_hash) for index lookup without decryption.
}

// ─────────────────────────────────────────────────────────────────────
// MappingEscrow
// ─────────────────────────────────────────────────────────────────────

// MappingEscrowConfig configures the escrow.
type MappingEscrowConfig struct {
	// ShareThreshold is the K in K-of-N secret sharing.
	ShareThreshold int

	// TotalShares is the N in K-of-N secret sharing.
	TotalShares int
}

// DefaultMappingEscrowConfig returns production defaults.
func DefaultMappingEscrowConfig() MappingEscrowConfig {
	return MappingEscrowConfig{
		ShareThreshold: 3,
		TotalShares:    5,
	}
}

// MappingEscrow manages encrypted identity ↔ credential mappings.
type MappingEscrow struct {
	store  storage.ContentStore
	cfg    MappingEscrowConfig

	// In-memory index: identity tag → stored mapping metadata.
	// Production deployments would use a database index.
	mu    sync.RWMutex
	index map[[32]byte]*StoredMapping
}

// NewMappingEscrow creates an escrow with the given content store.
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
// StoreMapping — encrypt and store an identity ↔ credential mapping
// ─────────────────────────────────────────────────────────────────────

// StoreMapping encrypts a mapping record and stores it in the content store.
//
// Steps:
//  1. Serialize mapping to JSON
//  2. Encrypt with artifact.EncryptArtifact → ciphertext + key
//  3. Split key with escrow.SplitGF256 → K-of-N shares
//  4. Push ciphertext to ContentStore
//  5. Return StoredMapping with CID + escrow package
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

	// 2. Encrypt.
	encrypted, err := artifact.EncryptArtifact(plaintext)
	if err != nil {
		return nil, fmt.Errorf("identity/escrow: encrypt: %w", err)
	}

	// 3. Split key into shares.
	shares, err := escrow.SplitGF256(
		encrypted.Key,
		me.cfg.ShareThreshold,
		me.cfg.TotalShares,
	)
	if err != nil {
		return nil, fmt.Errorf("identity/escrow: split key: %w", err)
	}

	// 4. Push ciphertext to content store.
	cid := storage.Compute(encrypted.Ciphertext)
	if err := me.store.Push(cid, encrypted.Ciphertext); err != nil {
		return nil, fmt.Errorf("identity/escrow: push: %w", err)
	}

	// 5. Build escrow package.
	escrowPkg := types.EscrowPackage{
		CID:    cid,
		Shares: shares,
		K:      me.cfg.ShareThreshold,
		N:      me.cfg.TotalShares,
	}

	// Identity tag for index lookup (double-hash for privacy).
	identityTag := sha256.Sum256(record.IdentityHash[:])

	stored := &StoredMapping{
		CID:         cid,
		EscrowPkg:   escrowPkg,
		IdentityTag: identityTag,
	}

	// Store in index.
	me.mu.Lock()
	me.index[identityTag] = stored
	me.mu.Unlock()

	return stored, nil
}

// ─────────────────────────────────────────────────────────────────────
// LookupMapping — retrieve and decrypt a mapping
// ─────────────────────────────────────────────────────────────────────

// LookupMapping retrieves an encrypted mapping by identity hash and
// decrypts it using the provided key shares.
//
// The caller must provide at least K shares (from the escrow package)
// to reconstruct the decryption key.
func (me *MappingEscrow) LookupMapping(
	identityHash [32]byte,
	keyShares [][]byte,
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

	// Fetch ciphertext from content store.
	ciphertext, err := me.store.Fetch(stored.CID)
	if err != nil {
		return nil, fmt.Errorf("identity/escrow: fetch: %w", err)
	}

	// Reassemble key from shares.
	key, err := escrow.CombineGF256(keyShares, me.cfg.ShareThreshold)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrShareAssemblyFailed, err)
	}

	// Decrypt.
	plaintext, err := artifact.DecryptArtifact(ciphertext, key)
	if err != nil {
		return nil, fmt.Errorf("identity/escrow: decrypt: %w", err)
	}

	// Deserialize.
	var record MappingRecord
	if err := json.Unmarshal(plaintext, &record); err != nil {
		return nil, fmt.Errorf("identity/escrow: unmarshal: %w", err)
	}

	return &record, nil
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

// HasMapping checks if a mapping exists for the given identity hash
// without decrypting it.
func (me *MappingEscrow) HasMapping(identityHash [32]byte) bool {
	identityTag := sha256.Sum256(identityHash[:])
	me.mu.RLock()
	_, ok := me.index[identityTag]
	me.mu.RUnlock()
	return ok
}

// MappingCount returns the number of stored mappings.
func (me *MappingEscrow) MappingCount() int {
	me.mu.RLock()
	defer me.mu.RUnlock()
	return len(me.index)
}

// DeleteMapping removes a mapping from the index. Does not delete from
// the content store (ciphertext is content-addressed and may be referenced
// by other entries).
func (me *MappingEscrow) DeleteMapping(identityHash [32]byte) bool {
	identityTag := sha256.Sum256(identityHash[:])
	me.mu.Lock()
	_, ok := me.index[identityTag]
	delete(me.index, identityTag)
	me.mu.Unlock()
	return ok
}
