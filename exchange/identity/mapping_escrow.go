/*
Package identity provides identity ↔ credential mapping with escrow
protection for the Ortholog exchange protocol.

mapping_escrow.go implements MappingEscrow:
  - Stores encrypted mapping: identity hash → credential reference.
  - Encrypts mappings using artifact encryption (AES-256-GCM).
  - Splits the 32-byte encryption key using GF(256) secret sharing
    (crypto/escrow V1).
  - ECIES-wraps each share for a specific escrow node's public key.
    Plaintext shares never leave StoreMapping.
  - Pushes encrypted mapping blobs to ContentStore.
  - Lookups require the caller to present at least M plaintext shares
    from the split (supplied by the recovery orchestrator, which
    coordinates node-side decryption).

Security model:

	After StoreMapping returns:
	  - The plaintext ArtifactKey has been zeroized.
	  - The plaintext shares have been zeroized.
	  - MappingEscrow's in-memory state contains NO key material and NO
	    plaintext share material.
	  - The caller receives only ECIES ciphertexts (one per node). These
	    ciphertexts are safe to transmit or persist; the plaintext share
	    inside each ciphertext is recoverable only by the target node
	    using its secp256k1 private key.

	The AES-GCM nonce is NOT a secret and is stored in plaintext on the
	StoredMapping. Escrowing the nonce would waste share space without
	security benefit.

	Distribution failure semantics:
	  If ECIES encryption fails for any node, StoreMapping rolls back by
	  deleting the pushed ciphertext from the content store and returning
	  an error. No index entry is created. The caller can retry.

	Zeroization:
	  All secret-buffer clearing routes through escrow.ZeroBytes and
	  escrow.ZeroArray32, which are elision-proof (go:noinline +
	  runtime.KeepAlive). ecies.go additionally zeroizes the transient
	  plaintext share buffer inside EncryptShareForNode, closing the
	  earlier transient-plaintext window.

Composes SDK primitives + injected ContentStore:
  - crypto/artifact.EncryptArtifact — encrypts the mapping blob (AES-GCM).
  - crypto/escrow.Split / crypto/escrow.Reconstruct — V1 Shamir sharing
    of the 32-byte AES key.
  - crypto/escrow.EncryptShareForNode — ECIES wrap of plaintext shares.
  - crypto/escrow.ZeroBytes / crypto/escrow.ZeroArray32 — authoritative
    zeroization primitives.
  - storage.ContentStore — stores encrypted blobs.
  - storage.Compute — derives CID from blob bytes.

Consumed by:
  - Phase 6 exchange orchestrator.
  - Judicial network identity verification flows.
  - lifecycle/recovery — supplies plaintext shares to LookupMapping
    after collecting them from escrow nodes.
*/
package identity

import (
	"crypto/ecdsa"
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

var (
	ErrMappingNotFound      = errors.New("identity/escrow: mapping not found")
	ErrInvalidIdentity      = errors.New("identity/escrow: invalid identity hash")
	ErrInvalidCredentialRef = errors.New("identity/escrow: invalid credential reference")
	ErrShareAssemblyFailed  = errors.New("identity/escrow: share assembly failed")
	ErrSplitIDMismatch      = errors.New("identity/escrow: shares do not belong to this mapping")
	ErrNodeCountMismatch    = errors.New("identity/escrow: node count does not match TotalShares")
	ErrInvalidNode          = errors.New("identity/escrow: invalid escrow node")
)

// ─────────────────────────────────────────────────────────────────────
// Compile-time sanity
// ─────────────────────────────────────────────────────────────────────

func init() {
	if artifact.KeySize != 32 || artifact.NonceSize != 12 {
		panic("identity/escrow: unexpected artifact constants")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────

// CredentialRef identifies a credential entry in a log.
type CredentialRef struct {
	LogDID    string   `json:"log_did"`
	Sequence  uint64   `json:"sequence"`
	EntryHash [32]byte `json:"entry_hash"`
}

// MappingRecord is the plaintext mapping stored (encrypted) in the content
// store.
type MappingRecord struct {
	IdentityHash  [32]byte      `json:"identity_hash"`
	CredentialRef CredentialRef `json:"credential_ref"`
	SchemaID      string        `json:"schema_id,omitempty"`
	CreatedAt     int64         `json:"created_at"`
}

// EscrowNode identifies a destination for one share of a split.
//
// DID is the node's stable identifier (e.g., "did:web:escrow1.example.org").
// It is carried through to the EncryptedShare result so callers can route
// ciphertexts to the right destinations without tracking a parallel
// index-to-DID mapping.
//
// PubKey is the node's secp256k1 public key, used as the ECIES recipient
// key. The plaintext share is recoverable only by holders of the matching
// private key.
type EscrowNode struct {
	DID    string
	PubKey *ecdsa.PublicKey
}

// EncryptedShare is an ECIES-wrapped share destined for a specific node.
//
// Position in the returned slice is parallel to the nodes slice passed to
// StoreMapping: EncryptedShares[i] is the ciphertext for nodes[i]. NodeDID
// duplicates the identifier for self-describing routing.
//
// The Ciphertext is safe to transmit or persist. Only the target node's
// private key can recover the underlying plaintext share.
type EncryptedShare struct {
	NodeDID    string
	Ciphertext []byte
}

// StoredMapping holds ONLY NON-SECRET metadata about an escrowed mapping.
//
// By construction:
//   - No key material.
//   - No plaintext shares.
//   - No ECIES ciphertexts (the caller owns those after StoreMapping).
//   - Every field is safe to log, persist, or transmit.
//
// The Nonce is the AES-GCM IV, which is public by design; storing it here
// (rather than splitting it into shares) avoids wasting share space on
// non-secret material.
type StoredMapping struct {
	CID         storage.CID
	Nonce       [12]byte // AES-GCM nonce — public, non-secret.
	K           int
	N           int
	SplitID     [32]byte // Binds this mapping's shares; checked at lookup.
	IdentityTag [32]byte // SHA-256(identity_hash) for index lookup without decryption.
	CreatedAt   int64
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
	// indexV2Map is the V2 counterpart to index. Lives alongside the
	// V1 map because the stored metadata shape differs (V2 adds
	// SplitNonce and DealerDID so the on-log commitment binding can
	// be recomputed by verifiers). Lazily initialized on first V2
	// insert by indexV2.
	indexV2Map map[[32]byte]*StoredMappingV2
}

// NewMappingEscrow constructs a MappingEscrow. ShareThreshold < 2 is
// treated as "use default" because V1 rejects degenerate 1-of-N splits
// at Split time.
func NewMappingEscrow(store storage.ContentStore, cfg MappingEscrowConfig) *MappingEscrow {
	if cfg.ShareThreshold < 2 {
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

// StoreMapping encrypts the record, splits the encryption key via V1
// Shamir sharing, ECIES-wraps each share for its destination escrow
// node, and indexes the resulting StoredMapping.
//
// Returns:
//   - *StoredMapping: non-secret metadata. Contains no keys and no shares.
//     Safe to log, persist, or transmit.
//   - []EncryptedShare: one per node, parallel to the nodes slice. The
//     caller delivers each EncryptedShare to its NodeDID. Ciphertexts
//     are safe to transmit.
//
// Plaintext shares exist only inside StoreMapping. They are zeroized
// before the function returns, regardless of success or failure. The
// plaintext AES key is likewise zeroized.
//
// Rollback: if any step fails after the ciphertext has been pushed to
// the content store (e.g., ECIES encryption fails for a node), the
// ciphertext is deleted and no index entry is created. The caller sees
// the underlying error and can retry.
//
// Overwrite: if a mapping already exists for the same IdentityHash, its
// ciphertext is deleted from the content store as part of the index
// swap. This prevents orphan ciphertexts from accumulating. The old
// mapping's shares (now unrecoverable because the new shares use a
// different key and SplitID) are effectively abandoned.
//
// The nodes slice must have exactly TotalShares entries. Each node must
// have a non-empty DID and a non-nil PubKey.
func (me *MappingEscrow) StoreMapping(
	record MappingRecord,
	nodes []EscrowNode,
) (*StoredMapping, []EncryptedShare, error) {
	// Input validation.
	if record.IdentityHash == [32]byte{} {
		return nil, nil, ErrInvalidIdentity
	}
	if record.CredentialRef.LogDID == "" {
		return nil, nil, ErrInvalidCredentialRef
	}
	if len(nodes) != me.cfg.TotalShares {
		return nil, nil, fmt.Errorf(
			"%w: got %d nodes, expected %d",
			ErrNodeCountMismatch, len(nodes), me.cfg.TotalShares,
		)
	}
	for i, n := range nodes {
		if n.DID == "" {
			return nil, nil, fmt.Errorf(
				"%w: node %d has empty DID", ErrInvalidNode, i,
			)
		}
		if n.PubKey == nil {
			return nil, nil, fmt.Errorf(
				"%w: node %d (%s) has nil PubKey",
				ErrInvalidNode, i, n.DID,
			)
		}
	}

	// 1. Serialize the mapping record as plaintext.
	plaintext, err := json.Marshal(record)
	if err != nil {
		return nil, nil, fmt.Errorf("identity/escrow: marshal: %w", err)
	}

	// 2. Encrypt via artifact.EncryptArtifact (AES-256-GCM). Returns
	//    ciphertext plus an ArtifactKey{Key [32]byte, Nonce [12]byte}.
	ciphertext, artKey, err := artifact.EncryptArtifact(plaintext)
	if err != nil {
		return nil, nil, fmt.Errorf("identity/escrow: encrypt: %w", err)
	}

	// 3. Capture the nonce BEFORE any zeroization. The nonce is
	//    non-secret and must survive past key destruction.
	nonce := artKey.Nonce

	// 4. Split ONLY the 32-byte Key. The nonce stays public on the
	//    StoredMapping; this aligns the split size with V2 Pedersen
	//    VSS's native 32-byte scalar width.
	shares, splitID, err := escrow.Split(
		artKey.Key[:],
		me.cfg.ShareThreshold,
		me.cfg.TotalShares,
	)
	if err != nil {
		zeroArtKey(&artKey)
		return nil, nil, fmt.Errorf("identity/escrow: split key: %w", err)
	}

	// 5. Zeroize the plaintext key immediately. The shares now collectively
	//    encode it; reassembling requires M of them.
	zeroArtKey(&artKey)

	// From here on, any failure path must zeroize `shares` before
	// returning. We track that via a single defer that runs unconditionally
	// — success paths zero shares just as much as failure paths, because
	// by the time StoreMapping returns the shares should not exist in any
	// reachable memory.
	defer escrow.ZeroizeShares(shares)

	// 6. Push the ciphertext to the content store.
	cid := storage.Compute(ciphertext)
	if err := me.store.Push(cid, ciphertext); err != nil {
		return nil, nil, fmt.Errorf("identity/escrow: push: %w", err)
	}

	// 7. ECIES-wrap each share for its destination node. Plaintext shares
	//    never leave this function (ecies.go also zeroizes its internal
	//    transient wire buffer). If any wrap fails, we roll back: the
	//    content store ciphertext is deleted and no index entry is
	//    created.
	encShares := make([]EncryptedShare, len(nodes))
	for i, node := range nodes {
		ct, encErr := escrow.EncryptShareForNode(shares[i], node.PubKey)
		if encErr != nil {
			// Rollback: remove the pushed ciphertext. Zeroize any
			// already-produced EncryptedShare ciphertexts defensively —
			// they're not secret (the target private keys aren't
			// compromised just because we're aborting), but clearing
			// them avoids leaving partial results in caller-visible
			// memory.
			for j := 0; j < i; j++ {
				escrow.ZeroBytes(encShares[j].Ciphertext)
			}
			if delErr := me.store.Delete(cid); delErr != nil {
				return nil, nil, fmt.Errorf(
					"identity/escrow: ecies node %d (%s): %w; rollback delete also failed: %v",
					i, node.DID, encErr, delErr,
				)
			}
			return nil, nil, fmt.Errorf(
				"identity/escrow: ecies node %d (%s): %w",
				i, node.DID, encErr,
			)
		}
		encShares[i] = EncryptedShare{
			NodeDID:    node.DID,
			Ciphertext: ct,
		}
	}

	// 8. Build StoredMapping (non-secret metadata only).
	identityTag := sha256.Sum256(record.IdentityHash[:])
	stored := &StoredMapping{
		CID:         cid,
		Nonce:       nonce,
		K:           me.cfg.ShareThreshold,
		N:           me.cfg.TotalShares,
		SplitID:     splitID,
		IdentityTag: identityTag,
		CreatedAt:   record.CreatedAt,
	}

	// 9. Insert into the index, evicting any predecessor.
	oldCID, hadOld := me.swapIndex(identityTag, stored)
	if hadOld {
		// Best-effort delete of the evicted ciphertext. A failure here
		// leaves an orphan ciphertext but an otherwise consistent index.
		_ = me.store.Delete(oldCID)
	}

	// The deferred ZeroizeShares(shares) runs now, clearing the plaintext
	// shares before this function returns. The caller receives only
	// StoredMapping (metadata) and []EncryptedShare (safe ciphertexts).
	return stored, encShares, nil
}

// swapIndex inserts stored under identityTag and returns the prior
// entry's CID (if any). Holds the lock only for the map operation.
func (me *MappingEscrow) swapIndex(
	identityTag [32]byte,
	stored *StoredMapping,
) (oldCID storage.CID, hadOld bool) {
	me.mu.Lock()
	defer me.mu.Unlock()
	if prev, ok := me.index[identityTag]; ok {
		oldCID = prev.CID
		hadOld = true
	}
	me.index[identityTag] = stored
	return
}

// ─────────────────────────────────────────────────────────────────────
// LookupMapping
// ─────────────────────────────────────────────────────────────────────

// LookupMapping reconstructs and returns the plaintext MappingRecord
// given at least M valid plaintext shares from the split that produced
// this mapping.
//
// The caller is responsible for collecting plaintext shares from the
// escrow nodes before invoking LookupMapping. Each node decrypts its
// own ECIES ciphertext locally and returns a plaintext Share; the
// caller (typically lifecycle/recovery) aggregates them. This function
// does NOT accept ECIES ciphertexts — it cannot, because the exchange
// does not hold node private keys.
//
// The provided shares must all belong to THIS mapping's split
// (validated via SplitID). escrow.Reconstruct additionally enforces
// threshold, consistent Version/Threshold/SplitID across shares, and
// unique indices.
//
// The reconstructed key is zeroized before LookupMapping returns,
// regardless of success or failure.
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

	// Bind-check each share against the stored SplitID. escrow.Reconstruct
	// will also enforce mutual consistency; the stored-ID check catches
	// the case where the caller supplies a wholly unrelated (but
	// internally consistent) share set.
	for i, s := range keyShares {
		if s.SplitID != stored.SplitID {
			return nil, fmt.Errorf(
				"%w: share %d has split id %x, mapping expects %x",
				ErrSplitIDMismatch, i, s.SplitID[:8], stored.SplitID[:8],
			)
		}
	}

	// Fetch ciphertext.
	ciphertext, err := me.store.Fetch(stored.CID)
	if err != nil {
		return nil, fmt.Errorf("identity/escrow: fetch: %w", err)
	}

	// Reconstruct the 32-byte key. Threshold enforcement happens here.
	keyBytes, err := escrow.Reconstruct(keyShares)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrShareAssemblyFailed, err)
	}
	defer escrow.ZeroBytes(keyBytes)

	// Rebuild ArtifactKey from reconstructed key + stored (non-secret) nonce.
	var artKey artifact.ArtifactKey
	copy(artKey.Key[:], keyBytes)
	artKey.Nonce = stored.Nonce
	defer zeroArtKey(&artKey)

	// Decrypt. AES-GCM provides integrity — corrupted ciphertext or a
	// wrong key produces a tag-mismatch error here.
	plaintextBytes, err := artifact.DecryptArtifact(ciphertext, artKey)
	if err != nil {
		return nil, fmt.Errorf("identity/escrow: decrypt: %w", err)
	}

	var record MappingRecord
	if err := json.Unmarshal(plaintextBytes, &record); err != nil {
		return nil, fmt.Errorf("identity/escrow: unmarshal: %w", err)
	}

	return &record, nil
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

// HasMapping returns true if a mapping with the given IdentityHash is
// indexed. Does not touch the content store.
func (me *MappingEscrow) HasMapping(identityHash [32]byte) bool {
	identityTag := sha256.Sum256(identityHash[:])
	me.mu.RLock()
	_, ok := me.index[identityTag]
	me.mu.RUnlock()
	return ok
}

// MappingCount returns the number of indexed mappings.
func (me *MappingEscrow) MappingCount() int {
	me.mu.RLock()
	defer me.mu.RUnlock()
	return len(me.index)
}

// DeleteMapping removes a mapping from the index AND from the content
// store. Returns ErrMappingNotFound if no mapping exists for the given
// IdentityHash.
//
// Index removal happens first. Content-store deletion is best-effort;
// a failure leaves an orphaned ciphertext but an otherwise consistent
// index.
//
// Note: this does NOT instruct escrow nodes to destroy their share
// ciphertexts. Those are the caller's responsibility to manage (each
// node holds an ECIES ciphertext in its own storage). However, even
// if all node-side ciphertexts survive, the deletion of the AES-GCM
// ciphertext from the content store renders any future share
// reconstruction useless — there is nothing left to decrypt.
func (me *MappingEscrow) DeleteMapping(identityHash [32]byte) error {
	identityTag := sha256.Sum256(identityHash[:])

	me.mu.Lock()
	stored, ok := me.index[identityTag]
	if !ok {
		me.mu.Unlock()
		return ErrMappingNotFound
	}
	cid := stored.CID
	delete(me.index, identityTag)
	me.mu.Unlock()

	if err := me.store.Delete(cid); err != nil {
		return fmt.Errorf("identity/escrow: delete ciphertext: %w", err)
	}
	return nil
}

// ─────────────────────────────────────────────────────────────────────
// Package-local helpers (route through escrow.ZeroArray32)
// ─────────────────────────────────────────────────────────────────────

// zeroArtKey clears both the Key and Nonce fields of an ArtifactKey
// via the authoritative escrow zeroization primitives.
//
// ArtifactKey.Nonce is [12]byte, not [32]byte — ZeroArray32 doesn't
// fit directly. We route through escrow.ZeroBytes on a slice view of
// the nonce array.
func zeroArtKey(k *artifact.ArtifactKey) {
	escrow.ZeroArray32(&k.Key)
	escrow.ZeroBytes(k.Nonce[:])
}
