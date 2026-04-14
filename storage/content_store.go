// Package storage — content_store.go implements the CID-aware blob storage interface.
//
// RENAMED from cas_interface.go (old interface preserved for backward compat).
// The key architectural difference: the SDK computes the CID before calling the
// backend. The backend receives (cid, data) — it never hashes. Two backends
// storing the same bytes produce the same CID because the SDK controls addressing.
//
// The old CAS interface (cas_interface.go) is preserved for existing tests and
// the transition period. New code should use ContentStore.
package storage

import (
	"fmt"
	"sync"
	"time"
)

// ContentStore is the CID-aware content-addressed blob storage interface.
// The SDK computes CIDs. Backends store by CID. Backends never hash.
//
// Implementations: GCS, S3, IPFS in ortholog-operator/ (Phase 2).
// In-memory reference impl below for SDK testing.
// SDK never imports cloud storage libraries.
type ContentStore interface {
	// Push stores data at the given CID. The SDK has already computed the CID.
	// The backend stores (cid → data). The backend MUST NOT recompute the hash.
	// Two backends storing the same bytes receive the same CID from the SDK.
	Push(cid CID, data []byte) error

	// Fetch retrieves data by CID. Returns ErrContentNotFound if the CID
	// does not exist. "Not found" is a normal condition (cryptographic erasure:
	// key destroyed, ciphertext may or may not remain).
	Fetch(cid CID) ([]byte, error)

	// Pin marks a CID for persistent storage (prevent garbage collection).
	Pin(cid CID) error

	// Exists checks if a CID is present without fetching.
	Exists(cid CID) (bool, error)

	// Delete removes a CID from the store. For cryptographic erasure cleanup.
	// Optional: backends that don't support deletion return ErrNotSupported.
	// IPFS returns ErrNotSupported (best-effort GC). GCS/S3 actually delete.
	Delete(cid CID) error
}

// ErrContentNotFound is returned when a CID does not exist in the ContentStore.
// "Not found" is a normal condition (cryptographic erasure).
var ErrContentNotFound = fmt.Errorf("content store: content not found")

// ErrNotFound is an alias for ErrContentNotFound (plan-specified name).
var ErrNotFound = ErrContentNotFound

// ErrNotSupported is returned by backends that don't support an operation.
// IPFS Delete returns this (best-effort GC, not guaranteed deletion).
var ErrNotSupported = fmt.Errorf("content store: operation not supported")

// ── RetrievalProvider — read-side counterpart of ContentStore ──────────

// RetrievalProvider resolves a CID to a retrieval credential.
// "How to give someone else a way to fetch bytes."
// Operator implements per backend (GCS signed URL, S3 presigned, IPFS gateway).
// Operator never sees decryption keys.
//
// Phase 2 operator provides concrete implementations.
// Phase 5 GrantArtifactAccess takes this as a parameter.
type RetrievalProvider interface {
	Resolve(artifactCID CID, expiry time.Duration) (*RetrievalCredential, error)
}

// RetrievalCredential describes how to fetch artifact bytes.
type RetrievalCredential struct {
	Method string     // "signed_url", "ipfs", "direct"
	URL    string     // The retrieval URL or address
	Expiry *time.Time // nil for IPFS (public, no expiry)
}

// ── In-memory reference implementation ─────────────────────────────────

// InMemoryContentStore is a reference ContentStore backed by an in-memory map.
// Thread-safe. Supports Delete (unlike IPFS which would return ErrNotSupported).
type InMemoryContentStore struct {
	mu    sync.RWMutex
	store map[string][]byte // keyed by CID.String()
	pins  map[string]bool
}

// NewInMemoryContentStore creates a new in-memory content store.
func NewInMemoryContentStore() *InMemoryContentStore {
	return &InMemoryContentStore{
		store: make(map[string][]byte),
		pins:  make(map[string]bool),
	}
}

func (s *InMemoryContentStore) Push(cid CID, data []byte) error {
	key := cid.String()
	s.mu.Lock()
	defer s.mu.Unlock()
	stored := make([]byte, len(data))
	copy(stored, data)
	s.store[key] = stored
	return nil
}

func (s *InMemoryContentStore) Fetch(cid CID) ([]byte, error) {
	key := cid.String()
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, ok := s.store[key]
	if !ok {
		return nil, ErrContentNotFound
	}
	result := make([]byte, len(data))
	copy(result, data)
	return result, nil
}

func (s *InMemoryContentStore) Pin(cid CID) error {
	key := cid.String()
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.store[key]; !ok {
		return ErrContentNotFound
	}
	s.pins[key] = true
	return nil
}

func (s *InMemoryContentStore) Exists(cid CID) (bool, error) {
	key := cid.String()
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.store[key]
	return ok, nil
}

func (s *InMemoryContentStore) Delete(cid CID) error {
	key := cid.String()
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.store, key)
	delete(s.pins, key)
	return nil
}

// ── In-memory RetrievalProvider reference implementation ────────────

// InMemoryRetrievalProvider is a reference RetrievalProvider for SDK testing.
// Returns Method "direct" with URL = cid.String(). No expiry.
type InMemoryRetrievalProvider struct{}

// NewInMemoryRetrievalProvider creates a new in-memory retrieval provider.
func NewInMemoryRetrievalProvider() *InMemoryRetrievalProvider {
	return &InMemoryRetrievalProvider{}
}

func (p *InMemoryRetrievalProvider) Resolve(artifactCID CID, _ time.Duration) (*RetrievalCredential, error) {
	return &RetrievalCredential{
		Method: "direct",
		URL:    artifactCID.String(),
		Expiry: nil, // in-memory, no expiry
	}, nil
}
