// Package storage — content_store.go implements the CID-aware blob storage interface.
//
// The SDK computes the CID before calling the backend. The backend receives
// (cid, data) — it never hashes. Two backends storing the same bytes produce
// the same CID because the SDK controls addressing.
package storage

import (
	"fmt"
	"sync"
	"time"
)

// ── Retrieval method vocabulary ────────────────────────────────────────
//
// RetrievalMethod constants describe HOW a recipient fetches artifact bytes.
// Each constant names a capability, not a provider. Backends return one of
// these in RetrievalCredential.Method. Delivery adapters route on them.
//
// New backends pick from existing constants when possible. A new constant
// is added only when the retrieval mechanic is genuinely novel — not when
// the provider is new. Most providers map to MethodSignedURL or MethodDirect.

const (
	// MethodSignedURL: time-limited authenticated URL. The URL itself
	// carries the authorization (query-string signature). Recipient GETs
	// directly; URL expires. Used by GCS (V4 signed), S3 (presigned),
	// R2, Wasabi, MinIO, and any S3-compatible backend.
	MethodSignedURL = "signed_url"

	// MethodIPFS: content-addressed public gateway URL. No expiry, no
	// signing. The CID in the URL IS the authorization (anyone with the
	// CID can fetch). Used by Kubo, Filebase, Pinata, and any IPFS gateway.
	MethodIPFS = "ipfs"

	// MethodDirect: unauthenticated direct URL. No expiry, no signing.
	// Used by in-memory reference implementations, CDN endpoints, and
	// backends where the URL is inherently public (Arweave, test servers).
	MethodDirect = "direct"
)

// ── ContentStore — write-side blob storage ─────────────────────────────

// ContentStore is the CID-aware content-addressed blob storage interface.
// The SDK computes CIDs. Backends store by CID. Backends never hash.
//
// Implementations: GCS, S3, IPFS in ortholog-artifact-store/.
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
// The artifact store implements this per backend (GCS signed URL, S3 presigned,
// IPFS gateway). The operator calls Resolve and returns the credential to the
// exchange. The exchange gives it to the recipient. The artifact store holds
// storage credentials. The operator never generates signed URLs.
type RetrievalProvider interface {
	Resolve(artifactCID CID, expiry time.Duration) (*RetrievalCredential, error)
}

// RetrievalCredential describes how to fetch artifact bytes.
// Method is one of the MethodXxx constants defined above.
type RetrievalCredential struct {
	Method string     // MethodSignedURL, MethodIPFS, or MethodDirect
	URL    string     // The retrieval URL or address
	Expiry *time.Time // nil for IPFS and direct (no expiry)
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
// Returns MethodDirect with URL = cid.String(). No expiry.
type InMemoryRetrievalProvider struct{}

// NewInMemoryRetrievalProvider creates a new in-memory retrieval provider.
func NewInMemoryRetrievalProvider() *InMemoryRetrievalProvider {
	return &InMemoryRetrievalProvider{}
}

func (p *InMemoryRetrievalProvider) Resolve(artifactCID CID, _ time.Duration) (*RetrievalCredential, error) {
	return &RetrievalCredential{
		Method: MethodDirect,
		URL:    artifactCID.String(),
		Expiry: nil,
	}, nil
}
