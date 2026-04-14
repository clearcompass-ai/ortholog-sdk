// Package storage defines the content-addressed blob storage interface.
package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sync"
)

// CAS is the content-addressed blob storage interface.
// Implementations: IPFS, institutional CAS, GCS with CID addressing, etc.
// "Not found" is a normal condition (cryptographic erasure: key destroyed,
// ciphertext remains but is irrecoverable).
type CAS interface {
	// Push stores data and returns its content address (CID).
	Push(data []byte) (cid string, err error)

	// Fetch retrieves data by CID. Returns ErrNotFound if the CID
	// does not exist (normal for cryptographic erasure).
	Fetch(cid string) ([]byte, error)

	// Pin marks a CID for persistent storage (prevent garbage collection).
	Pin(cid string) error

	// Exists checks if a CID is present without fetching.
	Exists(cid string) (bool, error)
}

// ErrNotFound is returned when a CID does not exist in the CAS.
// This is a normal condition — not an error that requires intervention.
var ErrNotFound = fmt.Errorf("CAS: content not found")

// ── In-memory reference implementation ─────────────────────────────────

// InMemoryCAS is a reference CAS implementation backed by an in-memory map.
// Thread-safe. Includes a Delete helper for testing cryptographic erasure.
type InMemoryCAS struct {
	mu    sync.RWMutex
	store map[string][]byte
	pins  map[string]bool
}

// NewInMemoryCAS creates a new in-memory CAS.
func NewInMemoryCAS() *InMemoryCAS {
	return &InMemoryCAS{
		store: make(map[string][]byte),
		pins:  make(map[string]bool),
	}
}

func (c *InMemoryCAS) Push(data []byte) (string, error) {
	hash := sha256.Sum256(data)
	cid := "sha256:" + hex.EncodeToString(hash[:])
	c.mu.Lock()
	defer c.mu.Unlock()
	stored := make([]byte, len(data))
	copy(stored, data)
	c.store[cid] = stored
	return cid, nil
}

func (c *InMemoryCAS) Fetch(cid string) ([]byte, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	data, ok := c.store[cid]
	if !ok {
		return nil, ErrNotFound
	}
	result := make([]byte, len(data))
	copy(result, data)
	return result, nil
}

func (c *InMemoryCAS) Pin(cid string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.store[cid]; !ok {
		return ErrNotFound
	}
	c.pins[cid] = true
	return nil
}

func (c *InMemoryCAS) Exists(cid string) (bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.store[cid]
	return ok, nil
}

// Delete removes a CID from the store. Testing helper for cryptographic erasure.
// Not part of the CAS interface — erasure in production is key destruction,
// not blob deletion.
func (c *InMemoryCAS) Delete(cid string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.store, cid)
	delete(c.pins, cid)
}
