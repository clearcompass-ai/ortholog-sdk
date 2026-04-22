// Package lifecycle — testhelpers_test.go provides shared fixtures for
// the lifecycle test suite. Internal (package lifecycle) so test files
// can touch unexported helpers.
package lifecycle

import (
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"sync"
	"testing"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/clearcompass-ai/ortholog-sdk/storage"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// -------------------------------------------------------------------------------------------------
// Test constants
// -------------------------------------------------------------------------------------------------

// testDestination is a non-empty DID used across tests that need a valid
// destination field. Chosen to pass envelope.ValidateDestination for
// well-formed DIDs.
const testDestination = "did:web:test-exchange.example.org"

// -------------------------------------------------------------------------------------------------
// Fresh secp256k1 keypair
// -------------------------------------------------------------------------------------------------

// freshSecp256k1KeyPair returns a fresh secp256k1 keypair for tests that
// need real cryptographic material (delegation keys, ECIES wrapping, etc.).
func freshSecp256k1KeyPair(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		t.Fatalf("freshSecp256k1KeyPair: %v", err)
	}
	return priv
}

// freshUncompressedPubKey returns the 65-byte uncompressed encoding
// (0x04 || X || Y) of a fresh secp256k1 public key.
func freshUncompressedPubKey(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()
	priv := freshSecp256k1KeyPair(t)
	out := make([]byte, 65)
	out[0] = 0x04
	xBytes := priv.PublicKey.X.Bytes()
	yBytes := priv.PublicKey.Y.Bytes()
	copy(out[33-len(xBytes):33], xBytes)
	copy(out[65-len(yBytes):65], yBytes)
	return out, priv
}

// -------------------------------------------------------------------------------------------------
// In-memory ContentStore implementing storage.ContentStore
// -------------------------------------------------------------------------------------------------

// memContentStore is a tests-only in-memory ContentStore. It satisfies
// the Fetch / Push / Delete surface used by the lifecycle package. Any
// additional methods the real interface defines can be added here if
// the tests need them; a test that touches an unimplemented method
// will fail at compile time and we add it here.
type memContentStore struct {
	mu   sync.RWMutex
	data map[string][]byte
}

func newMemContentStore() *memContentStore {
	return &memContentStore{data: make(map[string][]byte)}
}

func (m *memContentStore) Fetch(cid storage.CID) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	b, ok := m.data[cid.String()]
	if !ok {
		return nil, fmt.Errorf("memContentStore: cid %s not found", cid)
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	return cp, nil
}

func (m *memContentStore) Push(cid storage.CID, data []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]byte, len(data))
	copy(cp, data)
	m.data[cid.String()] = cp
	return nil
}

func (m *memContentStore) Delete(cid storage.CID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, cid.String())
	return nil
}

// -------------------------------------------------------------------------------------------------
// CosignatureQuerier mock (for scope_governance tests)
// -------------------------------------------------------------------------------------------------

// stubCosignatureQuerier returns a fixed list of EntryWithMetadata on
// every call to QueryByCosignatureOf.
type stubCosignatureQuerier struct {
	entries []types.EntryWithMetadata
	err     error
}

func (s *stubCosignatureQuerier) QueryByCosignatureOf(_ types.LogPosition) ([]types.EntryWithMetadata, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.entries, nil
}
