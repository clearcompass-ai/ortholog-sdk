package tests

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/escrow"
	"github.com/clearcompass-ai/ortholog-sdk/exchange/identity"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// ─────────────────────────────────────────────────────────────────────
// Mock ContentStore (only defined here — not in other test files)
// ─────────────────────────────────────────────────────────────────────

type mappingTestStore struct {
	data map[string][]byte
}

func newMappingTestStore() *mappingTestStore {
	return &mappingTestStore{data: make(map[string][]byte)}
}

func (s *mappingTestStore) Push(cid storage.CID, data []byte) error {
	s.data[cid.String()] = append([]byte(nil), data...)
	return nil
}

func (s *mappingTestStore) Fetch(cid storage.CID) ([]byte, error) {
	data, ok := s.data[cid.String()]
	if !ok {
		return nil, errors.New("not found")
	}
	return data, nil
}

func (s *mappingTestStore) Exists(cid storage.CID) (bool, error) {
	_, ok := s.data[cid.String()]
	return ok, nil
}

func (s *mappingTestStore) Pin(cid storage.CID) error    { return nil }
func (s *mappingTestStore) Delete(cid storage.CID) error { delete(s.data, cid.String()); return nil }

// ─────────────────────────────────────────────────────────────────────
// Test helpers for the EscrowNode-based StoreMapping API.
// ─────────────────────────────────────────────────────────────────────

// makeEscrowNodes returns n fresh escrow nodes (DID + secp256k1 pubkey)
// paired with their private keys so the test can decrypt shares back
// out of EncryptedShare ciphertexts. Private keys never leak past the
// test function; real deployments keep them on separate custodians.
func makeEscrowNodes(t *testing.T, n int) ([]identity.EscrowNode, []*ecdsa.PrivateKey) {
	t.Helper()
	nodes := make([]identity.EscrowNode, n)
	privs := make([]*ecdsa.PrivateKey, n)
	for i := 0; i < n; i++ {
		priv, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate escrow node key %d: %v", i, err)
		}
		nodes[i] = identity.EscrowNode{
			DID:    "did:example:escrow-" + string(rune('a'+i)),
			PubKey: &priv.PublicKey,
		}
		privs[i] = priv
	}
	return nodes, privs
}

// decryptShares recovers the plaintext escrow.Share values for the
// given subset of node indices. Mirrors the real-deployment lookup
// path: the caller collects K ciphertexts from K cooperating nodes
// and each node decrypts its assigned share.
func decryptShares(
	t *testing.T,
	encrypted []identity.EncryptedShare,
	privs []*ecdsa.PrivateKey,
	indices []int,
) []escrow.Share {
	t.Helper()
	out := make([]escrow.Share, len(indices))
	for i, idx := range indices {
		s, err := escrow.DecryptShareFromNode(encrypted[idx].Ciphertext, privs[idx])
		if err != nil {
			t.Fatalf("decrypt share at node index %d: %v", idx, err)
		}
		out[i] = s
	}
	return out
}

// firstK returns the first k sequential indices — a convenience for
// the common "any K of N" subset tests.
func firstK(k int) []int {
	out := make([]int, k)
	for i := range out {
		out[i] = i
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────
// Tests: StoreMapping
// ─────────────────────────────────────────────────────────────────────

func TestMappingEscrow_StoreAndLookup(t *testing.T) {
	store := newMappingTestStore()
	me := identity.NewMappingEscrow(store, identity.DefaultMappingEscrowConfig())
	nodes, privs := makeEscrowNodes(t, 5)

	idHash := sha256.Sum256([]byte("test-identity"))
	record := identity.MappingRecord{
		IdentityHash: idHash,
		CredentialRef: identity.CredentialRef{
			LogDID:   "did:web:court.example.com",
			Sequence: 42,
		},
		SchemaID:  "criminal-record-v1",
		CreatedAt: 1700000000,
	}

	stored, encShares, err := me.StoreMapping(record, nodes)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	if stored.CID.String() == "" {
		t.Fatal("CID should not be empty")
	}
	if stored.IdentityTag == [32]byte{} {
		t.Fatal("identity tag should not be zero")
	}
	if len(encShares) != 5 {
		t.Fatalf("encrypted shares: %d", len(encShares))
	}
	if stored.K != 3 {
		t.Fatalf("K: %d", stored.K)
	}
	if stored.N != 5 {
		t.Fatalf("N: %d", stored.N)
	}

	// Lookup with sufficient shares (K=3).
	shares := decryptShares(t, encShares, privs, firstK(3))
	result, err := me.LookupMapping(idHash, shares)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if result.CredentialRef.LogDID != "did:web:court.example.com" {
		t.Fatalf("log DID: %s", result.CredentialRef.LogDID)
	}
	if result.CredentialRef.Sequence != 42 {
		t.Fatalf("sequence: %d", result.CredentialRef.Sequence)
	}
	if result.SchemaID != "criminal-record-v1" {
		t.Fatalf("schema: %s", result.SchemaID)
	}
}

func TestMappingEscrow_StoreZeroIdentity_Error(t *testing.T) {
	me := identity.NewMappingEscrow(newMappingTestStore(), identity.DefaultMappingEscrowConfig())
	nodes, _ := makeEscrowNodes(t, 5)
	record := identity.MappingRecord{
		IdentityHash:  [32]byte{},
		CredentialRef: identity.CredentialRef{LogDID: "did:web:test"},
	}
	_, _, err := me.StoreMapping(record, nodes)
	if !errors.Is(err, identity.ErrInvalidIdentity) {
		t.Fatalf("expected ErrInvalidIdentity, got: %v", err)
	}
}

func TestMappingEscrow_StoreEmptyCredRef_Error(t *testing.T) {
	me := identity.NewMappingEscrow(newMappingTestStore(), identity.DefaultMappingEscrowConfig())
	nodes, _ := makeEscrowNodes(t, 5)
	record := identity.MappingRecord{
		IdentityHash:  sha256.Sum256([]byte("id")),
		CredentialRef: identity.CredentialRef{LogDID: ""},
	}
	_, _, err := me.StoreMapping(record, nodes)
	if !errors.Is(err, identity.ErrInvalidCredentialRef) {
		t.Fatalf("expected ErrInvalidCredentialRef, got: %v", err)
	}
}

// TestMappingEscrow_StoreNodeCountMismatch covers the new
// EscrowNode-based API: supplying a node slice whose length does
// not equal TotalShares must fail with ErrNodeCountMismatch.
func TestMappingEscrow_StoreNodeCountMismatch(t *testing.T) {
	me := identity.NewMappingEscrow(newMappingTestStore(), identity.DefaultMappingEscrowConfig())
	nodes, _ := makeEscrowNodes(t, 4) // config expects 5
	_, _, err := me.StoreMapping(identity.MappingRecord{
		IdentityHash:  sha256.Sum256([]byte("id")),
		CredentialRef: identity.CredentialRef{LogDID: "did:web:test"},
	}, nodes)
	if !errors.Is(err, identity.ErrNodeCountMismatch) {
		t.Fatalf("expected ErrNodeCountMismatch, got: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Tests: LookupMapping
// ─────────────────────────────────────────────────────────────────────

func TestMappingEscrow_LookupNotFound(t *testing.T) {
	me := identity.NewMappingEscrow(newMappingTestStore(), identity.DefaultMappingEscrowConfig())
	idHash := sha256.Sum256([]byte("nonexistent"))
	_, err := me.LookupMapping(idHash, nil)
	if !errors.Is(err, identity.ErrMappingNotFound) {
		t.Fatalf("expected ErrMappingNotFound, got: %v", err)
	}
}

func TestMappingEscrow_LookupZeroIdentity_Error(t *testing.T) {
	me := identity.NewMappingEscrow(newMappingTestStore(), identity.DefaultMappingEscrowConfig())
	_, err := me.LookupMapping([32]byte{}, nil)
	if !errors.Is(err, identity.ErrInvalidIdentity) {
		t.Fatalf("expected ErrInvalidIdentity, got: %v", err)
	}
}

func TestMappingEscrow_LookupDifferentShareSubsets(t *testing.T) {
	me := identity.NewMappingEscrow(newMappingTestStore(), identity.DefaultMappingEscrowConfig())
	nodes, privs := makeEscrowNodes(t, 5)
	idHash := sha256.Sum256([]byte("subset-test"))
	_, encShares, err := me.StoreMapping(identity.MappingRecord{
		IdentityHash:  idHash,
		CredentialRef: identity.CredentialRef{LogDID: "did:web:test", Sequence: 99},
	}, nodes)
	if err != nil {
		t.Fatalf("store: %v", err)
	}

	// Any 3-of-5 subset should work. Indices name which escrow nodes
	// cooperate on the lookup.
	subsets := [][]int{
		{0, 1, 2},
		{0, 2, 4},
		{1, 3, 4},
		{2, 3, 4},
	}
	for i, indices := range subsets {
		shares := decryptShares(t, encShares, privs, indices)
		result, err := me.LookupMapping(idHash, shares)
		if err != nil {
			t.Fatalf("subset %d: %v", i, err)
		}
		if result.CredentialRef.Sequence != 99 {
			t.Fatalf("subset %d: sequence %d", i, result.CredentialRef.Sequence)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────
// Tests: HasMapping / MappingCount / DeleteMapping
// ─────────────────────────────────────────────────────────────────────

func TestMappingEscrow_HasMapping(t *testing.T) {
	me := identity.NewMappingEscrow(newMappingTestStore(), identity.DefaultMappingEscrowConfig())
	nodes, _ := makeEscrowNodes(t, 5)
	idHash := sha256.Sum256([]byte("check"))
	if me.HasMapping(idHash) {
		t.Fatal("should not have mapping before store")
	}
	if _, _, err := me.StoreMapping(identity.MappingRecord{
		IdentityHash:  idHash,
		CredentialRef: identity.CredentialRef{LogDID: "did:web:test"},
	}, nodes); err != nil {
		t.Fatalf("store: %v", err)
	}
	if !me.HasMapping(idHash) {
		t.Fatal("should have mapping after store")
	}
}

func TestMappingEscrow_MappingCount(t *testing.T) {
	me := identity.NewMappingEscrow(newMappingTestStore(), identity.DefaultMappingEscrowConfig())
	nodes, _ := makeEscrowNodes(t, 5)
	if me.MappingCount() != 0 {
		t.Fatal("initial: 0")
	}
	for i := 0; i < 3; i++ {
		idHash := sha256.Sum256([]byte{byte(i)})
		if _, _, err := me.StoreMapping(identity.MappingRecord{
			IdentityHash:  idHash,
			CredentialRef: identity.CredentialRef{LogDID: "did:web:test"},
		}, nodes); err != nil {
			t.Fatalf("store %d: %v", i, err)
		}
	}
	if me.MappingCount() != 3 {
		t.Fatalf("count: %d", me.MappingCount())
	}
}

func TestMappingEscrow_DeleteMapping(t *testing.T) {
	me := identity.NewMappingEscrow(newMappingTestStore(), identity.DefaultMappingEscrowConfig())
	nodes, _ := makeEscrowNodes(t, 5)
	idHash := sha256.Sum256([]byte("delete-me"))
	if _, _, err := me.StoreMapping(identity.MappingRecord{
		IdentityHash:  idHash,
		CredentialRef: identity.CredentialRef{LogDID: "did:web:test"},
	}, nodes); err != nil {
		t.Fatalf("store: %v", err)
	}
	if err := me.DeleteMapping(idHash); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if me.HasMapping(idHash) {
		t.Fatal("should not have mapping after delete")
	}
}

func TestMappingEscrow_DeleteNonexistent(t *testing.T) {
	me := identity.NewMappingEscrow(newMappingTestStore(), identity.DefaultMappingEscrowConfig())
	err := me.DeleteMapping(sha256.Sum256([]byte("nope")))
	if !errors.Is(err, identity.ErrMappingNotFound) {
		t.Fatalf("delete of nonexistent: want ErrMappingNotFound, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Tests: Configuration
// ─────────────────────────────────────────────────────────────────────

func TestMappingEscrow_DefaultConfig(t *testing.T) {
	cfg := identity.DefaultMappingEscrowConfig()
	if cfg.ShareThreshold != 3 {
		t.Fatalf("threshold: %d", cfg.ShareThreshold)
	}
	if cfg.TotalShares != 5 {
		t.Fatalf("total: %d", cfg.TotalShares)
	}
}

func TestMappingEscrow_CustomConfig(t *testing.T) {
	cfg := identity.MappingEscrowConfig{ShareThreshold: 2, TotalShares: 3}
	me := identity.NewMappingEscrow(newMappingTestStore(), cfg)
	nodes, _ := makeEscrowNodes(t, 3)
	idHash := sha256.Sum256([]byte("custom"))
	stored, encShares, err := me.StoreMapping(identity.MappingRecord{
		IdentityHash:  idHash,
		CredentialRef: identity.CredentialRef{LogDID: "did:web:test"},
	}, nodes)
	if err != nil {
		t.Fatal(err)
	}
	if len(encShares) != 3 {
		t.Fatalf("shares: %d (expected 3)", len(encShares))
	}
	if stored.K != 2 {
		t.Fatalf("K: %d", stored.K)
	}
}

func TestMappingEscrow_ZeroConfig_UsesDefaults(t *testing.T) {
	me := identity.NewMappingEscrow(newMappingTestStore(), identity.MappingEscrowConfig{})
	// Zero-config falls back to DefaultMappingEscrowConfig (5 nodes).
	nodes, _ := makeEscrowNodes(t, 5)
	idHash := sha256.Sum256([]byte("zero-cfg"))
	stored, _, err := me.StoreMapping(identity.MappingRecord{
		IdentityHash:  idHash,
		CredentialRef: identity.CredentialRef{LogDID: "did:web:test"},
	}, nodes)
	if err != nil {
		t.Fatal(err)
	}
	if stored.K != 3 {
		t.Fatalf("K: %d (expected 3 default)", stored.K)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Tests: Multiple mappings
// ─────────────────────────────────────────────────────────────────────

func TestMappingEscrow_MultipleIdentities(t *testing.T) {
	me := identity.NewMappingEscrow(newMappingTestStore(), identity.DefaultMappingEscrowConfig())
	nodes, privs := makeEscrowNodes(t, 5)

	id1 := sha256.Sum256([]byte("alice"))
	id2 := sha256.Sum256([]byte("bob"))

	_, enc1, err := me.StoreMapping(identity.MappingRecord{
		IdentityHash:  id1,
		CredentialRef: identity.CredentialRef{LogDID: "did:web:log1", Sequence: 10},
	}, nodes)
	if err != nil {
		t.Fatalf("store alice: %v", err)
	}
	_, enc2, err := me.StoreMapping(identity.MappingRecord{
		IdentityHash:  id2,
		CredentialRef: identity.CredentialRef{LogDID: "did:web:log2", Sequence: 20},
	}, nodes)
	if err != nil {
		t.Fatalf("store bob: %v", err)
	}

	shares1 := decryptShares(t, enc1, privs, firstK(3))
	result1, err := me.LookupMapping(id1, shares1)
	if err != nil {
		t.Fatalf("lookup alice: %v", err)
	}
	if result1.CredentialRef.Sequence != 10 {
		t.Fatalf("alice seq: %d", result1.CredentialRef.Sequence)
	}

	shares2 := decryptShares(t, enc2, privs, firstK(3))
	result2, err := me.LookupMapping(id2, shares2)
	if err != nil {
		t.Fatalf("lookup bob: %v", err)
	}
	if result2.CredentialRef.Sequence != 20 {
		t.Fatalf("bob seq: %d", result2.CredentialRef.Sequence)
	}
}

func TestMappingEscrow_IdentityTagIsDoubleHash(t *testing.T) {
	idHash := sha256.Sum256([]byte("test"))
	expectedTag := sha256.Sum256(idHash[:])

	me := identity.NewMappingEscrow(newMappingTestStore(), identity.DefaultMappingEscrowConfig())
	nodes, _ := makeEscrowNodes(t, 5)
	stored, _, err := me.StoreMapping(identity.MappingRecord{
		IdentityHash:  idHash,
		CredentialRef: identity.CredentialRef{LogDID: "did:web:test"},
	}, nodes)
	if err != nil {
		t.Fatalf("store: %v", err)
	}

	if stored.IdentityTag != expectedTag {
		t.Fatal("identity tag should be SHA-256(identity_hash)")
	}
}
