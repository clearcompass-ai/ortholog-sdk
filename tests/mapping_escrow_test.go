package tests

import (
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/exchange/identity"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
)

// ─────────────────────────────────────────────────────────────────────
// Mock ContentStore
// ─────────────────────────────────────────────────────────────────────

type inMemoryContentStore struct {
	data map[string][]byte
}

func newInMemoryContentStore() *inMemoryContentStore {
	return &inMemoryContentStore{data: make(map[string][]byte)}
}

func (s *inMemoryContentStore) Push(cid storage.CID, data []byte) error {
	s.data[cid.String()] = append([]byte(nil), data...)
	return nil
}

func (s *inMemoryContentStore) Fetch(cid storage.CID) ([]byte, error) {
	data, ok := s.data[cid.String()]
	if !ok {
		return nil, errors.New("not found")
	}
	return data, nil
}

func (s *inMemoryContentStore) Exists(cid storage.CID) (bool, error) {
	_, ok := s.data[cid.String()]
	return ok, nil
}

func (s *inMemoryContentStore) Pin(cid storage.CID) error { return nil }

func (s *inMemoryContentStore) Delete(cid storage.CID) error {
	delete(s.data, cid.String())
	return nil
}

// ─────────────────────────────────────────────────────────────────────
// Tests: StoreMapping
// ─────────────────────────────────────────────────────────────────────

func TestMappingEscrow_StoreAndLookup(t *testing.T) {
	store := newInMemoryContentStore()
	escrow := identity.NewMappingEscrow(store, identity.DefaultMappingEscrowConfig())

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

	stored, err := escrow.StoreMapping(record)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	if stored.CID.String() == "" {
		t.Fatal("CID should not be empty")
	}
	if stored.IdentityTag == [32]byte{} {
		t.Fatal("identity tag should not be zero")
	}
	if len(stored.EscrowPkg.Shares) != 5 {
		t.Fatalf("shares: %d", len(stored.EscrowPkg.Shares))
	}

	// Lookup with sufficient shares.
	result, err := escrow.LookupMapping(idHash, stored.EscrowPkg.Shares[:3])
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
	store := newInMemoryContentStore()
	escrow := identity.NewMappingEscrow(store, identity.DefaultMappingEscrowConfig())

	record := identity.MappingRecord{
		IdentityHash:  [32]byte{}, // Zero.
		CredentialRef: identity.CredentialRef{LogDID: "did:web:test"},
	}
	_, err := escrow.StoreMapping(record)
	if !errors.Is(err, identity.ErrInvalidIdentity) {
		t.Fatalf("expected ErrInvalidIdentity, got: %v", err)
	}
}

func TestMappingEscrow_StoreEmptyCredRef_Error(t *testing.T) {
	store := newInMemoryContentStore()
	escrow := identity.NewMappingEscrow(store, identity.DefaultMappingEscrowConfig())

	record := identity.MappingRecord{
		IdentityHash:  sha256.Sum256([]byte("id")),
		CredentialRef: identity.CredentialRef{LogDID: ""}, // Empty.
	}
	_, err := escrow.StoreMapping(record)
	if !errors.Is(err, identity.ErrInvalidCredentialRef) {
		t.Fatalf("expected ErrInvalidCredentialRef, got: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Tests: LookupMapping
// ─────────────────────────────────────────────────────────────────────

func TestMappingEscrow_LookupNotFound(t *testing.T) {
	store := newInMemoryContentStore()
	escrow := identity.NewMappingEscrow(store, identity.DefaultMappingEscrowConfig())

	idHash := sha256.Sum256([]byte("nonexistent"))
	_, err := escrow.LookupMapping(idHash, nil)
	if !errors.Is(err, identity.ErrMappingNotFound) {
		t.Fatalf("expected ErrMappingNotFound, got: %v", err)
	}
}

func TestMappingEscrow_LookupZeroIdentity_Error(t *testing.T) {
	store := newInMemoryContentStore()
	escrow := identity.NewMappingEscrow(store, identity.DefaultMappingEscrowConfig())

	_, err := escrow.LookupMapping([32]byte{}, nil)
	if !errors.Is(err, identity.ErrInvalidIdentity) {
		t.Fatalf("expected ErrInvalidIdentity, got: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Tests: HasMapping / MappingCount / DeleteMapping
// ─────────────────────────────────────────────────────────────────────

func TestMappingEscrow_HasMapping(t *testing.T) {
	store := newInMemoryContentStore()
	escrow := identity.NewMappingEscrow(store, identity.DefaultMappingEscrowConfig())

	idHash := sha256.Sum256([]byte("check"))
	if escrow.HasMapping(idHash) {
		t.Fatal("should not have mapping before store")
	}

	escrow.StoreMapping(identity.MappingRecord{
		IdentityHash:  idHash,
		CredentialRef: identity.CredentialRef{LogDID: "did:web:test"},
	})

	if !escrow.HasMapping(idHash) {
		t.Fatal("should have mapping after store")
	}
}

func TestMappingEscrow_MappingCount(t *testing.T) {
	store := newInMemoryContentStore()
	escrow := identity.NewMappingEscrow(store, identity.DefaultMappingEscrowConfig())

	if escrow.MappingCount() != 0 {
		t.Fatal("initial: 0")
	}

	for i := 0; i < 3; i++ {
		idHash := sha256.Sum256([]byte{byte(i)})
		escrow.StoreMapping(identity.MappingRecord{
			IdentityHash:  idHash,
			CredentialRef: identity.CredentialRef{LogDID: "did:web:test"},
		})
	}

	if escrow.MappingCount() != 3 {
		t.Fatalf("count: %d", escrow.MappingCount())
	}
}

func TestMappingEscrow_DeleteMapping(t *testing.T) {
	store := newInMemoryContentStore()
	escrow := identity.NewMappingEscrow(store, identity.DefaultMappingEscrowConfig())

	idHash := sha256.Sum256([]byte("delete-me"))
	escrow.StoreMapping(identity.MappingRecord{
		IdentityHash:  idHash,
		CredentialRef: identity.CredentialRef{LogDID: "did:web:test"},
	})

	if !escrow.DeleteMapping(idHash) {
		t.Fatal("delete should return true for existing")
	}
	if escrow.HasMapping(idHash) {
		t.Fatal("should not have mapping after delete")
	}
}

func TestMappingEscrow_DeleteNonexistent(t *testing.T) {
	store := newInMemoryContentStore()
	escrow := identity.NewMappingEscrow(store, identity.DefaultMappingEscrowConfig())

	idHash := sha256.Sum256([]byte("nope"))
	if escrow.DeleteMapping(idHash) {
		t.Fatal("delete of nonexistent should return false")
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
	store := newInMemoryContentStore()
	cfg := identity.MappingEscrowConfig{ShareThreshold: 2, TotalShares: 3}
	escrow := identity.NewMappingEscrow(store, cfg)

	idHash := sha256.Sum256([]byte("custom"))
	stored, err := escrow.StoreMapping(identity.MappingRecord{
		IdentityHash:  idHash,
		CredentialRef: identity.CredentialRef{LogDID: "did:web:test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(stored.EscrowPkg.Shares) != 3 {
		t.Fatalf("shares: %d (expected 3)", len(stored.EscrowPkg.Shares))
	}
	if stored.EscrowPkg.K != 2 {
		t.Fatalf("K: %d", stored.EscrowPkg.K)
	}
}

func TestMappingEscrow_ZeroConfig_UsesDefaults(t *testing.T) {
	store := newInMemoryContentStore()
	escrow := identity.NewMappingEscrow(store, identity.MappingEscrowConfig{})

	idHash := sha256.Sum256([]byte("zero-cfg"))
	stored, err := escrow.StoreMapping(identity.MappingRecord{
		IdentityHash:  idHash,
		CredentialRef: identity.CredentialRef{LogDID: "did:web:test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Should use defaults: K=3, N=5.
	if stored.EscrowPkg.K != 3 {
		t.Fatalf("K: %d (expected 3 default)", stored.EscrowPkg.K)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Tests: Multiple mappings
// ─────────────────────────────────────────────────────────────────────

func TestMappingEscrow_MultipleIdentities(t *testing.T) {
	store := newInMemoryContentStore()
	escrow := identity.NewMappingEscrow(store, identity.DefaultMappingEscrowConfig())

	id1 := sha256.Sum256([]byte("alice"))
	id2 := sha256.Sum256([]byte("bob"))

	stored1, _ := escrow.StoreMapping(identity.MappingRecord{
		IdentityHash:  id1,
		CredentialRef: identity.CredentialRef{LogDID: "did:web:log1", Sequence: 10},
	})
	stored2, _ := escrow.StoreMapping(identity.MappingRecord{
		IdentityHash:  id2,
		CredentialRef: identity.CredentialRef{LogDID: "did:web:log2", Sequence: 20},
	})

	result1, err := escrow.LookupMapping(id1, stored1.EscrowPkg.Shares[:3])
	if err != nil {
		t.Fatalf("lookup alice: %v", err)
	}
	if result1.CredentialRef.Sequence != 10 {
		t.Fatalf("alice seq: %d", result1.CredentialRef.Sequence)
	}

	result2, err := escrow.LookupMapping(id2, stored2.EscrowPkg.Shares[:3])
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

	store := newInMemoryContentStore()
	escrow := identity.NewMappingEscrow(store, identity.DefaultMappingEscrowConfig())

	stored, _ := escrow.StoreMapping(identity.MappingRecord{
		IdentityHash:  idHash,
		CredentialRef: identity.CredentialRef{LogDID: "did:web:test"},
	})

	if stored.IdentityTag != expectedTag {
		t.Fatal("identity tag should be SHA-256(identity_hash)")
	}
}
