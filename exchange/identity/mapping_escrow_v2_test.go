package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"

	secp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/escrow"
	"github.com/clearcompass-ai/ortholog-sdk/schema"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
)

// ─────────────────────────────────────────────────────────────────────
// In-memory store for tests
// ─────────────────────────────────────────────────────────────────────

type v2TestStore struct {
	data map[string][]byte
}

func newV2TestStore() *v2TestStore {
	return &v2TestStore{data: make(map[string][]byte)}
}

func (s *v2TestStore) Push(cid storage.CID, data []byte) error {
	s.data[cid.String()] = append([]byte(nil), data...)
	return nil
}

func (s *v2TestStore) Fetch(cid storage.CID) ([]byte, error) {
	if d, ok := s.data[cid.String()]; ok {
		return append([]byte(nil), d...), nil
	}
	return nil, errors.New("not found")
}

func (s *v2TestStore) Delete(cid storage.CID) error {
	delete(s.data, cid.String())
	return nil
}

func (s *v2TestStore) Exists(cid storage.CID) (bool, error) {
	_, ok := s.data[cid.String()]
	return ok, nil
}

func (s *v2TestStore) Pin(cid storage.CID) error { return nil }

func newV2Node(t *testing.T, did string) EscrowNode {
	t.Helper()
	priv, err := ecdsa.GenerateKey(secp256k1.S256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate node key: %v", err)
	}
	return EscrowNode{DID: did, PubKey: &priv.PublicKey}
}

func mkV2Record() MappingRecord {
	var id [32]byte
	for i := range id {
		id[i] = byte(i + 1)
	}
	return MappingRecord{
		IdentityHash:  id,
		CredentialRef: CredentialRef{LogDID: "did:web:example.com:log", Sequence: 1},
		CreatedAt:     1700000000,
	}
}

func mkV2Cfg() StoreMappingV2Config {
	return StoreMappingV2Config{
		DealerDID:   "did:web:example.com:dealer",
		Destination: "did:web:example.com:exchange",
		EventTime:   1700000001,
	}
}

// ─────────────────────────────────────────────────────────────────────
// Atomic emission happy path
// ─────────────────────────────────────────────────────────────────────

func TestStoreMappingV2_AtomicCommitmentEmission(t *testing.T) {
	me := NewMappingEscrow(newV2TestStore(), DefaultMappingEscrowConfig())
	nodes := make([]EscrowNode, me.cfg.TotalShares)
	for i := range nodes {
		nodes[i] = newV2Node(t, "did:web:example.com:node"+string(rune('a'+i)))
	}
	result, err := me.StoreMappingV2(mkV2Record(), nodes, mkV2Cfg())
	if err != nil {
		t.Fatalf("StoreMappingV2: %v", err)
	}
	if result == nil || result.Stored == nil {
		t.Fatal("nil result or stored")
	}
	if len(result.EncShares) != me.cfg.TotalShares {
		t.Fatalf("encShares=%d want %d", len(result.EncShares), me.cfg.TotalShares)
	}
	if result.Commitment == nil {
		t.Fatal("Commitment must not be nil")
	}
	if result.CommitmentEntry == nil {
		t.Fatal("CommitmentEntry must not be nil (atomic emission violated)")
	}

	// Commitment entry must pass the admission validator.
	if err := schema.ValidateEscrowSplitCommitmentEntry(result.CommitmentEntry); err != nil {
		t.Fatalf("admission validator: %v", err)
	}

	// Re-derive the SplitID from the stored metadata and confirm the
	// on-log commitment binds to it.
	want := escrow.ComputeEscrowSplitID(result.Stored.DealerDID, result.Stored.SplitNonce)
	if result.Stored.SplitID != want {
		t.Fatalf("stored SplitID drift")
	}
	if err := escrow.VerifyEscrowSplitCommitment(result.Commitment, result.Stored.SplitNonce); err != nil {
		t.Fatalf("commitment does not verify: %v", err)
	}

	// Parse the on-log payload and verify parity with the returned commitment.
	parsed, err := schema.ParseEscrowSplitCommitmentEntry(result.CommitmentEntry)
	if err != nil {
		t.Fatalf("parse commitment entry: %v", err)
	}
	if parsed.SplitID != result.Commitment.SplitID ||
		parsed.DealerDID != result.Commitment.DealerDID {
		t.Fatal("on-log commitment does not match returned commitment")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Negative paths
// ─────────────────────────────────────────────────────────────────────

func TestStoreMappingV2_RejectsEmptyDealerDID(t *testing.T) {
	me := NewMappingEscrow(newV2TestStore(), DefaultMappingEscrowConfig())
	nodes := make([]EscrowNode, me.cfg.TotalShares)
	for i := range nodes {
		nodes[i] = newV2Node(t, "did:web:example.com:node")
	}
	cfg := mkV2Cfg()
	cfg.DealerDID = ""
	_, err := me.StoreMappingV2(mkV2Record(), nodes, cfg)
	if !errors.Is(err, ErrV2MissingDealerDID) {
		t.Fatalf("want ErrV2MissingDealerDID, got %v", err)
	}
}

func TestStoreMappingV2_RejectsEmptyDestination(t *testing.T) {
	me := NewMappingEscrow(newV2TestStore(), DefaultMappingEscrowConfig())
	nodes := make([]EscrowNode, me.cfg.TotalShares)
	for i := range nodes {
		nodes[i] = newV2Node(t, "did:web:example.com:node")
	}
	cfg := mkV2Cfg()
	cfg.Destination = ""
	_, err := me.StoreMappingV2(mkV2Record(), nodes, cfg)
	if !errors.Is(err, ErrV2MissingDestination) {
		t.Fatalf("want ErrV2MissingDestination, got %v", err)
	}
}

func TestStoreMappingV2_RejectsNodeCountMismatch(t *testing.T) {
	me := NewMappingEscrow(newV2TestStore(), DefaultMappingEscrowConfig())
	nodes := make([]EscrowNode, me.cfg.TotalShares-1) // short
	for i := range nodes {
		nodes[i] = newV2Node(t, "did:web:example.com:node")
	}
	_, err := me.StoreMappingV2(mkV2Record(), nodes, mkV2Cfg())
	if !errors.Is(err, ErrNodeCountMismatch) {
		t.Fatalf("want ErrNodeCountMismatch, got %v", err)
	}
}

func TestStoreMappingV2_RejectsZeroIdentity(t *testing.T) {
	me := NewMappingEscrow(newV2TestStore(), DefaultMappingEscrowConfig())
	nodes := make([]EscrowNode, me.cfg.TotalShares)
	for i := range nodes {
		nodes[i] = newV2Node(t, "did:web:example.com:node")
	}
	rec := mkV2Record()
	rec.IdentityHash = [32]byte{}
	_, err := me.StoreMappingV2(rec, nodes, mkV2Cfg())
	if !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("want ErrInvalidIdentity, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// V1 backward-compat — unchanged path
// ─────────────────────────────────────────────────────────────────────

// TestStoreMapping_V1_UnchangedShape confirms that adding the V2 path
// did not change V1's return shape. The V1 StoreMapping still returns
// (stored, encShares, err) exactly as before.
func TestStoreMapping_V1_UnchangedShape(t *testing.T) {
	me := NewMappingEscrow(newV2TestStore(), DefaultMappingEscrowConfig())
	nodes := make([]EscrowNode, me.cfg.TotalShares)
	for i := range nodes {
		nodes[i] = newV2Node(t, "did:web:example.com:node")
	}
	stored, encShares, err := me.StoreMapping(mkV2Record(), nodes)
	if err != nil {
		t.Fatalf("V1 StoreMapping: %v", err)
	}
	if stored == nil || len(encShares) != me.cfg.TotalShares {
		t.Fatal("V1 shape regressed")
	}
}

// TestStoreMappingV2_IndexSeparation confirms V1 and V2 indices do
// not collide: a V2 insert does not populate the V1 index and vice
// versa. Callers must pick one path per identity.
func TestStoreMappingV2_IndexSeparation(t *testing.T) {
	me := NewMappingEscrow(newV2TestStore(), DefaultMappingEscrowConfig())
	nodes := make([]EscrowNode, me.cfg.TotalShares)
	for i := range nodes {
		nodes[i] = newV2Node(t, "did:web:example.com:node")
	}
	rec := mkV2Record()
	if _, err := me.StoreMappingV2(rec, nodes, mkV2Cfg()); err != nil {
		t.Fatalf("StoreMappingV2: %v", err)
	}
	if !me.HasMappingV2(rec.IdentityHash) {
		t.Fatal("V2 index missing entry")
	}
	if me.HasMapping(rec.IdentityHash) {
		t.Fatal("V2 insert leaked into V1 index")
	}
	if got := me.GetStoredV2(rec.IdentityHash); got == nil {
		t.Fatal("GetStoredV2 returned nil after insert")
	}
}

// Compile-time assertion that the store supports the three methods we
// use. Makes the narrow interface contract explicit.
var _ interface {
	Push(storage.CID, []byte) error
	Fetch(storage.CID) ([]byte, error)
	Delete(storage.CID) error
} = (*v2TestStore)(nil)

var _ = elliptic.P256 // keep elliptic imported for future curve helpers
