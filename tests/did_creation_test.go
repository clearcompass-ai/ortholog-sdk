package tests

import (
	"strings"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/did"
)

// ─────────────────────────────────────────────────────────────────────
// Tests: GenerateDIDKeySecp256k1
// ─────────────────────────────────────────────────────────────────────

func TestGenerateDIDKeySecp256k1_Valid(t *testing.T) {
	kp, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(kp.DID, "did:key:z") {
		t.Fatalf("DID should start with did:key:z, got: %s", kp.DID)
	}
	if kp.PrivateKey == nil {
		t.Fatal("private key should not be nil")
	}
	if len(kp.PublicKeyCompressed) != 33 {
		t.Fatalf("compressed pubkey should be 33 bytes, got %d", len(kp.PublicKeyCompressed))
	}
	if len(kp.PublicKeyUncompressed) != 65 {
		t.Fatalf("uncompressed pubkey should be 65 bytes, got %d", len(kp.PublicKeyUncompressed))
	}
	if kp.KeyID == [32]byte{} {
		t.Fatal("key ID should not be zero")
	}
}

func TestGenerateDIDKeySecp256k1_Unique(t *testing.T) {
	kp1, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatal(err)
	}
	kp2, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatal(err)
	}
	if kp1.DID == kp2.DID {
		t.Fatal("two generated DIDs should differ")
	}
	if kp1.KeyID == kp2.KeyID {
		t.Fatal("two key IDs should differ")
	}
}

func TestGenerateDIDKeySecp256k1_RoundTripParse(t *testing.T) {
	kp, err := did.GenerateDIDKeySecp256k1()
	if err != nil {
		t.Fatal(err)
	}
	pubKey, vmType, err := did.ParseDIDKey(kp.DID)
	if err != nil {
		t.Fatalf("ParseDIDKey: %v", err)
	}
	if vmType != did.VerificationMethodSecp256k1 {
		t.Fatalf("verification type: %s, expected %s", vmType, did.VerificationMethodSecp256k1)
	}
	if len(pubKey) != 33 {
		t.Fatalf("parsed compressed pubkey should be 33 bytes, got %d", len(pubKey))
	}
	// Round-trip must recover the exact compressed pubkey we generated.
	if string(pubKey) != string(kp.PublicKeyCompressed) {
		t.Fatal("parsed pubkey does not match generated pubkey")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Tests: GenerateDIDKeyEd25519
// ─────────────────────────────────────────────────────────────────────

func TestGenerateDIDKeyEd25519_Valid(t *testing.T) {
	kp, err := did.GenerateDIDKeyEd25519()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(kp.DID, "did:key:z") {
		t.Fatalf("DID should start with did:key:z, got: %s", kp.DID)
	}
	if len(kp.PrivateKey) == 0 {
		t.Fatal("private key should not be empty")
	}
	if len(kp.PublicKey) != 32 {
		t.Fatalf("Ed25519 pubkey should be 32 bytes, got %d", len(kp.PublicKey))
	}
	if kp.KeyID == [32]byte{} {
		t.Fatal("key ID should not be zero")
	}
}

func TestGenerateDIDKeyEd25519_RoundTripParse(t *testing.T) {
	kp, err := did.GenerateDIDKeyEd25519()
	if err != nil {
		t.Fatal(err)
	}
	pubKey, vmType, err := did.ParseDIDKey(kp.DID)
	if err != nil {
		t.Fatalf("ParseDIDKey: %v", err)
	}
	if vmType != did.VerificationMethodEd25519 {
		t.Fatalf("verification type: %s, expected %s", vmType, did.VerificationMethodEd25519)
	}
	if len(pubKey) != 32 {
		t.Fatalf("parsed Ed25519 pubkey should be 32 bytes, got %d", len(pubKey))
	}
	if string(pubKey) != string(kp.PublicKey) {
		t.Fatal("parsed pubkey does not match generated pubkey")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Tests: GenerateDIDKeyP256
// ─────────────────────────────────────────────────────────────────────

func TestGenerateDIDKeyP256_Valid(t *testing.T) {
	kp, err := did.GenerateDIDKeyP256()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(kp.DID, "did:key:z") {
		t.Fatalf("DID should start with did:key:z, got: %s", kp.DID)
	}
	if kp.PrivateKey == nil {
		t.Fatal("private key should not be nil")
	}
	if len(kp.PublicKeyCompressed) != 33 {
		t.Fatalf("P-256 compressed pubkey should be 33 bytes, got %d", len(kp.PublicKeyCompressed))
	}
	if kp.KeyID == [32]byte{} {
		t.Fatal("key ID should not be zero")
	}
}

func TestGenerateDIDKeyP256_RoundTripParse(t *testing.T) {
	kp, err := did.GenerateDIDKeyP256()
	if err != nil {
		t.Fatal(err)
	}
	pubKey, vmType, err := did.ParseDIDKey(kp.DID)
	if err != nil {
		t.Fatalf("ParseDIDKey: %v", err)
	}
	if vmType != did.VerificationMethodP256 {
		t.Fatalf("verification type: %s, expected %s", vmType, did.VerificationMethodP256)
	}
	if len(pubKey) != 33 {
		t.Fatalf("parsed P-256 compressed pubkey should be 33 bytes, got %d", len(pubKey))
	}
}

// ─────────────────────────────────────────────────────────────────────
// Tests: GenerateRawKey
// ─────────────────────────────────────────────────────────────────────

func TestGenerateRawKey(t *testing.T) {
	priv, pubBytes, err := did.GenerateRawKey()
	if err != nil {
		t.Fatal(err)
	}
	if priv == nil {
		t.Fatal("private key nil")
	}
	if len(pubBytes) != 65 {
		t.Fatalf("raw pubkey should be 65 bytes uncompressed, got %d", len(pubBytes))
	}
}

// ─────────────────────────────────────────────────────────────────────
// Tests: CreateDIDDocument
// ─────────────────────────────────────────────────────────────────────

func TestCreateDIDDocument_Full(t *testing.T) {
	doc, err := did.CreateDIDDocument(did.CreateDIDDocumentConfig{
		DID:                   "did:web:court.example.com",
		OperatorEndpoint:      "https://operator.court.example.com",
		WitnessEndpoints:      []string{"https://witness1.example.com", "https://witness2.example.com"},
		ArtifactStoreEndpoint: "https://artifacts.example.com",
		PublicKeys: []did.PublicKeyEntry{
			{VerificationMethodType: did.VerificationMethodSecp256k1, PublicKeyHex: "aabbccdd"},
		},
		WitnessQuorumK: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if doc.ID != "did:web:court.example.com" {
		t.Fatalf("id: %s", doc.ID)
	}
	if len(doc.Context) != 2 {
		t.Fatalf("context: %d", len(doc.Context))
	}
	if len(doc.VerificationMethod) != 1 {
		t.Fatalf("verification methods: %d", len(doc.VerificationMethod))
	}
	if doc.VerificationMethod[0].PublicKeyHex != "aabbccdd" {
		t.Fatal("public key mismatch")
	}
	if doc.VerificationMethod[0].Type != did.VerificationMethodSecp256k1 {
		t.Fatalf("VM type: %s", doc.VerificationMethod[0].Type)
	}
	if len(doc.Service) != 4 { // operator + 2 witnesses + artifact store
		t.Fatalf("services: %d", len(doc.Service))
	}
	if doc.WitnessQuorumK != 1 {
		t.Fatalf("quorumK: %d", doc.WitnessQuorumK)
	}
	if doc.Created == nil {
		t.Fatal("created should be set")
	}
}

func TestCreateDIDDocument_MinimalNoServices(t *testing.T) {
	doc, err := did.CreateDIDDocument(did.CreateDIDDocumentConfig{
		DID: "did:web:minimal.example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	if doc.ID != "did:web:minimal.example.com" {
		t.Fatalf("id: %s", doc.ID)
	}
	if len(doc.Service) != 0 {
		t.Fatalf("services: %d (expected 0)", len(doc.Service))
	}
	if len(doc.VerificationMethod) != 0 {
		t.Fatalf("keys: %d (expected 0)", len(doc.VerificationMethod))
	}
}

func TestCreateDIDDocument_EmptyDID_Error(t *testing.T) {
	_, err := did.CreateDIDDocument(did.CreateDIDDocumentConfig{})
	if err == nil {
		t.Fatal("empty DID should error")
	}
}

func TestCreateDIDDocument_MissingVMType_Error(t *testing.T) {
	_, err := did.CreateDIDDocument(did.CreateDIDDocumentConfig{
		DID: "did:web:test",
		PublicKeys: []did.PublicKeyEntry{
			{PublicKeyHex: "aabbcc"}, // no VerificationMethodType
		},
	})
	if err == nil {
		t.Fatal("missing VerificationMethodType should error")
	}
}

func TestCreateDIDDocument_MissingPubkeyHex_Error(t *testing.T) {
	_, err := did.CreateDIDDocument(did.CreateDIDDocumentConfig{
		DID: "did:web:test",
		PublicKeys: []did.PublicKeyEntry{
			{VerificationMethodType: did.VerificationMethodSecp256k1}, // no PublicKeyHex
		},
	})
	if err == nil {
		t.Fatal("missing PublicKeyHex should error")
	}
}

func TestCreateDIDDocument_MultipleKeys(t *testing.T) {
	doc, err := did.CreateDIDDocument(did.CreateDIDDocumentConfig{
		DID: "did:web:test",
		PublicKeys: []did.PublicKeyEntry{
			{VerificationMethodType: did.VerificationMethodSecp256k1, PublicKeyHex: "key1hex"},
			{VerificationMethodType: did.VerificationMethodSecp256k1, PublicKeyHex: "key2hex"},
			{VerificationMethodType: did.VerificationMethodSecp256k1, PublicKeyHex: "key3hex"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.VerificationMethod) != 3 {
		t.Fatalf("keys: %d", len(doc.VerificationMethod))
	}
	// Verify key IDs are sequential.
	for i, vm := range doc.VerificationMethod {
		expected := "did:web:test#key-" + string(rune('0'+i))
		if vm.ID != expected {
			t.Fatalf("key[%d] id: %s, expected %s", i, vm.ID, expected)
		}
	}
}

func TestCreateDIDDocument_MixedCurveKeys(t *testing.T) {
	// A single DID document may hold keys across multiple curves — Ortholog
	// supports this via per-key VerificationMethodType.
	doc, err := did.CreateDIDDocument(did.CreateDIDDocumentConfig{
		DID: "did:web:multi.example.com",
		PublicKeys: []did.PublicKeyEntry{
			{VerificationMethodType: did.VerificationMethodSecp256k1, PublicKeyHex: "aabb"},
			{VerificationMethodType: did.VerificationMethodEd25519, PublicKeyHex: "ccdd"},
			{VerificationMethodType: did.VerificationMethodP256, PublicKeyHex: "eeff"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.VerificationMethod) != 3 {
		t.Fatalf("keys: %d", len(doc.VerificationMethod))
	}
	types := []string{
		doc.VerificationMethod[0].Type,
		doc.VerificationMethod[1].Type,
		doc.VerificationMethod[2].Type,
	}
	expected := []string{
		did.VerificationMethodSecp256k1,
		did.VerificationMethodEd25519,
		did.VerificationMethodP256,
	}
	for i := range types {
		if types[i] != expected[i] {
			t.Fatalf("key[%d] type: %s, expected %s", i, types[i], expected[i])
		}
	}
}

func TestCreateDIDDocument_ServiceIDs(t *testing.T) {
	doc, err := did.CreateDIDDocument(did.CreateDIDDocumentConfig{
		DID:              "did:web:test",
		OperatorEndpoint: "https://op.test",
		WitnessEndpoints: []string{"https://w.test"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if doc.Service[0].ID != "did:web:test#operator" {
		t.Fatalf("operator service id: %s", doc.Service[0].ID)
	}
	if doc.Service[1].ID != "did:web:test#witness-0" {
		t.Fatalf("witness service id: %s", doc.Service[1].ID)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Tests: NewWebDID
// ─────────────────────────────────────────────────────────────────────

func TestNewWebDID_DomainOnly(t *testing.T) {
	d := did.NewWebDID("court.example.com", "")
	if d != "did:web:court.example.com" {
		t.Fatalf("did: %s", d)
	}
}

func TestNewWebDID_WithPath(t *testing.T) {
	d := did.NewWebDID("example.com", "logs/court-01")
	if d != "did:web:example.com:logs:court-01" {
		t.Fatalf("did: %s", d)
	}
}

func TestNewWebDID_NestedPath(t *testing.T) {
	d := did.NewWebDID("example.com", "a/b/c/d")
	if d != "did:web:example.com:a:b:c:d" {
		t.Fatalf("did: %s", d)
	}
}
