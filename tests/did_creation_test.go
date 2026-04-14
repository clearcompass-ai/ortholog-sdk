package tests

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/did"
)

// ─────────────────────────────────────────────────────────────────────
// Tests: GenerateDIDKey
// ─────────────────────────────────────────────────────────────────────

func TestGenerateDIDKey_Valid(t *testing.T) {
	kp, err := did.GenerateDIDKey()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(kp.DID, "did:key:f") {
		t.Fatalf("DID should start with did:key:f, got: %s", kp.DID)
	}
	if kp.PrivateKey == nil {
		t.Fatal("private key should not be nil")
	}
	if len(kp.PublicKey) == 0 {
		t.Fatal("public key should not be empty")
	}
	if kp.KeyID == [32]byte{} {
		t.Fatal("key ID should not be zero")
	}
}

func TestGenerateDIDKey_Unique(t *testing.T) {
	kp1, _ := did.GenerateDIDKey()
	kp2, _ := did.GenerateDIDKey()
	if kp1.DID == kp2.DID {
		t.Fatal("two generated DIDs should differ")
	}
	if kp1.KeyID == kp2.KeyID {
		t.Fatal("two key IDs should differ")
	}
}

func TestGenerateDIDKey_PublicKeyDecodable(t *testing.T) {
	kp, _ := did.GenerateDIDKey()
	// Extract hex from did:key:f<hex>
	hexStr := strings.TrimPrefix(kp.DID, "did:key:f")
	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("DID hex not decodable: %v", err)
	}
	if len(decoded) == 0 {
		t.Fatal("decoded key should not be empty")
	}
}

func TestGenerateRawKey(t *testing.T) {
	priv, pubBytes, err := did.GenerateRawKey()
	if err != nil {
		t.Fatal(err)
	}
	if priv == nil {
		t.Fatal("private key nil")
	}
	if len(pubBytes) == 0 {
		t.Fatal("public key empty")
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
		PublicKeys:            []string{"aabbccdd"},
		WitnessQuorumK:        1,
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

func TestCreateDIDDocument_MultipleKeys(t *testing.T) {
	doc, _ := did.CreateDIDDocument(did.CreateDIDDocumentConfig{
		DID:        "did:web:test",
		PublicKeys: []string{"key1hex", "key2hex", "key3hex"},
	})
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

func TestCreateDIDDocument_ServiceIDs(t *testing.T) {
	doc, _ := did.CreateDIDDocument(did.CreateDIDDocumentConfig{
		DID:              "did:web:test",
		OperatorEndpoint: "https://op.test",
		WitnessEndpoints: []string{"https://w.test"},
	})
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
