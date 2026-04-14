package tests

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/did"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

func serveDIDDoc(doc did.DIDDocument) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(doc)
	}))
}

func makeSampleDIDDoc(didStr string) did.DIDDocument {
	priv, _ := signatures.GenerateKey()
	pubBytes := signatures.PubKeyBytes(&priv.PublicKey)
	return did.DIDDocument{
		Context: []string{"https://www.w3.org/ns/did/v1"},
		ID:      didStr,
		VerificationMethod: []did.VerificationMethod{
			{ID: didStr + "#key-0", Type: "EcdsaSecp256r1VerificationKey2019",
				Controller: didStr, PublicKeyHex: hex.EncodeToString(pubBytes)},
		},
		Service: []did.Service{
			{ID: didStr + "#operator", Type: did.ServiceTypeOperator, ServiceEndpoint: "https://operator.example.com"},
			{ID: didStr + "#witness-0", Type: did.ServiceTypeWitness, ServiceEndpoint: "https://witness1.example.com"},
			{ID: didStr + "#witness-1", Type: did.ServiceTypeWitness, ServiceEndpoint: "https://witness2.example.com"},
			{ID: didStr + "#artifact-store", Type: did.ServiceTypeArtifactStore, ServiceEndpoint: "https://artifacts.example.com"},
		},
		WitnessQuorumK: 1,
	}
}

// ─────────────────────────────────────────────────────────────────────
// Tests: DIDWebToURL
// ─────────────────────────────────────────────────────────────────────

func TestDIDWebToURL_RootDomain(t *testing.T) {
	url, err := did.DIDWebToURL("did:web:example.com")
	if err != nil {
		t.Fatal(err)
	}
	if url != "https://example.com/.well-known/did.json" {
		t.Fatalf("url: %s", url)
	}
}

func TestDIDWebToURL_WithPath(t *testing.T) {
	url, err := did.DIDWebToURL("did:web:example.com:path:to:resource")
	if err != nil {
		t.Fatal(err)
	}
	if url != "https://example.com/path/to/resource/did.json" {
		t.Fatalf("url: %s", url)
	}
}

func TestDIDWebToURL_SinglePathSegment(t *testing.T) {
	url, err := did.DIDWebToURL("did:web:example.com:logs")
	if err != nil {
		t.Fatal(err)
	}
	if url != "https://example.com/logs/did.json" {
		t.Fatalf("url: %s", url)
	}
}

func TestDIDWebToURL_NotWeb_Error(t *testing.T) {
	_, err := did.DIDWebToURL("did:key:abc123")
	if !errors.Is(err, did.ErrDIDMethodNotSupported) {
		t.Fatalf("expected ErrDIDMethodNotSupported, got: %v", err)
	}
}

func TestDIDWebToURL_EmptyDomain_Error(t *testing.T) {
	_, err := did.DIDWebToURL("did:web:")
	if err == nil {
		t.Fatal("empty domain should error")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Tests: WebDIDResolver (via mock HTTP server)
// ─────────────────────────────────────────────────────────────────────

func TestWebDIDResolver_FetchAndParse(t *testing.T) {
	doc := makeSampleDIDDoc("did:web:test.example.com")
	ts := serveDIDDoc(doc)
	defer ts.Close()

	resolver := &httpTestResolver{baseURL: ts.URL}
	result, err := resolver.Resolve("did:web:test.example.com")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if result.ID != "did:web:test.example.com" {
		t.Fatalf("id: %s", result.ID)
	}
	if len(result.VerificationMethod) != 1 {
		t.Fatalf("verification methods: %d", len(result.VerificationMethod))
	}
	if len(result.Service) != 4 {
		t.Fatalf("services: %d", len(result.Service))
	}
}

func TestWebDIDResolver_NotFound_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	resolver := &httpTestResolver{baseURL: ts.URL}
	_, err := resolver.Resolve("did:web:missing")
	if !errors.Is(err, did.ErrDIDNotFound) {
		t.Fatalf("expected ErrDIDNotFound, got: %v", err)
	}
}

func TestWebDIDResolver_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	resolver := &httpTestResolver{baseURL: ts.URL}
	_, err := resolver.Resolve("did:web:error")
	if err == nil {
		t.Fatal("server error should propagate")
	}
}

func TestWebDIDResolver_NilClient_UsesDefault(t *testing.T) {
	r := did.NewWebDIDResolver(nil)
	if r == nil {
		t.Fatal("should create resolver with default client")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Tests: DIDDocument helpers
// ─────────────────────────────────────────────────────────────────────

func TestDIDDoc_OperatorEndpointURL(t *testing.T) {
	doc := makeSampleDIDDoc("did:web:test")
	url, err := doc.OperatorEndpointURL()
	if err != nil {
		t.Fatal(err)
	}
	if url != "https://operator.example.com" {
		t.Fatalf("url: %s", url)
	}
}

func TestDIDDoc_OperatorEndpointURL_Missing(t *testing.T) {
	doc := did.DIDDocument{ID: "did:web:empty"}
	_, err := doc.OperatorEndpointURL()
	if err == nil {
		t.Fatal("missing operator should error")
	}
}

func TestDIDDoc_WitnessEndpointURLs(t *testing.T) {
	doc := makeSampleDIDDoc("did:web:test")
	urls := doc.WitnessEndpointURLs()
	if len(urls) != 2 {
		t.Fatalf("witness endpoints: %d", len(urls))
	}
}

func TestDIDDoc_WitnessEndpointURLs_Empty(t *testing.T) {
	doc := did.DIDDocument{ID: "did:web:empty"}
	urls := doc.WitnessEndpointURLs()
	if len(urls) != 0 {
		t.Fatal("should be empty")
	}
}

func TestDIDDoc_ArtifactStoreURL(t *testing.T) {
	doc := makeSampleDIDDoc("did:web:test")
	url, err := doc.ArtifactStoreURL()
	if err != nil {
		t.Fatal(err)
	}
	if url != "https://artifacts.example.com" {
		t.Fatalf("url: %s", url)
	}
}

func TestDIDDoc_WitnessKeys(t *testing.T) {
	doc := makeSampleDIDDoc("did:web:test")
	keys, err := doc.WitnessKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("witness keys: %d", len(keys))
	}
	if len(keys[0].PublicKey) == 0 {
		t.Fatal("public key empty")
	}
	if keys[0].ID == [32]byte{} {
		t.Fatal("key ID should not be zero")
	}
}

func TestDIDDoc_WitnessKeys_Multibase(t *testing.T) {
	priv, _ := signatures.GenerateKey()
	pubBytes := signatures.PubKeyBytes(&priv.PublicKey)
	doc := did.DIDDocument{
		ID: "did:web:test",
		VerificationMethod: []did.VerificationMethod{
			{ID: "did:web:test#key-0", Type: "EcdsaSecp256r1VerificationKey2019",
				Controller: "did:web:test", PublicKeyMultibase: "f" + hex.EncodeToString(pubBytes)},
		},
	}
	keys, _ := doc.WitnessKeys()
	if len(keys) != 1 {
		t.Fatalf("keys: %d", len(keys))
	}
}

func TestDIDDoc_WitnessKeys_NoKeys(t *testing.T) {
	doc := did.DIDDocument{ID: "did:web:empty"}
	keys, _ := doc.WitnessKeys()
	if len(keys) != 0 {
		t.Fatal("should be empty")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Tests: CachingResolver
// ─────────────────────────────────────────────────────────────────────

func TestCachingResolver_Hit(t *testing.T) {
	var calls atomic.Int64
	inner := &countingDIDRes{doc: makeSampleDIDDoc("did:web:cached"), calls: &calls}
	resolver := did.NewCachingResolver(inner, 1*time.Minute)

	resolver.Resolve("did:web:cached")
	resolver.Resolve("did:web:cached")
	if calls.Load() != 1 {
		t.Fatalf("expected 1 inner call, got %d", calls.Load())
	}
}

func TestCachingResolver_Expiry(t *testing.T) {
	var calls atomic.Int64
	inner := &countingDIDRes{doc: makeSampleDIDDoc("did:web:expire"), calls: &calls}
	resolver := did.NewCachingResolver(inner, 50*time.Millisecond)

	resolver.Resolve("did:web:expire")
	time.Sleep(100 * time.Millisecond)
	resolver.Resolve("did:web:expire")
	if calls.Load() != 2 {
		t.Fatalf("after expiry: expected 2, got %d", calls.Load())
	}
}

func TestCachingResolver_Invalidate(t *testing.T) {
	var calls atomic.Int64
	inner := &countingDIDRes{doc: makeSampleDIDDoc("did:web:inv"), calls: &calls}
	resolver := did.NewCachingResolver(inner, 1*time.Minute)

	resolver.Resolve("did:web:inv")
	resolver.InvalidateCache("did:web:inv")
	resolver.Resolve("did:web:inv")
	if calls.Load() != 2 {
		t.Fatalf("after invalidate: expected 2, got %d", calls.Load())
	}
}

func TestCachingResolver_Size(t *testing.T) {
	inner := &countingDIDRes{doc: makeSampleDIDDoc("did:web:a"), calls: new(atomic.Int64)}
	resolver := did.NewCachingResolver(inner, 1*time.Minute)
	if resolver.CacheSize() != 0 {
		t.Fatal("initial: 0")
	}
	resolver.Resolve("did:web:a")
	if resolver.CacheSize() != 1 {
		t.Fatal("after one: 1")
	}
}

func TestCachingResolver_ErrorNotCached(t *testing.T) {
	inner := &failingDIDRes{err: errors.New("network")}
	resolver := did.NewCachingResolver(inner, 1*time.Minute)
	resolver.Resolve("did:web:fail")
	if resolver.CacheSize() != 0 {
		t.Fatal("errors should not be cached")
	}
}

func TestCachingResolver_DefaultTTL(t *testing.T) {
	var calls atomic.Int64
	inner := &countingDIDRes{doc: makeSampleDIDDoc("did:web:x"), calls: &calls}
	resolver := did.NewCachingResolver(inner, 0)
	resolver.Resolve("did:web:x")
	resolver.Resolve("did:web:x")
	if calls.Load() != 1 {
		t.Fatal("default TTL should cache")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Tests: Adapters
// ─────────────────────────────────────────────────────────────────────

func TestEndpointAdapter_Operator(t *testing.T) {
	inner := &staticDIDRes{doc: makeSampleDIDDoc("did:web:test")}
	adapter := &did.DIDEndpointAdapter{Resolver: inner}
	url, err := adapter.OperatorEndpoint("did:web:test")
	if err != nil {
		t.Fatal(err)
	}
	if url != "https://operator.example.com" {
		t.Fatalf("url: %s", url)
	}
}

func TestEndpointAdapter_Witnesses(t *testing.T) {
	inner := &staticDIDRes{doc: makeSampleDIDDoc("did:web:test")}
	adapter := &did.DIDEndpointAdapter{Resolver: inner}
	urls, _ := adapter.WitnessEndpoints("did:web:test")
	if len(urls) != 2 {
		t.Fatalf("urls: %d", len(urls))
	}
}

func TestWitnessAdapter_Keys(t *testing.T) {
	inner := &staticDIDRes{doc: makeSampleDIDDoc("did:web:test")}
	adapter := &did.DIDWitnessAdapter{Resolver: inner}
	keys, quorumK, err := adapter.ResolveWitnessKeys("did:web:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 {
		t.Fatalf("keys: %d", len(keys))
	}
	if quorumK != 1 {
		t.Fatalf("quorumK: %d", quorumK)
	}
}

func TestWitnessAdapter_DefaultQuorum(t *testing.T) {
	doc := makeSampleDIDDoc("did:web:test")
	doc.WitnessQuorumK = 0
	for i := 0; i < 4; i++ {
		priv, _ := signatures.GenerateKey()
		pubBytes := signatures.PubKeyBytes(&priv.PublicKey)
		doc.VerificationMethod = append(doc.VerificationMethod, did.VerificationMethod{
			ID: fmt.Sprintf("did:web:test#key-%d", i+1), Type: "EcdsaSecp256r1VerificationKey2019",
			Controller: "did:web:test", PublicKeyHex: hex.EncodeToString(pubBytes),
		})
	}
	adapter := &did.DIDWitnessAdapter{Resolver: &staticDIDRes{doc: doc}}
	keys, quorumK, _ := adapter.ResolveWitnessKeys("did:web:test")
	expected := len(keys)/2 + 1
	if quorumK != expected {
		t.Fatalf("default quorum: expected %d, got %d", expected, quorumK)
	}
}

func TestWitnessAdapter_Error(t *testing.T) {
	adapter := &did.DIDWitnessAdapter{Resolver: &failingDIDRes{err: errors.New("net")}}
	_, _, err := adapter.ResolveWitnessKeys("did:web:fail")
	if err == nil {
		t.Fatal("should propagate")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Mock resolvers (for did tests)
// ─────────────────────────────────────────────────────────────────────

type httpTestResolver struct{ baseURL string }

func (r *httpTestResolver) Resolve(didStr string) (*did.DIDDocument, error) {
	resp, err := http.Get(r.baseURL + "/.well-known/did.json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return nil, did.ErrDIDNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	var doc did.DIDDocument
	json.NewDecoder(resp.Body).Decode(&doc)
	return &doc, nil
}

type countingDIDRes struct {
	doc   did.DIDDocument
	calls *atomic.Int64
}

func (r *countingDIDRes) Resolve(string) (*did.DIDDocument, error) {
	r.calls.Add(1)
	return &r.doc, nil
}

type staticDIDRes struct{ doc did.DIDDocument }

func (r *staticDIDRes) Resolve(string) (*did.DIDDocument, error) { return &r.doc, nil }

type failingDIDRes struct{ err error }

func (r *failingDIDRes) Resolve(string) (*did.DIDDocument, error) { return nil, r.err }

// Suppress unused imports.
var (
	_ = types.WitnessPublicKey{}
	_ = sha256.Sum256
)
