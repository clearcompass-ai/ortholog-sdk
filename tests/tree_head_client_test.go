/*
FILE PATH:

	tests/tree_head_client_test.go

DESCRIPTION:

	External black-box integration tests for witness.TreeHeadClient.
	Exercises public API (FetchLatestTreeHead, FetchFromURL, CachedHead,
	InvalidateCache, CacheSize) through HTTP test servers.

	BUG-012 CUTOVER UPDATE:
	  - All mock server responses now emit the post-cutover JSON:
	    {"pubkey_id": "<hex>", "sig_algo": N, "signature": "<hex>"}
	  - The pre-cutover "signer" string is no longer produced anywhere
	    in this file. A signature without pubkey_id is a wire-format
	    violation under the new contract and the parser rejects it.
	  - The dedicated wire-contract regression tests (missing pubkey_id,
	    wrong length, malformed hex) live next to the parser, in
	    witness/tree_head_client_test.go as white-box tests.

	Unit-level parser tests do not belong in this file. This file
	exercises the network path, the cache, the fallback ladder, and
	the static endpoint provider.
*/
package tests

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/types"
	"github.com/clearcompass-ai/ortholog-sdk/witness"
)

// ─────────────────────────────────────────────────────────────────────
// Test helpers
// ─────────────────────────────────────────────────────────────────────

// pubKeyIDHex returns a hex-encoded 32-byte pubkey_id derived by
// hashing a label. Used only to populate valid-shape fixtures in
// these integration tests — no verifier lookup is performed here,
// so the specific bytes don't matter as long as they're 32 bytes.
func pubKeyIDHex(label string) string {
	sum := sha256.Sum256([]byte(label))
	return hex.EncodeToString(sum[:])
}

// ─────────────────────────────────────────────────────────────────────
// Mock HTTP servers
// ─────────────────────────────────────────────────────────────────────

// newMockOperatorServer emits the minimal valid post-cutover response:
// tree_size + root_hash, no signatures. Used by tests that exercise
// the network / cache path and don't care about signature content.
func newMockOperatorServer(treeSize uint64, rootHash [32]byte) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/tree/head" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tree_size": treeSize,
			"root_hash": hex.EncodeToString(rootHash[:]),
			"hash_algo": 1,
		})
	}))
}

func newCountingOperatorServer(treeSize uint64) (*httptest.Server, *atomic.Int64) {
	var count atomic.Int64
	rootHash := sha256.Sum256([]byte(fmt.Sprintf("root-%d", treeSize)))
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tree_size": treeSize,
			"root_hash": hex.EncodeToString(rootHash[:]),
		})
	}))
	return ts, &count
}

func newFailingServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
}

// ─────────────────────────────────────────────────────────────────────
// Tests: FetchLatestTreeHead — basic
// ─────────────────────────────────────────────────────────────────────

func TestTreeHeadClient_FetchBasic(t *testing.T) {
	rootHash := sha256.Sum256([]byte("test-root"))
	ts := newMockOperatorServer(1000, rootHash)
	defer ts.Close()

	endpoints := &witness.StaticEndpoints{
		Operators: map[string]string{"did:test:log1": ts.URL},
	}
	client := witness.NewTreeHeadClient(endpoints, witness.DefaultTreeHeadClientConfig())

	head, fetchedAt, err := client.FetchLatestTreeHead("did:test:log1")
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if head.TreeSize != 1000 {
		t.Fatalf("tree_size: %d", head.TreeSize)
	}
	if head.RootHash != rootHash {
		t.Fatal("root_hash mismatch")
	}
	if fetchedAt.IsZero() {
		t.Fatal("fetchedAt should not be zero")
	}
}

func TestTreeHeadClient_FetchUnknownDID_Error(t *testing.T) {
	endpoints := &witness.StaticEndpoints{
		Operators: map[string]string{},
	}
	client := witness.NewTreeHeadClient(endpoints, witness.DefaultTreeHeadClientConfig())

	_, _, err := client.FetchLatestTreeHead("did:test:unknown")
	if err == nil {
		t.Fatal("unknown DID should error")
	}
}

func TestTreeHeadClient_FetchServerError_Error(t *testing.T) {
	ts := newFailingServer()
	defer ts.Close()

	endpoints := &witness.StaticEndpoints{
		Operators: map[string]string{"did:test:fail": ts.URL},
	}
	client := witness.NewTreeHeadClient(endpoints, witness.DefaultTreeHeadClientConfig())

	_, _, err := client.FetchLatestTreeHead("did:test:fail")
	if err == nil {
		t.Fatal("server error should propagate")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Tests: Cache behavior
// ─────────────────────────────────────────────────────────────────────

func TestTreeHeadClient_CacheHit_NoHTTPCall(t *testing.T) {
	ts, count := newCountingOperatorServer(2000)
	defer ts.Close()

	endpoints := &witness.StaticEndpoints{
		Operators: map[string]string{"did:test:cached": ts.URL},
	}
	cfg := witness.TreeHeadClientConfig{CacheTTL: 1 * time.Minute, HTTPTimeout: 5 * time.Second}
	client := witness.NewTreeHeadClient(endpoints, cfg)

	// First call → HTTP.
	_, _, _ = client.FetchLatestTreeHead("did:test:cached")
	if count.Load() != 1 {
		t.Fatalf("first call: expected 1 HTTP call, got %d", count.Load())
	}

	// Second call → cache hit, no HTTP.
	head, _, err := client.FetchLatestTreeHead("did:test:cached")
	if err != nil {
		t.Fatal(err)
	}
	if count.Load() != 1 {
		t.Fatalf("second call: expected still 1 HTTP call, got %d", count.Load())
	}
	if head.TreeSize != 2000 {
		t.Fatalf("cached tree_size: %d", head.TreeSize)
	}
}

func TestTreeHeadClient_CacheExpiry_RefreshesHTTP(t *testing.T) {
	ts, count := newCountingOperatorServer(3000)
	defer ts.Close()

	endpoints := &witness.StaticEndpoints{
		Operators: map[string]string{"did:test:expire": ts.URL},
	}
	cfg := witness.TreeHeadClientConfig{
		CacheTTL:    50 * time.Millisecond, // Very short TTL.
		HTTPTimeout: 5 * time.Second,
	}
	client := witness.NewTreeHeadClient(endpoints, cfg)

	// First call.
	_, _, _ = client.FetchLatestTreeHead("did:test:expire")
	if count.Load() != 1 {
		t.Fatal("first: expected 1")
	}

	// Wait for TTL to expire.
	time.Sleep(100 * time.Millisecond)

	// Third call → cache expired → HTTP.
	_, _, _ = client.FetchLatestTreeHead("did:test:expire")
	if count.Load() != 2 {
		t.Fatalf("after expiry: expected 2, got %d", count.Load())
	}
}

func TestTreeHeadClient_CacheKeyedByDID(t *testing.T) {
	ts1, count1 := newCountingOperatorServer(100)
	ts2, count2 := newCountingOperatorServer(200)
	defer ts1.Close()
	defer ts2.Close()

	endpoints := &witness.StaticEndpoints{
		Operators: map[string]string{
			"did:test:log-a": ts1.URL,
			"did:test:log-b": ts2.URL,
		},
	}
	client := witness.NewTreeHeadClient(endpoints, witness.DefaultTreeHeadClientConfig())

	headA, _, _ := client.FetchLatestTreeHead("did:test:log-a")
	headB, _, _ := client.FetchLatestTreeHead("did:test:log-b")

	if headA.TreeSize != 100 {
		t.Fatalf("A: %d", headA.TreeSize)
	}
	if headB.TreeSize != 200 {
		t.Fatalf("B: %d", headB.TreeSize)
	}
	if count1.Load() != 1 || count2.Load() != 1 {
		t.Fatal("each DID should trigger exactly 1 HTTP call")
	}

	// Second fetch of A → cache, no HTTP.
	client.FetchLatestTreeHead("did:test:log-a")
	if count1.Load() != 1 {
		t.Fatal("A cache should prevent second HTTP")
	}
}

func TestTreeHeadClient_CacheSize(t *testing.T) {
	client := witness.NewTreeHeadClient(
		&witness.StaticEndpoints{Operators: map[string]string{}},
		witness.DefaultTreeHeadClientConfig(),
	)
	if client.CacheSize() != 0 {
		t.Fatal("empty client should have 0 cache entries")
	}
}

func TestTreeHeadClient_InvalidateCache(t *testing.T) {
	ts, count := newCountingOperatorServer(4000)
	defer ts.Close()

	endpoints := &witness.StaticEndpoints{
		Operators: map[string]string{"did:test:invalidate": ts.URL},
	}
	client := witness.NewTreeHeadClient(endpoints, witness.DefaultTreeHeadClientConfig())

	client.FetchLatestTreeHead("did:test:invalidate")
	if count.Load() != 1 {
		t.Fatal("first: 1")
	}

	// Invalidate.
	client.InvalidateCache("did:test:invalidate")

	// Next fetch → HTTP (cache cleared).
	client.FetchLatestTreeHead("did:test:invalidate")
	if count.Load() != 2 {
		t.Fatalf("after invalidate: expected 2, got %d", count.Load())
	}
}

func TestTreeHeadClient_CachedHead_Direct(t *testing.T) {
	ts := newMockOperatorServer(5000, sha256.Sum256([]byte("r")))
	defer ts.Close()

	endpoints := &witness.StaticEndpoints{
		Operators: map[string]string{"did:test:direct": ts.URL},
	}
	client := witness.NewTreeHeadClient(endpoints, witness.DefaultTreeHeadClientConfig())

	// Before any fetch → not cached.
	_, _, ok := client.CachedHead("did:test:direct")
	if ok {
		t.Fatal("should not be cached before first fetch")
	}

	// Fetch.
	client.FetchLatestTreeHead("did:test:direct")

	// Now cached.
	head, fetchedAt, ok := client.CachedHead("did:test:direct")
	if !ok {
		t.Fatal("should be cached after fetch")
	}
	if head.TreeSize != 5000 {
		t.Fatalf("cached: %d", head.TreeSize)
	}
	if fetchedAt.IsZero() {
		t.Fatal("fetchedAt zero")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Tests: Fallback to witness endpoints
// ─────────────────────────────────────────────────────────────────────

func TestTreeHeadClient_FallbackToWitness(t *testing.T) {
	failingOP := newFailingServer()
	defer failingOP.Close()

	rootHash := sha256.Sum256([]byte("witness-root"))
	witnessServer := newMockOperatorServer(6000, rootHash)
	defer witnessServer.Close()

	endpoints := &witness.StaticEndpoints{
		Operators: map[string]string{"did:test:fallback": failingOP.URL},
		Witnesses: map[string][]string{"did:test:fallback": {witnessServer.URL}},
	}
	client := witness.NewTreeHeadClient(endpoints, witness.DefaultTreeHeadClientConfig())

	head, _, err := client.FetchLatestTreeHead("did:test:fallback")
	if err != nil {
		t.Fatalf("fallback should succeed: %v", err)
	}
	if head.TreeSize != 6000 {
		t.Fatalf("fallback tree_size: %d", head.TreeSize)
	}
}

func TestTreeHeadClient_FallbackMultipleWitnesses(t *testing.T) {
	failingOP := newFailingServer()
	defer failingOP.Close()

	failingWitness := newFailingServer()
	defer failingWitness.Close()

	rootHash := sha256.Sum256([]byte("second-witness"))
	goodWitness := newMockOperatorServer(7000, rootHash)
	defer goodWitness.Close()

	endpoints := &witness.StaticEndpoints{
		Operators: map[string]string{"did:test:multi-fallback": failingOP.URL},
		Witnesses: map[string][]string{"did:test:multi-fallback": {failingWitness.URL, goodWitness.URL}},
	}
	client := witness.NewTreeHeadClient(endpoints, witness.DefaultTreeHeadClientConfig())

	head, _, err := client.FetchLatestTreeHead("did:test:multi-fallback")
	if err != nil {
		t.Fatalf("second witness should succeed: %v", err)
	}
	if head.TreeSize != 7000 {
		t.Fatalf("tree_size: %d", head.TreeSize)
	}
}

func TestTreeHeadClient_AllEndpointsFail_Error(t *testing.T) {
	failingOP := newFailingServer()
	defer failingOP.Close()
	failingW := newFailingServer()
	defer failingW.Close()

	endpoints := &witness.StaticEndpoints{
		Operators: map[string]string{"did:test:allfail": failingOP.URL},
		Witnesses: map[string][]string{"did:test:allfail": {failingW.URL}},
	}
	client := witness.NewTreeHeadClient(endpoints, witness.DefaultTreeHeadClientConfig())

	_, _, err := client.FetchLatestTreeHead("did:test:allfail")
	if err == nil {
		t.Fatal("all endpoints failing should error")
	}
}

func TestTreeHeadClient_NoWitnessEndpoints_OperatorOnly(t *testing.T) {
	rootHash := sha256.Sum256([]byte("op-only"))
	ts := newMockOperatorServer(8000, rootHash)
	defer ts.Close()

	endpoints := &witness.StaticEndpoints{
		Operators: map[string]string{"did:test:oponly": ts.URL},
		// No witnesses configured.
	}
	client := witness.NewTreeHeadClient(endpoints, witness.DefaultTreeHeadClientConfig())

	head, _, err := client.FetchLatestTreeHead("did:test:oponly")
	if err != nil {
		t.Fatal(err)
	}
	if head.TreeSize != 8000 {
		t.Fatalf("tree_size: %d", head.TreeSize)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Tests: Response parsing — post-BUG-012 wire contract
// ─────────────────────────────────────────────────────────────────────

// TestTreeHeadClient_ParsesSignatures verifies the happy path with
// the post-cutover wire format. Each signature carries an explicit
// pubkey_id field (hex-encoded 32-byte canonical witness ID).
//
// BUG-012 UPDATE: fixture migrated from {"signer":"..."} to
// {"pubkey_id":"..."}. The pre-cutover format no longer parses.
func TestTreeHeadClient_ParsesSignatures(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rootHash := sha256.Sum256([]byte("signed-root"))
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tree_size": 9000,
			"root_hash": hex.EncodeToString(rootHash[:]),
			"hash_algo": 1,
			"signatures": []map[string]any{
				{"pubkey_id": pubKeyIDHex("witness-1"), "sig_algo": 1, "signature": hex.EncodeToString(make([]byte, 64))},
				{"pubkey_id": pubKeyIDHex("witness-2"), "sig_algo": 1, "signature": hex.EncodeToString(make([]byte, 64))},
			},
		})
	}))
	defer ts.Close()

	endpoints := &witness.StaticEndpoints{
		Operators: map[string]string{"did:test:sigs": ts.URL},
	}
	client := witness.NewTreeHeadClient(endpoints, witness.DefaultTreeHeadClientConfig())

	head, _, err := client.FetchLatestTreeHead("did:test:sigs")
	if err != nil {
		t.Fatal(err)
	}
	if len(head.Signatures) != 2 {
		t.Fatalf("sigs: %d", len(head.Signatures))
	}
	if len(head.Signatures[0].SigBytes) != 64 {
		t.Fatalf("sig[0] len: %d", len(head.Signatures[0].SigBytes))
	}
	// Post-BUG-012 invariant: PubKeyID transcribed verbatim from JSON,
	// NOT derived from any other field.
	sum := sha256.Sum256([]byte("witness-1"))
	if head.Signatures[0].PubKeyID != sum {
		t.Fatalf("pubkey_id not transcribed verbatim for witness-1; "+
			"got %x, want %x", head.Signatures[0].PubKeyID, sum)
	}
	if head.Signatures[0].SchemeTag != 1 {
		t.Fatalf("scheme tag not propagated; got %d, want 1", head.Signatures[0].SchemeTag)
	}
}

func TestTreeHeadClient_ParsesEmptySignatures(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"tree_size": 100,
			"root_hash": hex.EncodeToString(make([]byte, 32)),
		})
	}))
	defer ts.Close()

	endpoints := &witness.StaticEndpoints{
		Operators: map[string]string{"did:test:nosigs": ts.URL},
	}
	client := witness.NewTreeHeadClient(endpoints, witness.DefaultTreeHeadClientConfig())

	head, _, err := client.FetchLatestTreeHead("did:test:nosigs")
	if err != nil {
		t.Fatal(err)
	}
	if len(head.Signatures) != 0 {
		t.Fatalf("expected 0 sigs, got %d", len(head.Signatures))
	}
}

// ─────────────────────────────────────────────────────────────────────
// Tests: StaticEndpoints
// ─────────────────────────────────────────────────────────────────────

func TestStaticEndpoints_OperatorFound(t *testing.T) {
	ep := &witness.StaticEndpoints{
		Operators: map[string]string{"did:test:x": "http://op.test"},
	}
	url, err := ep.OperatorEndpoint("did:test:x")
	if err != nil {
		t.Fatal(err)
	}
	if url != "http://op.test" {
		t.Fatalf("url: %s", url)
	}
}

func TestStaticEndpoints_OperatorNotFound(t *testing.T) {
	ep := &witness.StaticEndpoints{Operators: map[string]string{}}
	_, err := ep.OperatorEndpoint("did:test:missing")
	if err == nil {
		t.Fatal("should error for missing DID")
	}
}

func TestStaticEndpoints_WitnessEmpty(t *testing.T) {
	ep := &witness.StaticEndpoints{}
	eps, err := ep.WitnessEndpoints("did:test:x")
	if err != nil {
		t.Fatal(err)
	}
	if len(eps) != 0 {
		t.Fatal("should be empty")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Tests: Config defaults
// ─────────────────────────────────────────────────────────────────────

func TestTreeHeadClient_DefaultConfig(t *testing.T) {
	cfg := witness.DefaultTreeHeadClientConfig()
	if cfg.CacheTTL != 30*time.Second {
		t.Fatalf("CacheTTL: %s", cfg.CacheTTL)
	}
	if cfg.HTTPTimeout != 15*time.Second {
		t.Fatalf("HTTPTimeout: %s", cfg.HTTPTimeout)
	}
}

// Suppress unused import.
var _ = types.TreeHead{}

func TestFetchFromURL_DirectCall(t *testing.T) {
	rootHash := sha256.Sum256([]byte("direct-fetch"))
	server := newMockOperatorServer(12345, rootHash)
	defer server.Close()

	client := witness.NewTreeHeadClient(&witness.StaticEndpoints{}, witness.DefaultTreeHeadClientConfig())
	head, fetchedAt, err := client.FetchFromURL(server.URL + "/v1/tree/head")
	if err != nil {
		t.Fatalf("FetchFromURL: %v", err)
	}
	if head.TreeSize != 12345 {
		t.Errorf("tree size: expected 12345, got %d", head.TreeSize)
	}
	if head.RootHash != rootHash {
		t.Errorf("root hash mismatch")
	}
	if fetchedAt.IsZero() {
		t.Errorf("fetchedAt should be populated")
	}

	// Cache was NOT populated by this call.
	if client.CacheSize() != 0 {
		t.Errorf("FetchFromURL must not populate cache, got size %d", client.CacheSize())
	}
}

func TestFetchFromURL_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	client := witness.NewTreeHeadClient(&witness.StaticEndpoints{}, witness.DefaultTreeHeadClientConfig())
	_, _, err := client.FetchFromURL(server.URL + "/v1/tree/head")
	if err == nil {
		t.Fatal("expected error from 503, got nil")
	}
}
