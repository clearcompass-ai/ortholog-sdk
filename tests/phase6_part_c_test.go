/*
FILE PATH: tests/phase6_part_c_test.go

Phase 6 Part C: HTTP client smoke tests covering:
  - HTTPContentStore (6 tests): Push/Fetch/Pin/Exists/Delete
  - HTTPRetrievalProvider (5 tests): Resolve signed_url/ipfs/direct
  - HTTPLeafReader (6 tests): Get leaf, 404, parsing

The HTTPEntryFetcher tests previously housed here targeted the old
JSON metadata endpoint shape and have been retired — comprehensive
branch-coverage tests for the current /raw fetcher live in
log/http_entry_fetcher_test.go.

All tests use httptest.NewServer — no real network calls.
*/
package tests

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ═════════════════════════════════════════════════════════════════════
// 1. HTTPContentStore (6 tests)
// ═════════════════════════════════════════════════════════════════════

func newArtifactStoreServer() *httptest.Server {
	store := make(map[string][]byte)
	pins := make(map[string]bool)

	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		switch {
		case r.Method == http.MethodPost && path == "/v1/artifacts":
			cid := r.Header.Get("X-Artifact-CID")
			body, _ := io.ReadAll(r.Body)
			store[cid] = body
			w.WriteHeader(http.StatusCreated)

		case r.Method == http.MethodGet && len(path) > len("/v1/artifacts/"):
			cid := path[len("/v1/artifacts/"):]
			if data, ok := store[cid]; ok {
				w.Write(data)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}

		case r.Method == http.MethodHead && len(path) > len("/v1/artifacts/"):
			cid := path[len("/v1/artifacts/"):]
			if _, ok := store[cid]; ok {
				w.WriteHeader(http.StatusOK)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}

		case r.Method == http.MethodPost && len(path) > len("/v1/artifacts/") && path[len(path)-4:] == "/pin":
			cid := path[len("/v1/artifacts/") : len(path)-4]
			if _, ok := store[cid]; ok {
				pins[cid] = true
				w.WriteHeader(http.StatusNoContent)
			} else {
				w.WriteHeader(http.StatusNotFound)
			}

		case r.Method == http.MethodDelete && len(path) > len("/v1/artifacts/"):
			cid := path[len("/v1/artifacts/"):]
			delete(store, cid)
			delete(pins, cid)
			w.WriteHeader(http.StatusNoContent)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestHTTPContentStore_PushFetchRoundTrip(t *testing.T) {
	ts := newArtifactStoreServer()
	defer ts.Close()

	cs := storage.NewHTTPContentStore(storage.HTTPContentStoreConfig{BaseURL: ts.URL})
	data := []byte("artifact payload for HTTP test")
	cid := storage.Compute(data)

	if err := cs.Push(cid, data); err != nil {
		t.Fatalf("push: %v", err)
	}

	fetched, err := cs.Fetch(cid)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if string(fetched) != string(data) {
		t.Fatal("round-trip mismatch")
	}
}

func TestHTTPContentStore_FetchNotFound(t *testing.T) {
	ts := newArtifactStoreServer()
	defer ts.Close()

	cs := storage.NewHTTPContentStore(storage.HTTPContentStoreConfig{BaseURL: ts.URL})
	cid := storage.Compute([]byte("nonexistent"))

	_, err := cs.Fetch(cid)
	if err != storage.ErrContentNotFound {
		t.Fatalf("expected ErrContentNotFound, got: %v", err)
	}
}

func TestHTTPContentStore_Pin(t *testing.T) {
	ts := newArtifactStoreServer()
	defer ts.Close()

	cs := storage.NewHTTPContentStore(storage.HTTPContentStoreConfig{BaseURL: ts.URL})
	data := []byte("pin me")
	cid := storage.Compute(data)
	cs.Push(cid, data)

	if err := cs.Pin(cid); err != nil {
		t.Fatalf("pin: %v", err)
	}
}

func TestHTTPContentStore_Exists(t *testing.T) {
	ts := newArtifactStoreServer()
	defer ts.Close()

	cs := storage.NewHTTPContentStore(storage.HTTPContentStoreConfig{BaseURL: ts.URL})
	data := []byte("exists check")
	cid := storage.Compute(data)

	exists, _ := cs.Exists(cid)
	if exists {
		t.Fatal("should not exist before push")
	}

	cs.Push(cid, data)
	exists, _ = cs.Exists(cid)
	if !exists {
		t.Fatal("should exist after push")
	}
}

func TestHTTPContentStore_Delete(t *testing.T) {
	ts := newArtifactStoreServer()
	defer ts.Close()

	cs := storage.NewHTTPContentStore(storage.HTTPContentStoreConfig{BaseURL: ts.URL})
	data := []byte("delete me")
	cid := storage.Compute(data)
	cs.Push(cid, data)

	if err := cs.Delete(cid); err != nil {
		t.Fatalf("delete: %v", err)
	}

	_, err := cs.Fetch(cid)
	if err != storage.ErrContentNotFound {
		t.Fatal("should be gone after delete")
	}
}

func TestHTTPContentStore_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	cs := storage.NewHTTPContentStore(storage.HTTPContentStoreConfig{BaseURL: ts.URL})
	err := cs.Push(storage.Compute([]byte("x")), []byte("x"))
	if err == nil {
		t.Fatal("server error should propagate")
	}
}

// ═════════════════════════════════════════════════════════════════════
// 2. HTTPRetrievalProvider (5 tests)
// ═════════════════════════════════════════════════════════════════════

func newResolveServer(method, url, expiry string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]string{"method": method, "url": url}
		if expiry != "" {
			resp["expiry"] = expiry
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
}

func TestHTTPRetrieval_SignedURL(t *testing.T) {
	expiry := time.Now().Add(1 * time.Hour).Format(time.RFC3339)
	ts := newResolveServer("signed_url", "https://storage.example.com/signed?token=abc", expiry)
	defer ts.Close()

	rp := storage.NewHTTPRetrievalProvider(storage.HTTPRetrievalProviderConfig{BaseURL: ts.URL})
	cred, err := rp.Resolve(storage.Compute([]byte("test")), 1*time.Hour)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if cred.Method != "signed_url" {
		t.Fatalf("method: %s", cred.Method)
	}
	if cred.URL != "https://storage.example.com/signed?token=abc" {
		t.Fatalf("url: %s", cred.URL)
	}
	if cred.Expiry == nil {
		t.Fatal("signed_url should have expiry")
	}
}

func TestHTTPRetrieval_IPFS(t *testing.T) {
	ts := newResolveServer("ipfs", "https://gateway.ipfs.io/ipfs/Qm123", "")
	defer ts.Close()

	rp := storage.NewHTTPRetrievalProvider(storage.HTTPRetrievalProviderConfig{BaseURL: ts.URL})
	cred, err := rp.Resolve(storage.Compute([]byte("ipfs-test")), 0)
	if err != nil {
		t.Fatal(err)
	}
	if cred.Method != "ipfs" {
		t.Fatalf("method: %s", cred.Method)
	}
	if cred.Expiry != nil {
		t.Fatal("IPFS should have nil expiry")
	}
}

func TestHTTPRetrieval_Direct(t *testing.T) {
	ts := newResolveServer("direct", "http://localhost:8080/artifact/sha256:abc", "")
	defer ts.Close()

	rp := storage.NewHTTPRetrievalProvider(storage.HTTPRetrievalProviderConfig{BaseURL: ts.URL})
	cred, _ := rp.Resolve(storage.Compute([]byte("direct")), 0)
	if cred.Method != "direct" {
		t.Fatalf("method: %s", cred.Method)
	}
}

func TestHTTPRetrieval_NotFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	rp := storage.NewHTTPRetrievalProvider(storage.HTTPRetrievalProviderConfig{BaseURL: ts.URL})
	_, err := rp.Resolve(storage.Compute([]byte("missing")), 0)
	if err != storage.ErrContentNotFound {
		t.Fatalf("expected ErrContentNotFound, got: %v", err)
	}
}

func TestHTTPRetrieval_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	rp := storage.NewHTTPRetrievalProvider(storage.HTTPRetrievalProviderConfig{BaseURL: ts.URL})
	_, err := rp.Resolve(storage.Compute([]byte("err")), 0)
	if err == nil {
		t.Fatal("server error should propagate")
	}
}

// ═════════════════════════════════════════════════════════════════════
// 3. HTTPEntryFetcher — RETIRED
//
// The HTTPEntryFetcher tests previously housed here targeted the old
// JSON metadata endpoint (/v1/entries/{seq}). The fetcher now hits
// /v1/entries/{seq}/raw and follows the operator's 302 redirect to
// the bucket. Equivalent (and more comprehensive) branch-coverage
// tests live in log/http_entry_fetcher_test.go:
//
//   - happy 200 + X-Sequence + X-Log-Time
//   - 404 → (nil, nil)
//   - 500 / network errors
//   - missing / malformed X-Sequence and X-Log-Time headers
//   - oversize body cap (LimitReader)
//   - 302 redirect follow with final-response header semantics
// ═════════════════════════════════════════════════════════════════════

// ═════════════════════════════════════════════════════════════════════
// 4. HTTPLeafReader (6 tests)
// ═════════════════════════════════════════════════════════════════════

func newOperatorLeafServer(leaves map[string]*types.SMTLeaf) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if len(path) <= len("/v1/smt/leaf/") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		hexKey := path[len("/v1/smt/leaf/"):]

		leaf, ok := leaves[hexKey]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		resp := map[string]any{
			"key_hex":                hex.EncodeToString(leaf.Key[:]),
			"origin_tip_log_did":     leaf.OriginTip.LogDID,
			"origin_tip_sequence":    leaf.OriginTip.Sequence,
			"authority_tip_log_did":  leaf.AuthorityTip.LogDID,
			"authority_tip_sequence": leaf.AuthorityTip.Sequence,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
}

func TestHTTPLeafReader_GetExisting(t *testing.T) {
	p := pos(42)
	key := smt.DeriveKey(p)
	hexKey := hex.EncodeToString(key[:])

	leaf := &types.SMTLeaf{Key: key, OriginTip: p, AuthorityTip: p}
	leaves := map[string]*types.SMTLeaf{hexKey: leaf}
	ts := newOperatorLeafServer(leaves)
	defer ts.Close()

	reader := smt.NewHTTPLeafReader(smt.HTTPLeafReaderConfig{BaseURL: ts.URL})
	got, err := reader.Get(key)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got == nil {
		t.Fatal("leaf should not be nil")
	}
	if got.Key != key {
		t.Fatal("key mismatch")
	}
	if !got.OriginTip.Equal(p) {
		t.Fatalf("OriginTip: %s", got.OriginTip)
	}
	if !got.AuthorityTip.Equal(p) {
		t.Fatalf("AuthorityTip: %s", got.AuthorityTip)
	}
}

func TestHTTPLeafReader_GetNonExistent(t *testing.T) {
	ts := newOperatorLeafServer(map[string]*types.SMTLeaf{})
	defer ts.Close()

	reader := smt.NewHTTPLeafReader(smt.HTTPLeafReaderConfig{BaseURL: ts.URL})
	key := smt.DeriveKey(pos(999))
	got, err := reader.Get(key)
	if err != nil {
		t.Fatalf("not found should not error: %v", err)
	}
	if got != nil {
		t.Fatal("not found should return nil")
	}
}

func TestHTTPLeafReader_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer ts.Close()

	reader := smt.NewHTTPLeafReader(smt.HTTPLeafReaderConfig{BaseURL: ts.URL})
	_, err := reader.Get([32]byte{0x01})
	if err == nil {
		t.Fatal("server error should propagate")
	}
}

func TestHTTPLeafReader_DifferentTips(t *testing.T) {
	p := pos(10)
	key := smt.DeriveKey(p)
	hexKey := hex.EncodeToString(key[:])
	enfPos := pos(20)

	leaf := &types.SMTLeaf{Key: key, OriginTip: p, AuthorityTip: enfPos}
	ts := newOperatorLeafServer(map[string]*types.SMTLeaf{hexKey: leaf})
	defer ts.Close()

	reader := smt.NewHTTPLeafReader(smt.HTTPLeafReaderConfig{BaseURL: ts.URL})
	got, _ := reader.Get(key)
	if got.OriginTip.Equal(got.AuthorityTip) {
		t.Fatal("tips should differ")
	}
	if !got.OriginTip.Equal(p) {
		t.Fatalf("OriginTip: %s", got.OriginTip)
	}
	if !got.AuthorityTip.Equal(enfPos) {
		t.Fatalf("AuthorityTip: %s", got.AuthorityTip)
	}
}

func TestHTTPLeafReader_KeyHexEncoding(t *testing.T) {
	// Verify the key hex encoding round-trips correctly.
	p := pos(12345)
	key := smt.DeriveKey(p)
	hexKey := hex.EncodeToString(key[:])

	decoded, err := hex.DecodeString(hexKey)
	if err != nil {
		t.Fatal(err)
	}
	var roundTrip [32]byte
	copy(roundTrip[:], decoded)
	if roundTrip != key {
		t.Fatal("hex round-trip failed")
	}
}

func TestHTTPLeafReader_SatisfiesLeafReaderInterface(t *testing.T) {
	ts := newOperatorLeafServer(map[string]*types.SMTLeaf{})
	defer ts.Close()

	reader := smt.NewHTTPLeafReader(smt.HTTPLeafReaderConfig{BaseURL: ts.URL})

	var _ smt.LeafReader = reader
}
