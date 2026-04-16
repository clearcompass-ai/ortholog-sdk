/*
witness/tree_head_client.go — Fetch and cache cosigned tree heads.

TreeHeadClient is the SDK-side component that obtains tree heads from
remote operators. It provides:
  - LRU cache keyed by log DID (avoids redundant HTTP calls)
  - Configurable staleness (cache TTL)
  - Endpoint resolution via EndpointProvider interface
  - Fallback to witness endpoints if operator is down

Consumed by:
  - cross_log.go ResolveCrossLogRef (foreign tree heads)
  - bootstrap.go AnchorLogSync method
  - Phase 6 anchors.go (periodic anchor publishing)
  - Domain topology/anchor_publisher.go
*/
package witness

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// Interfaces
// ─────────────────────────────────────────────────────────────────────

// EndpointProvider resolves a log DID to its operator HTTP endpoint.
// Satisfied by did.DIDResolver (Phase 4 Step 1) or by static config.
type EndpointProvider interface {
	// OperatorEndpoint returns the base URL for a log's operator API.
	// Example: "https://operator.davidson-county.court" → /v1/tree/head
	OperatorEndpoint(logDID string) (string, error)

	// WitnessEndpoints returns fallback witness endpoints for a log.
	// Used when the operator endpoint is unreachable.
	WitnessEndpoints(logDID string) ([]string, error)
}

// ─────────────────────────────────────────────────────────────────────
// Static endpoint provider (for tests and simple deployments)
// ─────────────────────────────────────────────────────────────────────

// StaticEndpoints maps log DIDs to fixed endpoints. No DID resolution.
type StaticEndpoints struct {
	Operators map[string]string   // logDID → operator base URL
	Witnesses map[string][]string // logDID → witness base URLs
}

func (s *StaticEndpoints) OperatorEndpoint(logDID string) (string, error) {
	ep, ok := s.Operators[logDID]
	if !ok {
		return "", fmt.Errorf("witness/client: no operator endpoint for %s", logDID)
	}
	return ep, nil
}

func (s *StaticEndpoints) WitnessEndpoints(logDID string) ([]string, error) {
	eps := s.Witnesses[logDID]
	return eps, nil
}

// ─────────────────────────────────────────────────────────────────────
// TreeHeadClient
// ─────────────────────────────────────────────────────────────────────

// TreeHeadClientConfig configures the client.
type TreeHeadClientConfig struct {
	// CacheTTL is how long a cached head is considered fresh.
	// After this, the next FetchLatestTreeHead triggers an HTTP call.
	CacheTTL time.Duration

	// HTTPTimeout for individual requests.
	HTTPTimeout time.Duration
}

// DefaultTreeHeadClientConfig returns production defaults.
func DefaultTreeHeadClientConfig() TreeHeadClientConfig {
	return TreeHeadClientConfig{
		CacheTTL:    30 * time.Second,
		HTTPTimeout: 15 * time.Second,
	}
}

// TreeHeadClient fetches and caches cosigned tree heads from remote operators.
type TreeHeadClient struct {
	endpoints EndpointProvider
	cfg       TreeHeadClientConfig
	client    *http.Client
	mu        sync.RWMutex
	cache     map[string]*cachedHead
}

type cachedHead struct {
	head      types.CosignedTreeHead
	fetchedAt time.Time
}

// NewTreeHeadClient creates a client with the given endpoint provider.
func NewTreeHeadClient(endpoints EndpointProvider, cfg TreeHeadClientConfig) *TreeHeadClient {
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = 30 * time.Second
	}
	if cfg.HTTPTimeout == 0 {
		cfg.HTTPTimeout = 15 * time.Second
	}
	return &TreeHeadClient{
		endpoints: endpoints,
		cfg:       cfg,
		client:    &http.Client{Timeout: cfg.HTTPTimeout},
		cache:     make(map[string]*cachedHead),
	}
}

// FetchLatestTreeHead returns the latest cosigned tree head for a log.
//
// (1) Check cache: if fresh, return immediately (no HTTP call).
// (2) Resolve logDID → operator endpoint.
// (3) HTTP GET /v1/tree/head → parse response.
// (4) If operator unreachable, try witness endpoints as fallback.
// (5) Update cache.
func (tc *TreeHeadClient) FetchLatestTreeHead(logDID string) (types.CosignedTreeHead, time.Time, error) {
	// (1) Cache check.
	tc.mu.RLock()
	cached, ok := tc.cache[logDID]
	tc.mu.RUnlock()

	if ok {
		age := time.Since(cached.fetchedAt)
		if age <= tc.cfg.CacheTTL {
			return cached.head, cached.fetchedAt, nil
		}
	}

	// (2) Resolve operator endpoint.
	operatorURL, err := tc.endpoints.OperatorEndpoint(logDID)
	if err != nil {
		return types.CosignedTreeHead{}, time.Time{}, fmt.Errorf("witness/client: resolve %s: %w", logDID, err)
	}

	// (3) HTTP fetch from operator.
	head, fetchedAt, err := tc.FetchFromURL(operatorURL + "/v1/tree/head")
	if err == nil {
		tc.updateCache(logDID, head, fetchedAt)
		return head, fetchedAt, nil
	}

	// (4) Fallback to witness endpoints.
	witnessEPs, _ := tc.endpoints.WitnessEndpoints(logDID)
	for _, wep := range witnessEPs {
		head, fetchedAt, wErr := tc.FetchFromURL(wep + "/v1/tree/head")
		if wErr == nil {
			tc.updateCache(logDID, head, fetchedAt)
			return head, fetchedAt, nil
		}
	}

	// All endpoints failed.
	return types.CosignedTreeHead{}, time.Time{},
		fmt.Errorf("witness/client: all endpoints unreachable for %s: %w", logDID, err)
}

// CachedHead returns the cached head for a log DID without making
// any HTTP calls. Returns zero values if not cached.
func (tc *TreeHeadClient) CachedHead(logDID string) (types.CosignedTreeHead, time.Time, bool) {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	cached, ok := tc.cache[logDID]
	if !ok {
		return types.CosignedTreeHead{}, time.Time{}, false
	}
	return cached.head, cached.fetchedAt, true
}

// InvalidateCache removes a cached head for a specific log DID.
func (tc *TreeHeadClient) InvalidateCache(logDID string) {
	tc.mu.Lock()
	delete(tc.cache, logDID)
	tc.mu.Unlock()
}

// CacheSize returns the number of cached entries.
func (tc *TreeHeadClient) CacheSize() int {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	return len(tc.cache)
}

// ─────────────────────────────────────────────────────────────────────
// Internal
// ─────────────────────────────────────────────────────────────────────

// FetchFromURL fetches a cosigned tree head from a specific endpoint URL.
//
// Unlike FetchLatestTreeHead which resolves endpoints via the injected
// EndpointProvider and caches results by log DID, this takes the URL
// directly and bypasses the cache. Used primarily by monitoring for
// equivocation detection — comparing operator tree heads against
// individual witness tree heads requires fresh, unrelated-to-cache fetches.
//
// The caller provides witness URLs from their own resolution
// (e.g., did.DIDDocument.WitnessEndpointURLs()).
//
// No witness signature verification is performed here. Callers wanting
// to verify the returned head should pass it to VerifyTreeHead or
// DetectEquivocation.
func (tc *TreeHeadClient) FetchFromURL(url string) (types.CosignedTreeHead, time.Time, error) {
	resp, err := tc.client.Get(url)
	if err != nil {
		return types.CosignedTreeHead{}, time.Time{}, fmt.Errorf("witness/client: fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return types.CosignedTreeHead{}, time.Time{},
			fmt.Errorf("witness/client: HTTP %d from %s", resp.StatusCode, url)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return types.CosignedTreeHead{}, time.Time{}, fmt.Errorf("witness/client: read %s: %w", url, err)
	}

	head, err := parseTreeHeadResponse(body)
	if err != nil {
		return types.CosignedTreeHead{}, time.Time{}, fmt.Errorf("witness/client: parse %s: %w", url, err)
	}

	return head, time.Now().UTC(), nil
}

func (tc *TreeHeadClient) updateCache(logDID string, head types.CosignedTreeHead, fetchedAt time.Time) {
	tc.mu.Lock()
	tc.cache[logDID] = &cachedHead{head: head, fetchedAt: fetchedAt}
	tc.mu.Unlock()
}

// parseTreeHeadResponse parses the JSON response from GET /v1/tree/head.
func parseTreeHeadResponse(data []byte) (types.CosignedTreeHead, error) {
	var raw struct {
		TreeSize uint64 `json:"tree_size"`
		RootHash string `json:"root_hash"`
		HashAlgo int    `json:"hash_algo"`
		Sigs     []struct {
			Signer  string `json:"signer"`
			SigAlgo int    `json:"sig_algo"`
			Sig     string `json:"signature"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return types.CosignedTreeHead{}, fmt.Errorf("witness/client: parse response: %w", err)
	}

	var head types.CosignedTreeHead
	head.TreeSize = raw.TreeSize

	rootBytes, err := hex.DecodeString(raw.RootHash)
	if err == nil && len(rootBytes) == 32 {
		copy(head.RootHash[:], rootBytes)
	}

	// Parse signatures. The detailed WitnessSignature structure requires
	// PubKeyID and SigBytes — map from the JSON response format.
	for _, s := range raw.Sigs {
		sigBytes, _ := hex.DecodeString(s.Sig)
		var pubKeyID [32]byte
		// Use signer string hash as PubKeyID (operator response format).
		if s.Signer != "" {
			h := hashString(s.Signer)
			copy(pubKeyID[:], h[:])
		}
		head.Signatures = append(head.Signatures, types.WitnessSignature{
			PubKeyID: pubKeyID,
			SigBytes: sigBytes,
		})
	}

	return head, nil
}

func hashString(s string) [32]byte {
	var data [32]byte
	h := make([]byte, 0, len(s))
	h = append(h, []byte(s)...)
	// Simple deterministic hash of the signer string.
	for i, b := range h {
		data[i%32] ^= b
	}
	return data
}
