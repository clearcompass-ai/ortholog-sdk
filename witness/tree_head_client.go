/*
FILE PATH:

	witness/tree_head_client.go

DESCRIPTION:

	Fetch and cache cosigned tree heads from remote operators.

	TreeHeadClient is the SDK-side component that obtains tree heads
	from remote operators. It provides:
	  - LRU cache keyed by log DID (avoids redundant HTTP calls)
	  - Configurable staleness (cache TTL)
	  - Endpoint resolution via EndpointProvider interface
	  - Fallback to witness endpoints if operator is down

	Consumed by:
	  - cross_log.go ResolveCrossLogRef (foreign tree heads)
	  - bootstrap.go AnchorLogSync method
	  - Phase 6 anchors.go (periodic anchor publishing)
	  - Domain topology/anchor_publisher.go

WAVE 2 CHANGE: Propagate SchemeTag from operator wire format

	Pre-Wave-2 the operator's SigAlgo JSON field was parsed into
	the raw struct but then silently discarded when constructing
	WitnessSignature — the head-level CosignedTreeHead.SchemeTag
	was set upstream by the caller.

	Post-Wave-2 SchemeTag lives on each WitnessSignature, and
	parseTreeHeadResponse populates it directly from SigAlgo.
	This is a single-field addition in the struct literal.

	If an operator response lacks SigAlgo (absent field, zero
	value), the resulting WitnessSignature carries SchemeTag=0
	and will be rejected by the verifier's strict zero-tag check.
	This is intentional: a Wave-2+ verifier cannot safely dispatch
	a signature whose scheme is not declared, and operators that
	produce such responses need to be fixed (not papered over with
	a defensive default).

KNOWN PRE-EXISTING TECHNICAL DEBT (not a Wave 2 concern):

	The hashString function at the bottom of this file is not a
	cryptographic hash — it's an XOR-fold that produces frequent
	collisions and is therefore not suitable as a witness identity
	derivation. This pre-dates Wave 2 and is not addressed here.
	Consumers that need correct PubKeyID derivation should either:
	  - Re-populate WitnessSignature.PubKeyID from the actual
	    witness registry after fetch, OR
	  - Not rely on TreeHeadClient's parsed IDs for verification.
	A follow-up issue should replace this with sha256 of the
	signer string, but that is out of scope for Wave 2.
*/
package witness

import (
	"crypto/sha256"
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

// TreeHeadClient fetches and caches cosigned tree heads from remote
// operators.
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

// FetchFromURL fetches a cosigned tree head from a specific endpoint
// URL.
//
// Unlike FetchLatestTreeHead which resolves endpoints via the injected
// EndpointProvider and caches results by log DID, this takes the URL
// directly and bypasses the cache. Used primarily by monitoring for
// equivocation detection — comparing operator tree heads against
// individual witness tree heads requires fresh, unrelated-to-cache
// fetches.
//
// The caller provides witness URLs from their own resolution
// (e.g., did.DIDDocument.WitnessEndpointURLs()).
//
// No witness signature verification is performed here. Callers
// wanting to verify the returned head should pass it to VerifyTreeHead
// or DetectEquivocation.
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

// parseTreeHeadResponse parses the JSON response from GET
// /v1/tree/head.
//
// WAVE 2: The SigAlgo field is now propagated to each
// WitnessSignature's SchemeTag. Pre-Wave-2 this field was parsed
// into the raw struct but then dropped; the head-level SchemeTag
// was populated by the caller instead. Post-Wave-2 the per-signature
// SchemeTag is the source of truth and must be populated here.
//
// Operators that emit tree-head responses with SigAlgo absent or
// zero will produce WitnessSignature values with SchemeTag=0, which
// Wave-2+ verifiers reject via their strict zero-tag check. This is
// intentional — it surfaces malformed operator responses as loud
// verification failures rather than silent misdispatch.
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

	/// Parse signatures. PubKeyID is derived via SHA-256 over the signer
	// string, which is the cryptographically sound identity derivation
	// expected by the verifier. An earlier version of this parser used a
	// custom XOR-fold helper (hashString); that was removed in Wave 2
	// because XOR-fold produces frequent collisions and therefore
	// misidentifies witnesses.
	for _, s := range raw.Sigs {
		sigBytes, _ := hex.DecodeString(s.Sig)
		var pubKeyID [32]byte
		if s.Signer != "" {
			pubKeyID = sha256.Sum256([]byte(s.Signer))
		}
		head.Signatures = append(head.Signatures, types.WitnessSignature{
			PubKeyID:  pubKeyID,
			SchemeTag: byte(s.SigAlgo), // Wave 2: propagate from operator response
			SigBytes:  sigBytes,
		})
	}

	return head, nil
}
