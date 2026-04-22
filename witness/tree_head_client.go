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

BUG-012 FIX — WIRE FORMAT CUTOVER

	Previously the parser received only the "signer" string from
	operator JSON and attempted to derive PubKeyID by hashing that
	string: sha256([]byte(s.Signer)). The canonical PubKeyID used
	throughout the SDK — produced by did/resolver.go:181 and every
	verifier keyMap — is sha256(publicKeyBytes), i.e., the hash of
	the raw key material. Hash(string) ≠ Hash(bytes), so the parser
	and verifier disagreed on identity and every HTTP-fetched tree
	head failed verification silently.

	The clean-cutover fix:

	1. Operator JSON contract now REQUIRES a "pubkey_id" field
	   carrying the hex-encoded 32-byte canonical ID. The operator
	   already holds this value (computed at witness-registration
	   time as sha256(pubkey)); it now serializes it on the wire.

	2. The parser is a dumb deserializer. It copies "pubkey_id"
	   verbatim into WitnessSignature.PubKeyID. It does NOT derive,
	   compute, or fabricate identity. Missing or malformed fields
	   are hard errors.

	3. The legacy "signer" field is REMOVED from the wire contract.
	   A human-readable label in the JSON would invite exactly the
	   confusion that produced BUG-012 — the temptation to "use
	   signer instead" of pubkey_id. One identity field, period.

	4. No compatibility path. The SDK fails loud on the old format.
	   Operators that don't emit pubkey_id get a precise error
	   message from the parser and know exactly what to fix.

	Epoch-correctness note: PubKeyID is sha256(pubkey_bytes), so
	a key rotation produces a new PubKeyID. Signatures bind to the
	exact key material that produced them. The verifier does no
	historical DID resolution. This aligns with RFC 6962 / SPKI
	Key Identifier semantics.
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
// # BUG-012 FIX — STRICT PARSING, NO DERIVATION
//
// The parser is a pure deserializer. It transcribes JSON into
// *types.CosignedTreeHead and nothing more. It does NOT derive
// PubKeyID from any other field. It does NOT default missing
// fields. It does NOT tolerate malformed input.
//
// Required fields (hard error on absence, malformed value, or
// wrong length):
//
//   - root_hash: 32-byte hex (64 chars)
//   - signatures[i].pubkey_id: 32-byte hex (64 chars) — the
//     canonical witness identifier, sha256(pubkey_bytes), as
//     produced by did/resolver.go:181
//   - signatures[i].sig_algo: non-zero (Wave 2 strict zero-tag)
//   - signatures[i].signature: hex, decodable
//
// The "signer" field from the pre-cutover format is explicitly
// NOT read. Operators emitting the old format will fail parsing
// with "missing required pubkey_id field" — a precise, actionable
// diagnostic.
func parseTreeHeadResponse(data []byte) (types.CosignedTreeHead, error) {
	var raw struct {
		TreeSize uint64 `json:"tree_size"`
		RootHash string `json:"root_hash"`
		HashAlgo int    `json:"hash_algo"`
		Sigs     []struct {
			PubKeyID string `json:"pubkey_id"`
			SigAlgo  int    `json:"sig_algo"`
			Sig      string `json:"signature"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return types.CosignedTreeHead{}, fmt.Errorf("witness/client: decode JSON: %w", err)
	}

	// root_hash: required, 32 bytes.
	if raw.RootHash == "" {
		return types.CosignedTreeHead{}, fmt.Errorf(
			"witness/client: missing required root_hash field")
	}
	rootBytes, err := hex.DecodeString(raw.RootHash)
	if err != nil {
		return types.CosignedTreeHead{}, fmt.Errorf(
			"witness/client: invalid root_hash hex: %w", err)
	}
	if len(rootBytes) != 32 {
		return types.CosignedTreeHead{}, fmt.Errorf(
			"witness/client: root_hash must be 32 bytes, got %d", len(rootBytes))
	}

	var head types.CosignedTreeHead
	head.TreeSize = raw.TreeSize
	copy(head.RootHash[:], rootBytes)

	// signatures: each element must carry pubkey_id, sig_algo, signature.
	// Empty signature list is permitted — the verifier rejects it
	// separately. What we guard here is wire-format validity.
	for i, s := range raw.Sigs {
		if s.PubKeyID == "" {
			return types.CosignedTreeHead{}, fmt.Errorf(
				"witness/client: signature[%d]: missing required pubkey_id field", i)
		}
		idBytes, err := hex.DecodeString(s.PubKeyID)
		if err != nil {
			return types.CosignedTreeHead{}, fmt.Errorf(
				"witness/client: signature[%d]: invalid pubkey_id hex: %w", i, err)
		}
		if len(idBytes) != 32 {
			return types.CosignedTreeHead{}, fmt.Errorf(
				"witness/client: signature[%d]: pubkey_id must be 32 bytes, got %d",
				i, len(idBytes))
		}
		if s.SigAlgo == 0 {
			return types.CosignedTreeHead{}, fmt.Errorf(
				"witness/client: signature[%d]: missing or zero sig_algo", i)
		}
		// signature hex: required and decodable. Empty string is
		// rejected — a zero-byte signature is never correct.
		if s.Sig == "" {
			return types.CosignedTreeHead{}, fmt.Errorf(
				"witness/client: signature[%d]: missing signature field", i)
		}
		sigBytes, err := hex.DecodeString(s.Sig)
		if err != nil {
			return types.CosignedTreeHead{}, fmt.Errorf(
				"witness/client: signature[%d]: invalid signature hex: %w", i, err)
		}

		var pubKeyID [32]byte
		copy(pubKeyID[:], idBytes)

		head.Signatures = append(head.Signatures, types.WitnessSignature{
			PubKeyID:  pubKeyID,
			SchemeTag: byte(s.SigAlgo),
			SigBytes:  sigBytes,
		})
	}

	return head, nil
}
