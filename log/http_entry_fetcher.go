/*
Package log — http_entry_fetcher.go implements builder.EntryFetcher over HTTP,
targeting the ortholog-operator's entry read endpoint.

Endpoint: GET /v1/entries/{sequence}

The operator serves canonical entry bytes + metadata. The fetcher returns
types.EntryWithMetadata, which the builder, verifier, and lifecycle packages
consume without knowing whether the source is Postgres or HTTP.

The judicial network injects this at deployment time:
  fetcher := log.NewHTTPEntryFetcher("https://operator.court.gov", "did:web:courts.nashville.gov:cases")

No import of ortholog-operator/. The HTTP boundary is the contract.

Consumed by:
  - verifier/condition_evaluator.go EvaluateConditions
  - verifier/delegation_tree.go WalkDelegationTree
  - lifecycle/recovery.go ExecuteRecovery
  - lifecycle/scope_governance.go CollectApprovals
  - builder/occ_retry.go ProcessWithRetry (via interface injection)
*/
package log

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// HTTPEntryFetcher
// ─────────────────────────────────────────────────────────────────────

// HTTPEntryFetcher implements builder.EntryFetcher (and verifier.EntryFetcher,
// lifecycle.EntryFetcher — all structurally identical) by calling the
// operator's REST API.
type HTTPEntryFetcher struct {
	baseURL string
	logDID  string
	client  *http.Client
}

// HTTPEntryFetcherConfig configures the HTTP entry fetcher.
type HTTPEntryFetcherConfig struct {
	// BaseURL is the operator's base URL (e.g., "https://operator.court.gov").
	BaseURL string

	// LogDID is the log this fetcher reads from. Used to populate
	// EntryWithMetadata.Position.LogDID and for URL routing when the
	// operator serves multiple logs.
	LogDID string

	// Timeout for HTTP requests. Default: 15s.
	Timeout time.Duration
}

// NewHTTPEntryFetcher creates an EntryFetcher backed by the operator API.
func NewHTTPEntryFetcher(cfg HTTPEntryFetcherConfig) *HTTPEntryFetcher {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &HTTPEntryFetcher{
		baseURL: cfg.BaseURL,
		logDID:  cfg.LogDID,
		client:  &http.Client{Timeout: timeout},
	}
}

// Fetch retrieves an entry by log position via GET /v1/entries/{sequence}.
// Returns nil, nil if the entry does not exist (404).
// The response carries canonical bytes as hex and metadata as JSON fields.
//
// Satisfies builder.EntryFetcher, verifier.EntryFetcher, and
// lifecycle.EntryFetcher through Go structural typing.
func (f *HTTPEntryFetcher) Fetch(pos types.LogPosition) (*types.EntryWithMetadata, error) {
	url := fmt.Sprintf("%s/v1/entries/%d", f.baseURL, pos.Sequence)

	resp, err := f.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("log/http: fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // Entry not found — normal condition.
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("log/http: fetch: HTTP %d for seq %d", resp.StatusCode, pos.Sequence)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20)) // 2MB limit (1MB entry + overhead)
	if err != nil {
		return nil, fmt.Errorf("log/http: fetch read: %w", err)
	}

	var raw entryResponse
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("log/http: fetch parse: %w", err)
	}

	canonicalBytes, err := hex.DecodeString(raw.CanonicalHex)
	if err != nil {
		return nil, fmt.Errorf("log/http: decode canonical: %w", err)
	}

	meta := &types.EntryWithMetadata{
		CanonicalBytes: canonicalBytes,
		Position: types.LogPosition{
			LogDID:   f.logDID,
			Sequence: raw.Sequence,
		},
		SignatureAlgoID: raw.SigAlgoID,
	}

	if raw.LogTimeUnixMicro != 0 {
		meta.LogTime = time.UnixMicro(raw.LogTimeUnixMicro)
	}

	if raw.SignatureHex != "" {
		sigBytes, err := hex.DecodeString(raw.SignatureHex)
		if err == nil {
			meta.SignatureBytes = sigBytes
		}
	}

	return meta, nil
}

// entryResponse is the JSON response from the operator's entry read endpoint.
// Field names match ortholog-operator/api/entries_read.go.
type entryResponse struct {
	Sequence         uint64 `json:"sequence"`
	CanonicalHex     string `json:"canonical_hex"`
	LogTimeUnixMicro int64  `json:"log_time_unix_micro"`
	SigAlgoID        uint16 `json:"sig_algo_id,omitempty"`
	SignatureHex     string `json:"signature_hex,omitempty"`
}
