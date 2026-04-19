/*
FILE PATH:
    log/http_entry_fetcher.go

DESCRIPTION:
    HTTP-backed implementation of builder.EntryFetcher (and
    verifier.EntryFetcher, lifecycle.EntryFetcher — all structurally
    identical). Targets the ortholog-operator's GET /v1/entries/{sequence}
    endpoint.

KEY ARCHITECTURAL DECISIONS:
    - Under v6 the fetcher no longer populates EntryWithMetadata's
      SignatureAlgoID / SignatureBytes fields — those fields have been
      removed from the type. Signatures live inside CanonicalBytes (in
      the v6 signatures section) and are extracted via envelope.Deserialize
      when needed.
    - The HTTP response schema is unchanged. The operator may continue
      to return sig_algo_id and signature_hex as JSON sidecar fields for
      human-readable diagnostics or for legacy clients. The fetcher
      simply ignores those fields under v6.
    - This non-breaking HTTP contract means external operators
      (ortholog-operator) do not need a coordinated release with this
      SDK bump. Operators can upgrade the SDK at their own pace; their
      HTTP response format continues to work.
    - The fetcher is strict about the CanonicalBytes field. If
      canonical_hex is missing, empty, or malformed, Fetch returns an
      error — the entry's canonical bytes are the authoritative content,
      and missing them is a fatal fetch failure.
    - HTTP timeout is 15s by default. The client is not retried internally
      — retry policy is the caller's concern (builder/occ_retry.go for
      the builder loop, explicit caller control for verifier/lifecycle
      paths).

OVERVIEW:
    GET /v1/entries/{sequence} returns:
      {
        "sequence":            uint64,
        "canonical_hex":       string,  // authoritative wire bytes
        "log_time_unix_micro": int64,   // operator admission time
        "sig_algo_id":         uint16,  // IGNORED under v6 (inside canonical)
        "signature_hex":       string   // IGNORED under v6 (inside canonical)
      }

    404 → Fetch returns (nil, nil) — entry not found is a normal
    condition, not an error. Any other non-200 → Fetch returns an error.

    2 MiB response body limit (1 MiB envelope cap + overhead).

KEY DEPENDENCIES:
    - types/entry_with_metadata.go: EntryWithMetadata struct (no longer
      carries sig sidecar fields under v6)
    - types/log_position.go: LogPosition struct
    - net/http, encoding/hex, encoding/json (standard library)
*/
package log

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// -------------------------------------------------------------------------------------------------
// 1) HTTPEntryFetcher
// -------------------------------------------------------------------------------------------------

// HTTPEntryFetcher implements builder.EntryFetcher, verifier.EntryFetcher,
// and lifecycle.EntryFetcher (all structurally identical interfaces) by
// calling the operator's REST API.
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

// -------------------------------------------------------------------------------------------------
// 2) Constructor
// -------------------------------------------------------------------------------------------------

// NewHTTPEntryFetcher creates an EntryFetcher backed by the operator API.
// A zero or negative Timeout defaults to 15 seconds.
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

// -------------------------------------------------------------------------------------------------
// 3) Fetch — single-entry retrieval
// -------------------------------------------------------------------------------------------------

// Fetch retrieves an entry by log position via GET /v1/entries/{sequence}.
// Returns (nil, nil) if the entry does not exist (HTTP 404). Returns an
// error for any other non-200 response, network failure, parse failure,
// or canonical-bytes decode failure.
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

	// 2 MiB cap: 1 MiB entry + HTTP/JSON overhead + hex expansion
	// (hex is 2x the binary size).
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, fmt.Errorf("log/http: fetch read: %w", err)
	}

	var raw entryResponse
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("log/http: fetch parse: %w", err)
	}

	if raw.CanonicalHex == "" {
		return nil, errors.New("log/http: response missing canonical_hex")
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
	}

	if raw.LogTimeUnixMicro != 0 {
		meta.LogTime = time.UnixMicro(raw.LogTimeUnixMicro)
	}

	// Note: raw.SigAlgoID and raw.SignatureHex are intentionally NOT
	// consumed under v6. Signatures are inside CanonicalBytes (v6
	// signatures section) and are extracted via envelope.Deserialize
	// when needed. The fields remain in entryResponse so the JSON
	// decoder does not fail on operator responses that still include
	// them (backward-compatible HTTP contract).

	return meta, nil
}

// -------------------------------------------------------------------------------------------------
// 4) HTTP response schema
// -------------------------------------------------------------------------------------------------

// entryResponse is the JSON response from the operator's entry read
// endpoint. Field names match ortholog-operator/api/entries_read.go.
//
// SigAlgoID and SignatureHex remain declared here for JSON
// unmarshalling compatibility with operators that continue to return
// them. Under v6 the fetcher does not use their values — signatures
// live inside CanonicalHex — but decoding them does not fail, so
// operators on either side of the v6 upgrade can interoperate.
type entryResponse struct {
	Sequence         uint64 `json:"sequence"`
	CanonicalHex     string `json:"canonical_hex"`
	LogTimeUnixMicro int64  `json:"log_time_unix_micro"`

	// Deprecated sidecar fields. Ignored by v6 fetcher. Preserved in
	// the response struct so JSON decoding does not fail on operators
	// that still populate them.
	SigAlgoID    uint16 `json:"sig_algo_id,omitempty"`
	SignatureHex string `json:"signature_hex,omitempty"`
}
