/*
FILE PATH:
    log/http_entry_fetcher.go

DESCRIPTION:
    HTTP-backed implementation of types.EntryFetcher (and
    verifier.EntryFetcher, lifecycle.EntryFetcher — all structurally
    identical). Targets the ortholog-operator's GET /v1/entries/{seq}/raw
    endpoint.

KEY ARCHITECTURAL DECISIONS:

    The /raw endpoint, not /v1/entries/{seq}:

	The operator splits read semantics across two endpoints:

	  GET /v1/entries/{seq}      → JSON metadata (no canonical bytes)
	  GET /v1/entries/{seq}/raw  → raw wire bytes:
	                                 200 + application/octet-stream (un-shipped)
	                                 302 + presigned URL          (shipped)

	This fetcher targets the /raw endpoint because EntryWithMetadata
	requires CanonicalBytes — the cryptographic payload — and the
	JSON metadata endpoint deliberately omits that field to protect
	operator RAM and S3 egress (see api/queries.go::EntryResponse).

    302 follow-through is automatic:

	Go's default http.Client follows up to 10 redirects. When the
	operator returns 302 + Location: <presigned URL>, the client
	disconnects from the operator and fetches directly from the
	bucket. The operator is OUT of the byte path. Presigned URLs
	carry their authentication in query parameters, not the
	Authorization header, so Go's standard "strip Authorization on
	cross-origin redirect" behavior is harmless here.

    Headers carry sidecar metadata:

	X-Sequence    — the canonical sequence number (uint64 decimal).
	                Set by both serveWALInline and serveBytestoreRedirect.
	X-Log-Time    — admission time as RFC-3339Nano UTC. Set by the
	                operator side; absence is tolerated (zero-value
	                LogTime in the returned EntryWithMetadata).

    Connection pooling and backpressure:

	Constructed via log.DefaultClient(timeout) so every fetcher in
	a process shares the tuned transport (MaxIdleConnsPerHost=100,
	IdleConnTimeout=90s) and the 503-Retry-After middleware. No
	more fresh &http.Client per fetcher.

    Strict byte-handling:

	The response body is raw octet bytes — no hex, no JSON. The
	fetcher reads up to maxRawBodyBytes (2 MiB) and returns the
	bytes verbatim. Consumers feed them to envelope.Deserialize.

OVERVIEW:
    GET /v1/entries/{seq}/raw returns one of:
      200 OK + application/octet-stream + raw wire bytes
      302 Found + Location: <presigned URL>  (auto-followed → 200 + raw bytes)
      404 Not Found

    404 → Fetch returns (nil, nil) — entry not found is a normal
    condition, not an error. Any other non-200 → Fetch returns an error.

KEY DEPENDENCIES:
    - types/entry_with_metadata.go: EntryWithMetadata struct
    - types/log_position.go:        LogPosition struct
    - log/transport.go:             DefaultClient, DefaultTransport
*/
package log

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// -------------------------------------------------------------------------------------------------
// 1) HTTPEntryFetcher
// -------------------------------------------------------------------------------------------------

// maxRawBodyBytes caps the inline-or-redirected response body. Sized
// to comfortably exceed the operator's default OPERATOR_MAX_ENTRY_SIZE
// of 1 MiB while bounding heap use under malicious or buggy peers.
const maxRawBodyBytes = 2 << 20 // 2 MiB

// rawSequenceHeader names the response header where the operator
// stamps the canonical sequence number on /raw responses.
const rawSequenceHeader = "X-Sequence"

// rawLogTimeHeader names the response header carrying the
// admission timestamp on /raw responses.
const rawLogTimeHeader = "X-Log-Time"

// HTTPEntryFetcher implements types.EntryFetcher,
// verifier.EntryFetcher, and lifecycle.EntryFetcher (all
// structurally identical) by calling the operator's /raw endpoint.
type HTTPEntryFetcher struct {
	baseURL string
	logDID  string
	client  *http.Client
}

// HTTPEntryFetcherConfig configures the HTTP entry fetcher.
type HTTPEntryFetcherConfig struct {
	// BaseURL is the operator's base URL (e.g.,
	// "https://operator.example.com"). No trailing slash.
	BaseURL string

	// LogDID populates EntryWithMetadata.Position.LogDID and is
	// used by callers to disambiguate when a process holds
	// multiple fetchers against multiple logs.
	LogDID string

	// Timeout caps the total round-trip including any 503-Retry
	// loops. Default: 30s.
	Timeout time.Duration

	// Client overrides the HTTP client. nil → DefaultClient(Timeout).
	// Tests pass an httptest-backed client here.
	Client *http.Client
}

// -------------------------------------------------------------------------------------------------
// 2) Constructor
// -------------------------------------------------------------------------------------------------

// NewHTTPEntryFetcher creates an EntryFetcher backed by the operator
// API. A zero or negative Timeout defaults to 30 seconds.
//
// If cfg.Client is nil, DefaultClient(Timeout) is used so every
// fetcher in the process shares the SDK's tuned transport and
// 503-Retry-After middleware.
func NewHTTPEntryFetcher(cfg HTTPEntryFetcherConfig) *HTTPEntryFetcher {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	client := cfg.Client
	if client == nil {
		client = DefaultClient(timeout)
	}
	return &HTTPEntryFetcher{
		baseURL: cfg.BaseURL,
		logDID:  cfg.LogDID,
		client:  client,
	}
}

// -------------------------------------------------------------------------------------------------
// 3) Fetch — single-entry retrieval
// -------------------------------------------------------------------------------------------------

// Fetch retrieves an entry by log position via
// GET /v1/entries/{seq}/raw. Returns (nil, nil) if the entry does not
// exist (HTTP 404). Returns an error for any other non-200 response
// (post-redirect-follow), network failure, or read failure.
//
// Satisfies types.EntryFetcher, verifier.EntryFetcher, and
// lifecycle.EntryFetcher through Go structural typing.
func (f *HTTPEntryFetcher) Fetch(pos types.LogPosition) (*types.EntryWithMetadata, error) {
	url := fmt.Sprintf("%s/v1/entries/%d/raw", f.baseURL, pos.Sequence)

	resp, err := f.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("log/http: fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("log/http: fetch: HTTP %d for seq %d", resp.StatusCode, pos.Sequence)
	}

	// BUG #3 fix: read maxRawBodyBytes+1 so an oversize response is
	// detectable rather than silently truncated. Pre-fix, a 3 MiB
	// response was chopped to 2 MiB and envelope.Deserialize returned
	// a confusing "incomplete frame" error with no attribution.
	wire, err := io.ReadAll(io.LimitReader(resp.Body, maxRawBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("log/http: fetch read: %w", err)
	}
	if len(wire) > maxRawBodyBytes {
		return nil, fmt.Errorf(
			"log/http: response body for seq %d exceeds %d bytes",
			pos.Sequence, maxRawBodyBytes)
	}
	if len(wire) == 0 {
		return nil, errors.New("log/http: empty wire body")
	}

	// Sequence: prefer the response header (truthful for both
	// inline and post-redirect responses); fall back to the request
	// position only if the header is absent (e.g., a future operator
	// version omits it). Mismatch is loud — header trumps and
	// disagreement returns an error to surface the misrouting.
	seq := pos.Sequence
	if h := resp.Header.Get(rawSequenceHeader); h != "" {
		parsed, parseErr := strconv.ParseUint(h, 10, 64)
		if parseErr != nil {
			return nil, fmt.Errorf("log/http: malformed %s header %q: %w",
				rawSequenceHeader, h, parseErr)
		}
		if parsed != pos.Sequence {
			return nil, fmt.Errorf(
				"log/http: %s=%d disagrees with requested seq %d",
				rawSequenceHeader, parsed, pos.Sequence)
		}
		seq = parsed
	}

	// LogTime: parse the X-Log-Time header if present. Absence is
	// tolerated — older operators do not set it; consumers that
	// need LogTime should fall back to the metadata endpoint.
	var logTime time.Time
	if h := resp.Header.Get(rawLogTimeHeader); h != "" {
		t, parseErr := time.Parse(time.RFC3339Nano, h)
		if parseErr != nil {
			return nil, fmt.Errorf("log/http: malformed %s header %q: %w",
				rawLogTimeHeader, h, parseErr)
		}
		logTime = t.UTC()
	}

	return &types.EntryWithMetadata{
		CanonicalBytes: wire,
		Position: types.LogPosition{
			LogDID:   f.logDID,
			Sequence: seq,
		},
		LogTime: logTime,
	}, nil
}
