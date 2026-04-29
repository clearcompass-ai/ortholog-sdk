/*
Package log — http_query_api.go declares HTTPOperatorQueryAPI and
its shared machinery (constructor, JSON parser, position encoder).

The five query methods (QueryByCosignatureOf, QueryByTargetRoot,
QueryBySignerDID, QueryBySchemaRef, ScanFromPosition) live in
http_query_api_methods.go so each file stays under 250 lines.

Egress-protection contract:

	Every method returns []types.EntryWithMetadata with
	CanonicalBytes == nil. The operator's query endpoints
	deliberately serve metadata only to protect operator RAM and
	S3 egress (per ortholog-operator/api/queries.go::EntryResponse).
	Consumers who need raw bytes pass the resulting Position to
	HTTPEntryFetcher.Fetch, which hits /v1/entries/{seq}/raw and
	follows the 302 directly to the bucket.

Position encoding (last-colon split):

	The operator parses {pos} arguments as "did:sequence" by
	splitting on the LAST colon (per
	api/queries.go::parseLogPosition) so DIDs containing colons
	(did:web:x, did:ortholog:a:b:c) round-trip correctly.
	encodePosition mirrors that contract.

Pagination:

	ScanFromPosition is a flat-offset endpoint. The SDK passes
	start + count and returns the resulting slice. Consumers
	track lastSeq+1 for the next page; no hidden cursor state in
	the SDK.
*/
package log

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────

// maxQueryResponseBytes caps query response bodies. Sized for a
// large multi-entry result (1000 entries × 1KB metadata each =
// 1 MiB; cap at 16 MiB for headroom).
const maxQueryResponseBytes = 16 << 20

// defaultQueryTimeout caps each query round-trip including the
// 503-Retry-After middleware's retries. Queries are read-only and
// should be fast on the operator side.
const defaultQueryTimeout = 30 * time.Second

// ─────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────

// ErrInvalidQueryConfig wraps constructor validation failures.
var ErrInvalidQueryConfig = errors.New("log/query: invalid configuration")

// ErrQueryFailed wraps non-200 responses from query endpoints.
// Callers errors.Is(err, ErrQueryFailed) to dispatch.
var ErrQueryFailed = errors.New("log/query: operator returned non-200")

// ─────────────────────────────────────────────────────────────────────
// Wire types (mirror operator's api/queries.go::EntryResponse)
// ─────────────────────────────────────────────────────────────────────

// queryEntryResponse is one row in the operator's metadata
// response. Fields match api/queries.go::EntryResponse JSON tags.
type queryEntryResponse struct {
	SequenceNumber  uint64 `json:"sequence_number"`
	CanonicalHash   string `json:"canonical_hash"`
	LogTime         string `json:"log_time"`
	SignerDID       string `json:"signer_did,omitempty"`
	ProtocolVersion uint16 `json:"protocol_version"`
	PayloadSize     int    `json:"payload_size"`
	CanonicalSize   int    `json:"canonical_size"`
}

// queryListResponse is the JSON envelope for the five header-field
// query handlers.
type queryListResponse struct {
	Entries []queryEntryResponse `json:"entries"`
	Count   int                  `json:"count"`
}

// ─────────────────────────────────────────────────────────────────────
// HTTPOperatorQueryAPI
// ─────────────────────────────────────────────────────────────────────

// HTTPOperatorQueryAPIConfig configures the query client.
type HTTPOperatorQueryAPIConfig struct {
	BaseURL string        // operator base URL, no trailing slash
	LogDID  string        // populates Position.LogDID on returned entries
	Timeout time.Duration // default 30s
	Client  *http.Client  // default DefaultClient(Timeout)
}

// HTTPOperatorQueryAPI implements OperatorQueryAPI over HTTP.
// Goroutine-safe; share one instance across goroutines.
type HTTPOperatorQueryAPI struct {
	baseURL string
	logDID  string
	client  *http.Client
}

// NewHTTPOperatorQueryAPI returns a query client wired against
// the operator at cfg.BaseURL. cfg.LogDID is required so returned
// EntryWithMetadata.Position.LogDID is populated.
func NewHTTPOperatorQueryAPI(cfg HTTPOperatorQueryAPIConfig) (*HTTPOperatorQueryAPI, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("%w: BaseURL required", ErrInvalidQueryConfig)
	}
	if cfg.LogDID == "" {
		return nil, fmt.Errorf("%w: LogDID required", ErrInvalidQueryConfig)
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultQueryTimeout
	}
	client := cfg.Client
	if client == nil {
		client = DefaultClient(timeout)
	}
	return &HTTPOperatorQueryAPI{
		baseURL: cfg.BaseURL,
		logDID:  cfg.LogDID,
		client:  client,
	}, nil
}

// ─────────────────────────────────────────────────────────────────────
// Helpers used by every query method
// ─────────────────────────────────────────────────────────────────────

// encodePosition formats a LogPosition as "{logDID}:{seq}" for
// the operator's last-colon-split parser. URL-escapes the resulting
// string so DIDs containing reserved URL characters survive the
// path segment.
func encodePosition(pos types.LogPosition) string {
	return url.PathEscape(fmt.Sprintf("%s:%d", pos.LogDID, pos.Sequence))
}

// doGet performs a GET against the given path and returns the
// decoded list response. Always uses the wired *http.Client and
// drains the body before close for HTTP/2 stream hygiene.
func (q *HTTPOperatorQueryAPI) doGet(
	ctx context.Context,
	path string,
) (*queryListResponse, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, q.baseURL+path, nil)
	if err != nil {
		return nil, fmt.Errorf("log/query: build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := q.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("log/query: do request: %w", err)
	}
	defer drainAndClose(resp)

	if resp.StatusCode != http.StatusOK {
		body := readBodySnippet(resp.Body)
		return nil, fmt.Errorf("%w: HTTP %d: %s", ErrQueryFailed, resp.StatusCode, body)
	}
	// BUG #3 fix: read maxQueryResponseBytes+1 to surface oversize
	// responses with a typed error rather than silent truncation +
	// downstream JSON parse failure.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxQueryResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("log/query: read body: %w", err)
	}
	if len(body) > maxQueryResponseBytes {
		return nil, fmt.Errorf("log/query: response body exceeds %d bytes",
			maxQueryResponseBytes)
	}
	var out queryListResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("log/query: parse response: %w", err)
	}
	return &out, nil
}

// toEntries converts wire rows to EntryWithMetadata. CanonicalBytes
// is intentionally left nil (egress-protection mandate); LogTime
// is parsed as RFC3339Nano.
func (q *HTTPOperatorQueryAPI) toEntries(rows []queryEntryResponse) []types.EntryWithMetadata {
	out := make([]types.EntryWithMetadata, 0, len(rows))
	for _, r := range rows {
		ewm := types.EntryWithMetadata{
			CanonicalBytes: nil, // explicit: egress mandate
			Position: types.LogPosition{
				LogDID:   q.logDID,
				Sequence: r.SequenceNumber,
			},
		}
		if r.LogTime != "" {
			if t, err := time.Parse(time.RFC3339Nano, r.LogTime); err == nil {
				ewm.LogTime = t.UTC()
			}
		}
		out = append(out, ewm)
	}
	return out
}
