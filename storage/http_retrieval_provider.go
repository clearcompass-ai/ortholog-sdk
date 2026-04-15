/*
Package storage — http_retrieval_provider.go implements RetrievalProvider
over HTTP, targeting the artifact store's resolve endpoint.

Endpoint: GET /v1/artifacts/{cid}/resolve?expiry={duration}

The artifact store generates a backend-specific retrieval credential:
  - GCS/S3: signed URL with TTL
  - IPFS: gateway URL with no expiry
  - Direct: plain URL

Response JSON:
  { "method": "signed_url", "url": "https://...", "expiry": "2026-05-14T..." }

Consumed by:
  - lifecycle/artifact_access.go GrantArtifactAccess
  - judicial-network deployment wiring
*/
package storage

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ─────────────────────────────────────────────────────────────────────
// HTTPRetrievalProvider
// ─────────────────────────────────────────────────────────────────────

// HTTPRetrievalProvider implements RetrievalProvider by calling the
// artifact store's resolve endpoint.
type HTTPRetrievalProvider struct {
	baseURL string
	client  *http.Client
}

// HTTPRetrievalProviderConfig configures the HTTP retrieval provider.
type HTTPRetrievalProviderConfig struct {
	// BaseURL is the artifact store's base URL. No trailing slash.
	BaseURL string

	// Timeout for HTTP requests. Default: 15s.
	Timeout time.Duration
}

// NewHTTPRetrievalProvider creates a RetrievalProvider backed by the
// artifact store's resolve API.
func NewHTTPRetrievalProvider(cfg HTTPRetrievalProviderConfig) *HTTPRetrievalProvider {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &HTTPRetrievalProvider{
		baseURL: cfg.BaseURL,
		client:  &http.Client{Timeout: timeout},
	}
}

// Resolve generates a retrieval credential for an artifact CID.
// Calls GET /v1/artifacts/{cid}/resolve?expiry={seconds}.
// The artifact store generates a backend-specific credential (signed URL,
// IPFS gateway, or direct URL).
func (p *HTTPRetrievalProvider) Resolve(artifactCID CID, expiry time.Duration) (*RetrievalCredential, error) {
	url := fmt.Sprintf("%s/v1/artifacts/%s/resolve?expiry=%d",
		p.baseURL, artifactCID.String(), int(expiry.Seconds()))

	resp, err := p.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("storage/http: resolve: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrContentNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("storage/http: resolve: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("storage/http: resolve read: %w", err)
	}

	var raw resolveResponse
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("storage/http: resolve parse: %w", err)
	}

	cred := &RetrievalCredential{
		Method: raw.Method,
		URL:    raw.URL,
	}

	if raw.Expiry != "" {
		t, err := time.Parse(time.RFC3339, raw.Expiry)
		if err == nil {
			cred.Expiry = &t
		}
	}

	return cred, nil
}

// resolveResponse is the JSON response from the artifact store's resolve endpoint.
type resolveResponse struct {
	Method string `json:"method"`
	URL    string `json:"url"`
	Expiry string `json:"expiry,omitempty"` // RFC3339. Empty for IPFS/direct.
}
