/*
Package storage — http_content_store.go implements ContentStore over HTTP,
targeting the ortholog-artifact-store REST API.

Endpoint mapping:
  Push    → POST   /v1/artifacts          (body=data, header X-Artifact-CID)
  Fetch   → GET    /v1/artifacts/{cid}    (returns raw bytes)
  Pin     → POST   /v1/artifacts/{cid}/pin
  Exists  → HEAD   /v1/artifacts/{cid}    (200=exists, 404=not)
  Delete  → DELETE /v1/artifacts/{cid}

The judicial network injects this at deployment time:
  contentStore := storage.NewHTTPContentStore("https://artifacts.court.gov")

No import of ortholog-artifact-store/. The HTTP boundary is the contract.

Consumed by:
  - lifecycle/artifact_access.go GrantArtifactAccess
  - lifecycle/recovery.go ExecuteRecovery
  - judicial-network deployment wiring
*/
package storage

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ─────────────────────────────────────────────────────────────────────
// HTTPContentStore
// ─────────────────────────────────────────────────────────────────────

// HTTPContentStore implements ContentStore by calling the artifact store's
// REST API over HTTP. Thread-safe (http.Client is safe for concurrent use).
type HTTPContentStore struct {
	baseURL string
	client  *http.Client
}

// HTTPContentStoreConfig configures the HTTP content store.
type HTTPContentStoreConfig struct {
	// BaseURL is the artifact store's base URL (e.g., "https://artifacts.court.gov").
	// No trailing slash.
	BaseURL string

	// Timeout for HTTP requests. Default: 30s.
	Timeout time.Duration
}

// NewHTTPContentStore creates a ContentStore backed by the artifact store API.
func NewHTTPContentStore(cfg HTTPContentStoreConfig) *HTTPContentStore {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &HTTPContentStore{
		baseURL: cfg.BaseURL,
		client:  &http.Client{Timeout: timeout},
	}
}

// Push stores data at the given CID via POST /v1/artifacts.
// The CID is sent as a header; the body carries raw artifact bytes.
func (s *HTTPContentStore) Push(cid CID, data []byte) error {
	url := s.baseURL + "/v1/artifacts"
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("storage/http: push request: %w", err)
	}
	req.Header.Set("X-Artifact-CID", cid.String())
	req.Header.Set("Content-Type", "application/octet-stream")

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("storage/http: push: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("storage/http: push: HTTP %d", resp.StatusCode)
	}
	return nil
}

// Fetch retrieves data by CID via GET /v1/artifacts/{cid}.
// Returns ErrContentNotFound if 404.
func (s *HTTPContentStore) Fetch(cid CID) ([]byte, error) {
	url := s.baseURL + "/v1/artifacts/" + cid.String()
	resp, err := s.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("storage/http: fetch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, ErrContentNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("storage/http: fetch: HTTP %d", resp.StatusCode)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, 100<<20)) // 100MB limit
	if err != nil {
		return nil, fmt.Errorf("storage/http: fetch read: %w", err)
	}
	return data, nil
}

// Pin marks a CID for persistent storage via POST /v1/artifacts/{cid}/pin.
func (s *HTTPContentStore) Pin(cid CID) error {
	url := s.baseURL + "/v1/artifacts/" + cid.String() + "/pin"
	resp, err := s.client.Post(url, "", nil)
	if err != nil {
		return fmt.Errorf("storage/http: pin: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return ErrContentNotFound
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("storage/http: pin: HTTP %d", resp.StatusCode)
	}
	return nil
}

// Exists checks if a CID is present via HEAD /v1/artifacts/{cid}.
func (s *HTTPContentStore) Exists(cid CID) (bool, error) {
	url := s.baseURL + "/v1/artifacts/" + cid.String()
	req, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return false, fmt.Errorf("storage/http: exists request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("storage/http: exists: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		return true, nil
	}
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	return false, fmt.Errorf("storage/http: exists: HTTP %d", resp.StatusCode)
}

// Delete removes a CID via DELETE /v1/artifacts/{cid}.
func (s *HTTPContentStore) Delete(cid CID) error {
	url := s.baseURL + "/v1/artifacts/" + cid.String()
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		return fmt.Errorf("storage/http: delete request: %w", err)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("storage/http: delete: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("storage/http: delete: HTTP %d", resp.StatusCode)
	}
	return nil
}
