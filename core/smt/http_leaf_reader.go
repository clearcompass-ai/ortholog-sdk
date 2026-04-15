/*
Package smt — http_leaf_reader.go implements smt.LeafReader over HTTP,
targeting the ortholog-operator's SMT leaf read endpoint.

Endpoint: GET /v1/smt/leaf/{hex_key}

The operator returns the current SMT leaf state (Key, OriginTip, AuthorityTip)
as JSON. The reader returns *types.SMTLeaf, satisfying smt.LeafReader through
Go structural typing.

The judicial network injects this at deployment time:
  leafReader := smt.NewHTTPLeafReader("https://operator.court.gov")

No import of ortholog-operator/. The HTTP boundary is the contract.

Consumed by:
  - verifier/delegation_tree.go WalkDelegationTree
  - builder/assemble_path_b.go AssemblePathB (via LeafReader)
  - verifier/authority_evaluator.go EvaluateAuthority
  - verifier/origin_evaluator.go EvaluateOrigin
  - lifecycle/scope_governance.go (scope leaf reads)
*/
package smt

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
// HTTPLeafReader
// ─────────────────────────────────────────────────────────────────────

// HTTPLeafReader implements smt.LeafReader by calling the operator's
// SMT leaf read endpoint. Thread-safe.
type HTTPLeafReader struct {
	baseURL string
	client  *http.Client
}

// HTTPLeafReaderConfig configures the HTTP leaf reader.
type HTTPLeafReaderConfig struct {
	// BaseURL is the operator's base URL (e.g., "https://operator.court.gov").
	BaseURL string

	// Timeout for HTTP requests. Default: 10s.
	Timeout time.Duration
}

// NewHTTPLeafReader creates a LeafReader backed by the operator's REST API.
func NewHTTPLeafReader(cfg HTTPLeafReaderConfig) *HTTPLeafReader {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &HTTPLeafReader{
		baseURL: cfg.BaseURL,
		client:  &http.Client{Timeout: timeout},
	}
}

// Get retrieves an SMT leaf by key via GET /v1/smt/leaf/{hex_key}.
// Returns nil, nil if the leaf does not exist (404).
//
// Satisfies smt.LeafReader through Go structural typing:
//
//	type LeafReader interface {
//	    Get(key [32]byte) (*types.SMTLeaf, error)
//	}
func (r *HTTPLeafReader) Get(key [32]byte) (*types.SMTLeaf, error) {
	hexKey := hex.EncodeToString(key[:])
	url := fmt.Sprintf("%s/v1/smt/leaf/%s", r.baseURL, hexKey)

	resp, err := r.client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("smt/http: get leaf: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil // Leaf not found — normal condition.
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("smt/http: get leaf: HTTP %d for key %s", resp.StatusCode, hexKey)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16)) // 64KB limit
	if err != nil {
		return nil, fmt.Errorf("smt/http: read leaf: %w", err)
	}

	var raw leafResponse
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("smt/http: parse leaf: %w", err)
	}

	// Decode hex key from response.
	var leafKey [32]byte
	if raw.KeyHex != "" {
		keyBytes, err := hex.DecodeString(raw.KeyHex)
		if err == nil && len(keyBytes) == 32 {
			copy(leafKey[:], keyBytes)
		}
	} else {
		leafKey = key // Use the requested key if response doesn't echo it.
	}

	leaf := &types.SMTLeaf{
		Key: leafKey,
		OriginTip: types.LogPosition{
			LogDID:   raw.OriginTipLogDID,
			Sequence: raw.OriginTipSequence,
		},
		AuthorityTip: types.LogPosition{
			LogDID:   raw.AuthorityTipLogDID,
			Sequence: raw.AuthorityTipSequence,
		},
	}

	return leaf, nil
}

// leafResponse is the JSON response from the operator's SMT leaf endpoint.
// Field names match ortholog-operator/api/smt_read.go.
type leafResponse struct {
	KeyHex               string `json:"key_hex"`
	OriginTipLogDID      string `json:"origin_tip_log_did"`
	OriginTipSequence    uint64 `json:"origin_tip_sequence"`
	AuthorityTipLogDID   string `json:"authority_tip_log_did"`
	AuthorityTipSequence uint64 `json:"authority_tip_sequence"`
}
