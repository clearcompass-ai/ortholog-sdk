/*
Package log — submitter_batch.go is the bulk submission path.
Posts up to MaxBatchSize entries in one HTTP call, verifies each
returned SCT, and returns the verified slice.
*/
package log

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/sct"
)

// maxBatchResponseBytes caps the JSON response body. 256 SCTs at
// ~600 bytes JSON = ~150 KiB; cap at 16 MiB for headroom and to
// guard against runaway operator responses.
const maxBatchResponseBytes = 16 << 20

// batchEntryWire mirrors ortholog-operator/api/batch.go::BatchEntry.
type batchEntryWire struct {
	WireBytesHex string `json:"wire_bytes_hex"`
}

// batchRequest mirrors ortholog-operator/api/batch.go::BatchSubmissionRequest.
type batchRequest struct {
	Entries []batchEntryWire `json:"entries"`
}

// batchResultWire mirrors ortholog-operator/api/batch.go::BatchResultEntry.
type batchResultWire struct {
	SCT sct.SignedCertificateTimestamp `json:"sct"`
}

// batchResponse mirrors ortholog-operator/api/batch.go::BatchSubmissionResponse.
type batchResponse struct {
	Results []batchResultWire `json:"results"`
}

// SubmitBatch posts a slice of entries to /v1/entries/batch and
// returns one verified SCT per item, in request order. All items
// share the submitter's Mode A/B configuration; difficulty is
// fetched once and reused across the batch's Mode B builds.
//
// Returns:
//   - ErrBatchEmpty if items is empty.
//   - ErrBatchTooLarge if len(items) > MaxBatchSize.
//   - ErrBatchResultMismatch if the operator's response carries a
//     different count than was requested.
//   - ErrSCTRejected (with index in the message) if any returned
//     SCT fails signature verification.
//   - Any error returned by buildOne for a specific item (PoW
//     exhaustion, ctx cancellation, validation).
//   - Typed HTTP-status errors from mapStatusToError on non-202.
//   - context.Canceled / context.DeadlineExceeded directly when
//     ctx is pre-cancelled.
func (s *HTTPSubmitter) SubmitBatch(
	ctx context.Context,
	items []SubmitItem,
) ([]*sct.SignedCertificateTimestamp, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	// Surface cancellation directly without wrapping it inside a
	// difficulty-fetch error — pre-cancelled ctx must produce
	// context.Canceled cleanly.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(items) == 0 {
		return nil, ErrBatchEmpty
	}
	if len(items) > MaxBatchSize {
		return nil, fmt.Errorf("%w: %d > %d", ErrBatchTooLarge, len(items), MaxBatchSize)
	}

	// Resolve difficulty once for Mode B, reused across all items.
	var difficulty uint32
	var hashFuncName string
	if !s.modeIsAuthenticated() {
		d, h, err := s.getDifficulty(ctx)
		if err != nil {
			return nil, err
		}
		difficulty, hashFuncName = d, h
	}

	// Per-item build. Sequential — Mode B PoW is the expensive
	// step; concurrent fan-out would saturate cores without
	// reducing wall-clock since each PoW is itself CPU-bound.
	wires := make([]string, len(items))
	for i, item := range items {
		// Honor ctx between items so cancellation surfaces fast.
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		wire, err := s.buildOne(ctx, item.Header, item.Payload, difficulty, hashFuncName)
		if err != nil {
			return nil, fmt.Errorf("batch item %d: %w", i, err)
		}
		wires[i] = hex.EncodeToString(wire)
	}

	// Build request body.
	reqBody := batchRequest{Entries: make([]batchEntryWire, len(wires))}
	for i, w := range wires {
		reqBody.Entries[i] = batchEntryWire{WireBytesHex: w}
	}
	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("log/submitter: marshal batch: %w", err)
	}

	results, err := s.postBatch(ctx, jsonBody)
	if err != nil {
		return nil, err
	}

	// Verify count.
	if len(results) != len(items) {
		return nil, fmt.Errorf("%w: requested %d, got %d",
			ErrBatchResultMismatch, len(items), len(results))
	}

	// Verify each SCT.
	out := make([]*sct.SignedCertificateTimestamp, len(results))
	for i, r := range results {
		s_ := r.SCT
		if err := sct.Verify(s.operatorPub, &s_); err != nil {
			return nil, fmt.Errorf("%w: result[%d]: %v", ErrSCTRejected, i, err)
		}
		out[i] = &s_
	}
	return out, nil
}

// postBatch sends the JSON body and returns the parsed results
// slice, or a typed error for non-202 statuses.
func (s *HTTPSubmitter) postBatch(
	ctx context.Context,
	jsonBody []byte,
) ([]batchResultWire, error) {
	url := s.cfg.BaseURL + "/v1/entries/batch"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("log/submitter: build batch request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if s.modeIsAuthenticated() {
		req.Header.Set("Authorization", "Bearer "+s.cfg.AuthToken)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("log/submitter: do batch request: %w", err)
	}
	defer drainAndClose(resp)

	if resp.StatusCode != http.StatusAccepted {
		body := readBodySnippet(resp.Body)
		return nil, mapStatusToError(resp.StatusCode, body)
	}

	// BUG #3 fix: detect-and-error on overflow.
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxBatchResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("log/submitter: read batch response: %w", err)
	}
	if len(bodyBytes) > maxBatchResponseBytes {
		return nil, fmt.Errorf(
			"log/submitter: batch response body exceeds %d bytes",
			maxBatchResponseBytes)
	}

	var br batchResponse
	if err := json.Unmarshal(bodyBytes, &br); err != nil {
		return nil, fmt.Errorf("log/submitter: parse batch response: %w", err)
	}
	return br.Results, nil
}
