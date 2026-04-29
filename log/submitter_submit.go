/*
Package log — submitter_submit.go is the single-entry submission
path. Composes buildOne (Mode A/B builder) + getDifficulty +
HTTP POST + SCT verification, with one bounded 403-cache-bust
retry for Mode B stamp rejections.
*/
package log

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/sct"
)

// maxSCTResponseBytes caps the JSON body the submitter accepts
// from /v1/entries. Single SCT JSON is ~1 KiB; cap at 64 KiB to
// guard against a misbehaving operator returning megabytes of
// response without making legitimate responses fail.
const maxSCTResponseBytes = 64 << 10

// Submit builds an entry from header + payload, posts to
// /v1/entries, and returns the verified SCT. Auto-handles Mode
// A vs Mode B based on cfg.AuthToken.
//
// Mode B 403-retry: if the operator rejects the stamp with the
// stamp-failed marker AND a fresh difficulty fetch reveals a
// changed (difficulty, hashFunc), the submitter rebuilds the
// entry with the new parameters and re-POSTs ONCE. If the
// difficulty has not changed, ErrStampRejected surfaces — no
// infinite retry loop.
//
// Returns:
//   - (*sct.SignedCertificateTimestamp, nil) on 202 + verified SCT.
//   - (nil, ErrInvalidConfig) if Mode B requested but difficulty
//     fetch failed.
//   - (nil, typed sentinel) for documented HTTP statuses
//     (401/402/403/409/413/422/503).
//   - (nil, *HTTPError) for any other non-2xx.
//   - (nil, ErrSCTRejected) if 202 returned but the SCT signature
//     does not verify against the operator's key.
func (s *HTTPSubmitter) Submit(
	ctx context.Context,
	header envelope.ControlHeader,
	payload []byte,
) (*sct.SignedCertificateTimestamp, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	// Mode A: no PoW, no difficulty cache. Build, post, verify.
	if s.modeIsAuthenticated() {
		wire, err := s.buildModeA(header, payload)
		if err != nil {
			return nil, err
		}
		return s.postAndVerify(ctx, wire)
	}

	// Mode B: fetch difficulty (cached), build, post.
	difficulty, hashFuncName, err := s.getDifficulty(ctx)
	if err != nil {
		return nil, err
	}
	wire, err := s.buildModeB(ctx, header, payload, difficulty, hashFuncName)
	if err != nil {
		return nil, err
	}

	res, postErr := s.postAndVerify(ctx, wire)
	if postErr == nil {
		return res, nil
	}

	// 403 with stamp-failed marker → refresh difficulty and try
	// once more if values changed.
	if !errors.Is(postErr, ErrStampRejected) {
		return nil, postErr
	}
	newDiff, newHash, changed, refreshErr := s.refreshDifficulty(ctx)
	if refreshErr != nil {
		// Difficulty fetch failed; return the original
		// stamp-rejection so the caller sees both signals.
		return nil, fmt.Errorf("%w; refresh difficulty also failed: %v",
			postErr, refreshErr)
	}
	if !changed {
		// Same difficulty would produce the same rejection — fail
		// fast rather than spin.
		return nil, postErr
	}
	wire2, err := s.buildModeB(ctx, header, payload, newDiff, newHash)
	if err != nil {
		return nil, err
	}
	return s.postAndVerify(ctx, wire2)
}

// ─────────────────────────────────────────────────────────────────────
// HTTP roundtrip + verification
// ─────────────────────────────────────────────────────────────────────

// postAndVerify sends canonical wire bytes to /v1/entries and
// returns the verified SCT on 202. Maps non-202 statuses to typed
// errors via mapStatusToError.
//
// Stream hygiene: drainAndClose runs in a defer so HTTP/2 streams
// release properly even when JSON parsing fails mid-body.
func (s *HTTPSubmitter) postAndVerify(
	ctx context.Context,
	wire []byte,
) (*sct.SignedCertificateTimestamp, error) {
	url := s.cfg.BaseURL + "/v1/entries"

	// bytes.NewReader sets GetBody automatically for the
	// RetryAfterRoundTripper's 503 replay path.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(wire))
	if err != nil {
		return nil, fmt.Errorf("log/submitter: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Accept", "application/json")
	if s.modeIsAuthenticated() {
		req.Header.Set("Authorization", "Bearer "+s.cfg.AuthToken)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("log/submitter: do request: %w", err)
	}
	defer drainAndClose(resp)

	if resp.StatusCode != http.StatusAccepted {
		body := readBodySnippet(resp.Body)
		return nil, mapStatusToError(resp.StatusCode, body)
	}

	// BUG #3 fix: read maxSCTResponseBytes+1 to detect oversize
	// responses. A misbehaving operator returning megabytes of JSON
	// would otherwise be silently truncated, producing a parse error
	// downstream with no attribution to the cause.
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxSCTResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("log/submitter: read response body: %w", err)
	}
	if len(bodyBytes) > maxSCTResponseBytes {
		return nil, fmt.Errorf(
			"log/submitter: SCT response body exceeds %d bytes",
			maxSCTResponseBytes)
	}

	var s_ sct.SignedCertificateTimestamp
	if err := json.Unmarshal(bodyBytes, &s_); err != nil {
		return nil, fmt.Errorf("log/submitter: parse SCT JSON: %w", err)
	}

	if err := sct.Verify(s.operatorPub, &s_); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSCTRejected, err)
	}
	return &s_, nil
}
