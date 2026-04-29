/*
Package log — submitter_difficulty.go owns the cached operator
difficulty and the single fetch path that populates it.
*/
package log

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	sdkadmission "github.com/clearcompass-ai/ortholog-sdk/crypto/admission"
)

// difficultyResponse mirrors the JSON shape returned by
// ortholog-operator/api/queries.go::NewDifficultyHandler.
type difficultyResponse struct {
	Difficulty   uint32 `json:"difficulty"`
	HashFunction string `json:"hash_function"`
}

// ErrDifficultyFetch is returned when the operator's difficulty
// endpoint cannot be reached or returns an error response. Callers
// do errors.Is(err, ErrDifficultyFetch) to distinguish "couldn't
// learn difficulty" from "computed PoW but operator rejected it".
var ErrDifficultyFetch = errors.New("log/submitter: difficulty fetch failed")

// ─────────────────────────────────────────────────────────────────────
// Cache reads
// ─────────────────────────────────────────────────────────────────────

// getDifficulty returns the cached (difficulty, hashFunc) for Mode
// B PoW. Lazy-fetches on first call and re-fetches when the cache
// is older than DifficultyCacheTTL.
//
// Concurrency: read lock for the fast path; write lock with
// double-check for the cache-miss path. Only one goroutine
// fetches under thundering-herd conditions.
func (s *HTTPSubmitter) getDifficulty(ctx context.Context) (uint32, string, error) {
	// Fast path: cached and fresh.
	s.diffMu.RLock()
	if s.diff.Initialized && time.Since(s.diff.FetchedAt) < s.cfg.DifficultyCacheTTL {
		d, h := s.diff.Difficulty, s.diff.HashFunc
		s.diffMu.RUnlock()
		return d, h, nil
	}
	s.diffMu.RUnlock()

	// Slow path: fetch under write lock with double-check.
	return s.fetchDifficultyLocked(ctx)
}

// fetchDifficultyLocked acquires the write lock, re-checks the
// cache (another goroutine may have just refreshed), and on miss
// performs the network fetch. Always returns the post-fetch
// (difficulty, hashFunc) on success.
func (s *HTTPSubmitter) fetchDifficultyLocked(ctx context.Context) (uint32, string, error) {
	s.diffMu.Lock()
	defer s.diffMu.Unlock()

	// Double-check: another goroutine may have populated while we
	// were waiting for the lock.
	if s.diff.Initialized && time.Since(s.diff.FetchedAt) < s.cfg.DifficultyCacheTTL {
		return s.diff.Difficulty, s.diff.HashFunc, nil
	}

	d, h, err := s.doDifficultyFetch(ctx)
	if err != nil {
		return 0, "", err
	}
	s.diff = difficultyState{
		Difficulty:  d,
		HashFunc:    h,
		FetchedAt:   time.Now(),
		Initialized: true,
	}
	return d, h, nil
}

// ─────────────────────────────────────────────────────────────────────
// Refresh on demand (403 path)
// ─────────────────────────────────────────────────────────────────────

// refreshDifficulty forces a fresh fetch and returns whether the
// new value differs from the prior cache. Used by the Submit
// path's stamp-rejection retry: if the operator's difficulty has
// not changed since our last cache, retrying with the same
// (difficulty, hashFunc) will fail again — surface the rejection.
//
// Returns (newDiff, newHash, changed, err). changed is true iff
// the prior cache was Initialized AND any of difficulty or hash
// function changed from the prior values. (Uninitialized prior
// cache is treated as "changed" so the first stamp-rejection on
// an uncached client triggers exactly one retry.)
func (s *HTTPSubmitter) refreshDifficulty(ctx context.Context) (uint32, string, bool, error) {
	s.diffMu.Lock()
	defer s.diffMu.Unlock()

	priorInit := s.diff.Initialized
	priorDiff, priorHash := s.diff.Difficulty, s.diff.HashFunc

	d, h, err := s.doDifficultyFetch(ctx)
	if err != nil {
		return 0, "", false, err
	}
	s.diff = difficultyState{
		Difficulty:  d,
		HashFunc:    h,
		FetchedAt:   time.Now(),
		Initialized: true,
	}

	changed := !priorInit || d != priorDiff || h != priorHash
	return d, h, changed, nil
}

// ─────────────────────────────────────────────────────────────────────
// HTTP fetch
// ─────────────────────────────────────────────────────────────────────

// doDifficultyFetch performs a single GET /v1/admission/difficulty
// request. Caller MUST hold s.diffMu.Lock to serialize updates to
// the cache.
//
// Always uses the submitter's wired *http.Client so the call
// participates in the same connection pool and 503-Retry-After
// middleware as Submit/SubmitBatch — operators under WAL pressure
// also serve difficulty under pressure.
func (s *HTTPSubmitter) doDifficultyFetch(ctx context.Context) (uint32, string, error) {
	url := s.cfg.BaseURL + "/v1/admission/difficulty"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return 0, "", fmt.Errorf("%w: %v", ErrDifficultyFetch, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := s.client.Do(req)
	if err != nil {
		return 0, "", fmt.Errorf("%w: %v", ErrDifficultyFetch, err)
	}
	defer drainAndClose(resp)

	if resp.StatusCode != http.StatusOK {
		body := readBodySnippet(resp.Body)
		return 0, "", fmt.Errorf("%w: HTTP %d: %s",
			ErrDifficultyFetch, resp.StatusCode, body)
	}

	// Cap at 4 KiB — the legitimate response is ~50 bytes; anything
	// larger is suspect.
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
	if err != nil {
		return 0, "", fmt.Errorf("%w: read body: %v", ErrDifficultyFetch, err)
	}

	var dr difficultyResponse
	if err := json.Unmarshal(body, &dr); err != nil {
		return 0, "", fmt.Errorf("%w: parse: %v", ErrDifficultyFetch, err)
	}
	if dr.Difficulty == 0 {
		return 0, "", fmt.Errorf("%w: operator returned zero difficulty", ErrDifficultyFetch)
	}
	if dr.HashFunction == "" {
		return 0, "", fmt.Errorf("%w: operator returned empty hash_function", ErrDifficultyFetch)
	}
	return dr.Difficulty, dr.HashFunction, nil
}

// hashFuncByte translates the operator's hash_function string into
// the wire byte the AdmissionProofBody.HashFunc field expects.
// Unknown values return ErrDifficultyFetch with a "unsupported hash"
// detail. The previous implementation silently fell back to SHA-256;
// that hid operator-side hash upgrades and produced un-verifiable
// stamps with no telemetry path back to the cause (BUG #4).
func hashFuncByte(name string) (uint8, error) {
	switch name {
	case "sha256":
		return sdkadmission.WireByteHashSHA256, nil
	case "argon2id":
		return sdkadmission.WireByteHashArgon2id, nil
	default:
		return 0, fmt.Errorf("%w: unsupported hash %q", ErrDifficultyFetch, name)
	}
}

// hashFuncTyped translates the operator's hash_function string to
// the typed admission.HashFunc constant used by VerifyStamp during
// PoW self-check. Symmetric error contract with hashFuncByte; both
// must agree on the supported set or the build/verify pair will
// drift.
func hashFuncTyped(name string) (sdkadmission.HashFunc, error) {
	switch name {
	case "sha256":
		return sdkadmission.HashSHA256, nil
	case "argon2id":
		return sdkadmission.HashArgon2id, nil
	default:
		return 0, fmt.Errorf("%w: unsupported hash %q", ErrDifficultyFetch, name)
	}
}
