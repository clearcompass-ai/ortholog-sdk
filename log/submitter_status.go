/*
Package log — submitter_status.go provides shared HTTP status helpers
for the submit and batch paths.
*/
package log

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// ─────────────────────────────────────────────────────────────────────
// Body lifecycle
// ─────────────────────────────────────────────────────────────────────

// maxDrainBytes caps how many bytes drainAndClose will read into
// io.Discard. A malicious or buggy operator returning a multi-GB
// error body cannot pin the client; anything beyond this cap is
// dropped and the connection reuses a fresh stream on the next
// request. 4 KiB is generous for legitimate JSON error responses
// (typical: <500 bytes) while bounding worst-case latency to
// drain.
const maxDrainBytes = 4 << 10

// drainAndClose ensures the HTTP/2 stream backing resp is properly
// released before close. Without this, a body closed mid-stream
// keeps the stream half-open and the operator's keep-alive pool
// gradually fills with unusable connections, surfacing as
// "stream is idle" / INTERNAL_ERROR errors at scale.
//
// Safe on nil resp / nil resp.Body. Errors during drain or close
// are intentionally ignored — the caller has already produced
// whatever value they care about; the drain is purely about
// connection hygiene.
func drainAndClose(resp *http.Response) {
	if resp == nil || resp.Body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxDrainBytes))
	_ = resp.Body.Close()
}

// ─────────────────────────────────────────────────────────────────────
// Body snippet for error messages
// ─────────────────────────────────────────────────────────────────────

// readBodySnippet reads up to maxErrBodyBytes from r and returns
// the bytes as a string for inclusion in error messages. Truncates
// silently — the snippet is for diagnostics, not for protocol
// parsing. Caller is responsible for closing the body afterward.
const maxErrBodyBytes = 1 << 12 // 4 KiB

func readBodySnippet(r io.Reader) string {
	if r == nil {
		return ""
	}
	buf, _ := io.ReadAll(io.LimitReader(r, maxErrBodyBytes))
	return strings.TrimSpace(string(buf))
}

// ─────────────────────────────────────────────────────────────────────
// Status code → typed error
// ─────────────────────────────────────────────────────────────────────

// stampFailedMarker is the substring the operator's
// api/submission.go::Step 7 writes into 403 response bodies on
// stamp verification failure. Pinned here so the submitter's
// 403-refetch path can distinguish stamp-rejection (retry-worthy
// after difficulty refresh) from other 403s like
// destination-mismatch (terminal).
//
// If the operator's wording ever drifts, the submitter's
// auto-refetch quietly degrades to never retry — a build-time
// regression test in submitter_status_test.go pins the exact
// substring against the operator's source.
const stampFailedMarker = "stamp verification failed:"

// isStampRejection reports whether a 403 body carries the
// stamp-failed marker. Used by the Submit path to gate the
// difficulty cache-bust + single-retry behavior.
func isStampRejection(body string) bool {
	return strings.Contains(body, stampFailedMarker)
}

// mapStatusToError converts an HTTP status code + body snippet
// into the appropriate typed error. Returns nil for 2xx — the
// caller is responsible for parsing success bodies.
//
// 503 is a special case: the RetryAfterRoundTripper transparently
// retries up to MaxRetries times before returning, so a 503 here
// means retries were exhausted (or the request body was not
// replayable, surfaced via X-Retry-Aborted). Either way, surface
// ErrServiceUnavailable with the body snippet.
func mapStatusToError(statusCode int, body string) error {
	switch statusCode {
	case http.StatusOK, http.StatusAccepted, http.StatusNoContent:
		return nil
	case http.StatusUnauthorized:
		return fmt.Errorf("%w: %s", ErrUnauthorized, body)
	case http.StatusPaymentRequired:
		return fmt.Errorf("%w: %s", ErrInsufficientCredits, body)
	case http.StatusForbidden:
		if isStampRejection(body) {
			return fmt.Errorf("%w: %s", ErrStampRejected, body)
		}
		return &HTTPError{StatusCode: statusCode, Body: body}
	case http.StatusConflict:
		return fmt.Errorf("%w: %s", ErrDuplicateEntry, body)
	case http.StatusRequestEntityTooLarge:
		return fmt.Errorf("%w: %s", ErrEntryTooLarge, body)
	case http.StatusUnprocessableEntity:
		return fmt.Errorf("%w: %s", ErrValidation, body)
	case http.StatusServiceUnavailable:
		return fmt.Errorf("%w: %s", ErrServiceUnavailable, body)
	default:
		return &HTTPError{StatusCode: statusCode, Body: body}
	}
}

// statusToTypedSentinel returns the typed sentinel that
// mapStatusToError would wrap for a given status, or nil if the
// status maps to HTTPError. Exposed for tests that want to assert
// errors.Is(err, sentinel) without rebuilding the wrap chain.
func statusToTypedSentinel(statusCode int, body string) error {
	if err := mapStatusToError(statusCode, body); err != nil {
		// Unwrap once: mapStatusToError uses fmt.Errorf("%w: ...")
		// for sentinels, so errors.Unwrap returns the sentinel.
		// HTTPError is its own type — return it as-is.
		if _, ok := err.(*HTTPError); ok {
			return err
		}
		return errors.Unwrap(err)
	}
	return nil
}
