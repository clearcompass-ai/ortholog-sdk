/*
Package log — transport.go gives the SDK a single, tuned-and-
backpressure-aware HTTP transport.

Why this file exists:

	Every prior fetcher in the SDK (HTTPEntryFetcher,
	HTTPContentStore) constructed its own &http.Client{Timeout: 15s}
	with no Transport tuning, inheriting stdlib defaults including
	MaxIdleConnsPerHost=2. Against a single operator at 10M
	entries/day (≈115 RPS sustained, ≈1k RPS peak), 2 idle conns
	per host produces a TIME_WAIT pile-up and steady TLS handshake
	overhead that consumes more CPU than the verifier itself.

	Separately, the operator's admission and batch handlers return
	HTTP 503 with Retry-After: 5 when the WAL queue is saturated
	(see ortholog-operator/api/submission.go::Step 11 and
	api/batch.go's WAL branch). Without a client-side honor of that
	header, every micro-burst of disk pressure drops entries and
	forces consumers to reinvent retry logic.

What this file ships:

  - DefaultTransport() — production-tuned *http.Transport.
  - RetryAfterRoundTripper — middleware honoring 503 Retry-After.
  - DefaultClient(timeout) — composes both into one *http.Client.

Threading model:

	*http.Transport and *http.Client are documented as safe for
	concurrent use; the RoundTripper here is stateless apart from a
	clock and an inner transport, both shared. Callers can keep one
	*http.Client per process and reuse it across goroutines.

The replay invariant:

	Retry-on-503 only works for requests whose body is replayable.
	Stdlib's http.NewRequest auto-populates req.GetBody when the
	body is *bytes.Buffer, *bytes.Reader, or *strings.Reader. For
	any other io.Reader (streaming uploads), the caller MUST set
	req.GetBody explicitly OR accept that retries on those requests
	will not consume the body and will fail at the operator with a
	short-body error. The middleware logs and surfaces the original
	503 in that case rather than retrying half-blind.
*/
package log

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ─────────────────────────────────────────────────────────────────────
// DefaultTransport
// ─────────────────────────────────────────────────────────────────────

// Connection-pool tuning constants. Exposed as exported constants so
// integration tests and observability tooling can pin against the
// same numbers without re-derivation.
const (
	// DefaultMaxIdleConns caps the total idle connections the
	// transport keeps across all hosts. 200 sized to a typical
	// Judicial Network deployment hitting ≤4 operators with ≤100
	// concurrent goroutines per operator.
	DefaultMaxIdleConns = 200

	// DefaultMaxIdleConnsPerHost caps idle connections to any one
	// host. The stdlib default of 2 is the TIME_WAIT bomb at high
	// throughput; 100 keeps TLS sessions warm.
	DefaultMaxIdleConnsPerHost = 100

	// DefaultIdleConnTimeout is how long an idle keep-alive
	// connection lives before the transport closes it. 90s aligns
	// with most reverse proxies' default keep-alive (60–120s) so
	// the client closes before the server does — avoids the
	// "connection reset by peer" race after server-initiated
	// close.
	DefaultIdleConnTimeout = 90 * time.Second

	// DefaultTLSHandshakeTimeout caps how long a TLS handshake may
	// take. 10s catches genuinely broken peers without killing
	// slow-but-OK ones on the first request after a long idle.
	DefaultTLSHandshakeTimeout = 10 * time.Second

	// DefaultResponseHeaderTimeout caps the wait for response
	// headers after the request body is sent. 30s guards against a
	// hung operator that accepts the body but never returns
	// status. Without this, a goroutine pinned by a hung operator
	// stays pinned forever.
	DefaultResponseHeaderTimeout = 30 * time.Second

	// DefaultExpectContinueTimeout caps the wait for a 100 Continue
	// response after sending Expect: 100-continue. 1s is the stdlib
	// default; pinned here for explicitness.
	DefaultExpectContinueTimeout = 1 * time.Second
)

// DefaultTransport returns a fresh *http.Transport tuned for the
// SDK's high-throughput Judicial Network workload.
//
// Each call returns a NEW transport — share one across requests for
// connection-pool benefit; do not allocate per-request.
func DefaultTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		MaxIdleConns:          DefaultMaxIdleConns,
		MaxIdleConnsPerHost:   DefaultMaxIdleConnsPerHost,
		IdleConnTimeout:       DefaultIdleConnTimeout,
		TLSHandshakeTimeout:   DefaultTLSHandshakeTimeout,
		ResponseHeaderTimeout: DefaultResponseHeaderTimeout,
		ExpectContinueTimeout: DefaultExpectContinueTimeout,
		ForceAttemptHTTP2:     true,
	}
}

// ─────────────────────────────────────────────────────────────────────
// RetryAfterRoundTripper
// ─────────────────────────────────────────────────────────────────────

// RetryAfter middleware constants.
const (
	// DefaultMaxRetries is the cap on attempts after the initial
	// request. 3 is the policy point: enough to ride out a
	// committer pause without amplifying load on a sustained
	// outage.
	DefaultMaxRetries = 3

	// DefaultMaxBackoff caps a single Retry-After wait. Operators
	// returning insane values (Retry-After: 86400) cannot pin the
	// client.
	DefaultMaxBackoff = 30 * time.Second

	// DefaultMinBackoff is the floor when Retry-After is missing,
	// malformed, or zero. Some servers return 503 without a
	// Retry-After header; the middleware must still wait long
	// enough that an immediate retry doesn't amplify load.
	DefaultMinBackoff = 1 * time.Second
)

// RetryAfterRoundTripper wraps an inner RoundTripper and retries
// requests that return HTTP 503 Service Unavailable. The wait between
// attempts is taken from the response's Retry-After header (RFC 7231
// §7.1.3), which the operator's admission handlers set to "5".
//
// Retries replay the request body via req.GetBody. Callers building
// requests with bodies that are not *bytes.Reader / *bytes.Buffer /
// *strings.Reader (where stdlib auto-sets GetBody) MUST set GetBody
// themselves; otherwise retries fall through and the original 503
// surfaces to the caller.
type RetryAfterRoundTripper struct {
	// Inner is the wrapped transport. nil means http.DefaultTransport.
	Inner http.RoundTripper

	// MaxRetries is the cap on retry attempts after the initial
	// request. Zero or negative defaults to DefaultMaxRetries.
	MaxRetries int

	// MaxBackoff caps any single Retry-After wait. Zero defaults
	// to DefaultMaxBackoff.
	MaxBackoff time.Duration

	// MinBackoff is the floor used when Retry-After is missing or
	// unparseable. Zero defaults to DefaultMinBackoff.
	MinBackoff time.Duration

	// Now returns the current wall-clock time. Injectable so tests
	// can pin HTTP-date math without sleeping. nil → time.Now.
	Now func() time.Time

	// Sleep blocks for d while honoring ctx. Injectable so tests
	// run instantly. nil → ctxSleep (waits the full duration).
	Sleep func(ctx context.Context, d time.Duration) error
}

// ErrBodyNotReplayable is returned (via the synthetic 503 surface)
// when the request has a body but no GetBody. Exported so callers
// can distinguish a "we couldn't retry" 503 from a "the operator
// returned 503" 503 by inspecting X-Retry-Aborted.
var ErrBodyNotReplayable = errors.New("log/transport: request body not replayable; set req.GetBody for retry support")

// RoundTrip executes req with bounded 503-retry semantics.
//
// On any non-503 response (including transport errors), returns
// immediately. On 503, drains the body, computes the backoff per
// Retry-After (clamped to [MinBackoff, MaxBackoff]), waits while
// honoring ctx, replays the body via req.GetBody, and retries.
// After MaxRetries attempts the final 503 response is returned to
// the caller.
func (rt *RetryAfterRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	inner := rt.Inner
	if inner == nil {
		inner = http.DefaultTransport
	}
	maxRetries := rt.MaxRetries
	if maxRetries <= 0 {
		maxRetries = DefaultMaxRetries
	}
	maxBackoff := rt.MaxBackoff
	if maxBackoff <= 0 {
		maxBackoff = DefaultMaxBackoff
	}
	minBackoff := rt.MinBackoff
	if minBackoff <= 0 {
		minBackoff = DefaultMinBackoff
	}
	now := rt.Now
	if now == nil {
		now = time.Now
	}
	sleep := rt.Sleep
	if sleep == nil {
		sleep = ctxSleep
	}

	// Replay loop. attempt counts from 0 (the original send); the
	// loop runs maxRetries+1 times in the worst case.
	for attempt := 0; attempt <= maxRetries; attempt++ {
		resp, err := inner.RoundTrip(req)
		if err != nil {
			// Transport-level errors are not retried — the caller
			// owns transport-error policy (network DNS, connection
			// refused). Returning here matches the contract of the
			// stdlib RoundTripper.
			return nil, err
		}
		if resp.StatusCode != http.StatusServiceUnavailable {
			return resp, nil
		}
		// 503 path: compute backoff, drain body, replay or surface.
		if attempt == maxRetries {
			// Out of attempts. Return the final 503 unchanged so
			// the caller can inspect it.
			return resp, nil
		}
		backoff := parseRetryAfter(resp.Header.Get("Retry-After"), now())
		if backoff < minBackoff {
			backoff = minBackoff
		}
		if backoff > maxBackoff {
			backoff = maxBackoff
		}
		// Drain and close so the connection can be reused.
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()

		// Replay the body. If GetBody is missing and the request
		// has a body, we cannot retry safely.
		if req.Body != nil && req.GetBody == nil {
			return rt.surface503(req, ErrBodyNotReplayable), nil
		}
		if req.GetBody != nil {
			body, err := req.GetBody()
			if err != nil {
				return rt.surface503(req, fmt.Errorf("log/transport: GetBody: %w", err)), nil
			}
			req.Body = body
		}

		// Wait, honoring ctx.
		if err := sleep(req.Context(), backoff); err != nil {
			// Context cancelled mid-wait. Surface a synthetic 503 —
			// the caller decides what to do.
			return rt.surface503(req, err), nil
		}
	}
	// Unreachable: the loop returns inside (success path or final
	// 503 return). If a future refactor breaks that invariant the
	// caller observes a nil response and a clear error.
	return nil, errors.New("log/transport: retry loop exited without response (impossible state)")
}

// surface503 returns a synthetic 503 response carrying the given
// error as the body so the caller's error handling path can read a
// sensible message. Used when retry preparation fails (no GetBody,
// ctx cancelled).
func (rt *RetryAfterRoundTripper) surface503(req *http.Request, cause error) *http.Response {
	msg := cause.Error()
	body := io.NopCloser(strings.NewReader(msg))
	hdr := make(http.Header)
	hdr.Set("Content-Type", "text/plain; charset=utf-8")
	hdr.Set("X-Retry-Aborted", msg)
	return &http.Response{
		Status:        "503 Service Unavailable",
		StatusCode:    http.StatusServiceUnavailable,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        hdr,
		Body:          body,
		ContentLength: int64(len(msg)),
		Request:       req,
	}
}

// ─────────────────────────────────────────────────────────────────────
// Retry-After parsing
// ─────────────────────────────────────────────────────────────────────

// parseRetryAfter implements RFC 7231 §7.1.3: the value is either
// delta-seconds (integer) or an HTTP-date. Returns 0 for missing,
// negative, or unparseable values; the caller clamps to [min, max].
func parseRetryAfter(value string, now time.Time) time.Duration {
	if value == "" {
		return 0
	}
	// delta-seconds: integer (could include leading + or whitespace
	// in pathological servers; strconv.Atoi tolerates neither, but
	// strict parsing is the safer default).
	if secs, err := strconv.Atoi(value); err == nil {
		if secs < 0 {
			return 0
		}
		return time.Duration(secs) * time.Second
	}
	// HTTP-date: try RFC1123 (preferred), then RFC850 and asctime
	// fallbacks per stdlib parser order.
	for _, layout := range []string{
		http.TimeFormat,
		time.RFC1123,
		time.RFC850,
		time.ANSIC,
	} {
		if t, err := time.Parse(layout, value); err == nil {
			d := t.Sub(now)
			if d < 0 {
				return 0
			}
			return d
		}
	}
	return 0
}

// ─────────────────────────────────────────────────────────────────────
// Client composition
// ─────────────────────────────────────────────────────────────────────

// DefaultClient returns a *http.Client wired with the SDK's default
// transport and the 503-Retry-After middleware. timeout caps the
// total round-trip including all retries; pass <=0 to disable
// (preserves request-context cancellation as the only cap).
//
// Each call returns a NEW client; share across requests for pool
// benefit.
func DefaultClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Transport: &RetryAfterRoundTripper{Inner: DefaultTransport()},
		Timeout:   timeout,
	}
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

// ctxSleep blocks for d, returning early with ctx.Err() if the
// context is cancelled. d <= 0 returns immediately with nil.
func ctxSleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
