package log

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ─────────────────────────────────────────────────────────────────────
// DefaultTransport
// ─────────────────────────────────────────────────────────────────────

func TestDefaultTransport_TunedFields(t *testing.T) {
	tr := DefaultTransport()
	if tr.MaxIdleConns != DefaultMaxIdleConns {
		t.Errorf("MaxIdleConns=%d, want %d", tr.MaxIdleConns, DefaultMaxIdleConns)
	}
	if tr.MaxIdleConnsPerHost != DefaultMaxIdleConnsPerHost {
		t.Errorf("MaxIdleConnsPerHost=%d, want %d", tr.MaxIdleConnsPerHost, DefaultMaxIdleConnsPerHost)
	}
	if tr.IdleConnTimeout != DefaultIdleConnTimeout {
		t.Errorf("IdleConnTimeout=%v, want %v", tr.IdleConnTimeout, DefaultIdleConnTimeout)
	}
	if tr.TLSHandshakeTimeout != DefaultTLSHandshakeTimeout {
		t.Errorf("TLSHandshakeTimeout=%v, want %v", tr.TLSHandshakeTimeout, DefaultTLSHandshakeTimeout)
	}
	if tr.ResponseHeaderTimeout != DefaultResponseHeaderTimeout {
		t.Errorf("ResponseHeaderTimeout=%v, want %v", tr.ResponseHeaderTimeout, DefaultResponseHeaderTimeout)
	}
	if tr.ExpectContinueTimeout != DefaultExpectContinueTimeout {
		t.Errorf("ExpectContinueTimeout=%v, want %v", tr.ExpectContinueTimeout, DefaultExpectContinueTimeout)
	}
	if !tr.ForceAttemptHTTP2 {
		t.Error("ForceAttemptHTTP2 should be true")
	}
	if tr.Proxy == nil {
		t.Error("Proxy should be set to ProxyFromEnvironment, not nil")
	}
}

// ─────────────────────────────────────────────────────────────────────
// parseRetryAfter
// ─────────────────────────────────────────────────────────────────────

func TestParseRetryAfter_Empty(t *testing.T) {
	if d := parseRetryAfter("", time.Now()); d != 0 {
		t.Errorf("empty=%v, want 0", d)
	}
}

func TestParseRetryAfter_Integer(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"5", 5 * time.Second},
		{"0", 0},
		{"-1", 0}, // negative rejected
		{"86400", 86400 * time.Second},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := parseRetryAfter(tc.in, time.Now()); got != tc.want {
				t.Errorf("parseRetryAfter(%q)=%v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseRetryAfter_HTTPDate_Future(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	future := now.Add(10 * time.Second)
	d := parseRetryAfter(future.UTC().Format(http.TimeFormat), now)
	// Allow 1s tolerance for second-truncation in http.TimeFormat.
	if d < 9*time.Second || d > 11*time.Second {
		t.Errorf("got %v, want ~10s", d)
	}
}

func TestParseRetryAfter_HTTPDate_Past(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	past := now.Add(-10 * time.Second)
	if d := parseRetryAfter(past.UTC().Format(http.TimeFormat), now); d != 0 {
		t.Errorf("past date got %v, want 0", d)
	}
}

func TestParseRetryAfter_HTTPDate_RFC850(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	future := now.Add(10 * time.Second)
	d := parseRetryAfter(future.UTC().Format(time.RFC850), now)
	if d < 9*time.Second || d > 11*time.Second {
		t.Errorf("RFC850 got %v, want ~10s", d)
	}
}

func TestParseRetryAfter_Garbage(t *testing.T) {
	if d := parseRetryAfter("not a date or number", time.Now()); d != 0 {
		t.Errorf("garbage got %v, want 0", d)
	}
}

// ─────────────────────────────────────────────────────────────────────
// RetryAfterRoundTripper — happy path & retry mechanics
// ─────────────────────────────────────────────────────────────────────

// fakeTransport returns scripted responses or an error. attempts is
// atomic so tests can assert how many times RoundTrip ran.
type fakeTransport struct {
	attempts atomic.Int32
	respond  func(attempt int, req *http.Request) (*http.Response, error)
}

func (f *fakeTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	n := int(f.attempts.Add(1))
	return f.respond(n, req)
}

func resp(code int, body string, retryAfter string) *http.Response {
	hdr := make(http.Header)
	if retryAfter != "" {
		hdr.Set("Retry-After", retryAfter)
	}
	return &http.Response{
		StatusCode: code,
		Header:     hdr,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

// noSleep replaces ctxSleep so tests run instantly. Honors ctx
// cancellation for the cancellation tests.
func noSleep(ctx context.Context, _ time.Duration) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func TestRoundTrip_TransportErrorPropagates(t *testing.T) {
	want := errors.New("connection refused")
	rt := &RetryAfterRoundTripper{
		Inner: &fakeTransport{respond: func(_ int, _ *http.Request) (*http.Response, error) {
			return nil, want
		}},
		Sleep: noSleep,
	}
	req, _ := http.NewRequest(http.MethodGet, "http://x", nil)
	_, err := rt.RoundTrip(req)
	if !errors.Is(err, want) {
		t.Fatalf("got %v, want %v", err, want)
	}
}

func TestRoundTrip_Non503Returned(t *testing.T) {
	rt := &RetryAfterRoundTripper{
		Inner: &fakeTransport{respond: func(_ int, _ *http.Request) (*http.Response, error) {
			return resp(200, "ok", ""), nil
		}},
		Sleep: noSleep,
	}
	req, _ := http.NewRequest(http.MethodGet, "http://x", nil)
	r, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if r.StatusCode != 200 {
		t.Errorf("status=%d, want 200", r.StatusCode)
	}
}

func TestRoundTrip_503ThenSuccess(t *testing.T) {
	ft := &fakeTransport{respond: func(n int, _ *http.Request) (*http.Response, error) {
		if n == 1 {
			return resp(503, "busy", "1"), nil
		}
		return resp(200, "ok", ""), nil
	}}
	rt := &RetryAfterRoundTripper{Inner: ft, Sleep: noSleep}
	req, _ := http.NewRequest(http.MethodGet, "http://x", nil)
	r, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if r.StatusCode != 200 {
		t.Errorf("status=%d, want 200 after retry", r.StatusCode)
	}
	if got := ft.attempts.Load(); got != 2 {
		t.Errorf("attempts=%d, want 2", got)
	}
}

func TestRoundTrip_503ExhaustsRetries(t *testing.T) {
	ft := &fakeTransport{respond: func(_ int, _ *http.Request) (*http.Response, error) {
		return resp(503, "still busy", "1"), nil
	}}
	rt := &RetryAfterRoundTripper{Inner: ft, MaxRetries: 2, Sleep: noSleep}
	req, _ := http.NewRequest(http.MethodGet, "http://x", nil)
	r, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if r.StatusCode != 503 {
		t.Errorf("final status=%d, want 503", r.StatusCode)
	}
	if got := ft.attempts.Load(); got != 3 {
		t.Errorf("attempts=%d, want 3 (1 initial + 2 retries)", got)
	}
}

func TestRoundTrip_503MissingRetryAfter_FallsBackToMin(t *testing.T) {
	var observed time.Duration
	ft := &fakeTransport{respond: func(n int, _ *http.Request) (*http.Response, error) {
		if n == 1 {
			return resp(503, "", ""), nil
		}
		return resp(200, "", ""), nil
	}}
	rt := &RetryAfterRoundTripper{
		Inner:      ft,
		MinBackoff: 250 * time.Millisecond,
		Sleep: func(_ context.Context, d time.Duration) error {
			observed = d
			return nil
		},
	}
	req, _ := http.NewRequest(http.MethodGet, "http://x", nil)
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatalf("err=%v", err)
	}
	if observed != 250*time.Millisecond {
		t.Errorf("observed wait=%v, want 250ms (min)", observed)
	}
}

func TestRoundTrip_503LargeRetryAfter_ClampedToMax(t *testing.T) {
	var observed time.Duration
	ft := &fakeTransport{respond: func(n int, _ *http.Request) (*http.Response, error) {
		if n == 1 {
			return resp(503, "", "86400"), nil
		}
		return resp(200, "", ""), nil
	}}
	rt := &RetryAfterRoundTripper{
		Inner:      ft,
		MaxBackoff: 2 * time.Second,
		Sleep: func(_ context.Context, d time.Duration) error {
			observed = d
			return nil
		},
	}
	req, _ := http.NewRequest(http.MethodGet, "http://x", nil)
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatalf("err=%v", err)
	}
	if observed != 2*time.Second {
		t.Errorf("observed wait=%v, want 2s (max clamp)", observed)
	}
}

func TestRoundTrip_BodyWithoutGetBody_SurfaceErr(t *testing.T) {
	ft := &fakeTransport{respond: func(_ int, _ *http.Request) (*http.Response, error) {
		return resp(503, "", "1"), nil
	}}
	rt := &RetryAfterRoundTripper{Inner: ft, Sleep: noSleep}
	// Build a request whose body is a custom reader (NOT bytes.Reader,
	// strings.Reader, or bytes.Buffer) so stdlib does NOT auto-set
	// GetBody.
	body := io.NopCloser(strings.NewReader("payload"))
	req, _ := http.NewRequest(http.MethodPost, "http://x", body)
	req.GetBody = nil // make explicit
	r, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if r.StatusCode != 503 {
		t.Errorf("status=%d, want 503", r.StatusCode)
	}
	if got := r.Header.Get("X-Retry-Aborted"); !strings.Contains(got, "not replayable") {
		t.Errorf("X-Retry-Aborted=%q, want contains 'not replayable'", got)
	}
	// Drain to make sure surface503's body is readable.
	if _, err := io.ReadAll(r.Body); err != nil {
		t.Errorf("drain surface503 body: %v", err)
	}
}

func TestRoundTrip_GetBodyReturnsError_SurfaceErr(t *testing.T) {
	ft := &fakeTransport{respond: func(_ int, _ *http.Request) (*http.Response, error) {
		return resp(503, "", "1"), nil
	}}
	rt := &RetryAfterRoundTripper{Inner: ft, Sleep: noSleep}
	getBodyErr := errors.New("disk full")
	req, _ := http.NewRequest(http.MethodPost, "http://x", bytes.NewReader([]byte("payload")))
	req.GetBody = func() (io.ReadCloser, error) { return nil, getBodyErr }
	r, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if r.StatusCode != 503 {
		t.Errorf("status=%d", r.StatusCode)
	}
	if got := r.Header.Get("X-Retry-Aborted"); !strings.Contains(got, "disk full") {
		t.Errorf("X-Retry-Aborted=%q", got)
	}
}

func TestRoundTrip_CtxCancelledMidWait_SurfaceErr(t *testing.T) {
	ft := &fakeTransport{respond: func(_ int, _ *http.Request) (*http.Response, error) {
		return resp(503, "", "1"), nil
	}}
	rt := &RetryAfterRoundTripper{
		Inner: ft,
		Sleep: func(_ context.Context, _ time.Duration) error {
			return context.Canceled
		},
	}
	req, _ := http.NewRequest(http.MethodGet, "http://x", nil)
	r, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if r.StatusCode != 503 {
		t.Errorf("status=%d", r.StatusCode)
	}
	if got := r.Header.Get("X-Retry-Aborted"); !strings.Contains(got, "context canceled") {
		t.Errorf("X-Retry-Aborted=%q", got)
	}
}

func TestRoundTrip_BodyReplay_ConsumesEachAttempt(t *testing.T) {
	// Confirms that each retry actually receives the full body —
	// catches a regression where GetBody is forgotten and the
	// second attempt sends an empty body.
	type seen struct {
		body string
	}
	var seenBodies []seen
	ft := &fakeTransport{respond: func(n int, req *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(req.Body)
		seenBodies = append(seenBodies, seen{body: string(b)})
		if n < 3 {
			return resp(503, "", "1"), nil
		}
		return resp(200, "", ""), nil
	}}
	rt := &RetryAfterRoundTripper{Inner: ft, Sleep: noSleep}
	req, _ := http.NewRequest(http.MethodPost, "http://x", bytes.NewReader([]byte("payload")))
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatalf("err=%v", err)
	}
	if len(seenBodies) != 3 {
		t.Fatalf("got %d attempts, want 3", len(seenBodies))
	}
	for i, s := range seenBodies {
		if s.body != "payload" {
			t.Errorf("attempt %d body=%q, want %q", i, s.body, "payload")
		}
	}
}

// ─────────────────────────────────────────────────────────────────────
// Defaults applied
// ─────────────────────────────────────────────────────────────────────

func TestRoundTrip_DefaultsApplied(t *testing.T) {
	// Inner=nil: should fall through to http.DefaultTransport. We
	// can't easily make that fail, but we can prove the code path
	// is reached by spinning up an httptest.Server and confirming a
	// real round-trip succeeds.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer srv.Close()
	rt := &RetryAfterRoundTripper{Sleep: noSleep}
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	r, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if r.StatusCode != 200 {
		t.Errorf("status=%d", r.StatusCode)
	}
}

func TestRoundTrip_NowDefault(t *testing.T) {
	// Now=nil branch: cover by leaving it unset.
	rt := &RetryAfterRoundTripper{
		Inner: &fakeTransport{respond: func(_ int, _ *http.Request) (*http.Response, error) {
			return resp(200, "", ""), nil
		}},
		Sleep: noSleep,
	}
	req, _ := http.NewRequest(http.MethodGet, "http://x", nil)
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatalf("err=%v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// DefaultClient
// ─────────────────────────────────────────────────────────────────────

func TestDefaultClient_WiredCorrectly(t *testing.T) {
	c := DefaultClient(5 * time.Second)
	if c == nil {
		t.Fatal("nil client")
	}
	if c.Timeout != 5*time.Second {
		t.Errorf("Timeout=%v, want 5s", c.Timeout)
	}
	rt, ok := c.Transport.(*RetryAfterRoundTripper)
	if !ok {
		t.Fatalf("Transport=%T, want *RetryAfterRoundTripper", c.Transport)
	}
	if _, ok := rt.Inner.(*http.Transport); !ok {
		t.Errorf("Inner=%T, want *http.Transport", rt.Inner)
	}
}

func TestDefaultClient_ZeroTimeoutDisables(t *testing.T) {
	c := DefaultClient(0)
	if c.Timeout != 0 {
		t.Errorf("Timeout=%v, want 0", c.Timeout)
	}
}

// ─────────────────────────────────────────────────────────────────────
// ctxSleep
// ─────────────────────────────────────────────────────────────────────

func TestCtxSleep_NonPositiveReturnsImmediately(t *testing.T) {
	if err := ctxSleep(context.Background(), 0); err != nil {
		t.Errorf("zero err=%v", err)
	}
	if err := ctxSleep(context.Background(), -1*time.Second); err != nil {
		t.Errorf("negative err=%v", err)
	}
}

func TestCtxSleep_CancelledCtx(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := ctxSleep(ctx, 1*time.Second); !errors.Is(err, context.Canceled) {
		t.Errorf("got %v, want Canceled", err)
	}
}

func TestCtxSleep_CompletesShortWait(t *testing.T) {
	start := time.Now()
	if err := ctxSleep(context.Background(), 5*time.Millisecond); err != nil {
		t.Fatalf("err=%v", err)
	}
	if elapsed := time.Since(start); elapsed < 4*time.Millisecond {
		t.Errorf("returned too fast: %v", elapsed)
	}
}

// ─────────────────────────────────────────────────────────────────────
// surface503
// ─────────────────────────────────────────────────────────────────────

func TestSurface503_Shape(t *testing.T) {
	rt := &RetryAfterRoundTripper{}
	req, _ := http.NewRequest(http.MethodGet, "http://x", nil)
	r := rt.surface503(req, fmt.Errorf("test reason"))
	if r.StatusCode != 503 {
		t.Errorf("status=%d", r.StatusCode)
	}
	if r.Header.Get("X-Retry-Aborted") != "test reason" {
		t.Errorf("X-Retry-Aborted=%q", r.Header.Get("X-Retry-Aborted"))
	}
	if r.Request != req {
		t.Error("Request not pinned")
	}
	if r.ContentLength != int64(len("test reason")) {
		t.Errorf("ContentLength=%d", r.ContentLength)
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(body) != "test reason" {
		t.Errorf("body=%q", body)
	}
}

// ─────────────────────────────────────────────────────────────────────
// BUG #2: RoundTrip must NOT mutate the caller's *http.Request
// ─────────────────────────────────────────────────────────────────────

// TestRoundTrip_DoesNotMutateRequest pins the Go RoundTripper
// contract: "RoundTrip should not modify the request". Pre-fix, the
// 503-replay path assigned `req.Body = body` directly on the
// caller's request, so a second use of the same *http.Request would
// see a corrupted Body. This test fails on the pre-fix code and
// passes after BUG #2's clone-then-mutate refactor.
func TestRoundTrip_DoesNotMutateRequest(t *testing.T) {
	originalBody := bytes.NewReader([]byte("payload"))
	req, _ := http.NewRequest(http.MethodPost, "http://x", originalBody)
	originalGetBody := req.GetBody
	originalBodyField := req.Body

	ft := &fakeTransport{respond: func(n int, _ *http.Request) (*http.Response, error) {
		if n < 3 {
			return resp(503, "", "1"), nil
		}
		return resp(200, "", ""), nil
	}}
	rt := &RetryAfterRoundTripper{Inner: ft, Sleep: noSleep}
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}

	// req.Body MAY have been consumed by the first attempt's
	// inner RoundTrip (stdlib contract permits that), but the
	// FIELD itself must not have been reassigned by the SDK
	// middleware — otherwise downstream callers re-using the
	// request would see a body the SDK fabricated, not the one
	// they constructed.
	if req.Body != originalBodyField {
		t.Errorf("req.Body field was reassigned by middleware (BUG #2 regression)")
	}
	// GetBody must remain the caller's original — middleware does
	// not own this slot.
	if reflectFuncEq(req.GetBody, originalGetBody) == false {
		t.Errorf("req.GetBody was replaced by middleware (BUG #2 regression)")
	}
}

// reflectFuncEq compares two func references by their pointer; nil
// vs nil is equal. Used because Go does not allow `func == func`.
func reflectFuncEq(a, b func() (io.ReadCloser, error)) bool {
	return fmt.Sprintf("%p", a) == fmt.Sprintf("%p", b)
}

// ─────────────────────────────────────────────────────────────────────
// BUG #6: MaxRetries < 0 disables retries explicitly
// ─────────────────────────────────────────────────────────────────────

// TestRoundTrip_MaxRetriesNegative_NoReplay pins the BUG #6 contract:
// MaxRetries: -1 means "do not retry", surfacing the first 503 to
// the caller. This is the latency-sensitive / deterministic-test
// escape hatch.
func TestRoundTrip_MaxRetriesNegative_NoReplay(t *testing.T) {
	ft := &fakeTransport{respond: func(_ int, _ *http.Request) (*http.Response, error) {
		return resp(503, "busy", "1"), nil
	}}
	rt := &RetryAfterRoundTripper{Inner: ft, MaxRetries: -1, Sleep: noSleep}
	req, _ := http.NewRequest(http.MethodGet, "http://x", nil)
	r, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if r.StatusCode != 503 {
		t.Errorf("status=%d, want 503", r.StatusCode)
	}
	if got := ft.attempts.Load(); got != 1 {
		t.Errorf("attempts=%d, want 1 (no replay)", got)
	}
}

// TestRoundTrip_MaxRetriesZero_DefaultsToThree pins the legacy
// contract that MaxRetries == 0 means "use DefaultMaxRetries". This
// preserves zero-value config compatibility — every existing caller
// constructing the struct without setting MaxRetries continues to
// retry up to 3 times.
func TestRoundTrip_MaxRetriesZero_DefaultsToThree(t *testing.T) {
	ft := &fakeTransport{respond: func(_ int, _ *http.Request) (*http.Response, error) {
		return resp(503, "busy", "1"), nil
	}}
	rt := &RetryAfterRoundTripper{Inner: ft /* MaxRetries: 0 */, Sleep: noSleep}
	req, _ := http.NewRequest(http.MethodGet, "http://x", nil)
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatalf("err=%v", err)
	}
	// 1 initial + 3 retries = 4 attempts.
	if got := ft.attempts.Load(); got != int32(DefaultMaxRetries+1) {
		t.Errorf("attempts=%d, want %d", got, DefaultMaxRetries+1)
	}
}

// TestResolvedMaxRetries unit-tests the BUG #6 selector directly so
// branch coverage on the negative / zero / positive paths is pinned
// in the smallest possible test.
func TestResolvedMaxRetries(t *testing.T) {
	cases := []struct {
		in   int
		want int
	}{
		{-5, 0},
		{-1, 0},
		{0, DefaultMaxRetries},
		{1, 1},
		{7, 7},
	}
	for _, tc := range cases {
		rt := &RetryAfterRoundTripper{MaxRetries: tc.in}
		if got := rt.resolvedMaxRetries(); got != tc.want {
			t.Errorf("MaxRetries=%d → %d, want %d", tc.in, got, tc.want)
		}
	}
}
