package log

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// ─────────────────────────────────────────────────────────────────────
// Tracer fixture
// ─────────────────────────────────────────────────────────────────────

func newRecordingTracer() (trace.Tracer, *tracetest.SpanRecorder) {
	rec := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(rec))
	return tp.Tracer("test"), rec
}

type stubRT struct {
	calls atomic.Int32
	resp  *http.Response
	err   error
}

func (s *stubRT) RoundTrip(*http.Request) (*http.Response, error) {
	s.calls.Add(1)
	return s.resp, s.err
}

func mkResp(code int) *http.Response {
	return &http.Response{
		StatusCode: code,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("")),
	}
}

// ─────────────────────────────────────────────────────────────────────
// Happy paths
// ─────────────────────────────────────────────────────────────────────

func TestOTel_HappyPath200(t *testing.T) {
	tracer, rec := newRecordingTracer()
	rt := &OTelTransport{Inner: &stubRT{resp: mkResp(200)}, Tracer: tracer}
	req, _ := http.NewRequest(http.MethodGet, "http://x/y/z?token=abc", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("%v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("status=%d", resp.StatusCode)
	}
	spans := rec.Ended()
	if len(spans) != 1 {
		t.Fatalf("spans=%d, want 1", len(spans))
	}
	if spans[0].Status().Code == codes.Error {
		t.Error("200 must not produce Error status")
	}
}

func TestOTel_4xxNotError(t *testing.T) {
	tracer, rec := newRecordingTracer()
	rt := &OTelTransport{Inner: &stubRT{resp: mkResp(404)}, Tracer: tracer}
	req, _ := http.NewRequest(http.MethodGet, "http://x", nil)
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatalf("%v", err)
	}
	if rec.Ended()[0].Status().Code == codes.Error {
		t.Error("4xx must NOT mark span Error")
	}
}

func TestOTel_5xxIsError(t *testing.T) {
	tracer, rec := newRecordingTracer()
	rt := &OTelTransport{Inner: &stubRT{resp: mkResp(503)}, Tracer: tracer}
	req, _ := http.NewRequest(http.MethodGet, "http://x", nil)
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatalf("%v", err)
	}
	if rec.Ended()[0].Status().Code != codes.Error {
		t.Errorf("5xx Status=%v, want Error", rec.Ended()[0].Status().Code)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Transport error
// ─────────────────────────────────────────────────────────────────────

func TestOTel_TransportError(t *testing.T) {
	tracer, rec := newRecordingTracer()
	want := errors.New("dns failure")
	rt := &OTelTransport{Inner: &stubRT{err: want}, Tracer: tracer}
	req, _ := http.NewRequest(http.MethodGet, "http://x", nil)
	_, err := rt.RoundTrip(req)
	if !errors.Is(err, want) {
		t.Fatalf("got %v, want %v", err, want)
	}
	span := rec.Ended()[0]
	if span.Status().Code != codes.Error {
		t.Error("transport err must mark span Error")
	}
	if len(span.Events()) == 0 {
		t.Error("transport err must record event (RecordError)")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Attributes
// ─────────────────────────────────────────────────────────────────────

func TestOTel_AttributesPopulated(t *testing.T) {
	tracer, rec := newRecordingTracer()
	rt := &OTelTransport{Inner: &stubRT{resp: mkResp(200)}, Tracer: tracer}
	req, _ := http.NewRequest(http.MethodPost,
		"http://operator.example.com/v1/entries?secret=xyz", nil)
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatalf("%v", err)
	}
	span := rec.Ended()[0]
	attrs := map[string]string{}
	for _, kv := range span.Attributes() {
		attrs[string(kv.Key)] = kv.Value.Emit()
	}
	if attrs["http.method"] != "POST" {
		t.Errorf("http.method=%q", attrs["http.method"])
	}
	if !strings.HasPrefix(attrs["http.url"], "http://operator.example.com/v1/entries") {
		t.Errorf("http.url=%q", attrs["http.url"])
	}
	if strings.Contains(attrs["http.url"], "secret") {
		t.Error("query string must be stripped from http.url")
	}
	if attrs["net.peer.name"] != "operator.example.com" {
		t.Errorf("net.peer.name=%q", attrs["net.peer.name"])
	}
	if attrs["http.status_code"] != "200" {
		t.Errorf("http.status_code=%q", attrs["http.status_code"])
	}
}

// ─────────────────────────────────────────────────────────────────────
// Defaults
// ─────────────────────────────────────────────────────────────────────

func TestOTel_NilInnerDefaults(t *testing.T) {
	tracer, rec := newRecordingTracer()
	rt := &OTelTransport{Tracer: tracer}
	req, _ := http.NewRequest(http.MethodGet, "http://127.0.0.1:1", nil)
	_, _ = rt.RoundTrip(req) // ignore err; we want span recorded
	if len(rec.Ended()) != 1 {
		t.Fatalf("spans=%d", len(rec.Ended()))
	}
}

func TestOTel_NilTracerUsesGlobal(t *testing.T) {
	rt := &OTelTransport{Inner: &stubRT{resp: mkResp(200)}}
	req, _ := http.NewRequest(http.MethodGet, "http://x", nil)
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatalf("%v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

func TestTrimQuery(t *testing.T) {
	cases := map[string]string{
		"http://x/y":          "http://x/y",
		"http://x/y?a=b":      "http://x/y",
		"http://x/y?a=b&c=d":  "http://x/y",
		"http://x/y#frag":     "http://x/y",
		"http://x/y?a=b#frag": "http://x/y",
		"":                    "",
	}
	for in, want := range cases {
		if got := trimQuery(in); got != want {
			t.Errorf("trimQuery(%q)=%q, want %q", in, got, want)
		}
	}
}

func TestSpanNameFor_PathOnly(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "http://x/foo/bar?q=1", nil)
	if got := spanNameFor(req); got != "HTTP GET /foo/bar" {
		t.Errorf("got %q", got)
	}
}

func TestSpanNameFor_NilURL(t *testing.T) {
	req := &http.Request{Method: "GET"}
	if got := spanNameFor(req); got != "HTTP GET" {
		t.Errorf("got %q", got)
	}
}

func TestSpanNameFor_EmptyPath(t *testing.T) {
	req := &http.Request{Method: "GET", URL: &url.URL{}}
	if got := spanNameFor(req); got != "HTTP GET /" {
		t.Errorf("got %q", got)
	}
}

// ─────────────────────────────────────────────────────────────────────
// WithOTel
// ─────────────────────────────────────────────────────────────────────

func TestWithOTel_Wraps(t *testing.T) {
	inner := &stubRT{resp: mkResp(200)}
	wrapped := WithOTel(inner)
	got, ok := wrapped.(*OTelTransport)
	if !ok {
		t.Fatalf("WithOTel returned %T, want *OTelTransport", wrapped)
	}
	if got.Inner != inner {
		t.Error("WithOTel did not preserve inner")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Composition: stacked with RetryAfter — one outer span captures
// the entire roundtrip including retries
// ─────────────────────────────────────────────────────────────────────

type retryingFake struct{ calls atomic.Int32 }

func (f *retryingFake) RoundTrip(*http.Request) (*http.Response, error) {
	n := f.calls.Add(1)
	if n == 1 {
		return mkResp(503), nil
	}
	return mkResp(200), nil
}

func TestOTel_StackedWithRetry(t *testing.T) {
	tracer, rec := newRecordingTracer()
	inner := &retryingFake{}
	retry := &RetryAfterRoundTripper{
		Inner: inner,
		Sleep: func(context.Context, time.Duration) error { return nil },
	}
	traced := &OTelTransport{Inner: retry, Tracer: tracer}
	req, _ := http.NewRequest(http.MethodGet, "http://x", nil)
	if _, err := traced.RoundTrip(req); err != nil {
		t.Fatalf("%v", err)
	}
	if len(rec.Ended()) != 1 {
		t.Errorf("outer spans=%d, want 1", len(rec.Ended()))
	}
	if inner.calls.Load() < 2 {
		t.Errorf("inner attempts=%d, want >=2 (retry occurred)", inner.calls.Load())
	}
}
