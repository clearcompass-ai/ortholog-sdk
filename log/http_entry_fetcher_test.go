package log

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// Constructor defaults
// ─────────────────────────────────────────────────────────────────────

func TestNewHTTPEntryFetcher_DefaultTimeout(t *testing.T) {
	f := NewHTTPEntryFetcher(HTTPEntryFetcherConfig{BaseURL: "http://x"})
	if f.client == nil {
		t.Fatal("client unset")
	}
	if f.client.Timeout != 30*time.Second {
		t.Errorf("Timeout=%v, want 30s", f.client.Timeout)
	}
}

func TestNewHTTPEntryFetcher_CustomClientHonored(t *testing.T) {
	custom := &http.Client{Timeout: 1 * time.Second}
	f := NewHTTPEntryFetcher(HTTPEntryFetcherConfig{BaseURL: "http://x", Client: custom})
	if f.client != custom {
		t.Error("custom client not used")
	}
}

func TestNewHTTPEntryFetcher_NegativeTimeoutDefaulted(t *testing.T) {
	f := NewHTTPEntryFetcher(HTTPEntryFetcherConfig{BaseURL: "http://x", Timeout: -1})
	if f.client.Timeout != 30*time.Second {
		t.Errorf("Timeout=%v, want 30s", f.client.Timeout)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Fetch — success paths
// ─────────────────────────────────────────────────────────────────────

func newServer(t *testing.T, h http.HandlerFunc) (*HTTPEntryFetcher, func()) {
	t.Helper()
	srv := httptest.NewServer(h)
	f := NewHTTPEntryFetcher(HTTPEntryFetcherConfig{
		BaseURL: srv.URL,
		LogDID:  "did:key:zLog",
		Client:  srv.Client(),
	})
	return f, srv.Close
}

func TestFetch_HappyPath(t *testing.T) {
	wire := []byte{0x01, 0x02, 0x03, 0x04}
	logTime := time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
	f, stop := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/entries/42/raw" {
			t.Errorf("path=%q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set(rawSequenceHeader, "42")
		w.Header().Set(rawLogTimeHeader, logTime.Format(time.RFC3339Nano))
		w.WriteHeader(200)
		_, _ = w.Write(wire)
	})
	defer stop()

	got, err := f.Fetch(types.LogPosition{LogDID: "did:key:zLog", Sequence: 42})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if got == nil {
		t.Fatal("nil result")
	}
	if string(got.CanonicalBytes) != string(wire) {
		t.Errorf("bytes=%x, want %x", got.CanonicalBytes, wire)
	}
	if got.Position.Sequence != 42 {
		t.Errorf("seq=%d", got.Position.Sequence)
	}
	if got.Position.LogDID != "did:key:zLog" {
		t.Errorf("logDID=%q", got.Position.LogDID)
	}
	if !got.LogTime.Equal(logTime) {
		t.Errorf("logTime=%v, want %v", got.LogTime, logTime)
	}
}

func TestFetch_NoSequenceHeader_FallsBackToPos(t *testing.T) {
	f, stop := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte{0x01})
	})
	defer stop()

	got, err := f.Fetch(types.LogPosition{Sequence: 7})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if got.Position.Sequence != 7 {
		t.Errorf("seq=%d, want 7 (from pos)", got.Position.Sequence)
	}
}

func TestFetch_NoLogTimeHeader_ZeroTime(t *testing.T) {
	f, stop := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(rawSequenceHeader, "1")
		w.WriteHeader(200)
		_, _ = w.Write([]byte{0x01})
	})
	defer stop()

	got, err := f.Fetch(types.LogPosition{Sequence: 1})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if !got.LogTime.IsZero() {
		t.Errorf("logTime=%v, want zero", got.LogTime)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Fetch — error paths
// ─────────────────────────────────────────────────────────────────────

func TestFetch_404ReturnsNilNil(t *testing.T) {
	f, stop := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(404)
	})
	defer stop()

	got, err := f.Fetch(types.LogPosition{Sequence: 1})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if got != nil {
		t.Errorf("got=%v, want nil", got)
	}
}

func TestFetch_500ReturnsError(t *testing.T) {
	f, stop := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(500)
	})
	defer stop()

	_, err := f.Fetch(types.LogPosition{Sequence: 1})
	if err == nil {
		t.Fatal("expected error on 500")
	}
	if !strings.Contains(err.Error(), "HTTP 500") {
		t.Errorf("err=%q, want contains HTTP 500", err.Error())
	}
}

func TestFetch_NetworkError(t *testing.T) {
	// Point at a closed port to trigger a connect error.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Close()
	f := NewHTTPEntryFetcher(HTTPEntryFetcherConfig{BaseURL: srv.URL})
	_, err := f.Fetch(types.LogPosition{Sequence: 1})
	if err == nil {
		t.Fatal("expected network error")
	}
}

func TestFetch_EmptyBodyError(t *testing.T) {
	f, stop := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(rawSequenceHeader, "1")
		w.WriteHeader(200)
		// No bytes written.
	})
	defer stop()
	_, err := f.Fetch(types.LogPosition{Sequence: 1})
	if err == nil {
		t.Fatal("expected empty-body error")
	}
	if !strings.Contains(err.Error(), "empty wire body") {
		t.Errorf("err=%q", err.Error())
	}
}

func TestFetch_MalformedSequenceHeader(t *testing.T) {
	f, stop := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(rawSequenceHeader, "not-a-number")
		w.WriteHeader(200)
		_, _ = w.Write([]byte{0x01})
	})
	defer stop()
	_, err := f.Fetch(types.LogPosition{Sequence: 1})
	if err == nil || !strings.Contains(err.Error(), "X-Sequence") {
		t.Errorf("err=%v", err)
	}
}

func TestFetch_SequenceMismatch(t *testing.T) {
	f, stop := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(rawSequenceHeader, "999")
		w.WriteHeader(200)
		_, _ = w.Write([]byte{0x01})
	})
	defer stop()
	_, err := f.Fetch(types.LogPosition{Sequence: 1})
	if err == nil || !strings.Contains(err.Error(), "disagrees") {
		t.Errorf("err=%v", err)
	}
}

func TestFetch_MalformedLogTime(t *testing.T) {
	f, stop := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(rawSequenceHeader, "1")
		w.Header().Set(rawLogTimeHeader, "not-a-date")
		w.WriteHeader(200)
		_, _ = w.Write([]byte{0x01})
	})
	defer stop()
	_, err := f.Fetch(types.LogPosition{Sequence: 1})
	if err == nil || !strings.Contains(err.Error(), "X-Log-Time") {
		t.Errorf("err=%v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Fetch — body cap
// ─────────────────────────────────────────────────────────────────────

// BUG #3 fix: oversize bodies now return a typed error rather than
// silent truncation. Pre-fix, the fetcher returned the truncated
// bytes and envelope.Deserialize downstream would fail with a
// confusing "incomplete frame" error with no attribution. Now an
// operator serving >2 MiB on /raw fails loudly with the SDK
// pointing at the cause.
func TestFetch_OversizeBodyErrors(t *testing.T) {
	huge := make([]byte, maxRawBodyBytes+1024)
	for i := range huge {
		huge[i] = byte(i)
	}
	f, stop := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(rawSequenceHeader, "1")
		w.WriteHeader(200)
		_, _ = w.Write(huge)
	})
	defer stop()
	_, err := f.Fetch(types.LogPosition{Sequence: 1})
	if err == nil {
		t.Fatal("expected error for oversize body")
	}
	if !strings.Contains(err.Error(), "exceeds") {
		t.Errorf("error %q should mention size cap", err.Error())
	}
}

// Boundary: exactly maxRawBodyBytes is accepted (no overflow).
func TestFetch_BodyAtCap_Accepted(t *testing.T) {
	body := make([]byte, maxRawBodyBytes)
	for i := range body {
		body[i] = byte(i)
	}
	f, stop := newServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(rawSequenceHeader, "1")
		w.WriteHeader(200)
		_, _ = w.Write(body)
	})
	defer stop()
	got, err := f.Fetch(types.LogPosition{Sequence: 1})
	if err != nil {
		t.Fatalf("body at exact cap should be accepted: %v", err)
	}
	if len(got.CanonicalBytes) != maxRawBodyBytes {
		t.Errorf("len=%d, want %d", len(got.CanonicalBytes), maxRawBodyBytes)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Fetch — 302 redirect follow
// ─────────────────────────────────────────────────────────────────────

func TestFetch_302RedirectFollowed(t *testing.T) {
	// Stand up a "bucket" server that serves the actual bytes and
	// stamps its own X-Sequence header (presigned URLs in production
	// don't, but this proves the fetcher correctly reads headers
	// from the FINAL response after redirect).
	wire := []byte{0xAA, 0xBB, 0xCC}
	bucket := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(rawSequenceHeader, "5")
		w.WriteHeader(200)
		_, _ = w.Write(wire)
	}))
	defer bucket.Close()

	operator := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", bucket.URL)
		// Operator also stamps X-Sequence on redirect responses,
		// but Go's redirect follow drops this — only the final
		// response's headers matter. Pin that behavior with a
		// disagreement: operator says 99, bucket says 5. If the
		// fetcher were reading the operator's headers, we'd see a
		// sequence-mismatch error.
		w.Header().Set(rawSequenceHeader, "99")
		w.WriteHeader(http.StatusFound)
	}))
	defer operator.Close()

	f := NewHTTPEntryFetcher(HTTPEntryFetcherConfig{
		BaseURL: operator.URL,
		Client:  operator.Client(),
	})
	got, err := f.Fetch(types.LogPosition{Sequence: 5})
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if string(got.CanonicalBytes) != string(wire) {
		t.Errorf("bytes=%x, want %x", got.CanonicalBytes, wire)
	}
	if got.Position.Sequence != 5 {
		t.Errorf("seq=%d, want 5 from final response", got.Position.Sequence)
	}
}

// ─────────────────────────────────────────────────────────────────────
// URL construction sanity
// ─────────────────────────────────────────────────────────────────────

func TestFetch_URLPath(t *testing.T) {
	var seenPath string
	f, stop := newServer(t, func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		w.WriteHeader(404)
	})
	defer stop()

	for _, seq := range []uint64{0, 1, 1234567890} {
		_, _ = f.Fetch(types.LogPosition{Sequence: seq})
		want := fmt.Sprintf("/v1/entries/%d/raw", seq)
		if seenPath != want {
			t.Errorf("path=%q, want %q", seenPath, want)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────
// Compile-time interface assertion
// ─────────────────────────────────────────────────────────────────────

var _ types.EntryFetcher = (*HTTPEntryFetcher)(nil)

// ─────────────────────────────────────────────────────────────────────
// Drain helper smoke (keeps strconv/io/errors imported even on
// stripped builds; harmless coverage of unused-import potholes)
// ─────────────────────────────────────────────────────────────────────

func TestFetch_Imports(t *testing.T) {
	var _ = strconv.Itoa
	var _ = io.EOF
	var _ = errors.New("")
}
