package log

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// newQueryServer — small fixture for query tests
// ─────────────────────────────────────────────────────────────────────

func newQueryServer(t *testing.T, h http.HandlerFunc) (*HTTPOperatorQueryAPI, func()) {
	t.Helper()
	srv := httptest.NewServer(h)
	q, err := NewHTTPOperatorQueryAPI(HTTPOperatorQueryAPIConfig{
		BaseURL: srv.URL,
		LogDID:  "did:key:zTestLog",
		Client:  srv.Client(),
	})
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	return q, srv.Close
}

// ─────────────────────────────────────────────────────────────────────
// Constructor
// ─────────────────────────────────────────────────────────────────────

func TestNewQueryAPI_EmptyBaseURL(t *testing.T) {
	_, err := NewHTTPOperatorQueryAPI(HTTPOperatorQueryAPIConfig{LogDID: "x"})
	if !errors.Is(err, ErrInvalidQueryConfig) {
		t.Fatalf("got %v, want ErrInvalidQueryConfig", err)
	}
	if !strings.Contains(err.Error(), "BaseURL") {
		t.Errorf("err must mention BaseURL: %v", err)
	}
}

func TestNewQueryAPI_EmptyLogDID(t *testing.T) {
	_, err := NewHTTPOperatorQueryAPI(HTTPOperatorQueryAPIConfig{BaseURL: "http://x"})
	if !errors.Is(err, ErrInvalidQueryConfig) {
		t.Fatalf("got %v, want ErrInvalidQueryConfig", err)
	}
	if !strings.Contains(err.Error(), "LogDID") {
		t.Errorf("err must mention LogDID: %v", err)
	}
}

func TestNewQueryAPI_DefaultTimeout(t *testing.T) {
	q, err := NewHTTPOperatorQueryAPI(HTTPOperatorQueryAPIConfig{
		BaseURL: "http://x", LogDID: "x",
	})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if q.client.Timeout != defaultQueryTimeout {
		t.Errorf("Timeout=%v, want %v", q.client.Timeout, defaultQueryTimeout)
	}
}

func TestNewQueryAPI_CustomClient(t *testing.T) {
	custom := &http.Client{Timeout: 1 * time.Second}
	q, err := NewHTTPOperatorQueryAPI(HTTPOperatorQueryAPIConfig{
		BaseURL: "http://x", LogDID: "x", Client: custom,
	})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if q.client != custom {
		t.Error("custom client not preserved")
	}
}

func TestNewQueryAPI_NegativeTimeoutDefaulted(t *testing.T) {
	q, err := NewHTTPOperatorQueryAPI(HTTPOperatorQueryAPIConfig{
		BaseURL: "http://x", LogDID: "x", Timeout: -1,
	})
	if err != nil {
		t.Fatalf("%v", err)
	}
	if q.client.Timeout != defaultQueryTimeout {
		t.Errorf("Timeout=%v", q.client.Timeout)
	}
}

// ─────────────────────────────────────────────────────────────────────
// encodePosition
// ─────────────────────────────────────────────────────────────────────

func TestEncodePosition_DidKey(t *testing.T) {
	got := encodePosition(types.LogPosition{LogDID: "did:key:zXyz", Sequence: 42})
	// did:key:zXyz → URL-escaped to did%3Akey%3AzXyz, then :42
	if !strings.Contains(got, "did%3Akey%3AzXyz") {
		t.Errorf("got %q, want did%%3Akey%%3AzXyz...", got)
	}
	if !strings.HasSuffix(got, "42") {
		t.Errorf("missing sequence suffix: %q", got)
	}
}

func TestEncodePosition_DidWebWithColons(t *testing.T) {
	got := encodePosition(types.LogPosition{
		LogDID: "did:web:example.com:logs:a", Sequence: 7,
	})
	// All colons (including those inside the DID) are escaped, so
	// the operator sees an unambiguous string after URL-decode.
	if !strings.HasSuffix(got, "7") {
		t.Errorf("missing seq: %q", got)
	}
}

func TestEncodePosition_SequenceZero(t *testing.T) {
	got := encodePosition(types.LogPosition{LogDID: "did:key:zX", Sequence: 0})
	if !strings.HasSuffix(got, "0") {
		t.Errorf("got %q", got)
	}
}

func TestEncodePosition_LargeSequence(t *testing.T) {
	got := encodePosition(types.LogPosition{
		LogDID: "did:key:zX", Sequence: 18446744073709551615,
	})
	if !strings.HasSuffix(got, "18446744073709551615") {
		t.Errorf("large seq lost: %q", got)
	}
}

// ─────────────────────────────────────────────────────────────────────
// doGet
// ─────────────────────────────────────────────────────────────────────

func TestDoGet_HappyPath(t *testing.T) {
	q, stop := newQueryServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(queryListResponse{
			Entries: []queryEntryResponse{{SequenceNumber: 1}},
			Count:   1,
		})
	})
	defer stop()
	resp, err := q.doGet(context.Background(), "/v1/query/scan")
	if err != nil {
		t.Fatalf("%v", err)
	}
	if resp.Count != 1 || len(resp.Entries) != 1 {
		t.Errorf("count=%d, entries=%d", resp.Count, len(resp.Entries))
	}
}

func TestDoGet_404(t *testing.T) {
	q, stop := newQueryServer(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", 404)
	})
	defer stop()
	_, err := q.doGet(context.Background(), "/x")
	if !errors.Is(err, ErrQueryFailed) {
		t.Fatalf("got %v, want ErrQueryFailed", err)
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("err missing status: %v", err)
	}
}

func TestDoGet_500(t *testing.T) {
	q, stop := newQueryServer(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", 500)
	})
	defer stop()
	_, err := q.doGet(context.Background(), "/x")
	if !errors.Is(err, ErrQueryFailed) {
		t.Fatalf("got %v, want ErrQueryFailed", err)
	}
}

func TestDoGet_BadJSON(t *testing.T) {
	q, stop := newQueryServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("{not json"))
	})
	defer stop()
	_, err := q.doGet(context.Background(), "/x")
	if err == nil {
		t.Fatal("expected parse error")
	}
	if errors.Is(err, ErrQueryFailed) {
		t.Errorf("parse error must NOT match ErrQueryFailed: %v", err)
	}
}

func TestDoGet_NetworkError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Close()
	q, _ := NewHTTPOperatorQueryAPI(HTTPOperatorQueryAPIConfig{
		BaseURL: srv.URL, LogDID: "x",
	})
	_, err := q.doGet(context.Background(), "/x")
	if err == nil {
		t.Fatal("expected network error")
	}
}

func TestDoGet_NilCtxDefaults(t *testing.T) {
	q, stop := newQueryServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"entries":[],"count":0}`))
	})
	defer stop()
	if _, err := q.doGet(nil, "/x"); err != nil {
		t.Fatalf("nil ctx: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// toEntries
// ─────────────────────────────────────────────────────────────────────

func TestToEntries_Empty(t *testing.T) {
	q, stop := newQueryServer(t, func(http.ResponseWriter, *http.Request) {})
	defer stop()
	got := q.toEntries(nil)
	if got == nil {
		t.Error("toEntries(nil) returned nil; want empty non-nil slice")
	}
	if len(got) != 0 {
		t.Errorf("len=%d, want 0", len(got))
	}
}

func TestToEntries_PopulatesPosition(t *testing.T) {
	q, stop := newQueryServer(t, func(http.ResponseWriter, *http.Request) {})
	defer stop()
	logTime := time.Date(2026, 4, 29, 12, 0, 0, 0, time.UTC)
	got := q.toEntries([]queryEntryResponse{{
		SequenceNumber: 7,
		LogTime:        logTime.Format(time.RFC3339Nano),
	}})
	if got[0].Position.Sequence != 7 {
		t.Errorf("Sequence=%d", got[0].Position.Sequence)
	}
	if got[0].Position.LogDID != "did:key:zTestLog" {
		t.Errorf("LogDID=%q", got[0].Position.LogDID)
	}
	if !got[0].LogTime.Equal(logTime) {
		t.Errorf("LogTime=%v", got[0].LogTime)
	}
	if got[0].CanonicalBytes != nil {
		t.Error("CanonicalBytes must be nil (egress mandate)")
	}
}

func TestToEntries_MalformedLogTimeIgnored(t *testing.T) {
	q, stop := newQueryServer(t, func(http.ResponseWriter, *http.Request) {})
	defer stop()
	got := q.toEntries([]queryEntryResponse{{
		SequenceNumber: 1, LogTime: "not-a-date",
	}})
	if !got[0].LogTime.IsZero() {
		t.Errorf("malformed LogTime should produce zero time, got %v", got[0].LogTime)
	}
}

func TestToEntries_EmptyLogTimeOK(t *testing.T) {
	q, stop := newQueryServer(t, func(http.ResponseWriter, *http.Request) {})
	defer stop()
	got := q.toEntries([]queryEntryResponse{{SequenceNumber: 1, LogTime: ""}})
	if !got[0].LogTime.IsZero() {
		t.Error("empty LogTime should produce zero time")
	}
}
