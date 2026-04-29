package log

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// Compile-time interface check (also belt-and-suspenders against
// future OperatorQueryAPI drift)
// ─────────────────────────────────────────────────────────────────────

func TestHTTPOperatorQueryAPI_SatisfiesInterface(t *testing.T) {
	var _ OperatorQueryAPI = (*HTTPOperatorQueryAPI)(nil)
}

// ─────────────────────────────────────────────────────────────────────
// Position-keyed queries — paths
// ─────────────────────────────────────────────────────────────────────

func TestQueryPositionKeyed_Paths(t *testing.T) {
	cases := []struct {
		method   func(*HTTPOperatorQueryAPI, types.LogPosition) ([]types.EntryWithMetadata, error)
		wantSeg  string
		failName string
	}{
		{
			method: func(q *HTTPOperatorQueryAPI, p types.LogPosition) ([]types.EntryWithMetadata, error) {
				return q.QueryByCosignatureOf(p)
			},
			wantSeg:  "/v1/query/cosignature_of/",
			failName: "QueryByCosignatureOf",
		},
		{
			method: func(q *HTTPOperatorQueryAPI, p types.LogPosition) ([]types.EntryWithMetadata, error) {
				return q.QueryByTargetRoot(p)
			},
			wantSeg:  "/v1/query/target_root/",
			failName: "QueryByTargetRoot",
		},
		{
			method: func(q *HTTPOperatorQueryAPI, p types.LogPosition) ([]types.EntryWithMetadata, error) {
				return q.QueryBySchemaRef(p)
			},
			wantSeg:  "/v1/query/schema_ref/",
			failName: "QueryBySchemaRef",
		},
	}
	for _, tc := range cases {
		t.Run(tc.failName, func(t *testing.T) {
			var seenPath string
			q, stop := newQueryServer(t, func(w http.ResponseWriter, r *http.Request) {
				seenPath = r.URL.Path
				w.WriteHeader(200)
				_, _ = w.Write([]byte(`{"entries":[],"count":0}`))
			})
			defer stop()
			pos := types.LogPosition{LogDID: "did:web:example.com:logs", Sequence: 42}
			if _, err := tc.method(q, pos); err != nil {
				t.Fatalf("%v", err)
			}
			if !strings.HasPrefix(seenPath, tc.wantSeg) {
				t.Errorf("path=%q, want prefix %q", seenPath, tc.wantSeg)
			}
			// Decode the trailing segment and confirm last-colon-split
			// would yield seq=42.
			tail := strings.TrimPrefix(seenPath, tc.wantSeg)
			decoded, err := url.PathUnescape(tail)
			if err != nil {
				t.Fatalf("decode tail: %v", err)
			}
			if !strings.HasSuffix(decoded, ":42") {
				t.Errorf("decoded tail %q missing :42", decoded)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────
// Position-keyed queries — error wrapping per method
// ─────────────────────────────────────────────────────────────────────

func TestQueryPositionKeyed_500Wrapped(t *testing.T) {
	q, stop := newQueryServer(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", 500)
	})
	defer stop()
	pos := types.LogPosition{LogDID: "did:key:zX", Sequence: 1}
	_, err := q.QueryByCosignatureOf(pos)
	if !errors.Is(err, ErrQueryFailed) {
		t.Fatalf("got %v, want ErrQueryFailed", err)
	}
	if !strings.Contains(err.Error(), "cosignature_of") {
		t.Errorf("err must mention method name: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// QueryBySignerDID
// ─────────────────────────────────────────────────────────────────────

func TestQueryBySignerDID_EmptyDID(t *testing.T) {
	q, stop := newQueryServer(t, func(http.ResponseWriter, *http.Request) {
		t.Error("must not hit network for empty DID")
	})
	defer stop()
	_, err := q.QueryBySignerDID("")
	if err == nil {
		t.Fatal("expected error on empty DID")
	}
}

func TestQueryBySignerDID_PathContainsEscapedDID(t *testing.T) {
	var seenPath string
	q, stop := newQueryServer(t, func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"entries":[{"sequence_number":3}],"count":1}`))
	})
	defer stop()
	got, err := q.QueryBySignerDID("did:web:example.com:logs/path")
	if err != nil {
		t.Fatalf("%v", err)
	}
	if !strings.HasPrefix(seenPath, "/v1/query/signer_did/") {
		t.Errorf("path=%q", seenPath)
	}
	// Reserved characters in path must be escaped.
	tail := strings.TrimPrefix(seenPath, "/v1/query/signer_did/")
	if strings.Contains(tail, "/") {
		t.Errorf("unescaped slash in tail: %q", tail)
	}
	if len(got) != 1 || got[0].Position.Sequence != 3 {
		t.Errorf("entries=%v", got)
	}
}

// ─────────────────────────────────────────────────────────────────────
// ScanFromPosition
// ─────────────────────────────────────────────────────────────────────

func TestScan_NoCountOmitsParam(t *testing.T) {
	var seenQuery string
	q, stop := newQueryServer(t, func(w http.ResponseWriter, r *http.Request) {
		seenQuery = r.URL.RawQuery
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"entries":[],"count":0}`))
	})
	defer stop()
	if _, err := q.ScanFromPosition(5, 0); err != nil {
		t.Fatalf("%v", err)
	}
	v, err := url.ParseQuery(seenQuery)
	if err != nil {
		t.Fatalf("parse query: %v", err)
	}
	if v.Get("start") != "5" {
		t.Errorf("start=%q, want 5", v.Get("start"))
	}
	if v.Has("count") {
		t.Errorf("count must be omitted when 0; got %q", v.Get("count"))
	}
}

func TestScan_WithCount(t *testing.T) {
	var seenQuery string
	q, stop := newQueryServer(t, func(w http.ResponseWriter, r *http.Request) {
		seenQuery = r.URL.RawQuery
		_ = json.NewEncoder(w).Encode(queryListResponse{
			Entries: []queryEntryResponse{{SequenceNumber: 5}, {SequenceNumber: 6}},
		})
	})
	defer stop()
	got, err := q.ScanFromPosition(5, 100)
	if err != nil {
		t.Fatalf("%v", err)
	}
	v, _ := url.ParseQuery(seenQuery)
	if v.Get("count") != "100" {
		t.Errorf("count=%q", v.Get("count"))
	}
	if len(got) != 2 {
		t.Errorf("entries=%d, want 2", len(got))
	}
}

func TestScan_500Error(t *testing.T) {
	q, stop := newQueryServer(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "x", 500)
	})
	defer stop()
	_, err := q.ScanFromPosition(0, 10)
	if !errors.Is(err, ErrQueryFailed) {
		t.Fatalf("got %v, want ErrQueryFailed", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Ctx-aware variants — cancellation propagation
// ─────────────────────────────────────────────────────────────────────

func TestCtxAwareVariants_PropagateCancellation(t *testing.T) {
	q, _ := NewHTTPOperatorQueryAPI(HTTPOperatorQueryAPIConfig{
		BaseURL: "http://127.0.0.1:1", LogDID: "x",
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	pos := types.LogPosition{LogDID: "did:key:zX", Sequence: 1}

	if _, err := q.QueryByCosignatureOfCtx(ctx, pos); err == nil {
		t.Error("CosignatureOfCtx: expected error")
	}
	if _, err := q.QueryByTargetRootCtx(ctx, pos); err == nil {
		t.Error("TargetRootCtx: expected error")
	}
	if _, err := q.QueryBySchemaRefCtx(ctx, pos); err == nil {
		t.Error("SchemaRefCtx: expected error")
	}
	if _, err := q.QueryBySignerDIDCtx(ctx, "did:key:zX"); err == nil {
		t.Error("SignerDIDCtx: expected error")
	}
	if _, err := q.ScanFromPositionCtx(ctx, 0, 10); err == nil {
		t.Error("ScanFromPositionCtx: expected error")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Empty entries list
// ─────────────────────────────────────────────────────────────────────

func TestQuery_EmptyResults(t *testing.T) {
	q, stop := newQueryServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"entries":[],"count":0}`))
	})
	defer stop()

	// httptest.Server only routes one handler; we just need the
	// "empty" response shape to round-trip through every method.
	pos := types.LogPosition{LogDID: "did:key:zX", Sequence: 1}
	calls := []func() ([]types.EntryWithMetadata, error){
		func() ([]types.EntryWithMetadata, error) { return q.QueryByCosignatureOf(pos) },
		func() ([]types.EntryWithMetadata, error) { return q.QueryByTargetRoot(pos) },
		func() ([]types.EntryWithMetadata, error) { return q.QueryBySchemaRef(pos) },
		func() ([]types.EntryWithMetadata, error) { return q.QueryBySignerDID("did:key:zX") },
		func() ([]types.EntryWithMetadata, error) { return q.ScanFromPosition(0, 10) },
	}
	for i, call := range calls {
		got, err := call()
		if err != nil {
			t.Errorf("method %d: %v", i, err)
		}
		if len(got) != 0 {
			t.Errorf("method %d returned %d entries, want 0", i, len(got))
		}
	}
}

// ─────────────────────────────────────────────────────────────────────
// SignerDIDCtx with empty DID skips network (already tested in
// non-Ctx variant) — added for explicit Ctx variant coverage
// ─────────────────────────────────────────────────────────────────────

func TestSignerDIDCtx_EmptyDID(t *testing.T) {
	q, stop := newQueryServer(t, func(http.ResponseWriter, *http.Request) {
		t.Error("must not hit network")
	})
	defer stop()
	if _, err := q.QueryBySignerDIDCtx(context.Background(), ""); err == nil {
		t.Fatal("expected error")
	}
}

// ─────────────────────────────────────────────────────────────────────
// httptest helper compile pin
// ─────────────────────────────────────────────────────────────────────

var _ = httptest.NewServer
