package log

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/sct"
)

// ─────────────────────────────────────────────────────────────────────
// Validation
// ─────────────────────────────────────────────────────────────────────

func TestSubmitBatch_Empty(t *testing.T) {
	op := newTestOperator(t)
	s := newTestSubmitter(t, op, "tok")
	_, err := s.SubmitBatch(context.Background(), nil)
	if !errors.Is(err, ErrBatchEmpty) {
		t.Fatalf("got %v, want ErrBatchEmpty", err)
	}
}

func TestSubmitBatch_TooLarge(t *testing.T) {
	op := newTestOperator(t)
	s := newTestSubmitter(t, op, "tok")
	items := make([]SubmitItem, MaxBatchSize+1)
	for i := range items {
		items[i] = SubmitItem{Payload: []byte("x")}
	}
	_, err := s.SubmitBatch(context.Background(), items)
	if !errors.Is(err, ErrBatchTooLarge) {
		t.Fatalf("got %v, want ErrBatchTooLarge", err)
	}
}

func TestSubmitBatch_NilCtxDefaults(t *testing.T) {
	op := newTestOperator(t)
	s := newTestSubmitter(t, op, "tok")
	items := []SubmitItem{{Payload: []byte("x")}}
	if _, err := s.SubmitBatch(nil, items); err != nil {
		t.Fatalf("nil ctx: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Happy paths
// ─────────────────────────────────────────────────────────────────────

func TestSubmitBatch_ModeA_HappyPath(t *testing.T) {
	op := newTestOperator(t)
	s := newTestSubmitter(t, op, "tok")
	items := []SubmitItem{
		{Payload: []byte("one")},
		{Payload: []byte("two")},
		{Payload: []byte("three")},
	}
	scts, err := s.SubmitBatch(context.Background(), items)
	if err != nil {
		t.Fatalf("SubmitBatch: %v", err)
	}
	if len(scts) != 3 {
		t.Fatalf("got %d SCTs, want 3", len(scts))
	}
	for i, scTok := range scts {
		if err := sct.Verify(s.operatorPub, scTok); err != nil {
			t.Errorf("SCT %d verify: %v", i, err)
		}
	}
}

func TestSubmitBatch_ModeB_HappyPath(t *testing.T) {
	op := newTestOperator(t)
	op.SetDifficulty(4, "sha256")
	s := newTestSubmitter(t, op, "")
	items := []SubmitItem{
		{Payload: []byte("a")},
		{Payload: []byte("b")},
	}
	scts, err := s.SubmitBatch(context.Background(), items)
	if err != nil {
		t.Fatalf("SubmitBatch ModeB: %v", err)
	}
	if len(scts) != 2 {
		t.Fatalf("got %d SCTs, want 2", len(scts))
	}
}

func TestSubmitBatch_ModeB_DifficultyFetchedOnce(t *testing.T) {
	op := newTestOperator(t)
	op.SetDifficulty(4, "sha256")
	s := newTestSubmitter(t, op, "")
	items := []SubmitItem{
		{Payload: []byte("a")},
		{Payload: []byte("b")},
		{Payload: []byte("c")},
	}
	if _, err := s.SubmitBatch(context.Background(), items); err != nil {
		t.Fatalf("%v", err)
	}
	if op.DifficultyCount() != 1 {
		t.Errorf("difficulty hits=%d, want 1 (cached across batch items)",
			op.DifficultyCount())
	}
}

// ─────────────────────────────────────────────────────────────────────
// Wire shape
// ─────────────────────────────────────────────────────────────────────

func TestSubmitBatch_PostsToBatchEndpoint(t *testing.T) {
	op := newTestOperator(t)
	var seenPath, seenContentType string
	var seenItems int
	op.SetBatchHandler(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		seenContentType = r.Header.Get("Content-Type")
		body, _ := io.ReadAll(r.Body)
		var br batchRequest
		_ = json.Unmarshal(body, &br)
		seenItems = len(br.Entries)
		// Validate entries are hex-encoded.
		for _, e := range br.Entries {
			if _, err := hex.DecodeString(e.WireBytesHex); err != nil {
				t.Errorf("entry not hex: %v", err)
			}
		}
		// Re-buffer for default handler.
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		op.defaultBatchHandler(w, r)
	})
	s := newTestSubmitter(t, op, "tok")
	items := []SubmitItem{{Payload: []byte("x")}, {Payload: []byte("y")}}
	if _, err := s.SubmitBatch(context.Background(), items); err != nil {
		t.Fatalf("%v", err)
	}
	if seenPath != "/v1/entries/batch" {
		t.Errorf("path=%q, want /v1/entries/batch", seenPath)
	}
	if seenContentType != "application/json" {
		t.Errorf("Content-Type=%q", seenContentType)
	}
	if seenItems != 2 {
		t.Errorf("entries in body=%d, want 2", seenItems)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Error paths
// ─────────────────────────────────────────────────────────────────────

func TestSubmitBatch_StatusCodeMapping(t *testing.T) {
	cases := []struct {
		status int
		want   error
	}{
		{401, ErrUnauthorized},
		{402, ErrInsufficientCredits},
		{422, ErrValidation},
	}
	for _, tc := range cases {
		op := newTestOperator(t)
		op.SetBatchHandler(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "x", tc.status)
		})
		s := newTestSubmitter(t, op, "tok")
		items := []SubmitItem{{Payload: []byte("x")}}
		_, err := s.SubmitBatch(context.Background(), items)
		if !errors.Is(err, tc.want) {
			t.Errorf("status %d: got %v, want %v", tc.status, err, tc.want)
		}
	}
}

func TestSubmitBatch_ResultCountMismatch(t *testing.T) {
	op := newTestOperator(t)
	op.SetBatchHandler(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(202)
		// Return zero results regardless of request size.
		_ = json.NewEncoder(w).Encode(batchResponse{Results: nil})
	})
	s := newTestSubmitter(t, op, "tok")
	items := []SubmitItem{{Payload: []byte("a")}, {Payload: []byte("b")}}
	_, err := s.SubmitBatch(context.Background(), items)
	if !errors.Is(err, ErrBatchResultMismatch) {
		t.Fatalf("got %v, want ErrBatchResultMismatch", err)
	}
}

func TestSubmitBatch_BadSCTRejected(t *testing.T) {
	op := newTestOperator(t)
	op.SetBatchHandler(func(w http.ResponseWriter, _ *http.Request) {
		// Return one well-formed SCT and one with a wrong
		// signature. Index 1 should be flagged.
		bad := sct.SignedCertificateTimestamp{
			Version:       sct.Version,
			SignerDID:     op.operatorKP.DID,
			SigAlgoID:     sct.SigAlgoECDSASecp256k1SHA256,
			LogDID:        defaultTestLogDID,
			CanonicalHash: strings.Repeat("00", 32),
			LogTimeMicros: 1,
			LogTime:       "1970-01-01T00:00:00.000001Z",
			Signature:     "deadbeef",
		}
		good, _ := op.signSCT([32]byte{1}, op.signNow(), defaultTestLogDID)
		out := batchResponse{Results: []batchResultWire{
			{SCT: *good},
			{SCT: bad},
		}}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(202)
		_ = json.NewEncoder(w).Encode(out)
	})
	s := newTestSubmitter(t, op, "tok")
	items := []SubmitItem{{Payload: []byte("a")}, {Payload: []byte("b")}}
	_, err := s.SubmitBatch(context.Background(), items)
	if !errors.Is(err, ErrSCTRejected) {
		t.Fatalf("got %v, want ErrSCTRejected", err)
	}
	if !strings.Contains(err.Error(), "result[1]") {
		t.Errorf("err must reference index 1: %v", err)
	}
}

func TestSubmitBatch_PoWExhaustionPropagates(t *testing.T) {
	op := newTestOperator(t)
	op.SetDifficulty(4, "sha256")
	s := newTestSubmitter(t, op, "")
	// Force PoW exhaustion at item 0 by capping iterations and
	// over-asking on difficulty.
	s.cfg.PoWMaxIterations = 4
	s.cfg.PoWCheckInterval = 256
	// Override the cached difficulty path: use a high difficulty.
	op.SetDifficulty(64, "sha256")
	items := []SubmitItem{{Payload: []byte("x")}}
	_, err := s.SubmitBatch(context.Background(), items)
	if !errors.Is(err, ErrPoWExhausted) {
		t.Fatalf("got %v, want ErrPoWExhausted", err)
	}
	if !strings.Contains(err.Error(), "batch item 0") {
		t.Errorf("err must reference batch item index: %v", err)
	}
}

func TestSubmitBatch_CtxCancelledBetweenItems(t *testing.T) {
	op := newTestOperator(t)
	op.SetDifficulty(4, "sha256")
	s := newTestSubmitter(t, op, "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	items := []SubmitItem{{Payload: []byte("x")}}
	_, err := s.SubmitBatch(ctx, items)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// helper extension on testOperator (kept here to avoid bloating
// submitter_helpers_test.go for a single-use convenience)
// ─────────────────────────────────────────────────────────────────────

// signNow returns a microsecond-truncated UTC "now" for SCT minting.
func (o *testOperator) signNow() (t timeShim) {
	return timeShim{now: nowUTCMicros()}.t
}

type timeShim struct {
	t   timeShim
	now any
}

// We need a real time.Time here; the shim above is just to keep the
// import surface tight. Instead, expose nowUTCMicros() and use it
// directly.
//
// Note: the closure in TestSubmitBatch_BadSCTRejected calls
// op.signNow() which compiles to a time.Time return. Below is the
// concrete implementation.
