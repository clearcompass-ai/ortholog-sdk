package log

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/sct"
)

// ─────────────────────────────────────────────────────────────────────
// Happy paths
// ─────────────────────────────────────────────────────────────────────

func TestSubmit_ModeA_HappyPath(t *testing.T) {
	op := newTestOperator(t)
	s := newTestSubmitter(t, op, "tok-xyz")

	scTok, err := s.Submit(context.Background(),
		envelope.ControlHeader{}, []byte("hello"))
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if scTok == nil {
		t.Fatal("nil SCT")
	}
	if scTok.LogDID != defaultTestLogDID {
		t.Errorf("LogDID=%q", scTok.LogDID)
	}
	// SCT signature already verified inside Submit; confirm it
	// independently.
	if err := sct.Verify(s.operatorPub, scTok); err != nil {
		t.Errorf("sct.Verify: %v", err)
	}
}

func TestSubmit_ModeB_HappyPath(t *testing.T) {
	op := newTestOperator(t)
	op.SetDifficulty(4, "sha256") // fast PoW
	s := newTestSubmitter(t, op, "")

	scTok, err := s.Submit(context.Background(),
		envelope.ControlHeader{}, []byte("hello"))
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if scTok == nil {
		t.Fatal("nil SCT")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Authorization header
// ─────────────────────────────────────────────────────────────────────

func TestSubmit_ModeA_SetsAuthorizationHeader(t *testing.T) {
	op := newTestOperator(t)
	var seen string
	op.SetSubmitHandler(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Authorization")
		op.defaultSubmitHandler(w, r)
	})
	s := newTestSubmitter(t, op, "tok-xyz")
	if _, err := s.Submit(context.Background(),
		envelope.ControlHeader{}, []byte("h")); err != nil {
		t.Fatalf("%v", err)
	}
	if seen != "Bearer tok-xyz" {
		t.Errorf("Authorization=%q, want %q", seen, "Bearer tok-xyz")
	}
}

func TestSubmit_ModeB_NoAuthorizationHeader(t *testing.T) {
	op := newTestOperator(t)
	op.SetDifficulty(4, "sha256")
	var seen string
	op.SetSubmitHandler(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Get("Authorization")
		op.defaultSubmitHandler(w, r)
	})
	s := newTestSubmitter(t, op, "")
	if _, err := s.Submit(context.Background(),
		envelope.ControlHeader{}, []byte("h")); err != nil {
		t.Fatalf("%v", err)
	}
	if seen != "" {
		t.Errorf("Authorization=%q, want empty (Mode B)", seen)
	}
}

// ─────────────────────────────────────────────────────────────────────
// SCT verification failure
// ─────────────────────────────────────────────────────────────────────

func TestSubmit_BadSCTRejected(t *testing.T) {
	op := newTestOperator(t)
	op.SetSubmitHandler(func(w http.ResponseWriter, _ *http.Request) {
		// Return a structurally valid SCT JSON but with a
		// signature that does NOT verify against the operator
		// pubkey (signed with a wrong key — use a fresh key per
		// call).
		var hash [32]byte
		bad := &sct.SignedCertificateTimestamp{
			Version:       sct.Version,
			SignerDID:     op.operatorKP.DID,
			SigAlgoID:     sct.SigAlgoECDSASecp256k1SHA256,
			LogDID:        defaultTestLogDID,
			CanonicalHash: "00" + strings.Repeat("00", 31),
			LogTimeMicros: 1,
			LogTime:       "1970-01-01T00:00:00.000001Z",
			Signature:     "deadbeef",
		}
		_ = hash
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(202)
		_ = json.NewEncoder(w).Encode(bad)
	})
	s := newTestSubmitter(t, op, "tok")
	_, err := s.Submit(context.Background(),
		envelope.ControlHeader{}, []byte("x"))
	if !errors.Is(err, ErrSCTRejected) {
		t.Fatalf("got %v, want ErrSCTRejected", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Status code mapping (Mode A keeps tests fast — no PoW)
// ─────────────────────────────────────────────────────────────────────

func TestSubmit_StatusCodeMapping(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		body     string
		wantSent error
	}{
		{"401", 401, "auth", ErrUnauthorized},
		{"402", 402, "no creds", ErrInsufficientCredits},
		{"409", 409, "dup", ErrDuplicateEntry},
		{"413", 413, "huge", ErrEntryTooLarge},
		{"422", 422, "bad shape", ErrValidation},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			op := newTestOperator(t)
			op.SetSubmitHandler(func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, tc.body, tc.status)
			})
			s := newTestSubmitter(t, op, "tok")
			_, err := s.Submit(context.Background(),
				envelope.ControlHeader{}, []byte("x"))
			if !errors.Is(err, tc.wantSent) {
				t.Fatalf("got %v, want %v", err, tc.wantSent)
			}
		})
	}
}

func TestSubmit_403WithoutStampMarker(t *testing.T) {
	op := newTestOperator(t)
	op.SetSubmitHandler(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "destination mismatch", 403)
	})
	s := newTestSubmitter(t, op, "tok")
	_, err := s.Submit(context.Background(),
		envelope.ControlHeader{}, []byte("x"))
	var he *HTTPError
	if !errors.As(err, &he) {
		t.Fatalf("got %v, want *HTTPError", err)
	}
	if errors.Is(err, ErrStampRejected) {
		t.Error("non-stamp 403 must not be ErrStampRejected")
	}
}

// ─────────────────────────────────────────────────────────────────────
// 403 cache-bust retry path
// ─────────────────────────────────────────────────────────────────────

func TestSubmit_403StampRejectedNoChangeFails(t *testing.T) {
	op := newTestOperator(t)
	op.SetDifficulty(4, "sha256")
	// Always return stamp-failed; difficulty unchanged.
	op.SetSubmitHandler(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "stamp verification failed: too low", 403)
	})
	s := newTestSubmitter(t, op, "")
	_, err := s.Submit(context.Background(),
		envelope.ControlHeader{}, []byte("x"))
	if !errors.Is(err, ErrStampRejected) {
		t.Fatalf("got %v, want ErrStampRejected", err)
	}
}

func TestSubmit_403RetriesWhenDifficultyChanges(t *testing.T) {
	op := newTestOperator(t)
	op.SetDifficulty(4, "sha256")
	var calls atomic.Int32
	op.SetSubmitHandler(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			// First attempt: change the operator's difficulty
			// THEN reject the stamp. Submit's retry path will
			// refresh, see a different difficulty, rebuild, and
			// resubmit — the second call here goes through the
			// default success handler.
			op.SetDifficulty(5, "sha256")
			http.Error(w, "stamp verification failed: bumped", 403)
			return
		}
		op.defaultSubmitHandler(w, r)
	})
	s := newTestSubmitter(t, op, "")
	scTok, err := s.Submit(context.Background(),
		envelope.ControlHeader{}, []byte("x"))
	if err != nil {
		t.Fatalf("Submit (after retry): %v", err)
	}
	if scTok == nil {
		t.Fatal("nil SCT after retry")
	}
	if calls.Load() != 2 {
		t.Errorf("submit call count=%d, want 2 (initial + retry)", calls.Load())
	}
}

func TestSubmit_ModeA_DoesNotRetry403(t *testing.T) {
	// In Mode A, ErrStampRejected can't happen normally (no PoW)
	// but if a 403 with stamp marker DOES surface, Submit returns
	// it without trying to refresh difficulty.
	op := newTestOperator(t)
	op.SetSubmitHandler(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "stamp verification failed: ???", 403)
	})
	s := newTestSubmitter(t, op, "tok")
	_, err := s.Submit(context.Background(),
		envelope.ControlHeader{}, []byte("x"))
	if !errors.Is(err, ErrStampRejected) {
		t.Fatalf("got %v, want ErrStampRejected", err)
	}
	if op.DifficultyCount() != 0 {
		t.Errorf("Mode A submitted hit difficulty endpoint %d times; should be 0",
			op.DifficultyCount())
	}
}

// ─────────────────────────────────────────────────────────────────────
// Stream hygiene + body shape
// ─────────────────────────────────────────────────────────────────────

func TestSubmit_PostsOctetStream(t *testing.T) {
	op := newTestOperator(t)
	var (
		seenContentType string
		seenAccept      string
		seenBodyLen     int
	)
	op.SetSubmitHandler(func(w http.ResponseWriter, r *http.Request) {
		seenContentType = r.Header.Get("Content-Type")
		seenAccept = r.Header.Get("Accept")
		body, _ := io.ReadAll(r.Body)
		seenBodyLen = len(body)
		// Need a valid response so SCT verify doesn't blow up.
		// Re-implement the default handler against the body we
		// already drained.
		_ = body
		// Simpler: delegate to default by re-buffering the body.
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		op.defaultSubmitHandler(w, r)
	})
	s := newTestSubmitter(t, op, "tok")
	if _, err := s.Submit(context.Background(),
		envelope.ControlHeader{}, []byte("hello")); err != nil {
		t.Fatalf("%v", err)
	}
	if seenContentType != "application/octet-stream" {
		t.Errorf("Content-Type=%q", seenContentType)
	}
	if seenAccept != "application/json" {
		t.Errorf("Accept=%q", seenAccept)
	}
	if seenBodyLen == 0 {
		t.Error("body empty")
	}
}

// ─────────────────────────────────────────────────────────────────────
// nil ctx handling
// ─────────────────────────────────────────────────────────────────────

func TestSubmit_NilCtxDefaultsToBackground(t *testing.T) {
	op := newTestOperator(t)
	s := newTestSubmitter(t, op, "tok")
	if _, err := s.Submit(nil, envelope.ControlHeader{}, []byte("x")); err != nil {
		t.Fatalf("nil ctx should default to Background: %v", err)
	}
}
