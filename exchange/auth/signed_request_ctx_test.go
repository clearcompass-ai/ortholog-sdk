package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/did"
)

// ctxCapturingNonceStore is a NonceStore stub that records the context
// it was invoked with. Returns a sentinel error so VerifyRequest exits
// on the Reserve call (before reaching signature verification, which
// is not what we're testing here).
type ctxCapturingNonceStore struct {
	gotCtx context.Context
	err    error
}

func (s *ctxCapturingNonceStore) Reserve(ctx context.Context, _ string) error {
	s.gotCtx = ctx
	return s.err
}

// validCtxEnvelope builds a SignedRequestEnvelope that passes
// validateFields and the validity-window check so execution reaches
// nonces.Reserve — the site of ORTHO-BUG-019.
func validCtxEnvelope(now time.Time) *SignedRequestEnvelope {
	return &SignedRequestEnvelope{
		Version:   EnvelopeVersion,
		DID:       "did:example:alice",
		Domain:    "api.example.com",
		Nonce:     "nonce-threaded-ctx",
		Method:    "POST",
		Path:      "/v1/submit",
		IssuedAt:  now.Add(-1 * time.Second),
		ExpiresAt: now.Add(30 * time.Second),
	}
}

// TestVerifyRequest_ThreadsContextToNonceStore is the ORTHO-BUG-019
// regression guard: the caller's context must reach NonceStore.Reserve
// verbatim. Previously VerifyRequest hard-coded context.Background(),
// so a canceled HTTP request could not signal its nonce-store query.
func TestVerifyRequest_ThreadsContextToNonceStore(t *testing.T) {
	sentinel := errors.New("stub reserve failure")
	store := &ctxCapturingNonceStore{err: sentinel}

	type ctxKey string
	want := "request-42"
	ctx := context.WithValue(context.Background(), ctxKey("trace"), want)

	now := time.Now()
	err := VerifyRequest(
		ctx,
		did.NewVerifierRegistry(),
		validCtxEnvelope(now),
		nil, 0,
		store,
		VerifyRequestOptions{Now: func() time.Time { return now }},
	)

	// Reserve ran and returned our sentinel: VerifyRequest must
	// surface it (wrapped in ErrEnvelopeNonceReused).
	if err == nil {
		t.Fatal("VerifyRequest: expected error from stub Reserve, got nil")
	}
	if !errors.Is(err, ErrEnvelopeNonceReused) {
		t.Fatalf("VerifyRequest: want wrapped ErrEnvelopeNonceReused, got %v", err)
	}

	// The captured context must be the exact caller context — not
	// context.Background(), which is what the pre-fix code used.
	if store.gotCtx == nil {
		t.Fatal("NonceStore.Reserve: no context captured (Reserve not invoked)")
	}
	if got := store.gotCtx.Value(ctxKey("trace")); got != want {
		t.Fatalf("NonceStore.Reserve: context value: want %q, got %v", want, got)
	}
}

// TestVerifyRequest_NilContextRejected asserts the defensive guard:
// passing a nil context is a programming error and produces a clean
// rejection rather than a downstream nil-dereference.
func TestVerifyRequest_NilContextRejected(t *testing.T) {
	err := VerifyRequest(
		nil, //nolint:staticcheck // testing nil-context guard
		did.NewVerifierRegistry(),
		validCtxEnvelope(time.Now()),
		nil, 0,
		&ctxCapturingNonceStore{},
		VerifyRequestOptions{Now: time.Now},
	)
	if err == nil {
		t.Fatal("VerifyRequest(nil ctx): want error, got nil")
	}
}
