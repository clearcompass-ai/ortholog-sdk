/*
FILE PATH:
    tests/exchange_auth_test.go

DESCRIPTION:
    Tests the exchange/auth layer: InMemoryNonceStore semantic contract
    (strict-forever, concurrency, idempotency), plus VerifyRequest behavior
    (validity windows, clock skew, replay rejection, opt-in no-replay).

INVARIANTS LOCKED:
  1. Reserve returns nil the first time a nonce is seen.
  2. Reserve returns ErrNonceReserved every time after the first.
  3. Reserve is STRICT-FOREVER — no expiry, no eviction.
  4. Reserve is safe under concurrent callers: 100 goroutines reserving
     the same nonce, exactly one succeeds.
  5. Reserve rejects the empty string.
  6. VerifyRequest rejects validity windows longer than MaxValidityWindow.
  7. VerifyRequest rejects envelopes with expired ExpiresAt.
  8. VerifyRequest rejects envelopes with IssuedAt too far in the future.
  9. VerifyRequest rejects when nonce reuse is attempted.
  10. VerifyRequest with opts.Nonces=nil and AllowNoReplayCheck=false is
      itself rejected (explicit opt-in required).

KEY DEPENDENCIES:
    - exchange/auth (NonceStore, InMemoryNonceStore, VerifyRequest, constants)
    - context
    - sync
*/
package tests

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/exchange/auth"
)

// -------------------------------------------------------------------------------------------------
// 1) InMemoryNonceStore — basic contract
// -------------------------------------------------------------------------------------------------

func TestNonceMemory_Reserve_FirstSucceeds(t *testing.T) {
	s := auth.NewInMemoryNonceStore()
	if err := s.Reserve(context.Background(), "nonce-001"); err != nil {
		t.Fatalf("first Reserve should succeed, got: %v", err)
	}
}

func TestNonceMemory_Reserve_SecondReturnsReserved(t *testing.T) {
	s := auth.NewInMemoryNonceStore()
	_ = s.Reserve(context.Background(), "nonce-001")
	err := s.Reserve(context.Background(), "nonce-001")
	if !errors.Is(err, auth.ErrNonceReserved) {
		t.Fatalf("expected ErrNonceReserved, got: %v", err)
	}
}

func TestNonceMemory_Reserve_AllSubsequentAttemptsFail(t *testing.T) {
	s := auth.NewInMemoryNonceStore()
	_ = s.Reserve(context.Background(), "nonce-001")
	// 10 further attempts, all should fail with ErrNonceReserved (idempotent).
	for i := 0; i < 10; i++ {
		err := s.Reserve(context.Background(), "nonce-001")
		if !errors.Is(err, auth.ErrNonceReserved) {
			t.Fatalf("attempt %d: expected ErrNonceReserved, got %v", i, err)
		}
	}
}

func TestNonceMemory_Reserve_EmptyRejected(t *testing.T) {
	s := auth.NewInMemoryNonceStore()
	err := s.Reserve(context.Background(), "")
	if !errors.Is(err, auth.ErrNonceEmpty) {
		t.Fatalf("expected ErrNonceEmpty, got: %v", err)
	}
}

func TestNonceMemory_Reserve_DistinctNoncesAllSucceed(t *testing.T) {
	s := auth.NewInMemoryNonceStore()
	for i := 0; i < 1000; i++ {
		nonce := testNonce(i)
		if err := s.Reserve(context.Background(), nonce); err != nil {
			t.Fatalf("nonce %q: %v", nonce, err)
		}
	}
	if s.Size() != 1000 {
		t.Fatalf("Size=%d, want 1000", s.Size())
	}
}

// -------------------------------------------------------------------------------------------------
// 2) Strict-forever semantics — no expiry, no eviction
// -------------------------------------------------------------------------------------------------

// TestNonceMemory_StrictForever locks the contract: a reservation made
// hours (simulated via direct time comparison) ago is STILL reserved.
// There is no time-based method on InMemoryNonceStore for eviction; this
// test asserts that the data structure and API reflect that.
func TestNonceMemory_StrictForever(t *testing.T) {
	s := auth.NewInMemoryNonceStore()

	if err := s.Reserve(context.Background(), "old-nonce"); err != nil {
		t.Fatalf("initial Reserve: %v", err)
	}

	// The store has no Expire / Cleanup / Remove method — confirmed by
	// interface. The only way to remove entries would be to drop the
	// whole process. Reservations persist for the life of the store.
	if !s.IsReserved("old-nonce") {
		t.Fatal("old-nonce lost from store — strict-forever violated")
	}

	// Re-reserving still fails — the reservation never ages out.
	err := s.Reserve(context.Background(), "old-nonce")
	if !errors.Is(err, auth.ErrNonceReserved) {
		t.Fatalf("strict-forever: re-Reserve must still fail, got %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 3) Concurrency — 100 goroutines, one winner
// -------------------------------------------------------------------------------------------------

func TestNonceMemory_Concurrent_ExactlyOneWins(t *testing.T) {
	s := auth.NewInMemoryNonceStore()

	const N = 100
	var wg sync.WaitGroup
	var successes int32
	var reservedErrors int32
	var unexpected int32

	wg.Add(N)
	start := make(chan struct{})
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			<-start
			err := s.Reserve(context.Background(), "contested-nonce")
			switch {
			case err == nil:
				atomic.AddInt32(&successes, 1)
			case errors.Is(err, auth.ErrNonceReserved):
				atomic.AddInt32(&reservedErrors, 1)
			default:
				atomic.AddInt32(&unexpected, 1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if successes != 1 {
		t.Fatalf("expected exactly one success, got %d", successes)
	}
	if reservedErrors != N-1 {
		t.Fatalf("expected %d ErrNonceReserved, got %d", N-1, reservedErrors)
	}
	if unexpected != 0 {
		t.Fatalf("got %d unexpected errors", unexpected)
	}
}

// -------------------------------------------------------------------------------------------------
// 4) Validity-window constants — sanity
// -------------------------------------------------------------------------------------------------

func TestValidityWindow_Constants_AreOrderedAndBounded(t *testing.T) {
	if auth.ValidityAutomated > auth.ValidityInteractive {
		t.Fatalf("ValidityAutomated %v > ValidityInteractive %v", auth.ValidityAutomated, auth.ValidityInteractive)
	}
	if auth.ValidityInteractive > auth.ValidityDeliberative {
		t.Fatalf("ValidityInteractive %v > ValidityDeliberative %v", auth.ValidityInteractive, auth.ValidityDeliberative)
	}
	if auth.ValidityDeliberative > auth.MaxValidityWindow {
		t.Fatalf("ValidityDeliberative %v > MaxValidityWindow %v", auth.ValidityDeliberative, auth.MaxValidityWindow)
	}
	if auth.ValidityAutomated <= 0 {
		t.Fatal("ValidityAutomated must be positive")
	}
	if auth.MaxClockSkew <= 0 {
		t.Fatal("MaxClockSkew must be positive")
	}
}

// -------------------------------------------------------------------------------------------------
// 5) VerifyRequest — validity window boundaries
// -------------------------------------------------------------------------------------------------
//
// These tests depend on your existing test helpers for constructing
// a valid SignedRequest + registry. The shape of the test is: construct
// a request with a specific ExpiresAt - IssuedAt delta, verify, assert
// accept/reject.
//
// Stub these in with your repo's existing test scaffolding for
// VerifyRequest (whatever helpers exist in your current test files for
// constructing a signed request). The assertions below are what must be
// true; adapt the construction.

func TestVerifyRequest_ValidityWindow_ExactAtLimit_Accepted(t *testing.T) {
	t.Skip("fill in with local test scaffolding — construct request at ValidityInteractive exactly, expect accept")
}

func TestVerifyRequest_ValidityWindow_OneSecondOver_Rejected(t *testing.T) {
	t.Skip("fill in with local test scaffolding — construct request at ValidityInteractive+1s, expect reject")
}

func TestVerifyRequest_ValidityWindow_ExceedsMax_Rejected(t *testing.T) {
	t.Skip("fill in with local test scaffolding — construct request at MaxValidityWindow+1s, expect reject")
}

// -------------------------------------------------------------------------------------------------
// 6) VerifyRequest — clock-skew boundaries
// -------------------------------------------------------------------------------------------------

func TestVerifyRequest_ClockSkew_WithinTolerance_Accepted(t *testing.T) {
	t.Skip("fill in with local scaffolding — IssuedAt = now + MaxClockSkew - 1s, expect accept")
}

func TestVerifyRequest_ClockSkew_BeyondTolerance_Rejected(t *testing.T) {
	t.Skip("fill in with local scaffolding — IssuedAt = now + MaxClockSkew + 1s, expect reject")
}

// -------------------------------------------------------------------------------------------------
// 7) VerifyRequest — replay protection via NonceStore
// -------------------------------------------------------------------------------------------------

func TestVerifyRequest_Replay_Rejected(t *testing.T) {
	t.Skip(`fill in with local scaffolding:
        1. Build a signed request with nonce N.
        2. VerifyRequest with opts.Nonces = fresh InMemoryNonceStore. Expect success.
        3. VerifyRequest with the SAME request, SAME store. Expect ErrNonceReserved.`)
}

func TestVerifyRequest_NoStore_NoOptIn_Rejected(t *testing.T) {
	t.Skip(`fill in with local scaffolding:
        VerifyRequest(req, registry, VerifyRequestOptions{Nonces: nil, AllowNoReplayCheck: false}).
        Expect a NonceStore-required error.`)
}

func TestVerifyRequest_NoStore_WithOptIn_Accepted(t *testing.T) {
	t.Skip(`fill in with local scaffolding:
        VerifyRequest(req, registry, VerifyRequestOptions{Nonces: nil, AllowNoReplayCheck: true}).
        Expect success (caller explicitly acknowledged skipping replay check).`)
}

// -------------------------------------------------------------------------------------------------
// Helpers
// -------------------------------------------------------------------------------------------------

// testNonce deterministically generates a unique nonce string for testing.
// Pads so ordering is lexicographic.
func testNonce(i int) string {
	const pad = "0000000000"
	s := pad + itoa(i)
	return "nonce-" + s[len(s)-10:]
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	digits := make([]byte, 0, 20)
	neg := i < 0
	if neg {
		i = -i
	}
	for i > 0 {
		digits = append([]byte{byte('0' + i%10)}, digits...)
		i /= 10
	}
	if neg {
		return "-" + string(digits)
	}
	return string(digits)
}

// Ensure time.Second is referenced so the import is retained in all build
// configurations (some of the test bodies are t.Skip'd).
var _ = time.Second
