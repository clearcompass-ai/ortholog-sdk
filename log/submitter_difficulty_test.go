package log

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"

	sdkadmission "github.com/clearcompass-ai/ortholog-sdk/crypto/admission"
)

// ─────────────────────────────────────────────────────────────────────
// getDifficulty — cache mechanics
// ─────────────────────────────────────────────────────────────────────

func TestGetDifficulty_CacheMissFetchesOnce(t *testing.T) {
	op := newTestOperator(t)
	op.SetDifficulty(7, "sha256")
	s := newTestSubmitter(t, op, "")

	d, h, err := s.getDifficulty(context.Background())
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if d != 7 || h != "sha256" {
		t.Errorf("got (%d,%q), want (7,sha256)", d, h)
	}
	if op.DifficultyCount() != 1 {
		t.Errorf("difficulty hit count=%d, want 1", op.DifficultyCount())
	}
}

func TestGetDifficulty_CacheHitNoFetch(t *testing.T) {
	op := newTestOperator(t)
	op.SetDifficulty(5, "sha256")
	s := newTestSubmitter(t, op, "")

	for i := 0; i < 10; i++ {
		if _, _, err := s.getDifficulty(context.Background()); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if op.DifficultyCount() != 1 {
		t.Errorf("count=%d, want 1 (cached)", op.DifficultyCount())
	}
}

func TestGetDifficulty_TTLExpiryRefetches(t *testing.T) {
	op := newTestOperator(t)
	op.SetDifficulty(5, "sha256")
	s := newTestSubmitter(t, op, "")
	// Shrink TTL so the next call sees an expired cache.
	s.cfg.DifficultyCacheTTL = 1 * time.Nanosecond

	if _, _, err := s.getDifficulty(context.Background()); err != nil {
		t.Fatalf("first: %v", err)
	}
	time.Sleep(2 * time.Nanosecond)
	if _, _, err := s.getDifficulty(context.Background()); err != nil {
		t.Fatalf("second: %v", err)
	}
	if op.DifficultyCount() < 2 {
		t.Errorf("count=%d, want >=2 after TTL", op.DifficultyCount())
	}
}

func TestGetDifficulty_ThunderingHerdSingleFetch(t *testing.T) {
	op := newTestOperator(t)
	op.SetDifficulty(5, "sha256")
	s := newTestSubmitter(t, op, "")

	// Slow the difficulty handler so all N goroutines pile up at
	// the lock — exercising the double-check path.
	op.SetDifficultyHandler(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Millisecond)
		op.defaultDifficultyHandler(w, r)
	})

	const N = 16
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			_, _, _ = s.getDifficulty(context.Background())
		}()
	}
	wg.Wait()
	if op.DifficultyCount() != 1 {
		t.Errorf("count=%d, want 1 (single fetch under herd)", op.DifficultyCount())
	}
}

// ─────────────────────────────────────────────────────────────────────
// refreshDifficulty
// ─────────────────────────────────────────────────────────────────────

func TestRefreshDifficulty_FirstInitChanged(t *testing.T) {
	op := newTestOperator(t)
	op.SetDifficulty(5, "sha256")
	s := newTestSubmitter(t, op, "")

	d, h, changed, err := s.refreshDifficulty(context.Background())
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if !changed {
		t.Error("first init must report changed=true")
	}
	if d != 5 || h != "sha256" {
		t.Errorf("got (%d,%q)", d, h)
	}
}

func TestRefreshDifficulty_SameValueNotChanged(t *testing.T) {
	op := newTestOperator(t)
	op.SetDifficulty(5, "sha256")
	s := newTestSubmitter(t, op, "")
	if _, _, err := s.getDifficulty(context.Background()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, _, changed, err := s.refreshDifficulty(context.Background())
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if changed {
		t.Error("identical refresh must report changed=false")
	}
}

func TestRefreshDifficulty_DifficultyChanged(t *testing.T) {
	op := newTestOperator(t)
	op.SetDifficulty(5, "sha256")
	s := newTestSubmitter(t, op, "")
	if _, _, err := s.getDifficulty(context.Background()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	op.SetDifficulty(7, "sha256")
	_, _, changed, err := s.refreshDifficulty(context.Background())
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if !changed {
		t.Error("difficulty change must report changed=true")
	}
}

func TestRefreshDifficulty_HashFuncChanged(t *testing.T) {
	op := newTestOperator(t)
	op.SetDifficulty(5, "sha256")
	s := newTestSubmitter(t, op, "")
	if _, _, err := s.getDifficulty(context.Background()); err != nil {
		t.Fatalf("seed: %v", err)
	}
	op.SetDifficulty(5, "argon2id")
	_, _, changed, err := s.refreshDifficulty(context.Background())
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if !changed {
		t.Error("hashFunc change must report changed=true")
	}
}

// ─────────────────────────────────────────────────────────────────────
// doDifficultyFetch error paths
// ─────────────────────────────────────────────────────────────────────

func TestDoDifficultyFetch_503(t *testing.T) {
	op := newTestOperator(t)
	s := newTestSubmitter(t, op, "")
	op.SetDifficultyHandler(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "no diff controller", http.StatusServiceUnavailable)
	})
	// 503 path: even after RetryAfterRoundTripper retries, the
	// final response will be 503. Speed test with a short
	// MinBackoff via raw client substitution would be ideal, but
	// the default 1s × 3 retries is acceptable for a single test.
	s.client.Timeout = 10 * time.Second
	_, _, _, err := s.refreshDifficulty(context.Background())
	if !errors.Is(err, ErrDifficultyFetch) {
		t.Fatalf("got %v, want ErrDifficultyFetch", err)
	}
}

func TestDoDifficultyFetch_MalformedJSON(t *testing.T) {
	op := newTestOperator(t)
	s := newTestSubmitter(t, op, "")
	op.SetDifficultyHandler(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("not json"))
	})
	_, _, _, err := s.refreshDifficulty(context.Background())
	if !errors.Is(err, ErrDifficultyFetch) {
		t.Fatalf("got %v, want ErrDifficultyFetch", err)
	}
}

func TestDoDifficultyFetch_ZeroDifficulty(t *testing.T) {
	op := newTestOperator(t)
	s := newTestSubmitter(t, op, "")
	op.SetDifficulty(0, "sha256")
	_, _, _, err := s.refreshDifficulty(context.Background())
	if !errors.Is(err, ErrDifficultyFetch) {
		t.Fatalf("got %v, want ErrDifficultyFetch on zero diff", err)
	}
}

func TestDoDifficultyFetch_EmptyHashFunc(t *testing.T) {
	op := newTestOperator(t)
	s := newTestSubmitter(t, op, "")
	op.SetDifficulty(5, "")
	_, _, _, err := s.refreshDifficulty(context.Background())
	if !errors.Is(err, ErrDifficultyFetch) {
		t.Fatalf("got %v, want ErrDifficultyFetch on empty hashFunc", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// hashFuncByte / hashFuncTyped
// ─────────────────────────────────────────────────────────────────────

func TestHashFuncByte_KnownNames(t *testing.T) {
	got, err := hashFuncByte("sha256")
	if err != nil || got != sdkadmission.WireByteHashSHA256 {
		t.Errorf("sha256: got %d err=%v", got, err)
	}
	got, err = hashFuncByte("argon2id")
	if err != nil || got != sdkadmission.WireByteHashArgon2id {
		t.Errorf("argon2id: got %d err=%v", got, err)
	}
}

// BUG #4 fix: previously unknown names silently returned SHA-256.
// Now they error so the caller learns the operator picked a hash the
// SDK cannot produce.
func TestHashFuncByte_UnknownErrors(t *testing.T) {
	_, err := hashFuncByte("future-hash-9000")
	if err == nil {
		t.Fatal("expected error for unknown hash")
	}
	if !errors.Is(err, ErrDifficultyFetch) {
		t.Errorf("error should wrap ErrDifficultyFetch: %v", err)
	}
}

func TestHashFuncTyped_KnownNames(t *testing.T) {
	got, err := hashFuncTyped("sha256")
	if err != nil || got != sdkadmission.HashSHA256 {
		t.Errorf("sha256: got %v err=%v", got, err)
	}
	got, err = hashFuncTyped("argon2id")
	if err != nil || got != sdkadmission.HashArgon2id {
		t.Errorf("argon2id: got %v err=%v", got, err)
	}
}

// BUG #4 fix: typed dispatcher mirrors the byte dispatcher's error
// semantics so build-time and verify-time symmetry is preserved.
func TestHashFuncTyped_UnknownErrors(t *testing.T) {
	_, err := hashFuncTyped("xyz")
	if err == nil {
		t.Fatal("expected error for unknown hash")
	}
	if !errors.Is(err, ErrDifficultyFetch) {
		t.Errorf("error should wrap ErrDifficultyFetch: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// ctx propagation
// ─────────────────────────────────────────────────────────────────────

func TestGetDifficulty_CancelledCtx(t *testing.T) {
	op := newTestOperator(t)
	s := newTestSubmitter(t, op, "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, err := s.getDifficulty(ctx)
	if err == nil {
		t.Fatal("expected error under cancelled ctx")
	}
}
