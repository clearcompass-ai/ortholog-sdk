/*
Package builder — occ_retry.go wraps ProcessBatch with exponential backoff
on OCC rejection. When entries are rejected due to Prior_Authority mismatches
(strict OCC) or delta-window misses (commutative OCC), the retry wrapper
re-fetches stale state and retries with configurable max attempts and backoff.

The operator's builder/loop.go calls ProcessWithRetry instead of ProcessBatch
directly. The retry logic is identical whether the underlying LeafStore is
in-memory (tests) or Postgres (production).

Consumed by:
  - ortholog-operator/builder/loop.go step (5)
  - lifecycle/scope_governance.go ExecuteAmendment
  - lifecycle/recovery.go ExecuteRecovery
  - judicial-network/enforcement/sealing.go
*/
package builder

import (
	"fmt"
	"math"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/core/smt"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ─────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────

// RetryConfig configures the OCC retry behavior.
type RetryConfig struct {
	// MaxAttempts is the maximum number of ProcessBatch calls before giving up.
	// Default: 5. Minimum: 1 (no retry).
	MaxAttempts int

	// BaseDelay is the initial backoff duration after the first rejection.
	// Subsequent delays double (exponential backoff).
	// Default: 50ms. For batch operations with >10 authorities: 200ms recommended.
	BaseDelay time.Duration

	// MaxDelay caps the exponential backoff.
	// Default: 5s.
	MaxDelay time.Duration

	// AcceptPartialSuccess controls whether a batch with some rejections
	// but some successes is considered a success. When true, the retry
	// stops as soon as zero rejections occur or max attempts is reached.
	// When false (default), any rejection triggers a retry.
	AcceptPartialSuccess bool
}

// DefaultRetryConfig returns production defaults.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:          5,
		BaseDelay:            50 * time.Millisecond,
		MaxDelay:             5 * time.Second,
		AcceptPartialSuccess: false,
	}
}

// BatchRetryConfig returns configuration for coordinated enforcement
// involving >10 simultaneous authorities (governance doc requirement).
func BatchRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts:          10,
		BaseDelay:            200 * time.Millisecond,
		MaxDelay:             10 * time.Second,
		AcceptPartialSuccess: true,
	}
}

// ─────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────

// RetryResult extends BatchResult with retry metadata.
type RetryResult struct {
	*BatchResult

	// Attempts is the number of ProcessBatch calls made.
	Attempts int

	// TotalDelay is the cumulative backoff time spent waiting.
	TotalDelay time.Duration

	// FinalRejections is the rejection count on the last attempt.
	// Zero means all entries were accepted.
	FinalRejections int
}

// ProcessWithRetryParams configures a single retry-wrapped batch.
type ProcessWithRetryParams struct {
	Tree        *smt.Tree
	Entries     []*envelope.Entry
	Positions   []types.LogPosition
	Fetcher     EntryFetcher
	SchemaRes   SchemaResolver
	LocalLogDID string
	DeltaBuffer *DeltaWindowBuffer
	Config      RetryConfig
}

// ─────────────────────────────────────────────────────────────────────
// ProcessWithRetry
// ─────────────────────────────────────────────────────────────────────

// ProcessWithRetry wraps ProcessBatch with exponential backoff on OCC
// rejection. It calls ProcessBatch, checks RejectedCounts, and if
// rejections occurred, waits with exponential backoff and retries.
//
// The retry is meaningful because between attempts:
//   - The DeltaWindowBuffer may have been updated by concurrent batches
//     on other goroutines (operator processes multiple batches)
//   - The SMT tree state may have advanced (new leaves from other batches)
//   - The fetcher returns fresher entries (Postgres reads latest state)
//
// The function does NOT re-fetch entries or re-resolve schemas between
// attempts — the caller's entries and positions are fixed. What changes
// is the tree state and buffer state, which are passed by reference.
//
// Returns the result from the last attempt (successful or not).
func ProcessWithRetry(p ProcessWithRetryParams) (*RetryResult, error) {
	cfg := p.Config
	if cfg.MaxAttempts < 1 {
		cfg.MaxAttempts = 1
	}
	if cfg.BaseDelay <= 0 {
		cfg.BaseDelay = 50 * time.Millisecond
	}
	if cfg.MaxDelay <= 0 {
		cfg.MaxDelay = 5 * time.Second
	}

	if len(p.Entries) == 0 {
		// Empty batch — process once, no retry needed.
		result, err := ProcessBatch(p.Tree, p.Entries, p.Positions, p.Fetcher, p.SchemaRes, p.LocalLogDID, p.DeltaBuffer)
		if err != nil {
			return nil, err
		}
		return &RetryResult{BatchResult: result, Attempts: 1}, nil
	}

	var totalDelay time.Duration
	var lastResult *BatchResult

	for attempt := 1; attempt <= cfg.MaxAttempts; attempt++ {
		result, err := ProcessBatch(p.Tree, p.Entries, p.Positions, p.Fetcher, p.SchemaRes, p.LocalLogDID, p.DeltaBuffer)
		if err != nil {
			return nil, fmt.Errorf("builder/retry: attempt %d: %w", attempt, err)
		}
		lastResult = result

		// Check for rejections.
		if result.RejectedCounts == 0 {
			return &RetryResult{
				BatchResult:     result,
				Attempts:        attempt,
				TotalDelay:      totalDelay,
				FinalRejections: 0,
			}, nil
		}

		// Partial success accepted — stop if we made progress.
		if cfg.AcceptPartialSuccess && result.RejectedCounts < len(p.Entries) {
			accepted := result.PathACounts + result.PathBCounts + result.PathCCounts +
				result.CommentaryCounts + result.NewLeafCounts
			if accepted > 0 {
				return &RetryResult{
					BatchResult:     result,
					Attempts:        attempt,
					TotalDelay:      totalDelay,
					FinalRejections: result.RejectedCounts,
				}, nil
			}
		}

		// Last attempt — don't sleep, just return.
		if attempt == cfg.MaxAttempts {
			break
		}

		// Exponential backoff: baseDelay * 2^(attempt-1), capped at maxDelay.
		delay := time.Duration(float64(cfg.BaseDelay) * math.Pow(2, float64(attempt-1)))
		if delay > cfg.MaxDelay {
			delay = cfg.MaxDelay
		}
		time.Sleep(delay)
		totalDelay += delay
	}

	return &RetryResult{
		BatchResult:     lastResult,
		Attempts:        cfg.MaxAttempts,
		TotalDelay:      totalDelay,
		FinalRejections: lastResult.RejectedCounts,
	}, nil
}
