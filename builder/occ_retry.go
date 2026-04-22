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
	Fetcher     types.EntryFetcher
	SchemaRes   SchemaResolver
	LocalLogDID string
	DeltaBuffer *DeltaWindowBuffer
	Config      RetryConfig
}

// ─────────────────────────────────────────────────────────────────────
// ProcessWithRetry
// ─────────────────────────────────────────────────────────────────────

// ProcessWithRetry wraps ProcessBatch with exponential backoff on
// rejection. It calls ProcessBatch, and if the result reports any
// RejectedPositions, waits and retries — but only for the rejected
// indices. Entries that were accepted on an earlier attempt are NOT
// re-submitted; re-submitting an already-applied entry would trigger
// ErrTipRegression and falsely classify the valid entry as rejected
// (ORTHO-BUG-003).
//
// Between attempts the SMT tree state, DeltaWindowBuffer, and fetcher
// may reflect writes from concurrent operators, which is what gives
// retry its chance to succeed. The caller's entries and positions
// slices are not mutated; retries work on internal views.
//
// Indices reported in the returned RetryResult.BatchResult.RejectedPositions
// are indices into the ORIGINAL p.Entries slice, not into any retry
// sub-batch. Callers always see rejections in terms of the batch they
// submitted.
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
		result, err := ProcessBatch(p.Tree, p.Entries, p.Positions, p.Fetcher, p.SchemaRes, p.LocalLogDID, p.DeltaBuffer)
		if err != nil {
			return nil, err
		}
		return &RetryResult{BatchResult: result, Attempts: 1}, nil
	}

	var (
		totalDelay time.Duration
		// aggregate accumulates accepted-entry state across attempts.
		// PathFailureReasons is sized to the full batch up front so
		// mergeAttempt can write per-original-index failure records.
		aggregate = &BatchResult{
			PathFailureReasons: make([]error, len(p.Entries)),
		}
		pending = make([]int, len(p.Entries))
	)
	for i := range pending {
		pending[i] = i
	}

	for attempt := 1; attempt <= cfg.MaxAttempts; attempt++ {
		// Build the sub-batch for this attempt from the entries still
		// pending after prior attempts. On attempt 1 this is the full
		// batch; on later attempts it contains only the previously-
		// rejected indices.
		subEntries := make([]*envelope.Entry, len(pending))
		subPositions := make([]types.LogPosition, len(pending))
		for k, origIdx := range pending {
			subEntries[k] = p.Entries[origIdx]
			subPositions[k] = p.Positions[origIdx]
		}

		attemptResult, err := ProcessBatch(
			p.Tree, subEntries, subPositions,
			p.Fetcher, p.SchemaRes, p.LocalLogDID, p.DeltaBuffer,
		)
		if err != nil {
			return nil, fmt.Errorf("builder/retry: attempt %d: %w", attempt, err)
		}

		// Map the sub-batch's RejectedPositions back to original indices
		// and fold this attempt's accepted-entry counts into the aggregate.
		aggregate = mergeAttempt(aggregate, attemptResult, pending)
		nextPending := make([]int, 0, len(attemptResult.RejectedPositions))
		for _, subIdx := range attemptResult.RejectedPositions {
			nextPending = append(nextPending, pending[subIdx])
		}
		pending = nextPending

		// Success — nothing left to retry.
		if len(pending) == 0 {
			return &RetryResult{
				BatchResult:     aggregate,
				Attempts:        attempt,
				TotalDelay:      totalDelay,
				FinalRejections: 0,
			}, nil
		}

		// Partial success is acceptable when the config permits it and
		// at least one entry was applied on the most recent attempt.
		if cfg.AcceptPartialSuccess &&
			attemptAccepted(attemptResult) > 0 {
			return &RetryResult{
				BatchResult:     aggregate,
				Attempts:        attempt,
				TotalDelay:      totalDelay,
				FinalRejections: len(pending),
			}, nil
		}

		if attempt == cfg.MaxAttempts {
			break
		}

		delay := time.Duration(float64(cfg.BaseDelay) * math.Pow(2, float64(attempt-1)))
		if delay > cfg.MaxDelay {
			delay = cfg.MaxDelay
		}
		time.Sleep(delay)
		totalDelay += delay
	}

	return &RetryResult{
		BatchResult:     aggregate,
		Attempts:        cfg.MaxAttempts,
		TotalDelay:      totalDelay,
		FinalRejections: len(aggregate.RejectedPositions),
	}, nil
}

// mergeAttempt folds a sub-batch attempt's result into the running
// aggregate. Rejected-position indices from the sub-batch are remapped
// into the original batch's index space via the pending slice.
// Mutations and counts are concatenated/accumulated. NewRoot and
// UpdatedBuffer always reflect the most recent attempt.
//
// PathFailureReasons are written at the ORIGINAL batch index so the
// final aggregate's slice is consumable by callers that hold the
// original entries slice. A later attempt's non-nil error for a
// retried index overwrites the earlier error (latest attempt wins).
func mergeAttempt(agg, attempt *BatchResult, pending []int) *BatchResult {
	if agg == nil {
		agg = &BatchResult{
			PathFailureReasons: make([]error, len(pending)),
		}
	}
	agg.PathACounts += attempt.PathACounts
	agg.PathBCounts += attempt.PathBCounts
	agg.PathCCounts += attempt.PathCCounts
	agg.PathDCounts += attempt.PathDCounts
	agg.CommentaryCounts += attempt.CommentaryCounts
	agg.NewLeafCounts += attempt.NewLeafCounts
	agg.Mutations = append(agg.Mutations, attempt.Mutations...)

	// Fold per-entry failure reasons into the original index space.
	for subIdx, reason := range attempt.PathFailureReasons {
		if reason == nil {
			continue
		}
		origIdx := pending[subIdx]
		if origIdx < len(agg.PathFailureReasons) {
			agg.PathFailureReasons[origIdx] = reason
		}
	}

	// Rejections are the indices still not applied after this attempt,
	// remapped to the original batch's index space.
	remapped := make([]int, 0, len(attempt.RejectedPositions))
	for _, subIdx := range attempt.RejectedPositions {
		remapped = append(remapped, pending[subIdx])
	}
	agg.RejectedPositions = remapped

	agg.NewRoot = attempt.NewRoot
	agg.UpdatedBuffer = attempt.UpdatedBuffer
	return agg
}

// attemptAccepted returns the number of entries a single attempt
// successfully classified into a state-advancing or zero-impact bucket
// (i.e. not Rejected and not routed to PathD).
func attemptAccepted(r *BatchResult) int {
	return r.PathACounts + r.PathBCounts + r.PathCCounts +
		r.CommentaryCounts + r.NewLeafCounts
}
