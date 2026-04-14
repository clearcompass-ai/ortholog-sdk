/*
witness/staleness.go — Configurable freshness bounds for tree heads.

Different use cases require different freshness guarantees:
  - Mobile credential wallet: 1 hour (background refresh)
  - Real-time monitoring: 60 seconds (continuous polling)
  - Smart contract bridge: per-block freshness (seconds)
  - Archival verification: no staleness check (historical data)

CheckFreshness compares the time a tree head was fetched against the
current time. If the delta exceeds MaxAge, the head is considered stale.
The caller decides what to do with a stale head — some use cases treat
staleness as an error, others as a warning.
*/
package witness

import (
	"errors"
	"fmt"
	"time"
)

// ─────────────────────────────────────────────────────────────────────
// Errors
// ─────────────────────────────────────────────────────────────────────

// ErrStaleTreeHead is returned when a tree head exceeds the configured
// maximum age. The head itself may still be valid — it's just old.
var ErrStaleTreeHead = errors.New("witness/staleness: tree head exceeds maximum age")

// ─────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────

// StalenessConfig configures freshness requirements for a specific use case.
type StalenessConfig struct {
	// MaxAge is the maximum acceptable age of a tree head.
	// Zero means no staleness check (always fresh).
	MaxAge time.Duration
}

// Common configurations.
var (
	// StalenessWallet is appropriate for mobile credential wallets.
	// 1 hour: background refresh, not latency-sensitive.
	StalenessWallet = StalenessConfig{MaxAge: 1 * time.Hour}

	// StalenessMonitoring is appropriate for real-time monitoring services.
	// 60 seconds: continuous polling, detect issues quickly.
	StalenessMonitoring = StalenessConfig{MaxAge: 60 * time.Second}

	// StalenessRealtime is appropriate for bridge contracts and critical paths.
	// 15 seconds: near-real-time freshness requirement.
	StalenessRealtime = StalenessConfig{MaxAge: 15 * time.Second}

	// StalenessNone disables the staleness check entirely.
	// Used for archival verification where historical heads are expected.
	StalenessNone = StalenessConfig{MaxAge: 0}
)

// ─────────────────────────────────────────────────────────────────────
// CheckFreshness
// ─────────────────────────────────────────────────────────────────────

// FreshnessResult holds the outcome of a freshness check.
type FreshnessResult struct {
	Age      time.Duration
	MaxAge   time.Duration
	IsFresh  bool
}

// CheckFreshness verifies that a tree head was fetched recently enough
// to satisfy the configured staleness requirements.
//
// fetchedAt: when the tree head was obtained (from cache or HTTP).
// now: current time (passed explicitly for testability).
// cfg: freshness configuration for the use case.
//
// Returns nil if fresh, ErrStaleTreeHead if stale.
func CheckFreshness(fetchedAt time.Time, now time.Time, cfg StalenessConfig) (*FreshnessResult, error) {
	// MaxAge == 0 means no check (always fresh).
	if cfg.MaxAge == 0 {
		return &FreshnessResult{
			Age:     now.Sub(fetchedAt),
			MaxAge:  0,
			IsFresh: true,
		}, nil
	}

	age := now.Sub(fetchedAt)
	result := &FreshnessResult{
		Age:     age,
		MaxAge:  cfg.MaxAge,
		IsFresh: age <= cfg.MaxAge,
	}

	if !result.IsFresh {
		return result, fmt.Errorf("%w: age %s exceeds max %s",
			ErrStaleTreeHead, age.Round(time.Millisecond), cfg.MaxAge)
	}

	return result, nil
}

// CheckFreshnessNow is a convenience wrapper that uses time.Now().UTC().
func CheckFreshnessNow(fetchedAt time.Time, cfg StalenessConfig) (*FreshnessResult, error) {
	return CheckFreshness(fetchedAt, time.Now().UTC(), cfg)
}
