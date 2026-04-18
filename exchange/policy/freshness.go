/*
FILE PATH:
    exchange/policy/freshness.go

DESCRIPTION:
    Ingestion-layer freshness policy. Called by an operator at the point of
    entry acceptance, BEFORE appending to the log. Rejects entries whose
    EventTime is outside a configurable tolerance of "now."

    This is the defense against late-replay: an attacker captures a
    legitimately-signed entry, blocks its delivery, and replays it
    arbitrarily later. Even though the entry's signature is still valid
    and the log has never seen its canonical hash, the freshness window
    rejects it at ingestion because EventTime is too far in the past.

KEY ARCHITECTURAL DECISIONS:
  - Freshness is OPERATOR POLICY, not PROTOCOL RULE. Different operators
    for different endpoint categories pick different tolerances. The SDK
    provides the helper and three suggested tolerances keyed to signing
    tempo; the consumer configures per endpoint.
  - Three tolerances describe SIGNING TEMPO, not ROLES. The domain using
    the SDK (legal, medical, financial, credentialing) maps its own
    actors onto these tempos.
  - Asymmetric clock-skew tolerance: entries from the near future
    (within ClockSkewTolerance) are accepted. Entries from the far
    future are rejected as a signal of clock tampering.
  - Zero tolerance is rejected at configuration time, not silently
    treated as "always reject." Fail-loud.

KEY DEPENDENCIES:
    - core/envelope.Entry (for EventTime access)
    - standard library time
*/
package policy

import (
	"errors"
	"fmt"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
)

// -------------------------------------------------------------------------------------------------
// 1) Freshness tolerances — keyed to signing tempo, not roles
// -------------------------------------------------------------------------------------------------
//
// Choose per endpoint based on the signing tempo the endpoint accepts.
// These MATCH the ValidityAutomated / ValidityInteractive /
// ValidityDeliberative windows in exchange/auth/signed_request.go — the
// two sets apply to different layers (transport envelope vs. signed
// entry) but describe the same signing-tempo categories.
//
// The SDK is domain-agnostic. Each consumer maps its own signer
// categories onto these tempos. Some illustrative mappings:
//
//   Automated   → machine-to-machine: service daemons, scheduled jobs,
//                 protocol actors (witnesses cosigning tree heads,
//                 anchor publishers, cross-log mirrors)
//   Interactive → human at a UI with immediate response: clerks, data-
//                 entry operators, dashboard users executing routine
//                 actions
//   Deliberative → human exercising judgment: review-and-decide
//                  workflows where the signer may pause to consider
//                  before committing

const (
	// FreshnessAutomated is for machine-to-machine signed entries where
	// no human is in the loop. The signer is a service, daemon, or
	// scheduled task that signs and submits within seconds.
	FreshnessAutomated = 60 * time.Second

	// FreshnessInteractive is for entries signed by a human at a UI
	// executing routine input. Accommodates UI latency and immediate
	// human response, but not deliberative pauses.
	FreshnessInteractive = 5 * time.Minute

	// FreshnessDeliberative is for entries signed as part of a review-
	// and-decide workflow. The signer opens the signing interface,
	// reviews content, may pause for consideration, then commits.
	FreshnessDeliberative = 30 * time.Minute

	// MaxFreshnessTolerance is the hard ceiling. Tolerances above this
	// are rejected at CheckFreshness call time as a misconfiguration
	// signal. If an entry legitimately needs to be ingested more than
	// an hour after it was signed, the pipeline has a queueing /
	// delivery problem to fix, not a tolerance to widen.
	MaxFreshnessTolerance = 1 * time.Hour

	// ClockSkewTolerance is the asymmetric future-tolerance. An entry
	// with EventTime up to this duration in the future is accepted.
	// Farther in the future → rejected as a clock-tampering signal.
	ClockSkewTolerance = 30 * time.Second
)

// -------------------------------------------------------------------------------------------------
// 2) Errors
// -------------------------------------------------------------------------------------------------

var (
	ErrEntryNil          = errors.New("policy: entry is nil")
	ErrToleranceZero     = errors.New("policy: tolerance must be > 0")
	ErrToleranceTooLarge = errors.New("policy: tolerance exceeds MaxFreshnessTolerance")
	ErrEntryStale        = errors.New("policy: entry is stale (EventTime too far in the past)")
	ErrEntryFuture       = errors.New("policy: entry EventTime is in the future beyond clock skew tolerance")
)

// -------------------------------------------------------------------------------------------------
// 3) CheckFreshness
// -------------------------------------------------------------------------------------------------

// CheckFreshness returns nil if the entry's EventTime is within the
// configured tolerance of `now`. Returns a non-nil error (wrapping one
// of the sentinels above) if the entry is stale, from the future, or
// the tolerance is misconfigured.
//
// Typical call:
//
//     if err := policy.CheckFreshness(entry, time.Now().UTC(), policy.FreshnessInteractive); err != nil {
//         return fmt.Errorf("ingestion: %w", err)
//     }
//
// The `now` parameter is explicit (not time.Now() internally) for
// determinism in tests and to make clock dependencies auditable.
func CheckFreshness(entry *envelope.Entry, now time.Time, tolerance time.Duration) error {
	if entry == nil {
		return ErrEntryNil
	}
	if tolerance <= 0 {
		return ErrToleranceZero
	}
	if tolerance > MaxFreshnessTolerance {
		return fmt.Errorf("%w: got %v, max %v",
			ErrToleranceTooLarge, tolerance, MaxFreshnessTolerance)
	}

	eventTime := time.Unix(entry.Header.EventTime, 0).UTC()
	delta := now.Sub(eventTime)

	// Future-skew check: entries from the future beyond clock skew are
	// rejected as a clock-tampering signal.
	if delta < -ClockSkewTolerance {
		return fmt.Errorf("%w: entry EventTime is %v in the future, max skew %v",
			ErrEntryFuture, -delta, ClockSkewTolerance)
	}

	// Staleness check: entries older than tolerance are rejected as
	// stale. This is the primary defense against late-replay of entries
	// that never reached the log when first signed.
	if delta > tolerance {
		return fmt.Errorf("%w: entry is %v old, tolerance %v",
			ErrEntryStale, delta, tolerance)
	}

	return nil
}

// -------------------------------------------------------------------------------------------------
// 4) Convenience wrappers
// -------------------------------------------------------------------------------------------------

// CheckFreshnessAutomated is CheckFreshness with tolerance=FreshnessAutomated.
func CheckFreshnessAutomated(entry *envelope.Entry, now time.Time) error {
	return CheckFreshness(entry, now, FreshnessAutomated)
}

// CheckFreshnessInteractive is CheckFreshness with tolerance=FreshnessInteractive.
func CheckFreshnessInteractive(entry *envelope.Entry, now time.Time) error {
	return CheckFreshness(entry, now, FreshnessInteractive)
}

// CheckFreshnessDeliberative is CheckFreshness with tolerance=FreshnessDeliberative.
func CheckFreshnessDeliberative(entry *envelope.Entry, now time.Time) error {
	return CheckFreshness(entry, now, FreshnessDeliberative)
}
