/*
FILE PATH:

	tests/freshness_policy_test.go

DESCRIPTION:

	Tests the ingestion-layer freshness policy. Rejects entries whose
	EventTime is outside configurable tolerance of "now." This test suite
	locks boundary behavior: exactly at the tolerance (accept), one second
	past (reject), clock-skew future (accept), far future (reject),
	misconfigurations.

INVARIANTS LOCKED:
 1. An entry exactly at the tolerance boundary is ACCEPTED (<= not <).
 2. An entry one second past the tolerance is REJECTED.
 3. An entry from the future within ClockSkewTolerance is ACCEPTED.
 4. An entry from the future beyond ClockSkewTolerance is REJECTED.
 5. tolerance == 0 is a configuration error (fails loudly).
 6. tolerance > MaxFreshnessTolerance is a configuration error.
 7. A nil entry is rejected.
 8. The three convenience wrappers (Automated/Interactive/Deliberative)
    match the constants.

ENTRY STRUCT NOTE:

	envelope.Entry has { Header ControlHeader; DomainPayload []byte }.
	EventTime and SignerDID live inside Header. Tests construct entries as:

	    &envelope.Entry{
	        Header: envelope.ControlHeader{
	            EventTime: ...,
	            SignerDID: "...",
	        },
	    }

KEY DEPENDENCIES:
  - core/envelope (Entry, ControlHeader)
  - exchange/policy (CheckFreshness and constants)
*/
package tests

import (
	"errors"
	"testing"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/exchange/policy"
)

// -------------------------------------------------------------------------------------------------
// Helper: entryWithEventTime constructs a minimal Entry for freshness tests.
// Every test here cares about EventTime only; other header fields are
// populated with placeholders sufficient to satisfy any downstream
// validation that doesn't apply to freshness policy itself.
// -------------------------------------------------------------------------------------------------

func entryWithEventTime(t *testing.T, ts time.Time) *envelope.Entry {
	t.Helper()
	return &envelope.Entry{
		Header: envelope.ControlHeader{
			EventTime: ts.Unix(),
			SignerDID: "did:web:test.example.com",
		},
	}
}

// -------------------------------------------------------------------------------------------------
// 1) Boundary tests — exactly-at-tolerance (accept) / one-past (reject)
// -------------------------------------------------------------------------------------------------

func TestFreshness_ExactlyAtTolerance_Accepted(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	entry := entryWithEventTime(t, now.Add(-policy.FreshnessInteractive))

	if err := policy.CheckFreshness(entry, now, policy.FreshnessInteractive); err != nil {
		t.Fatalf("expected accept at exact boundary, got: %v", err)
	}
}

func TestFreshness_OneSecondPastTolerance_Rejected(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	entry := entryWithEventTime(t, now.Add(-policy.FreshnessInteractive-time.Second))

	err := policy.CheckFreshness(entry, now, policy.FreshnessInteractive)
	if !errors.Is(err, policy.ErrEntryStale) {
		t.Fatalf("expected ErrEntryStale, got: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 2) Clock-skew tests — near future accept, far future reject
// -------------------------------------------------------------------------------------------------

func TestFreshness_NearFuture_WithinSkew_Accepted(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	entry := entryWithEventTime(t, now.Add(policy.ClockSkewTolerance-time.Second))

	if err := policy.CheckFreshness(entry, now, policy.FreshnessInteractive); err != nil {
		t.Fatalf("expected accept for near-future entry within skew, got: %v", err)
	}
}

func TestFreshness_FarFuture_BeyondSkew_Rejected(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	entry := entryWithEventTime(t, now.Add(policy.ClockSkewTolerance+time.Second))

	err := policy.CheckFreshness(entry, now, policy.FreshnessInteractive)
	if !errors.Is(err, policy.ErrEntryFuture) {
		t.Fatalf("expected ErrEntryFuture, got: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 3) Configuration errors — zero, over-max, nil
// -------------------------------------------------------------------------------------------------

func TestFreshness_ZeroTolerance_Rejected(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	entry := entryWithEventTime(t, now)

	err := policy.CheckFreshness(entry, now, 0)
	if !errors.Is(err, policy.ErrToleranceZero) {
		t.Fatalf("expected ErrToleranceZero, got: %v", err)
	}
}

func TestFreshness_NegativeTolerance_Rejected(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	entry := entryWithEventTime(t, now)

	err := policy.CheckFreshness(entry, now, -time.Second)
	if !errors.Is(err, policy.ErrToleranceZero) {
		t.Fatalf("expected ErrToleranceZero, got: %v", err)
	}
}

func TestFreshness_OverMaxTolerance_Rejected(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	entry := entryWithEventTime(t, now)

	err := policy.CheckFreshness(entry, now, policy.MaxFreshnessTolerance+time.Second)
	if !errors.Is(err, policy.ErrToleranceTooLarge) {
		t.Fatalf("expected ErrToleranceTooLarge, got: %v", err)
	}
}

func TestFreshness_NilEntry_Rejected(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	err := policy.CheckFreshness(nil, now, policy.FreshnessInteractive)
	if !errors.Is(err, policy.ErrEntryNil) {
		t.Fatalf("expected ErrEntryNil, got: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 4) The three wrappers — acceptance matches the constants
// -------------------------------------------------------------------------------------------------

func TestFreshness_Wrapper_Automated(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()

	// 59 seconds old → within FreshnessAutomated=60s
	entry := entryWithEventTime(t, now.Add(-59*time.Second))
	if err := policy.CheckFreshnessAutomated(entry, now); err != nil {
		t.Fatalf("wrapper accepted below boundary: %v", err)
	}

	// 61 seconds old → beyond FreshnessAutomated=60s
	entry = entryWithEventTime(t, now.Add(-61*time.Second))
	if err := policy.CheckFreshnessAutomated(entry, now); !errors.Is(err, policy.ErrEntryStale) {
		t.Fatalf("expected ErrEntryStale, got: %v", err)
	}
}

func TestFreshness_Wrapper_Interactive(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()

	entry := entryWithEventTime(t, now.Add(-4*time.Minute))
	if err := policy.CheckFreshnessInteractive(entry, now); err != nil {
		t.Fatalf("4min-old rejected by Interactive wrapper: %v", err)
	}

	entry = entryWithEventTime(t, now.Add(-6*time.Minute))
	if err := policy.CheckFreshnessInteractive(entry, now); !errors.Is(err, policy.ErrEntryStale) {
		t.Fatalf("6min-old accepted by Interactive wrapper: %v", err)
	}
}

func TestFreshness_Wrapper_Deliberative(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()

	entry := entryWithEventTime(t, now.Add(-29*time.Minute))
	if err := policy.CheckFreshnessDeliberative(entry, now); err != nil {
		t.Fatalf("29min-old rejected by Deliberative wrapper: %v", err)
	}

	entry = entryWithEventTime(t, now.Add(-31*time.Minute))
	if err := policy.CheckFreshnessDeliberative(entry, now); !errors.Is(err, policy.ErrEntryStale) {
		t.Fatalf("31min-old accepted by Deliberative wrapper: %v", err)
	}
}

// -------------------------------------------------------------------------------------------------
// 5) The attack scenario — a months-old signed entry is rejected at ingestion
// -------------------------------------------------------------------------------------------------

// TestFreshness_LateReplay_Rejected simulates the late-replay scenario:
// an attacker captures a legitimate signed entry, blocks its delivery,
// then replays it into the exchange months later. The signature is still
// cryptographically valid and the log has never seen the hash — but the
// freshness policy rejects it.
func TestFreshness_LateReplay_Rejected(t *testing.T) {
	signedAt := time.Unix(1_700_000_000, 0).UTC()
	replayedAt := signedAt.AddDate(0, 6, 0) // six months later

	entry := entryWithEventTime(t, signedAt)

	// Every tolerance rejects — even the MaxFreshnessTolerance ceiling.
	for _, tol := range []time.Duration{
		policy.FreshnessAutomated,
		policy.FreshnessInteractive,
		policy.FreshnessDeliberative,
		policy.MaxFreshnessTolerance,
	} {
		err := policy.CheckFreshness(entry, replayedAt, tol)
		if !errors.Is(err, policy.ErrEntryStale) {
			t.Errorf("tolerance=%v: expected ErrEntryStale, got %v", tol, err)
		}
	}
}
