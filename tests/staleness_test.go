package tests

import (
	"errors"
	"testing"
	"time"

	"github.com/clearcompass-ai/ortholog-sdk/witness"
)

// ─────────────────────────────────────────────────────────────────────
// Tests: CheckFreshness
// ─────────────────────────────────────────────────────────────────────

func TestStaleness_FreshHead_Pass(t *testing.T) {
	now := time.Now().UTC()
	fetchedAt := now.Add(-10 * time.Second)
	cfg := witness.StalenessConfig{MaxAge: 1 * time.Minute}

	result, err := witness.CheckFreshness(fetchedAt, now, cfg)
	if err != nil {
		t.Fatalf("fresh head should pass: %v", err)
	}
	if !result.IsFresh {
		t.Fatal("should be fresh")
	}
	if result.Age > 11*time.Second {
		t.Fatalf("age: %s", result.Age)
	}
}

func TestStaleness_StaleHead_Error(t *testing.T) {
	now := time.Now().UTC()
	fetchedAt := now.Add(-2 * time.Hour)
	cfg := witness.StalenessConfig{MaxAge: 1 * time.Hour}

	result, err := witness.CheckFreshness(fetchedAt, now, cfg)
	if err == nil {
		t.Fatal("stale head should error")
	}
	if !errors.Is(err, witness.ErrStaleTreeHead) {
		t.Fatalf("expected ErrStaleTreeHead, got: %v", err)
	}
	if result.IsFresh {
		t.Fatal("should not be fresh")
	}
	if result.Age < 2*time.Hour {
		t.Fatalf("age: %s", result.Age)
	}
}

func TestStaleness_ExactBoundary_Fresh(t *testing.T) {
	now := time.Now().UTC()
	fetchedAt := now.Add(-1 * time.Hour)
	cfg := witness.StalenessConfig{MaxAge: 1 * time.Hour}

	result, err := witness.CheckFreshness(fetchedAt, now, cfg)
	if err != nil {
		t.Fatalf("exact boundary should be fresh: %v", err)
	}
	if !result.IsFresh {
		t.Fatal("exact boundary should be fresh")
	}
}

func TestStaleness_OneMillisecondOver_Stale(t *testing.T) {
	now := time.Now().UTC()
	fetchedAt := now.Add(-1*time.Hour - 1*time.Millisecond)
	cfg := witness.StalenessConfig{MaxAge: 1 * time.Hour}

	_, err := witness.CheckFreshness(fetchedAt, now, cfg)
	if err == nil {
		t.Fatal("1ms over should be stale")
	}
}

func TestStaleness_ZeroMaxAge_AlwaysFresh(t *testing.T) {
	now := time.Now().UTC()
	fetchedAt := now.Add(-365 * 24 * time.Hour)
	cfg := witness.StalenessConfig{MaxAge: 0}

	result, err := witness.CheckFreshness(fetchedAt, now, cfg)
	if err != nil {
		t.Fatalf("MaxAge=0 should always pass: %v", err)
	}
	if !result.IsFresh {
		t.Fatal("should always be fresh with MaxAge=0")
	}
}

func TestStaleness_FutureTimestamp_Fresh(t *testing.T) {
	now := time.Now().UTC()
	fetchedAt := now.Add(1 * time.Hour)
	cfg := witness.StalenessConfig{MaxAge: 1 * time.Minute}

	result, err := witness.CheckFreshness(fetchedAt, now, cfg)
	if err != nil {
		t.Fatalf("future timestamp should be fresh: %v", err)
	}
	if !result.IsFresh {
		t.Fatal("future timestamp = negative age = fresh")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Tests: Predefined configurations
// ─────────────────────────────────────────────────────────────────────

func TestStaleness_WalletConfig(t *testing.T) {
	cfg := witness.StalenessWallet
	if cfg.MaxAge != 1*time.Hour {
		t.Fatalf("wallet MaxAge: %s", cfg.MaxAge)
	}

	now := time.Now().UTC()
	result, err := witness.CheckFreshness(now.Add(-30*time.Minute), now, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsFresh {
		t.Fatal("30min should be fresh for wallet")
	}

	_, err = witness.CheckFreshness(now.Add(-2*time.Hour), now, cfg)
	if err == nil {
		t.Fatal("2h should be stale for wallet")
	}
}

func TestStaleness_MonitoringConfig(t *testing.T) {
	cfg := witness.StalenessMonitoring
	if cfg.MaxAge != 60*time.Second {
		t.Fatalf("monitoring MaxAge: %s", cfg.MaxAge)
	}

	now := time.Now().UTC()
	result, _ := witness.CheckFreshness(now.Add(-30*time.Second), now, cfg)
	if !result.IsFresh {
		t.Fatal("30s should be fresh for monitoring")
	}

	_, err := witness.CheckFreshness(now.Add(-90*time.Second), now, cfg)
	if err == nil {
		t.Fatal("90s should be stale for monitoring")
	}
}

func TestStaleness_RealtimeConfig(t *testing.T) {
	cfg := witness.StalenessRealtime
	if cfg.MaxAge != 15*time.Second {
		t.Fatalf("realtime MaxAge: %s", cfg.MaxAge)
	}
}

func TestStaleness_NoneConfig(t *testing.T) {
	cfg := witness.StalenessNone
	if cfg.MaxAge != 0 {
		t.Fatal("none should have MaxAge=0")
	}
	now := time.Now().UTC()
	_, err := witness.CheckFreshness(now.Add(-100*365*24*time.Hour), now, cfg)
	if err != nil {
		t.Fatalf("StalenessNone should pass everything: %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Tests: FreshnessResult fields
// ─────────────────────────────────────────────────────────────────────

func TestStaleness_Result_AgeAccurate(t *testing.T) {
	now := time.Now().UTC()
	fetchedAt := now.Add(-42 * time.Second)
	cfg := witness.StalenessConfig{MaxAge: 1 * time.Minute}

	result, _ := witness.CheckFreshness(fetchedAt, now, cfg)
	if result.Age < 42*time.Second || result.Age > 43*time.Second {
		t.Fatalf("age should be ~42s, got %s", result.Age)
	}
	if result.MaxAge != 1*time.Minute {
		t.Fatalf("maxAge: %s", result.MaxAge)
	}
}

func TestStaleness_Result_StaleHasAge(t *testing.T) {
	now := time.Now().UTC()
	fetchedAt := now.Add(-5 * time.Minute)
	cfg := witness.StalenessConfig{MaxAge: 1 * time.Minute}

	result, err := witness.CheckFreshness(fetchedAt, now, cfg)
	if err == nil {
		t.Fatal("should be stale")
	}
	if result.Age < 5*time.Minute {
		t.Fatalf("stale result should still have accurate age: %s", result.Age)
	}
	if result.IsFresh {
		t.Fatal("stale result should have IsFresh=false")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Tests: CheckFreshnessNow convenience
// ─────────────────────────────────────────────────────────────────────

func TestStaleness_CheckFreshnessNow_Recent(t *testing.T) {
	fetchedAt := time.Now().UTC().Add(-1 * time.Second)
	cfg := witness.StalenessConfig{MaxAge: 1 * time.Minute}

	result, err := witness.CheckFreshnessNow(fetchedAt, cfg)
	if err != nil {
		t.Fatalf("1s ago should be fresh: %v", err)
	}
	if !result.IsFresh {
		t.Fatal("should be fresh")
	}
}

func TestStaleness_CheckFreshnessNow_Ancient(t *testing.T) {
	fetchedAt := time.Now().UTC().Add(-24 * time.Hour)
	cfg := witness.StalenessConfig{MaxAge: 1 * time.Hour}

	_, err := witness.CheckFreshnessNow(fetchedAt, cfg)
	if err == nil {
		t.Fatal("24h ago should be stale")
	}
}
