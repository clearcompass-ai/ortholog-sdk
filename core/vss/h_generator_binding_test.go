// Package vss — h_generator_binding_test.go holds the binding test
// for muEnableHGeneratorLiftX. The seed-flip mutation is bound by
// the existing TestHGenerator_FrozenSeed in h_generator_test.go
// (which checks both the seed string and the frozen xy_sha256
// hash), so no additional test is required for that probe.
package vss

import "testing"

// TestHGenerator_LiftXGate_Binding is the binding test for
// muEnableHGeneratorLiftX. Runs deriveHGenerator directly so the
// sync.Once cache in HGenerator() does not mask a fresh
// derivation.
//
// Switch ON  → liftX attempts ModSqrt + IsOnCurve; deriveHGenerator
//              returns a valid (x, y) pair at terminating_counter=1.
// Switch OFF → liftX short-circuits to (nil, false); the
//              try-and-increment loop exhausts
//              HGeneratorMaxAttempts and deriveHGenerator returns
//              ErrHGeneratorExhausted.
//
// This test asserts the ON behaviour. When the audit-v775 runner
// flips the switch OFF in a fresh test binary, deriveHGenerator
// returns ErrHGeneratorExhausted, the t.Fatalf fires, and the test
// fails — the signal that the switch is load-bearing.
func TestHGenerator_LiftXGate_Binding(t *testing.T) {
	x, y, err := deriveHGenerator()
	if err != nil {
		t.Fatalf("deriveHGenerator: %v (muEnableHGeneratorLiftX off?)", err)
	}
	if x == nil || y == nil {
		t.Fatal("deriveHGenerator returned nil coordinates")
	}
}
