//go:build escrow_mocks

package escrowtest_test

import (
	"strings"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/escrow"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/escrow/escrowtest"
)

// Compile-time assertion that the mocks satisfy the production
// EnclaveAttestation interface. If the interface drifts, this fails
// to build before any test runs.
var (
	_ escrow.EnclaveAttestation = (*escrowtest.MockAppleAttestation)(nil)
	_ escrow.EnclaveAttestation = (*escrowtest.MockAndroidAttestation)(nil)
)

// ─────────────────────────────────────────────────────────────────────
// MockAppleAttestation
// ─────────────────────────────────────────────────────────────────────

func TestApple_AcceptsNonEmpty(t *testing.T) {
	m := &escrowtest.MockAppleAttestation{}
	if err := m.VerifyAttestation([]byte{0x01}); err != nil {
		t.Fatalf("VerifyAttestation(non-empty): %v", err)
	}
}

func TestApple_RejectsEmpty(t *testing.T) {
	m := &escrowtest.MockAppleAttestation{}
	if err := m.VerifyAttestation([]byte{}); err == nil {
		t.Fatal("VerifyAttestation(empty) = nil, want error")
	}
}

func TestApple_RejectsNil(t *testing.T) {
	m := &escrowtest.MockAppleAttestation{}
	if err := m.VerifyAttestation(nil); err == nil {
		t.Fatal("VerifyAttestation(nil) = nil, want error")
	}
}

func TestApple_PlatformIsMockSuffixed(t *testing.T) {
	got := (&escrowtest.MockAppleAttestation{}).Platform()
	if got != "apple_secure_enclave_mock" {
		t.Fatalf("Platform() = %q, want apple_secure_enclave_mock", got)
	}
	// Load-bearing: production code is expected to reject any
	// EnclaveAttestation whose Platform() ends in "_mock". Pin the
	// suffix here so silent renames (e.g., "_dev", "_test") that
	// would defeat that guard fail this test loud.
	if !strings.HasSuffix(got, "_mock") {
		t.Fatalf("Platform() = %q lost the _mock suffix", got)
	}
}

// ─────────────────────────────────────────────────────────────────────
// MockAndroidAttestation
// ─────────────────────────────────────────────────────────────────────

func TestAndroid_AcceptsNonEmpty(t *testing.T) {
	m := &escrowtest.MockAndroidAttestation{}
	if err := m.VerifyAttestation([]byte{0xff}); err != nil {
		t.Fatalf("VerifyAttestation(non-empty): %v", err)
	}
}

func TestAndroid_RejectsEmpty(t *testing.T) {
	m := &escrowtest.MockAndroidAttestation{}
	if err := m.VerifyAttestation([]byte{}); err == nil {
		t.Fatal("VerifyAttestation(empty) = nil, want error")
	}
}

func TestAndroid_RejectsNil(t *testing.T) {
	m := &escrowtest.MockAndroidAttestation{}
	if err := m.VerifyAttestation(nil); err == nil {
		t.Fatal("VerifyAttestation(nil) = nil, want error")
	}
}

func TestAndroid_PlatformIsMockSuffixed(t *testing.T) {
	got := (&escrowtest.MockAndroidAttestation{}).Platform()
	if got != "android_strongbox_mock" {
		t.Fatalf("Platform() = %q, want android_strongbox_mock", got)
	}
	if !strings.HasSuffix(got, "_mock") {
		t.Fatalf("Platform() = %q lost the _mock suffix", got)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Distinct platform names
// ─────────────────────────────────────────────────────────────────────

func TestMocks_DistinctPlatforms(t *testing.T) {
	apple := (&escrowtest.MockAppleAttestation{}).Platform()
	android := (&escrowtest.MockAndroidAttestation{}).Platform()
	if apple == android {
		t.Fatalf("apple and android share platform name %q — must differ", apple)
	}
}
