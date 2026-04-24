// Package escrow — vss_v2_binding_test.go holds the binding tests
// for the five mutation-audit switches in vss_v2_mutation_switches.go.
// See crypto/escrow/vss_v2.mutation-audit.yaml for the registry.
//
// Each test constructs an input shape that exercises exactly one
// gate, asserts the specific sentinel the gate returns, and would
// silently pass if the gate were removed (downstream failures
// produce different errors or admit silently-wrong behaviour).
package escrow

import (
	"errors"
	"strings"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/vss"
)

// bindingDealer is a stable dealer DID used across these tests.
const bindingDealer = "did:web:example.com:dealer-binding"

// bindingNonce returns a non-zero 32-byte nonce for SplitV2.
func bindingNonce() [32]byte {
	var n [32]byte
	for i := range n {
		n[i] = byte(i) + 0x10
	}
	return n
}

// bindingSecret returns a valid 32-byte secret.
func bindingSecret() []byte {
	s := make([]byte, SecretSize)
	for i := range s {
		s[i] = byte(i) + 1
	}
	return s
}

// ─────────────────────────────────────────────────────────────────────
// Binding: muEnableEscrowSecretSizeCheck
// ─────────────────────────────────────────────────────────────────────

// TestSplitV2_SecretSizeBinding pins that SplitV2 rejects a secret
// of the wrong length. Off admits wrong-sized secrets; the copy
// into secretArr silently truncates or zero-pads, producing a
// split that reconstructs a different secret than the caller
// intended.
func TestSplitV2_SecretSizeBinding(t *testing.T) {
	short := make([]byte, SecretSize-1)
	_, _, _, err := SplitV2(short, 3, 5, bindingDealer, bindingNonce())
	if err == nil {
		t.Fatal("SplitV2 accepted under-sized secret")
	}
	if !strings.Contains(err.Error(), "secret must be") {
		t.Fatalf("want secret-size rejection, got %v", err)
	}

	long := make([]byte, SecretSize+1)
	_, _, _, err = SplitV2(long, 3, 5, bindingDealer, bindingNonce())
	if err == nil {
		t.Fatal("SplitV2 accepted over-sized secret")
	}
	if !strings.Contains(err.Error(), "secret must be") {
		t.Fatalf("want secret-size rejection, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Binding: muEnableEscrowDealerDIDNonEmpty
// ─────────────────────────────────────────────────────────────────────

// TestSplitV2_DealerDIDBinding pins that SplitV2 rejects an empty
// dealerDID. Off admits the empty DID into ComputeEscrowSplitID,
// producing a SplitID that collides across dealers.
func TestSplitV2_DealerDIDBinding(t *testing.T) {
	_, _, _, err := SplitV2(bindingSecret(), 3, 5, "", bindingNonce())
	if err == nil {
		t.Fatal("SplitV2 accepted empty dealerDID")
	}
	if !strings.Contains(err.Error(), "dealerDID must be non-empty") {
		t.Fatalf("want dealerDID rejection, got %v", err)
	}
}

// ─────────────────────────────────────────────────────────────────────
// Binding: muEnableEscrowThresholdBounds
// ─────────────────────────────────────────────────────────────────────

// TestSplitV2_ThresholdBoundsBinding pins that SplitV2 rejects
// degenerate / inverted / oversized threshold combinations. All
// three sub-checks are gated by the single
// muEnableEscrowThresholdBounds switch.
func TestSplitV2_ThresholdBoundsBinding(t *testing.T) {
	cases := []struct {
		name string
		M, N int
	}{
		{"M_below_2", 1, 5},
		{"M_above_N", 6, 5},
		{"N_above_255", 3, 256},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := SplitV2(bindingSecret(), tc.M, tc.N, bindingDealer, bindingNonce())
			if err == nil {
				t.Fatalf("SplitV2 accepted M=%d N=%d", tc.M, tc.N)
			}
			if !errors.Is(err, ErrInvalidThreshold) {
				t.Fatalf("want ErrInvalidThreshold, got %v", err)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────
// Binding: muEnableReconstructVersionCheck
// ─────────────────────────────────────────────────────────────────────

// TestReconstructV2_VersionCheckBinding pins that ReconstructV2
// rejects a V1 share set. Off admits V1 shares into the V2
// reconstruction path; downstream Pedersen verification would
// fail with a confusing error instead of the boundary
// ErrUnsupportedVersion.
func TestReconstructV2_VersionCheckBinding(t *testing.T) {
	// Build a valid V1 share set via Split.
	shares, _, err := Split(bindingSecret(), 3, 5)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	// Get a real V2 commitment set (independent of the V1 shares).
	var secretArr [vss.SecretSize]byte
	copy(secretArr[:], bindingSecret())
	_, commits, err := vss.Split(secretArr, 3, 5)
	if err != nil {
		t.Fatalf("vss.Split: %v", err)
	}

	_, err = ReconstructV2(shares[:3], commits)
	if err == nil {
		t.Fatal("ReconstructV2 accepted V1 share set")
	}
	// Gate 2 (muEnableReconstructVersionCheck) produces the
	// specific message "ReconstructV2 called with version 0x..."
	// Gate 3 (per-share VerifyShareAgainstCommitments) produces
	// "VerifyShareAgainstCommitments requires V2, got 0x..." on
	// the same input. When the audit runner flips gate 2 off,
	// gate 3 still rejects — but with gate 3's message, not gate
	// 2's. The specific-message assertion pins gate 2 as
	// load-bearing: only gate 2 produces this string.
	if !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("want ErrUnsupportedVersion, got %v", err)
	}
	if !strings.Contains(err.Error(), "ReconstructV2 called with version") {
		t.Fatalf("want gate-2 specific message, got %q (muEnableReconstructVersionCheck not load-bearing?)", err.Error())
	}
}

// ─────────────────────────────────────────────────────────────────────
// Binding: muEnableReconstructShareVerification
// ─────────────────────────────────────────────────────────────────────

// TestReconstructV2_ShareVerificationBinding pins the load-bearing
// V2 property: a substituted share MUST fail Pedersen verification
// before Lagrange combines. Off readmits the silent-wrong-secret
// failure mode that V2 exists to close.
func TestReconstructV2_ShareVerificationBinding(t *testing.T) {
	shares, commits, _, err := SplitV2(bindingSecret(), 3, 5, bindingDealer, bindingNonce())
	if err != nil {
		t.Fatalf("SplitV2: %v", err)
	}

	// Tamper with shares[0].Value: flip a byte. The tampered share
	// still satisfies ValidateShareFormat (all fields non-zero,
	// indices valid) so VerifyShareSet passes; only the per-share
	// Pedersen verification can reject.
	shares[0].Value[0] ^= 0xFF

	_, err = ReconstructV2(shares[:3], commits)
	if err == nil {
		t.Fatal("ReconstructV2 accepted tampered share (muEnableReconstructShareVerification not load-bearing?)")
	}
	if !errors.Is(err, ErrCommitmentMismatch) {
		t.Fatalf("want ErrCommitmentMismatch, got %v", err)
	}
}
