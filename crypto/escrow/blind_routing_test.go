// Package escrow — blind_routing_test.go tests the attestation interface
// and its two mock implementations. Also covers the BlindRouteResult
// type and ensures the mocks satisfy the EnclaveAttestation interface
// at compile time.
package escrow

import "testing"

// -------------------------------------------------------------------------------------------------
// Interface satisfaction (compile-time assertion)
// -------------------------------------------------------------------------------------------------

// Compile-time check: MockAppleAttestation and MockAndroidAttestation
// must satisfy EnclaveAttestation. Any signature drift breaks the build
// here before tests even run.
var (
	_ EnclaveAttestation = (*MockAppleAttestation)(nil)
	_ EnclaveAttestation = (*MockAndroidAttestation)(nil)
)

// -------------------------------------------------------------------------------------------------
// MockAppleAttestation
// -------------------------------------------------------------------------------------------------

func TestMockAppleAttestation_Platform(t *testing.T) {
	m := &MockAppleAttestation{}
	if got := m.Platform(); got != "apple_secure_enclave_mock" {
		t.Fatalf("Platform() = %q, want %q", got, "apple_secure_enclave_mock")
	}
}

func TestMockAppleAttestation_VerifyAttestationAcceptsNonEmpty(t *testing.T) {
	m := &MockAppleAttestation{}
	if err := m.VerifyAttestation([]byte{0x01}); err != nil {
		t.Fatalf("VerifyAttestation(non-empty): %v", err)
	}
}

func TestMockAppleAttestation_VerifyAttestationRejectsEmpty(t *testing.T) {
	m := &MockAppleAttestation{}
	if err := m.VerifyAttestation([]byte{}); err == nil {
		t.Fatal("VerifyAttestation(empty) = nil, want error")
	}
}

func TestMockAppleAttestation_VerifyAttestationRejectsNil(t *testing.T) {
	m := &MockAppleAttestation{}
	if err := m.VerifyAttestation(nil); err == nil {
		t.Fatal("VerifyAttestation(nil) = nil, want error")
	}
}

// -------------------------------------------------------------------------------------------------
// MockAndroidAttestation
// -------------------------------------------------------------------------------------------------

func TestMockAndroidAttestation_Platform(t *testing.T) {
	m := &MockAndroidAttestation{}
	if got := m.Platform(); got != "android_strongbox_mock" {
		t.Fatalf("Platform() = %q, want %q", got, "android_strongbox_mock")
	}
}

func TestMockAndroidAttestation_VerifyAttestationAcceptsNonEmpty(t *testing.T) {
	m := &MockAndroidAttestation{}
	if err := m.VerifyAttestation([]byte{0xFF}); err != nil {
		t.Fatalf("VerifyAttestation(non-empty): %v", err)
	}
}

func TestMockAndroidAttestation_VerifyAttestationRejectsEmpty(t *testing.T) {
	m := &MockAndroidAttestation{}
	if err := m.VerifyAttestation([]byte{}); err == nil {
		t.Fatal("VerifyAttestation(empty) = nil, want error")
	}
}

// -------------------------------------------------------------------------------------------------
// Platform names are distinct
// -------------------------------------------------------------------------------------------------

func TestMockAttestations_DistinctPlatforms(t *testing.T) {
	apple := (&MockAppleAttestation{}).Platform()
	android := (&MockAndroidAttestation{}).Platform()
	if apple == android {
		t.Fatalf("apple and android mocks share platform name %q — must differ", apple)
	}
}

// -------------------------------------------------------------------------------------------------
// BlindRouteResult
// -------------------------------------------------------------------------------------------------

func TestBlindRouteResult_ZeroValue(t *testing.T) {
	var r BlindRouteResult
	if r.CIDs != nil {
		t.Fatalf("zero-value BlindRouteResult.CIDs = %v, want nil", r.CIDs)
	}
}

func TestBlindRouteResult_HoldsCIDs(t *testing.T) {
	r := BlindRouteResult{CIDs: []string{"bafy...a", "bafy...b"}}
	if len(r.CIDs) != 2 {
		t.Fatalf("len(CIDs) = %d, want 2", len(r.CIDs))
	}
	if r.CIDs[0] != "bafy...a" || r.CIDs[1] != "bafy...b" {
		t.Fatal("CIDs content mismatch")
	}
}

// -------------------------------------------------------------------------------------------------
// BlindRouteShares type — compile-time usability check via nil literal
// -------------------------------------------------------------------------------------------------

func TestBlindRouteShares_TypeUsable(t *testing.T) {
	// Assert the function type is usable as a field value / variable.
	// A nil function literal is not callable, but declaring it ensures
	// the type is exported and has the expected signature shape at
	// compile time.
	var fn BlindRouteShares
	if fn != nil {
		t.Fatal("nil function literal compared non-nil")
	}
}
