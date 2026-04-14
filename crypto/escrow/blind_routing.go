package escrow

import "errors"

// EnclaveAttestation verifies that a client device's secure enclave
// generated and split keys locally, without exposing plaintext to the exchange.
// Implementations: Apple Secure Enclave, Android StrongBox, hardware tokens.
type EnclaveAttestation interface {
	// VerifyAttestation validates that the attestation blob was produced
	// by a genuine secure enclave and that keys were generated inside it.
	VerifyAttestation(attestation []byte) error

	// Platform returns the platform identifier for audit logging.
	Platform() string
}

// BlindRouteResult is returned after routing encrypted share blobs to CAS.
type BlindRouteResult struct {
	CIDs []string // Content addresses of the stored encrypted blobs
}

// BlindRouteShares routes pre-encrypted share blobs to content-addressed storage
// without the exchange ever seeing plaintext key material.
// The exchange is a routing-only intermediary for client_side_blind mode.
//
// Preconditions validated by the caller:
//   - encryptedBlobs were produced by a verified secure enclave
//   - each blob is encrypted with the corresponding escrow node's public key
//   - the exchange cannot decrypt any blob
type BlindRouteShares func(encryptedBlobs [][]byte) (*BlindRouteResult, error)

// ── Mock implementations for testing ───────────────────────────────────

// MockAppleAttestation simulates Apple Secure Enclave attestation for testing.
type MockAppleAttestation struct{}

func (m *MockAppleAttestation) VerifyAttestation(attestation []byte) error {
	if len(attestation) == 0 {
		return errors.New("mock: empty attestation")
	}
	// In testing, any non-empty attestation passes.
	return nil
}

func (m *MockAppleAttestation) Platform() string { return "apple_secure_enclave_mock" }

// MockAndroidAttestation simulates Android StrongBox attestation for testing.
type MockAndroidAttestation struct{}

func (m *MockAndroidAttestation) VerifyAttestation(attestation []byte) error {
	if len(attestation) == 0 {
		return errors.New("mock: empty attestation")
	}
	return nil
}

func (m *MockAndroidAttestation) Platform() string { return "android_strongbox_mock" }
