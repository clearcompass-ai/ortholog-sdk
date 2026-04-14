package escrow

import "errors"

type EnclaveAttestation interface {
	VerifyAttestation(attestation []byte) error
	Platform() string
}

type BlindRouteResult struct { CIDs []string }
type BlindRouteShares func(encryptedBlobs [][]byte) (*BlindRouteResult, error)

type MockAppleAttestation struct{}
func (m *MockAppleAttestation) VerifyAttestation(attestation []byte) error {
	if len(attestation) == 0 { return errors.New("mock: empty attestation") }; return nil
}
func (m *MockAppleAttestation) Platform() string { return "apple_secure_enclave_mock" }

type MockAndroidAttestation struct{}
func (m *MockAndroidAttestation) VerifyAttestation(attestation []byte) error {
	if len(attestation) == 0 { return errors.New("mock: empty attestation") }; return nil
}
func (m *MockAndroidAttestation) Platform() string { return "android_strongbox_mock" }
