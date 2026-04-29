//go:build escrow_mocks

/*
Package escrowtest holds test-only fixtures for crypto/escrow.

ALL contents of this package are gated behind the build tag
escrow_mocks. A production build (go build ./..., default flags)
sees an empty package and cannot link any symbol declared here.

Why a build tag and not just an _test.go file?

	The mocks below are used as EnclaveAttestation implementations
	by tests in MULTIPLE packages (escrow itself plus higher-level
	flows that compose blind-routing pipelines). _test.go files are
	package-private — only the same package's tests can see them.
	A separate non-_test.go package with a build tag is the only way
	to share fixtures across packages while still excluding them
	from production binaries.

Tag name choice:

	escrow_mocks rather than the bare tag test. The tag test would
	collide with a Go developer's expectation that "test" is a
	stdlib-blessed convention and might be silently turned on by an
	integrator's CI. escrow_mocks is unambiguous and self-describing.

CI integration:

	  go test -tags=escrow_mocks ./crypto/escrow/escrowtest/...

	Production builds:

	  go build ./...                  # mocks not linked
	  go vet ./...                    # mocks not visible
	  go test ./...                   # tests in escrowtest skipped

To verify a binary cannot reach a mock:

	  nm <binary> | grep -i mockappleattestation
	  # (no output expected for production builds)
*/
package escrowtest

import "errors"

// MockAppleAttestation is a test-only EnclaveAttestation that accepts
// any non-empty attestation blob. Returns "apple_secure_enclave_mock"
// from Platform(). Never link this into a production verifier path.
type MockAppleAttestation struct{}

// VerifyAttestation accepts any non-empty input. Empty/nil input
// returns an error. The error path is the only reason this mock
// surfaces a failure case at all — it makes test failures detectable
// when a fixture forgets to populate the attestation field.
func (m *MockAppleAttestation) VerifyAttestation(attestation []byte) error {
	if len(attestation) == 0 {
		return errors.New("mock: empty attestation")
	}
	return nil
}

// Platform returns the mock identifier. The "_mock" suffix is
// intentional and load-bearing: any production code that inspects
// Platform() and sees a "_mock" suffix should refuse the verifier.
func (m *MockAppleAttestation) Platform() string { return "apple_secure_enclave_mock" }

// MockAndroidAttestation mirrors MockAppleAttestation for the Android
// StrongBox attestation flow. Same accept-any-non-empty behavior;
// same "_mock"-suffixed Platform() return.
type MockAndroidAttestation struct{}

// VerifyAttestation accepts any non-empty input. Empty/nil input
// returns an error.
func (m *MockAndroidAttestation) VerifyAttestation(attestation []byte) error {
	if len(attestation) == 0 {
		return errors.New("mock: empty attestation")
	}
	return nil
}

// Platform returns the mock identifier with the load-bearing "_mock"
// suffix.
func (m *MockAndroidAttestation) Platform() string { return "android_strongbox_mock" }
