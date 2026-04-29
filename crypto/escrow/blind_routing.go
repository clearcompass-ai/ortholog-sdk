/*
Package escrow — blind_routing.go declares the production interface
and value types for blind routing of encrypted shares to an
attestation-protected enclave.

This file deliberately holds NO mock or test-only implementations.
Mocks (MockAppleAttestation, MockAndroidAttestation) live in
crypto/escrow/escrowtest under build tag escrow_mocks so a
production binary cannot accidentally link a verifier that accepts
any non-empty byte slice as "attested".

The interface is small on purpose:

  - VerifyAttestation cryptographically verifies a platform-supplied
    attestation blob (Apple Secure Enclave, Android StrongBox, etc.)
    and returns an error if the blob does not bind to a known root
    of trust.
  - Platform returns a stable string identifier the orchestrator can
    log and (load-bearing) refuse routes to when the suffix is
    "_mock".

BlindRouteResult and BlindRouteShares describe the value/function
shapes the orchestrator passes around; both are stable wire
contracts and must remain backward-compatible across SDK versions.
*/
package escrow

// EnclaveAttestation verifies platform-issued attestation blobs and
// reports the platform's stable identifier.
//
// Production implementations MUST chain to a hardware-rooted trust
// authority (e.g., Apple's App Attest CA, Google's Play Integrity
// service). Implementations whose Platform() return ends in "_mock"
// MUST be rejected by orchestrators in production routing decisions
// — see crypto/escrow/escrowtest for the test-only mocks.
type EnclaveAttestation interface {
	VerifyAttestation(attestation []byte) error
	Platform() string
}

// BlindRouteResult is the orchestrator's response after blind-routing
// encrypted share blobs through an attested enclave. CIDs is the
// list of content-addressed identifiers under which the routed
// shares are now retrievable.
type BlindRouteResult struct {
	CIDs []string
}

// BlindRouteShares is the function shape an orchestrator implements
// to receive a slice of encrypted blobs and emit the resulting CIDs.
// The function is opaque about routing topology — the only contract
// is "in: blobs, out: CIDs or error".
type BlindRouteShares func(encryptedBlobs [][]byte) (*BlindRouteResult, error)
