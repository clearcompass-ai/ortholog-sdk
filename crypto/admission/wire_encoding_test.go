// FILE PATH:
//
//	crypto/admission/wire_encoding_test.go
//
// DESCRIPTION:
//
//	Regression test for the wire encoding of admission proof enums.
//
//	The SDK exposes both typed Go constants (types.AdmissionModeB,
//	admission.HashSHA256) and uint8 wire-byte aliases
//	(types.WireByteModeB, admission.WireByteHashSHA256). External code
//	that constructs envelope.AdmissionProofBody uses the wire-byte
//	aliases; internal code uses the typed constants. ProofFromWire
//	bridges the two via direct cast — which is only correct as long as
//	the underlying numeric values match.
//
//	This test asserts that match. If a future change reorders the
//	AdmissionMode iota or renumbers HashFunc, the SDK build will fail
//	here BEFORE breaking every downstream operator that imported the
//	wire-byte aliases.
//
//	History: pre-v0.2, the wire encoding had to be discovered by
//	reading source. Operators routinely guessed wrong (assumed iota
//	started at 1 → wire byte 2 for ModeB) and only learned via
//	ProofFromWire-then-VerifyStamp test failures. The aliases + this
//	test eliminate that discovery loop.
package admission

import (
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// TestWireEncoding_AdmissionModeBytes locks the wire-byte values for
// AdmissionMode. Changing any of these is a wire-format-breaking change
// that requires a protocol version bump and migration plan.
func TestWireEncoding_AdmissionModeBytes(t *testing.T) {
	// The aliases must equal the typed constants cast to uint8. This is
	// what makes ProofFromWire's direct cast correct.
	if got, want := types.WireByteModeA, uint8(types.AdmissionModeA); got != want {
		t.Errorf("WireByteModeA = %d, want uint8(AdmissionModeA) = %d", got, want)
	}
	if got, want := types.WireByteModeB, uint8(types.AdmissionModeB); got != want {
		t.Errorf("WireByteModeB = %d, want uint8(AdmissionModeB) = %d", got, want)
	}

	// Pin the absolute numeric values. If these change, downstream
	// consumers compiled against an older SDK will silently misinterpret
	// wire bytes — a worse failure mode than a build break.
	if types.WireByteModeA != 0 {
		t.Errorf("WireByteModeA = %d, want 0 (wire-format-stable)", types.WireByteModeA)
	}
	if types.WireByteModeB != 1 {
		t.Errorf("WireByteModeB = %d, want 1 (wire-format-stable)", types.WireByteModeB)
	}
}

// TestWireEncoding_HashFuncBytes locks the wire-byte values for HashFunc.
// Same reasoning as TestWireEncoding_AdmissionModeBytes.
func TestWireEncoding_HashFuncBytes(t *testing.T) {
	if got, want := WireByteHashSHA256, uint8(HashSHA256); got != want {
		t.Errorf("WireByteHashSHA256 = %d, want uint8(HashSHA256) = %d", got, want)
	}
	if got, want := WireByteHashArgon2id, uint8(HashArgon2id); got != want {
		t.Errorf("WireByteHashArgon2id = %d, want uint8(HashArgon2id) = %d", got, want)
	}

	if WireByteHashSHA256 != 0 {
		t.Errorf("WireByteHashSHA256 = %d, want 0 (wire-format-stable)", WireByteHashSHA256)
	}
	if WireByteHashArgon2id != 1 {
		t.Errorf("WireByteHashArgon2id = %d, want 1 (wire-format-stable)", WireByteHashArgon2id)
	}
}

// TestWireEncoding_ProofFromWireRoundTrip is the behavioral lock: build
// a wire body using the exported aliases, run it through ProofFromWire,
// and confirm the resulting types.AdmissionProof.Mode equals the typed
// constant. If aliases ever drift from typed constants, this test catches
// it via VerifyStamp's mode check failing downstream — and it catches it
// in the SDK's own test suite, not in operator integration suites.
func TestWireEncoding_ProofFromWireRoundTrip(t *testing.T) {
	body := &envelope.AdmissionProofBody{
		Mode:       types.WireByteModeB,
		HashFunc:   WireByteHashSHA256,
		Difficulty: 8,
		Epoch:      100,
		Nonce:      42,
	}
	apiProof := ProofFromWire(body, "did:ortholog:wire-encoding-test")
	if apiProof == nil {
		t.Fatal("ProofFromWire returned nil for non-nil body")
	}
	if apiProof.Mode != types.AdmissionModeB {
		t.Errorf("after ProofFromWire: Mode = %d, want AdmissionModeB (= %d)",
			apiProof.Mode, types.AdmissionModeB)
	}
	if apiProof.Nonce != 42 {
		t.Errorf("Nonce did not round-trip: got %d, want 42", apiProof.Nonce)
	}
}
