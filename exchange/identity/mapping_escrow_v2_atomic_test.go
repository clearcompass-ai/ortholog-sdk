// Package identity — mapping_escrow_v2_atomic_test.go holds the
// binding test for muEnableCommitmentEmissionAtomicV2. The
// production happy path (StoreMappingV2 emitting shares with a
// commitment entry) is covered by
// TestStoreMappingV2_AtomicCommitmentEmission; this test
// exercises the gate's pathological (shares > 0, entry == nil)
// path directly via assertV2AtomicEmission so the audit runner
// observes the gate flipping cleanly.
package identity

import (
	"errors"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
)

// TestAssertV2AtomicEmission_FireOnSharesWithoutEntry pins the V2
// mirror of TestAtomicEmissionInvariant_FireOnSharesWithoutCommitment
// in the lifecycle package. Constructs the pathological tuple that
// the production happy path never produces — encShares non-empty
// while commitmentEntry is nil — and asserts the helper returns
// ErrV2AtomicEmissionViolated. With the gate off, the helper
// short-circuits to nil and this test fails: the load-bearing
// signal that the V2 atomic-emission switch is observable.
func TestAssertV2AtomicEmission_FireOnSharesWithoutEntry(t *testing.T) {
	encShares := []EncryptedShare{{NodeDID: "did:web:example.com:node", Ciphertext: []byte("ct")}}
	if err := assertV2AtomicEmission(encShares, nil); !errors.Is(err, ErrV2AtomicEmissionViolated) {
		t.Fatalf("want ErrV2AtomicEmissionViolated, got %v", err)
	}

	// Happy paths: empty shares + nil entry trivially satisfied.
	if err := assertV2AtomicEmission(nil, nil); err != nil {
		t.Fatalf("empty/nil: want nil, got %v", err)
	}

	// Non-empty shares + non-nil entry: invariant satisfied.
	dummy := &envelope.Entry{}
	if err := assertV2AtomicEmission(encShares, dummy); err != nil {
		t.Fatalf("populated tuple: want nil, got %v", err)
	}
}
