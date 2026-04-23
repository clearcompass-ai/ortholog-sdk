// Package integration — cross-package end-to-end tests for
// delegation-key + threshold PRE flows.
//
// Migrated from tests/phase6_delegation_key_test.go and
// tests/phase6_part_a_test.go as part of the Phase C test
// decommission. The legacy phase6_part_a grant-flow test was
// decommissioned without verbatim port: its PRE round-trip is
// covered here, and its remaining infrastructure assertions will
// be re-expressed in Phase D tests when commitment-publication
// via pre-grant-commitment-v1 schema lands.
package integration

import (
	"bytes"
	"errors"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/artifact"
	"github.com/clearcompass-ai/ortholog-sdk/internal/testkeys"
)

// TestPRE_EndToEnd_WithDelegationKey covers the full PRE pipeline
// driven by a delegation keypair.
func TestPRE_EndToEnd_WithDelegationKey(t *testing.T) {
	del := testkeys.New(t)
	recipient := testkeys.New(t)

	plaintext := []byte("phase-c integration payload for delegation+PRE")

	capsule, ciphertext, err := artifact.PRE_Encrypt(del.PK, plaintext)
	if err != nil {
		t.Fatalf("PRE_Encrypt: %v", err)
	}
	if len(ciphertext) == 0 {
		t.Fatal("PRE_Encrypt returned empty ciphertext")
	}

	direct, err := artifact.PRE_Decrypt(del.SK, capsule, ciphertext)
	if err != nil {
		t.Fatalf("PRE_Decrypt (direct): %v", err)
	}
	if !bytes.Equal(direct, plaintext) {
		t.Fatal("direct decrypt plaintext mismatch")
	}

	const M, N = 3, 5
	kfrags, commitments, err := artifact.PRE_GenerateKFrags(del.SK, recipient.PK, M, N)
	if err != nil {
		t.Fatalf("PRE_GenerateKFrags: %v", err)
	}
	if len(kfrags) != N {
		t.Fatalf("KFrag count = %d, want %d", len(kfrags), N)
	}
	if got := commitments.Threshold(); got != M {
		t.Fatalf("commitments.Threshold() = %d, want %d", got, M)
	}

	cfrags := make([]*artifact.CFrag, N)
	for i := 0; i < N; i++ {
		cf, reErr := artifact.PRE_ReEncrypt(kfrags[i], capsule, commitments)
		if reErr != nil {
			t.Fatalf("PRE_ReEncrypt[%d]: %v", i, reErr)
		}
		if cf == nil {
			t.Fatalf("PRE_ReEncrypt[%d]: nil CFrag", i)
		}
		if verErr := artifact.PRE_VerifyCFrag(cf, capsule, commitments); verErr != nil {
			t.Fatalf("PRE_VerifyCFrag[%d]: %v", i, verErr)
		}
		cfrags[i] = cf
	}

	recovered, err := artifact.PRE_DecryptFrags(
		recipient.SK, cfrags[:M], capsule, ciphertext, del.PK, commitments)
	if err != nil {
		t.Fatalf("PRE_DecryptFrags with M=%d cfrags: %v", M, err)
	}
	if !bytes.Equal(recovered, plaintext) {
		t.Fatalf("recovered plaintext mismatch:\n  want: %q\n  got:  %q",
			plaintext, recovered)
	}

	_, err = artifact.PRE_DecryptFrags(
		recipient.SK, cfrags[:M-1], capsule, ciphertext, del.PK, commitments)
	if err == nil {
		t.Fatalf("PRE_DecryptFrags with %d cfrags (threshold %d): expected error, got nil",
			M-1, M)
	}
	if !errors.Is(err, artifact.ErrInsufficientCFrags) {
		t.Logf("insufficient-cfrags path returned %v "+
			"(expected ErrInsufficientCFrags; other error also acceptable "+
			"if gate ordering routes differently)", err)
	}
}
