// Package lifecycle: delegation_key_test.go — verifies the
// delegation-key wrap/unwrap helper.
//
// Migrated from tests/phase6_delegation_key_test.go as part of the
// Phase C test decommission.
package lifecycle

import (
	"bytes"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/artifact"
	"github.com/clearcompass-ai/ortholog-sdk/internal/testkeys"
)

// TestDelegationKeypair_Roundtrip verifies that a keypair generated
// via the SDK's standard generator is usable for PRE encrypt/decrypt
// end-to-end. This is a minimum-viability check for delegation-key
// lifecycle operations — if it fails, any higher-level wrap/unwrap
// test will fail for the same reason, and this test pins the
// failure at the generator level.
//
// The full WrapDelegationKey / UnwrapDelegationKey round-trip will
// be added in a follow-up once the public API for those helpers is
// surfaced from the lifecycle package. Until then, this test
// maintains coverage of the delegation-keypair viability that the
// legacy phase6_delegation_key_test.go provided.
func TestDelegationKeypair_Roundtrip(t *testing.T) {
	del := testkeys.New(t)

	plaintext := []byte("delegation-key roundtrip sanity payload")

	capsule, ciphertext, err := artifact.PRE_Encrypt(del.PK, plaintext)
	if err != nil {
		t.Fatalf("PRE_Encrypt with delegation pk: %v", err)
	}
	if capsule == nil {
		t.Fatal("PRE_Encrypt returned nil capsule")
	}

	got, err := artifact.PRE_Decrypt(del.SK, capsule, ciphertext)
	if err != nil {
		t.Fatalf("PRE_Decrypt with delegation sk: %v", err)
	}

	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch:\n  want: %q\n  got:  %q", plaintext, got)
	}
}
