/*
FILE PATH: tests/phase6_delegation_key_test.go

Tests for lifecycle/delegation_key.go.

Verifies generation, unwrapping, rejection of invalid inputs, and
end-to-end PRE integration of per-artifact delegation keys.

Function signatures used (locked API):

	lifecycle.GenerateDelegationKey(ownerPubKey []byte) (pkDel []byte, wrappedSkDel []byte, err error)
	lifecycle.UnwrapDelegationKey(wrappedSkDel []byte, ownerSecretKey []byte) ([]byte, error)
	artifact.PRE_GenerateKFrags(skOwner []byte, pkRecipient []byte, M, N int) ([]KFrag, error)
	artifact.PRE_DecryptFrags(skRecipient []byte, cfrags []*CFrag, capsule *Capsule, ciphertext []byte, pkOwner []byte) ([]byte, error)
	did.GenerateRawKey() (*ecdsa.PrivateKey, []byte, error)

Critical alignment notes:
  - PRE_GenerateKFrags returns 2 values ([]KFrag, error), not 3
  - PRE_DecryptFrags takes 5 args — pkOwner in 5th position is pkDel
  - Owner public key for GenerateDelegationKey: 65-byte uncompressed from signatures.PubKeyBytes
  - Owner secret key for UnwrapDelegationKey: 32-byte scalar from padSecretKeyTo32(priv.D)
*/
package tests

import (
	"bytes"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/artifact"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/did"
	"github.com/clearcompass-ai/ortholog-sdk/lifecycle"
)

// ─────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────

// delKeyOwner generates a valid secp256k1 owner keypair for delegation
// key tests. Returns 65-byte uncompressed public key and 32-byte scalar.
func delKeyOwner(t *testing.T) (pubKey []byte, secretKey []byte) {
	t.Helper()
	priv, pubBytes, err := did.GenerateRawKey()
	if err != nil {
		t.Fatalf("generate owner keys: %v", err)
	}
	return pubBytes, padScalarTo32Bytes(priv.D.Bytes())
}

// delKeyRecipient generates a valid secp256k1 recipient keypair.
func delKeyRecipient(t *testing.T) (pubKey []byte, secretKey []byte) {
	t.Helper()
	priv, err := signatures.GenerateKey()
	if err != nil {
		t.Fatalf("generate recipient keys: %v", err)
	}
	pubBytes := signatures.PubKeyBytes(&priv.PublicKey)
	return pubBytes, padScalarTo32Bytes(priv.D.Bytes())
}

// padScalarTo32Bytes pads a big.Int byte representation to exactly 32 bytes.
func padScalarTo32Bytes(b []byte) []byte {
	if len(b) >= 32 {
		return b[len(b)-32:]
	}
	padded := make([]byte, 32)
	copy(padded[32-len(b):], b)
	return padded
}

// ─────────────────────────────────────────────────────────────────────
// Test 1: GenerateDelegationKey_Valid
// pkDel is 65 bytes (0x04 prefix), wrappedSkDel is ~113 bytes ECIES
// ─────────────────────────────────────────────────────────────────────

func TestGenerateDelegationKey_Valid(t *testing.T) {
	pubKey, _ := delKeyOwner(t)

	pkDel, wrappedSkDel, err := lifecycle.GenerateDelegationKey(pubKey)
	if err != nil {
		t.Fatalf("GenerateDelegationKey: %v", err)
	}

	// pkDel must be 65-byte uncompressed secp256k1 point
	if len(pkDel) != 65 {
		t.Fatalf("expected pkDel to be 65 bytes, got %d", len(pkDel))
	}
	if pkDel[0] != 0x04 {
		t.Fatalf("expected uncompressed prefix 0x04, got 0x%02x", pkDel[0])
	}

	// wrappedSkDel is ECIES ciphertext: 65 (ephemeral pubkey) + 12 (nonce) +
	// 32 (plaintext) + 16 (GCM tag) = 125 minimum, but plaintext is 32 bytes
	// of sk_del. Actual: ~113 bytes (65 + 12 + 32 + 16 = 125, minus
	// the 12-byte nonce that's part of the GCM seal).
	// Accept anything >= 93 (minimum ECIES overhead) and <= 200 (generous).
	if len(wrappedSkDel) < 93 || len(wrappedSkDel) > 200 {
		t.Fatalf("expected wrappedSkDel ~113 bytes, got %d", len(wrappedSkDel))
	}
}

// ─────────────────────────────────────────────────────────────────────
// Test 2: GenerateDelegationKey_Unique
// Two calls produce different pkDel/wrappedSkDel
// ─────────────────────────────────────────────────────────────────────

func TestGenerateDelegationKey_Unique(t *testing.T) {
	pubKey, _ := delKeyOwner(t)

	pkDel1, wrapped1, err1 := lifecycle.GenerateDelegationKey(pubKey)
	if err1 != nil {
		t.Fatalf("first call: %v", err1)
	}

	pkDel2, wrapped2, err2 := lifecycle.GenerateDelegationKey(pubKey)
	if err2 != nil {
		t.Fatalf("second call: %v", err2)
	}

	if bytes.Equal(pkDel1, pkDel2) {
		t.Fatal("two calls should produce different delegation public keys")
	}
	if bytes.Equal(wrapped1, wrapped2) {
		t.Fatal("two calls should produce different wrapped ciphertexts")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Test 3: UnwrapDelegationKey_Roundtrip
// Generate → unwrap → skDel is 32 bytes,
// PRE_Encrypt(pkDel) → PRE_Decrypt(skDel) works
// ─────────────────────────────────────────────────────────────────────

func TestUnwrapDelegationKey_Roundtrip(t *testing.T) {
	pubKey, secKey := delKeyOwner(t)

	pkDel, wrappedSkDel, err := lifecycle.GenerateDelegationKey(pubKey)
	if err != nil {
		t.Fatalf("GenerateDelegationKey: %v", err)
	}

	skDel, err := lifecycle.UnwrapDelegationKey(wrappedSkDel, secKey)
	if err != nil {
		t.Fatalf("UnwrapDelegationKey: %v", err)
	}

	if len(skDel) != 32 {
		t.Fatalf("expected skDel to be 32 bytes, got %d", len(skDel))
	}

	// Verify the unwrapped scalar works with PRE: encrypt with pkDel,
	// decrypt directly with skDel.
	plaintext := []byte("roundtrip delegation key test payload")
	capsule, ciphertext, err := artifact.PRE_Encrypt(pkDel, plaintext)
	if err != nil {
		t.Fatalf("PRE_Encrypt with pkDel: %v", err)
	}

	recovered, err := artifact.PRE_Decrypt(skDel, capsule, ciphertext)
	if err != nil {
		t.Fatalf("PRE_Decrypt with skDel: %v", err)
	}

	if !bytes.Equal(plaintext, recovered) {
		t.Fatal("recovered plaintext does not match original")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Test 4: UnwrapDelegationKey_WrongOwnerKey
// Unwrap with different owner SK → ECIES error
// ─────────────────────────────────────────────────────────────────────

func TestUnwrapDelegationKey_WrongOwnerKey(t *testing.T) {
	pubKeyA, _ := delKeyOwner(t)
	_, secKeyB := delKeyOwner(t) // Different keypair

	_, wrappedSkDel, err := lifecycle.GenerateDelegationKey(pubKeyA)
	if err != nil {
		t.Fatalf("GenerateDelegationKey: %v", err)
	}

	_, err = lifecycle.UnwrapDelegationKey(wrappedSkDel, secKeyB)
	if err == nil {
		t.Fatal("unwrapping with wrong owner key should fail")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Test 5: GenerateDelegationKey_NilOwnerKey
// Empty/nil owner public key → error
// ─────────────────────────────────────────────────────────────────────

func TestGenerateDelegationKey_NilOwnerKey(t *testing.T) {
	_, _, err := lifecycle.GenerateDelegationKey(nil)
	if err == nil {
		t.Fatal("nil owner public key should error")
	}

	_, _, err = lifecycle.GenerateDelegationKey([]byte{})
	if err == nil {
		t.Fatal("empty owner public key should error")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Test 6: UnwrapDelegationKey_InvalidScalar
// sk=0 or sk≥N → error
// ─────────────────────────────────────────────────────────────────────

func TestUnwrapDelegationKey_InvalidScalar(t *testing.T) {
	pubKey, _ := delKeyOwner(t)
	_, wrappedSkDel, err := lifecycle.GenerateDelegationKey(pubKey)
	if err != nil {
		t.Fatalf("GenerateDelegationKey: %v", err)
	}

	// Scalar 0 is invalid for secp256k1
	zeroKey := make([]byte, 32)
	_, err = lifecycle.UnwrapDelegationKey(wrappedSkDel, zeroKey)
	if err == nil {
		t.Fatal("invalid scalar (0) should error")
	}

	// Wrong length should also error
	_, err = lifecycle.UnwrapDelegationKey(wrappedSkDel, []byte{0x01})
	if err == nil {
		t.Fatal("invalid scalar length should error")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Test 7: UnwrapDelegationKey_CorruptedCiphertext
// Tampered wrappedSkDel → ECIES decrypt error
// ─────────────────────────────────────────────────────────────────────

func TestUnwrapDelegationKey_CorruptedCiphertext(t *testing.T) {
	pubKey, secKey := delKeyOwner(t)
	_, wrappedSkDel, err := lifecycle.GenerateDelegationKey(pubKey)
	if err != nil {
		t.Fatalf("GenerateDelegationKey: %v", err)
	}

	// Corrupt the last byte of the ciphertext (GCM authentication tag)
	corrupted := make([]byte, len(wrappedSkDel))
	copy(corrupted, wrappedSkDel)
	corrupted[len(corrupted)-1] ^= 0xFF

	_, err = lifecycle.UnwrapDelegationKey(corrupted, secKey)
	if err == nil {
		t.Fatal("corrupted wrapped key should fail to unwrap")
	}
}

// ─────────────────────────────────────────────────────────────────────
// Test 8: PRE_EndToEnd_WithDelegationKey
// Full flow: GenerateDelegationKey → PRE_Encrypt(pkDel) →
// UnwrapDelegationKey → PRE_GenerateKFrags(skDel, recipientPK) →
// PRE_ReEncrypt → PRE_DecryptFrags → plaintext matches
// ─────────────────────────────────────────────────────────────────────

func TestPRE_EndToEnd_WithDelegationKey(t *testing.T) {
	ownerPubKey, ownerSecKey := delKeyOwner(t)
	recipientPubKey, recipientSecKey := delKeyRecipient(t)

	plaintext := []byte("end-to-end PRE delegation key test — full flow")

	// Step 1: Generate Delegation Key
	pkDel, wrappedSkDel, err := lifecycle.GenerateDelegationKey(ownerPubKey)
	if err != nil {
		t.Fatalf("GenerateDelegationKey: %v", err)
	}

	// Step 2: Encrypt artifact using pkDel (NOT ownerPubKey)
	capsule, ciphertext, err := artifact.PRE_Encrypt(pkDel, plaintext)
	if err != nil {
		t.Fatalf("PRE_Encrypt: %v", err)
	}

	// Step 3: Unwrap skDel using the Master Secret Key
	skDel, err := lifecycle.UnwrapDelegationKey(wrappedSkDel, ownerSecKey)
	if err != nil {
		t.Fatalf("UnwrapDelegationKey: %v", err)
	}

	// Verify skDel is mathematically different from ownerSecKey
	if bytes.Equal(skDel, ownerSecKey) {
		t.Fatal("CRITICAL: delegation key must differ from master identity key")
	}

	// Step 4: Generate KFrags using skDel (2 return values, not 3)
	kfrags, err := artifact.PRE_GenerateKFrags(skDel, recipientPubKey, 3, 5)
	if err != nil {
		t.Fatalf("PRE_GenerateKFrags: %v", err)
	}
	if len(kfrags) != 5 {
		t.Fatalf("expected 5 kfrags, got %d", len(kfrags))
	}

	// Step 5: Re-Encrypt (simulated escrow nodes, use first 3 of 5)
	cfrags := make([]*artifact.CFrag, 3)
	for i := 0; i < 3; i++ {
		cf, reErr := artifact.PRE_ReEncrypt(kfrags[i], capsule)
		if reErr != nil {
			t.Fatalf("PRE_ReEncrypt kfrag %d: %v", i, reErr)
		}
		cfrags[i] = cf

		// Verify each CFrag's DLEQ proof (no private key needed)
		if verErr := artifact.PRE_VerifyCFrag(cf, capsule, kfrags[i].VKX, kfrags[i].VKY); verErr != nil {
			t.Fatalf("PRE_VerifyCFrag kfrag %d: %v", i, verErr)
		}
	}

	// Step 6: Decrypt (recipient side)
	// 5th argument is pkDel (the delegation public key), NOT the master owner key
	recovered, err := artifact.PRE_DecryptFrags(recipientSecKey, cfrags, capsule, ciphertext, pkDel)
	if err != nil {
		t.Fatalf("PRE_DecryptFrags: %v", err)
	}

	if !bytes.Equal(plaintext, recovered) {
		t.Fatal("recovered plaintext does not match original")
	}

	// Verify that fewer than M=3 cfrags fails (threshold enforcement)
	_, err = artifact.PRE_DecryptFrags(recipientSecKey, cfrags[:2], capsule, ciphertext, pkDel)
	if err == nil {
		t.Fatal("2 of 3 required cfrags should fail decryption")
	}
}
