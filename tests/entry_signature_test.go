package tests

import (
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/crypto"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
)

// Test 16: Sign -> verify -> pass.
func TestEntrySignature_SignVerifyPass(t *testing.T) {
	key, err := signatures.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	entry, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID: "did:example:signer",
	}, []byte("payload"))
	hash := crypto.CanonicalHash(entry)
	sig, err := signatures.SignEntry(hash, key)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := signatures.VerifyEntry(hash, sig, &key.PublicKey); err != nil {
		t.Fatalf("Verify should pass: %v", err)
	}
}

// Test 17: Corrupt signature -> fail.
func TestEntrySignature_CorruptFails(t *testing.T) {
	key, _ := signatures.GenerateKey()
	entry, _ := makeEntry(t, envelope.ControlHeader{
		SignerDID: "did:example:signer",
	}, []byte("payload"))
	hash := crypto.CanonicalHash(entry)
	sig, _ := signatures.SignEntry(hash, key)
	sig[0] ^= 0xFF // Corrupt.
	if err := signatures.VerifyEntry(hash, sig, &key.PublicKey); err == nil {
		t.Fatal("corrupted signature should fail verification")
	}
}
