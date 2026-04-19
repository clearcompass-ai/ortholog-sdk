package tests

import (
	"github.com/clearcompass-ai/ortholog-sdk/core/envelope"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"testing"
)

func TestEntrySignature_SignVerifyPass(t *testing.T) {
	key, err := signatures.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	entry, _ := makeEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:signer"}, []byte("payload"))
	hash := envelope.EntryIdentity(entry)
	sig, err := signatures.SignEntry(hash, key)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := signatures.VerifyEntry(hash, sig, &key.PublicKey); err != nil {
		t.Fatalf("Verify should pass: %v", err)
	}
}

func TestEntrySignature_CorruptFails(t *testing.T) {
	key, _ := signatures.GenerateKey()
	entry, _ := makeEntry(t, envelope.ControlHeader{Destination: testDestinationDID, SignerDID: "did:example:signer"}, []byte("payload"))
	hash := envelope.EntryIdentity(entry)
	sig, _ := signatures.SignEntry(hash, key)
	sig[0] ^= 0xFF
	if err := signatures.VerifyEntry(hash, sig, &key.PublicKey); err == nil {
		t.Fatal("corrupted signature should fail")
	}
}
