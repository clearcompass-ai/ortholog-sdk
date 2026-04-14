package tests

import (
	"crypto/elliptic"
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/artifact"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
)

// TestPRE_EncryptDecryptDirect: Encrypt with pk → decrypt with sk → matches plaintext.
func TestPRE_EncryptDecryptDirect(t *testing.T) {
	key, err := signatures.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pk := elliptic.Marshal(signatures.Secp256k1(), key.PublicKey.X, key.PublicKey.Y)
	sk := make([]byte, 32)
	b := key.D.Bytes()
	copy(sk[32-len(b):], b)

	plaintext := []byte("confidential evidence artifact for PRE test")

	capsule, ct, err := artifact.PRE_Encrypt(pk, plaintext)
	if err != nil {
		t.Fatalf("PRE_Encrypt: %v", err)
	}
	if capsule == nil {
		t.Fatal("capsule should not be nil")
	}

	recovered, err := artifact.PRE_Decrypt(sk, capsule, ct)
	if err != nil {
		t.Fatalf("PRE_Decrypt: %v", err)
	}
	if string(recovered) != string(plaintext) {
		t.Fatal("direct decrypt should recover original plaintext")
	}
}

// TestPRE_ThresholdReEncrypt: 3-of-5 KFrags → any 3 produce valid CFrags →
// recipient combines 3 → decrypts → matches plaintext; 2 CFrags → fails.
func TestPRE_ThresholdReEncrypt(t *testing.T) {
	// Owner key pair
	ownerKey, _ := signatures.GenerateKey()
	ownerPK := elliptic.Marshal(signatures.Secp256k1(), ownerKey.PublicKey.X, ownerKey.PublicKey.Y)
	ownerSK := make([]byte, 32)
	copy(ownerSK[32-len(ownerKey.D.Bytes()):], ownerKey.D.Bytes())

	// Recipient key pair
	recipientKey, _ := signatures.GenerateKey()
	recipientPK := elliptic.Marshal(signatures.Secp256k1(), recipientKey.PublicKey.X, recipientKey.PublicKey.Y)
	recipientSK := make([]byte, 32)
	copy(recipientSK[32-len(recipientKey.D.Bytes()):], recipientKey.D.Bytes())

	// Encrypt for owner
	plaintext := []byte("threshold PRE evidence chain-of-custody")
	capsule, ct, err := artifact.PRE_Encrypt(ownerPK, plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// Generate 5 KFrags with threshold 3
	kfrags, err := artifact.PRE_GenerateKFrags(ownerSK, recipientPK, 3, 5)
	if err != nil {
		t.Fatalf("PRE_GenerateKFrags: %v", err)
	}
	if len(kfrags) != 5 {
		t.Fatalf("expected 5 kfrags, got %d", len(kfrags))
	}

	// Re-encrypt with all 5, use any 3
	cfrags := make([]*artifact.CFrag, 5)
	for i, kf := range kfrags {
		cf, err := artifact.PRE_ReEncrypt(kf, capsule)
		if err != nil {
			t.Fatalf("PRE_ReEncrypt kfrag %d: %v", i, err)
		}
		cfrags[i] = cf
	}

	// Decrypt with 3 cfrags (indices 0,2,4)
	subset3 := []*artifact.CFrag{cfrags[0], cfrags[2], cfrags[4]}
	recovered, err := artifact.PRE_DecryptFrags(recipientSK, subset3, capsule, ct, ownerPK)
	if err != nil {
		t.Fatalf("PRE_DecryptFrags with 3 cfrags: %v", err)
	}
	if string(recovered) != string(plaintext) {
		t.Fatal("threshold decryption should recover plaintext")
	}

	// Decrypt with different 3 cfrags (indices 1,3,4)
	subset3b := []*artifact.CFrag{cfrags[1], cfrags[3], cfrags[4]}
	recovered2, err := artifact.PRE_DecryptFrags(recipientSK, subset3b, capsule, ct, ownerPK)
	if err != nil {
		t.Fatalf("PRE_DecryptFrags with different 3: %v", err)
	}
	if string(recovered2) != string(plaintext) {
		t.Fatal("different 3 cfrags should also recover plaintext")
	}

	// 2 cfrags should fail (below threshold)
	subset2 := []*artifact.CFrag{cfrags[0], cfrags[1]}
	_, err = artifact.PRE_DecryptFrags(recipientSK, subset2, capsule, ct, ownerPK)
	if err == nil {
		t.Fatal("2 cfrags (below threshold 3) should fail decryption")
	}
}

// TestPRE_VerifyCFrag: each CFrag passes VerifyCFrag with NO private key;
// corrupt CFrag → fails; wrong verification key → fails.
func TestPRE_VerifyCFrag(t *testing.T) {
	ownerKey, _ := signatures.GenerateKey()
	ownerPK := elliptic.Marshal(signatures.Secp256k1(), ownerKey.PublicKey.X, ownerKey.PublicKey.Y)
	ownerSK := make([]byte, 32)
	copy(ownerSK[32-len(ownerKey.D.Bytes()):], ownerKey.D.Bytes())

	recipientKey, _ := signatures.GenerateKey()
	recipientPK := elliptic.Marshal(signatures.Secp256k1(), recipientKey.PublicKey.X, recipientKey.PublicKey.Y)

	capsule, _, err := artifact.PRE_Encrypt(ownerPK, []byte("verify cfrag test"))
	if err != nil {
		t.Fatal(err)
	}

	kfrags, err := artifact.PRE_GenerateKFrags(ownerSK, recipientPK, 2, 3)
	if err != nil {
		t.Fatal(err)
	}

	// Re-encrypt and verify each
	for i, kf := range kfrags {
		cf, err := artifact.PRE_ReEncrypt(kf, capsule)
		if err != nil {
			t.Fatalf("ReEncrypt %d: %v", i, err)
		}
		// Verify with correct VK — no private key needed
		if err := artifact.PRE_VerifyCFrag(cf, capsule, kf.VKX, kf.VKY); err != nil {
			t.Fatalf("VerifyCFrag %d should pass: %v", i, err)
		}
	}

	// Corrupt a cfrag — verification should fail
	cf0, _ := artifact.PRE_ReEncrypt(kfrags[0], capsule)
	cf0.ProofZ.SetInt64(999) // corrupt the DLEQ response
	if err := artifact.PRE_VerifyCFrag(cf0, capsule, kfrags[0].VKX, kfrags[0].VKY); err == nil {
		t.Fatal("corrupt cfrag should fail verification")
	}

	// Wrong VK — verification should fail
	cf1, _ := artifact.PRE_ReEncrypt(kfrags[1], capsule)
	// Use kfrags[0]'s VK instead of kfrags[1]'s
	if err := artifact.PRE_VerifyCFrag(cf1, capsule, kfrags[0].VKX, kfrags[0].VKY); err == nil {
		t.Fatal("wrong VK should fail verification")
	}
}

// TestPRE_KFragIsolation: single KFrag insufficient to decrypt;
// M-1 CFrags insufficient to decrypt.
func TestPRE_KFragIsolation(t *testing.T) {
	ownerKey, _ := signatures.GenerateKey()
	ownerPK := elliptic.Marshal(signatures.Secp256k1(), ownerKey.PublicKey.X, ownerKey.PublicKey.Y)
	ownerSK := make([]byte, 32)
	copy(ownerSK[32-len(ownerKey.D.Bytes()):], ownerKey.D.Bytes())

	recipientKey, _ := signatures.GenerateKey()
	recipientPK := elliptic.Marshal(signatures.Secp256k1(), recipientKey.PublicKey.X, recipientKey.PublicKey.Y)
	recipientSK := make([]byte, 32)
	copy(recipientSK[32-len(recipientKey.D.Bytes()):], recipientKey.D.Bytes())

	capsule, ct, _ := artifact.PRE_Encrypt(ownerPK, []byte("isolation test data"))
	kfrags, _ := artifact.PRE_GenerateKFrags(ownerSK, recipientPK, 3, 5)

	// Single cfrag should fail
	cf0, _ := artifact.PRE_ReEncrypt(kfrags[0], capsule)
	_, err := artifact.PRE_DecryptFrags(recipientSK, []*artifact.CFrag{cf0}, capsule, ct, ownerPK)
	if err == nil {
		t.Fatal("single cfrag should be insufficient to decrypt (threshold is 3)")
	}

	// M-1 = 2 cfrags should fail
	cf1, _ := artifact.PRE_ReEncrypt(kfrags[1], capsule)
	_, err = artifact.PRE_DecryptFrags(recipientSK, []*artifact.CFrag{cf0, cf1}, capsule, ct, ownerPK)
	if err == nil {
		t.Fatal("M-1 cfrags should be insufficient to decrypt")
	}

	// M = 3 cfrags should succeed
	cf2, _ := artifact.PRE_ReEncrypt(kfrags[2], capsule)
	recovered, err := artifact.PRE_DecryptFrags(recipientSK, []*artifact.CFrag{cf0, cf1, cf2}, capsule, ct, ownerPK)
	if err != nil {
		t.Fatalf("M cfrags should succeed: %v", err)
	}
	if string(recovered) != "isolation test data" {
		t.Fatal("plaintext mismatch")
	}
}
