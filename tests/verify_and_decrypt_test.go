package tests

import (
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/artifact"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
)

// TestVerifyAndDecrypt_Pass:
//
//	EncryptArtifact(plaintext) → ciphertext, key
//	artifactCID := Compute(ciphertext, SHA256)
//	contentDigest := Compute(plaintext, SHA256)
//	VerifyAndDecrypt(ciphertext, key, artifactCID, contentDigest)
//	→ plaintext returned, matches original.
func TestVerifyAndDecrypt_Pass(t *testing.T) {
	plaintext := []byte("credential payload for escrow")
	ciphertext, key, _ := artifact.EncryptArtifact(plaintext)
	artifactCID := storage.Compute(ciphertext)
	contentDigest := storage.Compute(plaintext)

	recovered, err := artifact.VerifyAndDecrypt(ciphertext, key, artifactCID, contentDigest)
	if err != nil {
		t.Fatalf("VerifyAndDecrypt should pass: %v", err)
	}
	if string(recovered) != string(plaintext) {
		t.Fatal("recovered plaintext doesn't match")
	}

	// Legacy path: zero contentDigest skips step 3
	recovered2, err := artifact.VerifyAndDecrypt(ciphertext, key, artifactCID, storage.CID{})
	if err != nil {
		t.Fatalf("VerifyAndDecrypt legacy path: %v", err)
	}
	if string(recovered2) != string(plaintext) {
		t.Fatal("recovered plaintext doesn't match (legacy)")
	}
}

// TestVerifyAndDecrypt_TamperedCiphertext:
//
//	Flip one byte in ciphertext.
//	VerifyAndDecrypt → fails at step 1 (artifactCID.Verify mismatch).
//	Never reaches decryption.
func TestVerifyAndDecrypt_TamperedCiphertext(t *testing.T) {
	plaintext := []byte("tamper detection — ciphertext integrity")
	ciphertext, key, _ := artifact.EncryptArtifact(plaintext)
	artifactCID := storage.Compute(ciphertext)
	contentDigest := storage.Compute(plaintext)

	// Flip one byte in ciphertext
	tampered := append([]byte{}, ciphertext...)
	tampered[0] ^= 0xFF

	_, err := artifact.VerifyAndDecrypt(tampered, key, artifactCID, contentDigest)
	if !artifact.IsIrrecoverable(err) {
		t.Fatal("should detect tampered ciphertext at step 1 (artifactCID.Verify)")
	}

	// Zero artifactCID with valid contentDigest should also fail
	_, err = artifact.VerifyAndDecrypt(ciphertext, key, storage.CID{}, contentDigest)
	if err == nil {
		t.Fatal("should fail on zero artifact CID")
	}
}

// TestVerifyAndDecrypt_WrongContentDigest:
//
//	Correct ciphertext, correct key, correct artifactCID.
//	Wrong contentDigest (computed from different plaintext).
//	VerifyAndDecrypt → step 1 passes, step 2 decrypts successfully,
//	step 3 fails (contentDigest.Verify mismatch).
//	This catches: someone re-encrypted with different plaintext
//	but claimed the same content_digest.
func TestVerifyAndDecrypt_WrongContentDigest(t *testing.T) {
	plaintext := []byte("the real credential payload")
	ciphertext, key, _ := artifact.EncryptArtifact(plaintext)
	artifactCID := storage.Compute(ciphertext)

	// contentDigest from DIFFERENT plaintext
	wrongDigest := storage.Compute([]byte("attacker's forged content"))

	_, err := artifact.VerifyAndDecrypt(ciphertext, key, artifactCID, wrongDigest)
	if !artifact.IsIrrecoverable(err) {
		t.Fatal("should detect wrong content digest at step 3")
	}

	// Correct digest should pass (sanity check)
	correctDigest := storage.Compute(plaintext)
	recovered, err := artifact.VerifyAndDecrypt(ciphertext, key, artifactCID, correctDigest)
	if err != nil {
		t.Fatalf("correct digest should pass: %v", err)
	}
	if string(recovered) != string(plaintext) {
		t.Fatal("recovered plaintext should match")
	}
}
