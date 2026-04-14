package tests

import (
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/admission"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/artifact"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/escrow"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
)

// ── Admission stamps (2 tests) ─────────────────────────────────────────

// Test 20: Mode B stamp generate and verify.
func TestAdmissionStamp_GenerateVerify(t *testing.T) {
	entryHash := [32]byte{1, 2, 3}
	logDID := "did:ortholog:testlog"
	difficulty := uint32(8) // 8 leading zero bits — fast for testing.
	nonce, err := admission.GenerateStamp(entryHash, logDID, difficulty, admission.HashSHA256, nil)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if err := admission.VerifyStamp(entryHash, nonce, logDID, difficulty, admission.HashSHA256, nil); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// Test 21: Stamp bound to target log DID — wrong DID rejected.
func TestAdmissionStamp_WrongLogDIDRejected(t *testing.T) {
	entryHash := [32]byte{4, 5, 6}
	logDID := "did:ortholog:correct"
	difficulty := uint32(8)
	nonce, err := admission.GenerateStamp(entryHash, logDID, difficulty, admission.HashSHA256, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Verify against wrong log DID.
	err = admission.VerifyStamp(entryHash, nonce, "did:ortholog:wrong", difficulty, admission.HashSHA256, nil)
	if err == nil {
		t.Fatal("stamp should fail against wrong log DID")
	}
}

// ── Artifact encryption (2 tests) ──────────────────────────────────────

// Test 22: Encrypt -> decrypt round-trip.
func TestArtifact_EncryptDecrypt(t *testing.T) {
	plaintext := []byte("confidential credential data")
	ciphertext, key, err := artifact.EncryptArtifact(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := artifact.DecryptArtifact(ciphertext, key)
	if err != nil {
		t.Fatal(err)
	}
	if string(recovered) != string(plaintext) {
		t.Fatal("decrypted plaintext doesn't match original")
	}
}

// Test 23: Re-encrypt — old key destroyed, new key decrypts.
func TestArtifact_ReEncrypt(t *testing.T) {
	plaintext := []byte("re-encryption test")
	ciphertext, oldKey, _ := artifact.EncryptArtifact(plaintext)
	newCiphertext, newKey, err := artifact.ReEncryptArtifact(ciphertext, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	// New key decrypts new ciphertext.
	recovered, err := artifact.DecryptArtifact(newCiphertext, newKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(recovered) != string(plaintext) {
		t.Fatal("re-encrypted plaintext doesn't match")
	}
	// Old ciphertext with new key should fail.
	_, err = artifact.DecryptArtifact(ciphertext, newKey)
	if err == nil {
		t.Fatal("old ciphertext should not decrypt with new key")
	}
}

// ── Escrow (2 tests) ───────────────────────────────────────────────────

// Test 24: Shamir 3-of-5 — all C(5,3)=10 subsets reconstruct correctly.
func TestEscrow_Shamir3of5AllSubsets(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef") // 32 bytes.
	shares, err := escrow.SplitGF256(secret, 3, 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(shares) != 5 {
		t.Fatalf("expected 5 shares, got %d", len(shares))
	}
	// Test all C(5,3)=10 subsets.
	count := 0
	for i := 0; i < 5; i++ {
		for j := i + 1; j < 5; j++ {
			for k := j + 1; k < 5; k++ {
				subset := []escrow.Share{shares[i], shares[j], shares[k]}
				recovered, err := escrow.ReconstructGF256(subset)
				if err != nil {
					t.Fatalf("subset {%d,%d,%d}: %v", i, j, k, err)
				}
				if string(recovered) != string(secret) {
					t.Fatalf("subset {%d,%d,%d}: wrong secret", i, j, k)
				}
				count++
			}
		}
	}
	if count != 10 {
		t.Fatalf("tested %d subsets, expected 10", count)
	}
}

// Test 25: Field tag validation — wrong tag rejected.
func TestEscrow_TagValidation(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	shares, _ := escrow.SplitGF256(secret, 2, 3)
	// Corrupt first share's tag.
	shares[0].FieldTag = 0x02 // Wrong field.
	_, err := escrow.ReconstructGF256(shares[:2])
	if err == nil {
		t.Fatal("expected error for unrecognized field tag 0x02")
	}
}

// ── Blind routing (1 test) ─────────────────────────────────────────────

// Test 26: Mock attestation pass/fail.
func TestBlindRouting_MockAttestation(t *testing.T) {
	apple := &escrow.MockAppleAttestation{}
	if err := apple.VerifyAttestation([]byte("valid")); err != nil {
		t.Fatal(err)
	}
	if err := apple.VerifyAttestation(nil); err == nil {
		t.Fatal("nil attestation should fail")
	}
	if apple.Platform() != "apple_secure_enclave_mock" {
		t.Fatal("wrong platform")
	}
	android := &escrow.MockAndroidAttestation{}
	if err := android.VerifyAttestation([]byte("valid")); err != nil {
		t.Fatal(err)
	}
}

// ── Dead CID (1 test) ──────────────────────────────────────────────────

// Test 27: Dead CID -> structured "irrecoverable" error.
func TestDeadCID_Irrecoverable(t *testing.T) {
	cas := storage.NewInMemoryCAS()
	// Push, then delete (simulate key destruction / cryptographic erasure).
	cid, _ := cas.Push([]byte("sensitive data"))
	cas.Delete(cid)
	_, err := cas.Fetch(cid)
	if err == nil {
		t.Fatal("expected not-found error for deleted CID")
	}
	if err != storage.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}

	// Artifact decryption with wrong key -> irrecoverable.
	ciphertext, _, _ := artifact.EncryptArtifact([]byte("data"))
	wrongKey := artifact.ArtifactKey{} // Zero key.
	_, err = artifact.DecryptArtifact(ciphertext, wrongKey)
	if !artifact.IsIrrecoverable(err) {
		t.Fatal("expected IrrecoverableError for wrong key")
	}
}
