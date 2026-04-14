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

// ── CID (3 tests) ──────────────────────────────────────────────────────

// Test 28: CID compute → string → parse → verify round-trip.
func TestCID_RoundTrip(t *testing.T) {
	data := []byte("content-addressed artifact payload")
	cid := storage.Compute(data)

	// String round-trip.
	s := cid.String()
	parsed, err := storage.ParseCID(s)
	if err != nil {
		t.Fatalf("ParseCID(%q): %v", s, err)
	}
	if !cid.Equal(parsed) {
		t.Fatal("parsed CID should equal original")
	}

	// Bytes round-trip.
	b := cid.Bytes()
	parsedB, err := storage.ParseCIDBytes(b)
	if err != nil {
		t.Fatalf("ParseCIDBytes: %v", err)
	}
	if !cid.Equal(parsedB) {
		t.Fatal("bytes-parsed CID should equal original")
	}

	// Verify against original data.
	if !cid.Verify(data) {
		t.Fatal("CID should verify against original data")
	}

	// Verify rejects tampered data.
	tampered := append([]byte{}, data...)
	tampered[0] ^= 0xFF
	if cid.Verify(tampered) {
		t.Fatal("CID should reject tampered data")
	}

	// CAS interop: Push produces the same string as Compute.
	cas := storage.NewInMemoryCAS()
	casCID, _ := cas.Push(data)
	if casCID != s {
		t.Fatalf("CAS CID %q != Compute CID %q", casCID, s)
	}
}

// Test 29: VerifyAndDecrypt — full three-step chain passes.
func TestVerifyAndDecrypt_Pass(t *testing.T) {
	plaintext := []byte("credential payload for escrow")

	// Encrypt.
	ciphertext, key, err := artifact.EncryptArtifact(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	// Compute CIDs.
	artifactCID := storage.Compute(ciphertext)
	contentDigest := storage.Compute(plaintext)

	// VerifyAndDecrypt — all three steps pass.
	recovered, err := artifact.VerifyAndDecrypt(ciphertext, key, artifactCID, contentDigest)
	if err != nil {
		t.Fatalf("VerifyAndDecrypt should pass: %v", err)
	}
	if string(recovered) != string(plaintext) {
		t.Fatal("recovered plaintext doesn't match original")
	}

	// Also verify with zero contentDigest (legacy path — skips step 3).
	recovered2, err := artifact.VerifyAndDecrypt(ciphertext, key, artifactCID, storage.CID{})
	if err != nil {
		t.Fatalf("VerifyAndDecrypt with zero contentDigest should pass: %v", err)
	}
	if string(recovered2) != string(plaintext) {
		t.Fatal("recovered plaintext doesn't match (legacy path)")
	}
}

// Test 30: VerifyAndDecrypt — tampered ciphertext detected at step 1.
func TestVerifyAndDecrypt_TamperDetected(t *testing.T) {
	plaintext := []byte("tamper detection test")
	ciphertext, key, _ := artifact.EncryptArtifact(plaintext)
	artifactCID := storage.Compute(ciphertext)
	contentDigest := storage.Compute(plaintext)

	// Tamper ciphertext — step 1 (storage integrity) should catch this.
	tampered := append([]byte{}, ciphertext...)
	tampered[0] ^= 0xFF

	_, err := artifact.VerifyAndDecrypt(tampered, key, artifactCID, contentDigest)
	if err == nil {
		t.Fatal("VerifyAndDecrypt should fail on tampered ciphertext")
	}
	if !artifact.IsIrrecoverable(err) {
		t.Fatalf("expected IrrecoverableError, got: %v", err)
	}

	// Wrong content digest — step 3 (content integrity) should catch this.
	wrongDigest := storage.Compute([]byte("wrong content"))
	_, err = artifact.VerifyAndDecrypt(ciphertext, key, artifactCID, wrongDigest)
	if err == nil {
		t.Fatal("VerifyAndDecrypt should fail on wrong content digest")
	}
	if !artifact.IsIrrecoverable(err) {
		t.Fatalf("expected IrrecoverableError for content mismatch, got: %v", err)
	}

	// Zero artifact CID — rejected immediately.
	_, err = artifact.VerifyAndDecrypt(ciphertext, key, storage.CID{}, contentDigest)
	if err == nil {
		t.Fatal("VerifyAndDecrypt should fail on zero artifact CID")
	}
}
