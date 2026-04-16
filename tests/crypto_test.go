package tests

import (
	"testing"

	"github.com/clearcompass-ai/ortholog-sdk/crypto/admission"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/artifact"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/escrow"
	"github.com/clearcompass-ai/ortholog-sdk/crypto/signatures"
	"github.com/clearcompass-ai/ortholog-sdk/storage"
	"github.com/clearcompass-ai/ortholog-sdk/types"
)

// ── Admission stamps ───────────────────────────────────────────────────

func TestAdmissionStamp_GenerateVerify(t *testing.T) {
	entryHash := [32]byte{1, 2, 3}
	logDID := "did:ortholog:testlog"
	difficulty := uint32(8)

	nonce, err := admission.GenerateStamp(admission.StampParams{
		EntryHash:  entryHash,
		LogDID:     logDID,
		Difficulty: difficulty,
		HashFunc:   admission.HashSHA256,
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	proof := &types.AdmissionProof{
		Mode:       types.AdmissionModeB,
		Nonce:      nonce,
		TargetLog:  logDID,
		Difficulty: difficulty,
	}
	if err := admission.VerifyStamp(
		proof, entryHash, logDID, difficulty,
		admission.HashSHA256, nil,
		0, 0, // currentEpoch, acceptanceWindow (0 disables epoch check)
	); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestAdmissionStamp_WrongLogDIDRejected(t *testing.T) {
	entryHash := [32]byte{4, 5, 6}
	nonce, err := admission.GenerateStamp(admission.StampParams{
		EntryHash:  entryHash,
		LogDID:     "did:ortholog:correct",
		Difficulty: 8,
		HashFunc:   admission.HashSHA256,
	})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}

	proof := &types.AdmissionProof{
		Mode:       types.AdmissionModeB,
		Nonce:      nonce,
		TargetLog:  "did:ortholog:correct",
		Difficulty: 8,
	}
	err = admission.VerifyStamp(
		proof, entryHash, "did:ortholog:wrong", 8,
		admission.HashSHA256, nil,
		0, 0,
	)
	if err == nil {
		t.Fatal("stamp should fail against wrong log DID")
	}
}

// ── Artifact encryption ────────────────────────────────────────────────

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
		t.Fatal("decrypted plaintext doesn't match")
	}
}

func TestArtifact_ReEncrypt(t *testing.T) {
	plaintext := []byte("re-encryption test")
	ciphertext, oldKey, _ := artifact.EncryptArtifact(plaintext)
	newCT, newKey, err := artifact.ReEncryptArtifact(ciphertext, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := artifact.DecryptArtifact(newCT, newKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(recovered) != string(plaintext) {
		t.Fatal("re-encrypted plaintext doesn't match")
	}
	_, err = artifact.DecryptArtifact(ciphertext, newKey)
	if err == nil {
		t.Fatal("old ciphertext should not decrypt with new key")
	}
}

// ── Escrow ─────────────────────────────────────────────────────────────

func TestEscrow_Shamir3of5AllSubsets(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	shares, err := escrow.SplitGF256(secret, 3, 5)
	if err != nil {
		t.Fatal(err)
	}
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

func TestEscrow_TagValidation(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	shares, _ := escrow.SplitGF256(secret, 2, 3)
	shares[0].FieldTag = 0x02
	_, err := escrow.ReconstructGF256(shares[:2])
	if err == nil {
		t.Fatal("expected error for unrecognized field tag")
	}
}

// ── Blind routing ──────────────────────────────────────────────────────

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

// ── Dead CID ───────────────────────────────────────────────────────────

func TestDeadCID_Irrecoverable(t *testing.T) {
	cs := storage.NewInMemoryContentStore()
	data := []byte("sensitive data")
	cid := storage.Compute(data)
	cs.Push(cid, data)
	cs.Delete(cid)
	_, err := cs.Fetch(cid)
	if err != storage.ErrNotFound {
		t.Fatalf("expected ErrNotFound, got: %v", err)
	}
	ciphertext, _, _ := artifact.EncryptArtifact([]byte("data"))
	wrongKey := artifact.ArtifactKey{}
	_, err = artifact.DecryptArtifact(ciphertext, wrongKey)
	if !artifact.IsIrrecoverable(err) {
		t.Fatal("expected IrrecoverableError")
	}
}

// ═══════════════════════════════════════════════════════════════════════
// GAP 9: Re-encrypted artifact content_digest preservation
// ═══════════════════════════════════════════════════════════════════════

func TestVerifyAndDecrypt_ReEncryptPreservesContentDigest(t *testing.T) {
	plaintext := []byte("re-encryption invariant: content_digest survives, artifact_cid changes")

	// Original encryption
	ct1, key1, err := artifact.EncryptArtifact(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	artifactCID1 := storage.Compute(ct1)
	contentDigest := storage.Compute(plaintext)

	// Re-encrypt (Tier 1 key rotation)
	ct2, key2, err := artifact.ReEncryptArtifact(ct1, key1)
	if err != nil {
		t.Fatal(err)
	}
	artifactCID2 := storage.Compute(ct2)

	// artifact_cid MUST change (different ciphertext)
	if artifactCID1.Equal(artifactCID2) {
		t.Fatal("re-encryption must produce different artifact_cid")
	}

	// VerifyAndDecrypt with new key, new CID, but SAME content_digest
	recovered, err := artifact.VerifyAndDecrypt(ct2, key2, artifactCID2, contentDigest)
	if err != nil {
		t.Fatalf("VerifyAndDecrypt after re-encrypt should pass: %v", err)
	}
	if string(recovered) != string(plaintext) {
		t.Fatal("recovered plaintext should match original")
	}

	// Old key + old CID still works for old ciphertext
	recovered2, err := artifact.VerifyAndDecrypt(ct1, key1, artifactCID1, contentDigest)
	if err != nil {
		t.Fatalf("VerifyAndDecrypt with original should still pass: %v", err)
	}
	if string(recovered2) != string(plaintext) {
		t.Fatal("original decryption should still work")
	}
}

// ═══════════════════════════════════════════════════════════════════════
// GAP 6: CSPRNG nonce uniqueness across 10K generations
// ═══════════════════════════════════════════════════════════════════════

func TestCSPRNG_NonceUniqueness10K(t *testing.T) {
	const N = 10000
	type keyNonce struct {
		key   [32]byte
		nonce [12]byte
	}
	seen := make(map[keyNonce]bool, N)

	for i := 0; i < N; i++ {
		_, key, err := artifact.EncryptArtifact([]byte("test"))
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		kn := keyNonce{key: key.Key, nonce: key.Nonce}
		if seen[kn] {
			t.Fatalf("duplicate key+nonce at iteration %d", i)
		}
		seen[kn] = true
	}
}

// ═══════════════════════════════════════════════════════════════════════
// GAP 8: Per-node ECIES encrypt/decrypt
// ═══════════════════════════════════════════════════════════════════════

func TestECIES_EncryptDecryptRoundTrip(t *testing.T) {
	nodeKey, err := signatures.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}

	secret := []byte("0123456789abcdef0123456789abcdef")
	shares, err := escrow.SplitGF256(secret, 3, 5)
	if err != nil {
		t.Fatal(err)
	}

	encrypted, err := escrow.EncryptShareForNode(shares[0], &nodeKey.PublicKey)
	if err != nil {
		t.Fatalf("EncryptShareForNode: %v", err)
	}

	recovered, err := escrow.DecryptShareFromNode(encrypted, nodeKey)
	if err != nil {
		t.Fatalf("DecryptShareFromNode: %v", err)
	}

	if recovered.FieldTag != shares[0].FieldTag {
		t.Fatal("field tag mismatch")
	}
	if recovered.Index != shares[0].Index {
		t.Fatal("index mismatch")
	}
	for i := range recovered.Value {
		if recovered.Value[i] != shares[0].Value[i] {
			t.Fatalf("value byte %d mismatch", i)
		}
	}

	wrongKey, _ := signatures.GenerateKey()
	_, err = escrow.DecryptShareFromNode(encrypted, wrongKey)
	if err == nil {
		t.Fatal("wrong key should fail decryption")
	}
}

// ═══════════════════════════════════════════════════════════════════════
// GAP 2 validation: ContentStore interface
// ═══════════════════════════════════════════════════════════════════════

func TestContentStore_PushFetchDelete(t *testing.T) {
	store := storage.NewInMemoryContentStore()
	data := []byte("artifact data for content store")

	cid := storage.Compute(data)

	if err := store.Push(cid, data); err != nil {
		t.Fatal(err)
	}

	exists, err := store.Exists(cid)
	if err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatal("CID should exist after push")
	}

	fetched, err := store.Fetch(cid)
	if err != nil {
		t.Fatal(err)
	}
	if string(fetched) != string(data) {
		t.Fatal("fetched data doesn't match")
	}

	if err := store.Pin(cid); err != nil {
		t.Fatal(err)
	}

	if err := store.Delete(cid); err != nil {
		t.Fatal(err)
	}

	_, err = store.Fetch(cid)
	if err != storage.ErrContentNotFound {
		t.Fatalf("expected ErrContentNotFound, got: %v", err)
	}
}
